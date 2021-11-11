/*
 * Copyright 2020, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_BSD)
 */

#include <autoconf.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <sel4/sel4.h>

#include <camkes/dataport.h>
#include <lwip-ethernet-async.h>

#include <lwip/init.h>
#include <netif/etharp.h>
#include <lwip/pbuf.h>
#include <lwip/netif.h>
#include <lwip/stats.h>
#include <lwip/snmp.h>
#include <lwip/sys.h>

#include <ring.h>

#define LINK_SPEED 1000000000 // Gigabit
#define ETHER_MTU 1500
#define NUM_BUFFERS 512

/*
 * These structures track the buffers used to construct packets
 * sent via this network interface.
 *
 * As the interface is asynchronous, when a buffer is freed it isn't
 * returned to the pool until any outstanding asynchronous use
 * completes.
 */
typedef enum {
    ORIGIN_RX_QUEUE,
    ORIGIN_TX_QUEUE,
} ethernet_buffer_origin_t;

typedef struct ethernet_buffer {
    /* The acutal underlying memory of the buffer */
    unsigned char *buffer;
    /* The encoded DMA address */
    uintptr_t dma_addr;
    /* The physical size of the buffer */
    size_t size;
    /* Whether the buffer has been allocated */
    bool allocated;
    /* Whether the buffer is in use by the ethernet device */
    bool in_async_use;
    /* Queue from which the buffer was allocated */
    char origin;
} ethernet_buffer_t;

typedef struct state {
    struct netif netif;
    /* mac address for this client */
    uint8_t mac[6];
    ps_io_ops_t *io_ops;

    /* Pointers to shared buffers */
    dataport_t *tx;
    dataport_t *rx;

    rx_notify_fn server_rx_notify;
    tx_notify_fn server_tx_notify;
    /*
     * Metadata associated with buffers
     */
    ethernet_buffer_t buffer_metadata[NUM_BUFFERS * 2];
    /*
     * Associated data for each element of the TX & RX virtqueue
     */
    ethernet_buffer_t **tx_queue_data; /* These have the same index as the ring_t used */
    ethernet_buffer_t **rx_queue_data;
    /*
     * Free buffers for TX
     */
    ethernet_buffer_t *available_tx[NUM_BUFFERS];
    size_t num_available_tx;
} state_t;

static register_cb_fn reg_rx_cb;
static register_cb_fn reg_tx_cb;

/* Allocate an empty TX buffer from the empty pool */
static inline ethernet_buffer_t *alloc_tx_buffer(state_t *state, size_t length)
{
    if (state->num_available_tx > 0) {
        state->num_available_tx -= 1;
        ethernet_buffer_t *buffer =  state->available_tx[state->num_available_tx];

        if (buffer->size < length) {
            /* Requested size too large */
            state->num_available_tx += 1;
            ZF_LOGE("Requested buffer size too large.");
            return NULL;
        } else {
            buffer->allocated = true;
            return buffer;
        }
    } else {
        ZF_LOGF("No buffers left available");
        return NULL;
    }
}

/* Return a buffer to the appropriate queue */
static inline void return_buffer(state_t *state, ethernet_buffer_t *buffer)
{
    switch (buffer->origin) {
        case ORIGIN_TX_QUEUE:
            assert(state->num_available_tx < NUM_BUFFERS);
            state->available_tx[state->num_available_tx] = buffer;
            state->num_available_tx += 1;
            break;

        case ORIGIN_RX_QUEUE: {
            // As the rx_available ring is the size of the number of buffers we have, 
            // the ring should never be full. 
            ring_t *ring = state->rx->available;
            ring->buffer[ring->write_idx % RING_SIZE] = buffer->dma_addr;
            ring->len[ring->write_idx % RING_SIZE] = buffer->size;
            state->rx_queue_data[ring->write_idx % RING_SIZE] = buffer;
            COMPILER_MEMORY_RELEASE();
            ring->write_idx++;
            break;
        }
    }
}

static inline void free_buffer(state_t *data, ethernet_buffer_t *buffer)
{
    assert(buffer != NULL);
    assert(buffer->allocated);

    buffer->allocated = false;

    if (!buffer->in_async_use) {
        return_buffer(data, buffer);
    }
}

static inline void mark_buffer_used(ethernet_buffer_t *buffer)
{
    assert(buffer != NULL);
    assert(buffer->allocated);
    assert(!buffer->in_async_use);

    buffer->in_async_use = true;
}

static inline void mark_buffer_unused(state_t *data, ethernet_buffer_t *buffer)
{
    assert(buffer != NULL);
    assert(buffer->in_async_use);

    buffer->in_async_use = false;

    if (!buffer->allocated) {
        return_buffer(data, buffer);
    }
}

typedef struct lwip_custom_pbuf {
    struct pbuf_custom custom;
    ethernet_buffer_t *buffer;
    state_t *state;
} lwip_custom_pbuf_t;
LWIP_MEMPOOL_DECLARE(
    RX_POOL,
    NUM_BUFFERS * 2,
    sizeof(lwip_custom_pbuf_t),
    "Zero-copy RX pool"
);

static void interface_free_buffer(struct pbuf *buf)
{
    SYS_ARCH_DECL_PROTECT(old_level);

    lwip_custom_pbuf_t *custom_pbuf = (lwip_custom_pbuf_t *) buf;

    SYS_ARCH_PROTECT(old_level);
    free_buffer(custom_pbuf->state, custom_pbuf->buffer);
    LWIP_MEMPOOL_FREE(RX_POOL, custom_pbuf);
    SYS_ARCH_UNPROTECT(old_level);
}

static struct pbuf *create_interface_buffer(state_t *state, ethernet_buffer_t *buffer, size_t length) 
{
    lwip_custom_pbuf_t *custom_pbuf = (lwip_custom_pbuf_t *) LWIP_MEMPOOL_ALLOC(RX_POOL);

    custom_pbuf->state = state;
    custom_pbuf->buffer = buffer;
    custom_pbuf->custom.custom_free_function = interface_free_buffer;

    return pbuf_alloced_custom(
        PBUF_RAW,
        length,
        PBUF_REF,
        &custom_pbuf->custom,
        buffer->buffer,
        buffer->size
    );
}

/* New packets have been received and waiting in the used queue.*/
static void rx_queue(void *cookie)
{
    state_t *state = cookie;
    /* get buffers from used RX ring */
    ring_t *rx_used = state->rx->used;

    while((rx_used->write_idx - rx_used->read_idx) % RING_SIZE) {
        int index = rx_used->read_idx % RING_SIZE;

        ethernet_buffer_t *buffer = state->rx_queue_data[index];
        assert(!buffer->allocated);
        buffer->allocated = true;
        state->rx_queue_data[index] = NULL;

        COMPILER_MEMORY_RELEASE();
        rx_used->read_idx++;

        struct pbuf *p = create_interface_buffer(state, buffer, buffer->size);

        if (state->netif.input(p, &state->netif) != ERR_OK) {
            // If it is successfully received, the receiver controls whether or not it gets freed.
            ZF_LOGE("netif.input() != ERR_OK");
            pbuf_free(p);
        }

        COMPILER_MEMORY_ACQUIRE();
    }

    reg_rx_cb(rx_queue, cookie);
    // TODO: The queue is empty. Notify the driver to re-enable RX IRQs. 
}

/* We have packets to send */
static err_t lwip_eth_send(struct netif *netif, struct pbuf *p)
{
    /* Grab an available TX buffer, copy pbuf data over, 
    add to used tx ring, notify server */
    err_t ret = ERR_OK;

    if (p->tot_len > BUFFER_SIZE) {
        ZF_LOGF("len %hu is invalid in lwip_eth_send", p->tot_len);
        return ERR_MEM;
    }

    state_t *state = (state_t *)netif->state;

    ethernet_buffer_t *buffer = alloc_tx_buffer(state, p->tot_len);
    if (buffer == NULL) {
        ZF_LOGF("Out of ethernet memory");
        return ERR_MEM;
    }
    unsigned char *frame = buffer->buffer;

    /* Copy all buffers that need to be copied */
    unsigned int copied = 0;
    for (struct pbuf *curr = p; curr != NULL; curr = curr->next) {
        unsigned char *buffer_dest = &frame[copied];
        if ((uintptr_t)buffer_dest != (uintptr_t)curr->payload) {
            /* Don't copy memory back into the same location */
            memcpy(buffer_dest, curr->payload, curr->len);
        }
        copied += curr->len;
    }

    mark_buffer_used(buffer);

    ring_t *tx_used = state->tx->used;
    /* insert into the used tx queue */
    if ((tx_used->write_idx - tx_used->read_idx + 1) % RING_SIZE) {
        ZF_LOGF("lwip_eth_send: Error while enqueuing used buffer, tx used queue full");
        free_buffer(state, buffer);
    } else {
        tx_used->buffer[tx_used->write_idx % RING_SIZE] = (void*)ENCODE_DMA_ADDRESS(frame);
        tx_used->len[tx_used->write_idx % RING_SIZE] = copied;
        
        state->tx_queue_data[tx_used->write_idx % RING_SIZE] = buffer;
        COMPILER_MEMORY_RELEASE();
        tx_used->write_idx++;
        /* notify the server */
        state->server_tx_notify();
    }

    return ret;
}

/* Packets have been sent. We can reuse their buffers. */
static void tx_done(void *cookie)
{
    state_t *state = cookie;
    ring_t *tx_avail = state->tx->available;

    while((tx_avail->write_idx - tx_avail->read_idx) % RING_SIZE) {
        ethernet_buffer_t *buffer = state->tx_queue_data[tx_avail->read_idx % RING_SIZE];
        state->tx_queue_data[tx_avail->read_idx % RING_SIZE] = NULL;

        COMPILER_MEMORY_RELEASE();
        tx_avail->read_idx++;

        /* return buffer to unused queue. */
        mark_buffer_unused(state, buffer);

        COMPILER_MEMORY_ACQUIRE();
    }

    /* re register the notification callback. */
    reg_tx_cb(tx_done, state);
}

static err_t ethernet_init(struct netif *netif)
{
    if (netif->state == NULL) {
        return ERR_ARG;
    }

    state_t *data = netif->state;

    netif->hwaddr[0] = data->mac[0];
    netif->hwaddr[1] = data->mac[1];
    netif->hwaddr[2] = data->mac[2];
    netif->hwaddr[3] = data->mac[3];
    netif->hwaddr[4] = data->mac[4];
    netif->hwaddr[5] = data->mac[5];
    netif->mtu = ETHER_MTU;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    netif->output = etharp_output;
    netif->linkoutput = lwip_eth_send;
    NETIF_INIT_SNMP(netif, snmp_ifType_ethernet_csmacd, LINK_SPEED);
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_IGMP;

    return ERR_OK;
}

static void client_init_tx(state_t *data, dataport_t *tx_dataport_buf, register_cb_fn reg_tx)
{
    seL4_Word tx_badge;

    int error = reg_tx(tx_done, data);
    if (error) {
        ZF_LOGE("Unable to register handler");
    }

    reg_tx_cb = reg_tx;

    data->tx = tx_dataport_buf;

    ring_t *tx_avail = data->tx->available;
    tx_avail->write_idx = 0;
    tx_avail->read_idx = 0;

    ring_t *tx_used = data->tx->used;
    tx_used->write_idx = 0;
    tx_used->read_idx = 0;

    COMPILER_MEMORY_RELEASE();

    /* Allocate tx rings */
    data->num_available_tx = 0;
    for (int i = 0; i < NUM_BUFFERS - 1; i++) {
        void *buf = ps_dma_alloc(
            &data->io_ops->dma_manager,
            BUFFER_SIZE,
            64,
            1,
            PS_MEM_NORMAL
        );
        ZF_LOGF_IF(!buf, "Failed to allocate buffer for pending TX ring.");
        memset(buf, 0, BUFFER_SIZE);

        ethernet_buffer_t *buffer = &data->buffer_metadata[i + NUM_BUFFERS];
        *buffer = (ethernet_buffer_t) {
            .buffer = buf,
            .dma_addr = ENCODE_DMA_ADDRESS(buf),
            .size = BUFFER_SIZE,
            .origin = ORIGIN_TX_QUEUE,
            .allocated = false,
            .in_async_use = false,
        };

        data->available_tx[data->num_available_tx] = buffer;
        data->num_available_tx++;
    }
}

static void client_init_rx(state_t *state, dataport_t *rx_dataport_buf, register_cb_fn reg_rx)
{
    ZF_LOGW("Client_init_rx");
    int error = reg_rx(rx_queue, state);
    if (error) {
        ZF_LOGE("Unable to register handler");
    }

    reg_rx_cb = reg_rx;

    state->rx = rx_dataport_buf;
    ZF_LOGW("Do we get here");

    ring_t *rx_used = state->rx->used;
    ZF_LOGW("is this the problem");
    rx_used->write_idx = 0;
    rx_used->read_idx = 0;

    ring_t *rx_avail = state->rx->available;
    rx_avail->write_idx = 0;
    rx_avail->read_idx = 0;

    ZF_LOGW("Or here");
    /* Pre allocate buffers */  
    for (int i = 0; i < NUM_BUFFERS - 1; i++) {
        void *buf = ps_dma_alloc(
            &state->io_ops->dma_manager,
            BUFFER_SIZE,
            64,
            1,
            PS_MEM_NORMAL
        );
        assert(buf);
        memset(buf, 0, BUFFER_SIZE);
        ZF_LOGF_IF(buf == NULL, "Failed to allocate DMA memory for pending rx ring");

        ethernet_buffer_t *buffer = &state->buffer_metadata[i];

        *buffer = (ethernet_buffer_t) {
            .buffer = buf,
            .dma_addr = ENCODE_DMA_ADDRESS(buf),
            .size = BUFFER_SIZE,
            .origin = ORIGIN_RX_QUEUE,
            .allocated = false,
            .in_async_use = false,
        };

        rx_avail->buffer[rx_avail->write_idx % RING_SIZE] = (void *)buffer->dma_addr;
        rx_avail->buffer[rx_avail->write_idx % RING_SIZE] = buffer->size;

        state->rx_queue_data[rx_avail->write_idx % RING_SIZE] = buffer;
        COMPILER_MEMORY_RELEASE();
        rx_avail->write_idx++;
    }

    ZF_LOGW("Finished client init rx");
}

int lwip_ethernet_async_client_init(ps_io_ops_t *io_ops, get_mac_client_fn_t get_mac, void **cookie, 
                dataport_t *rx_dataport_buf, dataport_t *tx_dataport_buf, register_cb_fn reg_rx_cb, register_cb_fn reg_tx_cb, 
                rx_notify_fn rx_notify, tx_notify_fn tx_notify)
{
    ZF_LOGW("HELLO client\n");
    state_t *data;
    int error = ps_calloc(
        &io_ops->malloc_ops,
        1,
        sizeof(*data),
        (void **)&data
    );
    ZF_LOGF_IF(error != 0, "Unable to ethernet state");
    data->io_ops = io_ops;

    error = ps_calloc(
        &io_ops->malloc_ops,
        RING_SIZE,
        sizeof(data->rx_queue_data[0]),
        (void **)&data->rx_queue_data
    );
    ZF_LOGF_IF(error != 0, "Unable to allocate RX queue metadata");

    error = ps_calloc(
        &io_ops->malloc_ops,
        RING_SIZE,
        sizeof(data->tx_queue_data[0]),
        (void **)&data->tx_queue_data
    );
    ZF_LOGF_IF(error != 0, "Unable to allocate TX queue metadata");

    /*error = ps_calloc(&io_ops->malloc_ops, 1, sizeof(struct dataport), (void **)&data->tx);
    ZF_LOGF_IF(error, "Failed to calloc dataport tx");
    error = ps_calloc(&io_ops->malloc_ops, 1, sizeof(struct dataport), (void **)&data->rx);
    ZF_LOGF_IF(error, "Failed to calloc dataport rx"); */

    LWIP_MEMPOOL_INIT(RX_POOL);

    data->server_rx_notify = rx_notify;
    data->server_tx_notify = tx_notify;

    client_init_rx(data, rx_dataport_buf, reg_rx_cb);
    ZF_LOGW("Rx avail write_idx = %d", data->rx->available->write_idx);
    client_init_tx(data, tx_dataport_buf, reg_tx_cb);

    get_mac(&data->mac[0], &data->mac[1], &data->mac[2], &data->mac[3], &data->mac[4], &data->mac[5]);

    /* Set some dummy IP configuration values to get lwIP bootstrapped  */
    struct ip4_addr netmask, ipaddr, gw, multicast;
    ipaddr_aton("0.0.0.0", &gw);
    ipaddr_aton("0.0.0.0", &ipaddr);
    ipaddr_aton("0.0.0.0", &multicast);
    ipaddr_aton("255.255.255.0", &netmask);

    data->netif.name[0] = 'e';
    data->netif.name[1] = '0';

    netif_add(&data->netif, &ipaddr, &netmask, &gw, data,
              ethernet_init, ethernet_input);
    netif_set_default(&data->netif);

    *cookie = data;

    ZF_LOGW("Rx avail write_idx = %d", data->rx->available->write_idx);    
    ZF_LOGW("Finished lwip_ethernet_async_client_init");

    return 0;    
}