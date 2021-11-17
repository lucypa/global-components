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

#include <virtqueue.h>
#include <camkes/virtqueue.h>
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
    /* Index into buffer_metadata array */
    unsigned int index;
} ethernet_buffer_t;

typedef struct state {
    struct netif netif;
    /* mac address for this client */
    uint8_t mac[6];
    ps_io_ops_t *io_ops;

    /* Pointers to shared buffers */
    ring_t *rx_avail;
    ring_t *rx_used;
    ring_t *tx_avail;
    ring_t *tx_used;

    notify_fn server_rx_notify;
    notify_fn server_tx_notify;
    /*
     * Metadata associated with buffers
     */
    ethernet_buffer_t buffer_metadata[NUM_BUFFERS * 2];
    /*
     * Free buffers for TX
     */
    ethernet_buffer_t *available_tx[NUM_BUFFERS];
    size_t num_available_tx;
} state_t;

static register_cb_fn reg_rx_cb;
static register_cb_fn reg_tx_cb;

static int insert_ring(ring_t *ring, uintptr_t buffer, unsigned int len, unsigned int index)
{
    if ((ring->write_idx - ring->read_idx + 1) % RING_SIZE) {
        int i = ring->write_idx % RING_SIZE;
        ring->buffers[i].encoded_addr = buffer;
        ring->buffers[i].len = len;
        ring->buffers[i].idx = index;
        ring->write_idx++;
        THREAD_MEMORY_RELEASE();
        return 0;
    }

    ZF_LOGE("Ring full");
    return -1; 
}

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
            ZF_LOGW("Returning TX buffer");
            assert(state->num_available_tx < NUM_BUFFERS);
            state->available_tx[state->num_available_tx] = buffer;
            state->num_available_tx += 1;
            break;

        case ORIGIN_RX_QUEUE: {
            ZF_LOGW("Returning RX buffer");
            // As the rx_available ring is the size of the number of buffers we have, 
            // the ring should never be full. 
            insert_ring(state->rx_avail, buffer->dma_addr, buffer->size, buffer->index);
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
    ring_t *rx_used = state->rx_used;

    while((rx_used->write_idx - rx_used->read_idx) % RING_SIZE) {
        int index = rx_used->buffers[rx_used->read_idx % RING_SIZE].idx;

        ethernet_buffer_t *buffer = &state->buffer_metadata[index];
        assert(buffer->dma_addr = rx_used->buffers[index].encoded_addr);
        assert(!buffer->allocated);
        buffer->allocated = true;

        THREAD_MEMORY_RELEASE();
        rx_used->read_idx++;

        struct pbuf *p = create_interface_buffer(state, buffer, buffer->size);

        if (state->netif.input(p, &state->netif) != ERR_OK) {
            // If it is successfully received, the receiver controls whether or not it gets freed.
            ZF_LOGE("netif.input() != ERR_OK");
            pbuf_free(p);
        }

        COMPILER_MEMORY_ACQUIRE();
    }

    int error = reg_rx_cb(rx_queue, cookie);
    ZF_LOGF_IF(error, "Unable to register handler");
    // TODO: The queue is empty. Notify the driver to re-enable RX IRQs. 
}

static void checksum(unsigned char *buffer, unsigned int len) {
    unsigned int csum;
    unsigned char *p;
    unsigned int i;
    for (p = buffer, i=len, csum=0; i > 0; csum += *p++, --i);
    printf("check sum = %zu\n", csum);
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

    checksum(frame, copied);
    /* insert into the used tx queue */
    ZF_LOGW("Inserting buffer into tx_used queue");

    int error = insert_ring(state->tx_used, (void*)ENCODE_DMA_ADDRESS(frame), copied, buffer->index);
    if (error) {
        ZF_LOGF("lwip_eth_send: Error while enqueuing used buffer, tx used queue full");
        free_buffer(state, buffer);
    }

    /* Notify the server */
    state->server_tx_notify();

    return ret;
}

/* Packets have been sent. We can reuse their buffers. */
static void tx_done(void *cookie)
{
    state_t *state = cookie;
    ring_t *tx_avail = state->tx_avail;

    while((tx_avail->write_idx - tx_avail->read_idx) % RING_SIZE) {
        ZF_LOGW("returning buffer");
        unsigned int index = tx_avail->buffers[tx_avail->read_idx % RING_SIZE].idx;
        ethernet_buffer_t *buffer = &state->buffer_metadata[index];

        /* Little sanity check */
        assert(buffer->dma_addr = tx_avail->buffers[tx_avail->read_idx % RING_SIZE].encoded_addr);
        THREAD_MEMORY_RELEASE();
        tx_avail->read_idx++;

        /* return buffer to unused queue. */
        buffer->allocated = false;
        mark_buffer_unused(state, buffer);
    }

    /* re register the notification callback. */
    int error = reg_tx_cb(tx_done, state);
    ZF_LOGF_IF(error, "Unable to register handler");
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

    ZF_LOGW("Ethernet initialised");
    return ERR_OK;
}

static void client_init_tx(state_t *data, void *tx_available, void *tx_used, register_cb_fn reg_tx)
{
    int error = reg_tx(tx_done, data);
    if (error) {
        ZF_LOGE("Unable to register handler");
    }

    reg_tx_cb = reg_tx;

    data->tx_avail = (ring_t *)tx_available;
    data->tx_used = (ring_t *)tx_used;

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
            .index = i + NUM_BUFFERS,
        };

        data->available_tx[data->num_available_tx] = buffer;
        data->num_available_tx++;
    }
}

static void client_init_rx(state_t *state, void *rx_available, void *rx_used, register_cb_fn reg_rx)
{
    int error = reg_rx(rx_queue, state);
    if (error) {
        ZF_LOGE("Unable to register handler");
    }

    reg_rx_cb = reg_rx;

    ring_t *rx_avail = (ring_t *)rx_available;
    state->rx_avail = rx_avail;
    state->rx_used = (ring_t *)rx_used;

    rx_avail->write_idx = 0;
    rx_avail->read_idx = 0;

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
            .index = i,
        };

        insert_ring(rx_avail, buffer->dma_addr, BUFFER_SIZE, i);
    }

}

int lwip_ethernet_async_client_init(ps_io_ops_t *io_ops, get_mac_client_fn_t get_mac, void **cookie, 
                void *rx_available, void *rx_used, void *tx_available, void *tx_used, 
                register_cb_fn reg_rx_cb, register_cb_fn reg_tx_cb, 
                notify_fn rx_notify, notify_fn tx_notify)
{
    state_t *data;
    int error = ps_calloc(
        &io_ops->malloc_ops,
        1,
        sizeof(*data),
        (void **)&data
    );
    ZF_LOGF_IF(error != 0, "Unable to ethernet state");
    data->io_ops = io_ops;

    data->server_rx_notify = rx_notify;
    data->server_tx_notify = tx_notify;

    client_init_rx(data, rx_available, rx_used, reg_rx_cb);
    client_init_tx(data, tx_available, tx_used, reg_tx_cb);

    LWIP_MEMPOOL_INIT(RX_POOL);

    get_mac(&data->mac[0], &data->mac[1], &data->mac[2], &data->mac[3], &data->mac[4], &data->mac[5]);

    /* Set some dummy IP configuration values to get lwIP bootstrapped  */
    struct ip4_addr netmask, ipaddr, gw, multicast;
    ipaddr_aton("0.0.0.0", &gw);
    ipaddr_aton("0.0.0.0", &ipaddr);
    ipaddr_aton("0.0.0.0", &multicast);
    ipaddr_aton("255.255.255.0", &netmask);

    data->netif.name[0] = 'e';
    data->netif.name[1] = '0';

    if (!netif_add(&data->netif, &ipaddr, &netmask, &gw, data,
              ethernet_init, ethernet_input)) {
        ZF_LOGE("Netif add returned NULL");
    }
    netif_set_default(&data->netif);

    *cookie = data;

    return 0;    
}