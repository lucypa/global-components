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

typedef struct state {
    struct netif netif;
    /* mac address for this client */
    uint8_t mac[6];
    ps_io_ops_t *io_ops;
    /*
     * Metadata associated with buffers
     */
    ethernet_buffer_t buffer_metadata[NUM_BUFFERS * 2];
    /*
     * Free buffers for TX; this is a first in last out queue. 
     */
    ethernet_buffer_t *available_tx[NUM_BUFFERS]; 
    size_t num_available_tx;
} state_t;

static state_t *data;

/* Allocate an empty TX buffer from the empty pool */
static inline ethernet_buffer_t *alloc_tx_buffer(size_t length)
{
    if (data->num_available_tx > 0) {
        data->num_available_tx -= 1;
        ethernet_buffer_t *buffer =  data->available_tx[data->num_available_tx];

        if (buffer->size < length) {
            /* Requested size too large */
            data->num_available_tx += 1;
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
static inline void return_buffer(ethernet_buffer_t *buffer)
{
    switch (buffer->origin) {
        case ORIGIN_TX_QUEUE:
            assert(data->num_available_tx < NUM_BUFFERS);
            data->available_tx[data->num_available_tx] = buffer;
            data->num_available_tx += 1;
            break;

        case ORIGIN_RX_QUEUE: {
            // TODO: do we need to check if it's full?
            rx_avail->buffers[rx_avail->write_idx % RING_SIZE] = buffer;
            rx_avail_release();
            rx_avail->write_idx++;
            break;
        }
    }
}

static inline void free_buffer(ethernet_buffer_t *buffer)
{
    assert(buffer != NULL);
    assert(buffer->allocated);

    buffer->allocated = false;

    if (!buffer->in_async_use) {
        return_buffer(buffer);
    }
}

static inline void mark_buffer_used(ethernet_buffer_t *buffer)
{
    assert(buffer != NULL);
    assert(buffer->allocated);
    assert(!buffer->in_async_use);

    buffer->in_async_use = true;
}

static inline void mark_buffer_unused(ethernet_buffer_t *buffer)
{
    assert(buffer != NULL);
    assert(buffer->in_async_use);

    buffer->in_async_use = false;

    if (!buffer->allocated) {
        return_buffer(buffer);
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
    free_buffer(custom_pbuf->buffer);
    LWIP_MEMPOOL_FREE(RX_POOL, custom_pbuf);
    SYS_ARCH_UNPROTECT(old_level);
}

static struct pbuf *create_interface_buffer(ethernet_buffer_t *buffer, size_t length) 
{
    lwip_custom_pbuf_t *custom_pbuf = (lwip_custom_pbuf_t *) LWIP_MEMPOOL_ALLOC(RX_POOL);

    custom_pbuf->state = data;
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
static void rx_queue(void)
{
    /* get buffers from used RX ring */
    while((rx_used->write_idx - rx_used->read_idx) % RING_SIZE) {
        ethernet_buffer_t *buffer = rx_used->buffers[rx_used->read_idx];
        rx_used_release();
        rx_used->read_idx++;

        struct pbuf *p = create_interface_buffer(buffer, buffer->len);

        if (data->netif.input(p, data->netif) != ERR_OK) {
            // If it is successfully received, the receiver controls whether or not it gets freed.
            ZF_LOGE("netif.input() != ERR_OK");
            pbuf_free(p);
        }

        rx_used_acquire();
    }

    int res = rx_queue_reg_callback(rx_queue, NULL);
    if (res) {
        ZF_LOGE("Failed to register rx_queue notification callback");
    }
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

    ethernet_buffer_t *buffer = alloc_tx_buffer(p->tot_len);
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

    /* insert into the used tx queue */
    if ((tx_used->write - tx_used->read + 1) % RING_SIZE) {
        ZF_LOGF("lwip_eth_send: Error while enqueuing used buffer, tx_used queue full");
        free_buffer(buffer);
    } else {
        tx_used->buffers[tx_used->write_idx % RING_SIZE];
        tx_used_release();
        tx_used->write_idx++;
        /* notify the server */
        tx_send_emit();
    }

    return ret;
}

/* Packets have been sent. We can reuse their buffers. */
static void tx_done(void)
{
    while((tx_avail->write_idx - tx_avail->read_idx) % RING_SIZE) {
        ethernet_buffer_t *buffer = tx_avail->buffers[tx_avail->read_idx % RING_SIZE];
        mark_buffer_unused(buffer);
        tx_avail_release();
        tx_avail->read_idx++;
    }

    int res = tx_done_reg_callback(tx_done, NULL);
    if (res) {
        ZF_LOGE("Failed to register tx done notification callback");
    }
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

int lwip_ethernet_async_client_init(ps_io_ops_t *io_ops, register_callback_handler_fn_t register_handler, 
                                    get_mac_client_fn_t get_mac, void **cookie)
{
    int error = ps_calloc(
        &io_ops->malloc_ops,
        1,
        sizeof(*data),
        (void **)&data
    );
    ZF_LOGF_IF(error != 0, "Unable to ethernet state");
    data->io_ops = io_ops;

    seL4_Word tx_badge;
    seL4_Word rx_badge;

    int res = tx_done_reg_callback ? tx_done_reg_callback(tx_done, NULL): 0;
    if (res) {
        ZF_LOGE("Failed to register tx done notification callback");
    }

    res = rx_queue_reg_callback ? rx_queue_reg_callback(tx_done, NULL): 0;
    if (res) {
        ZF_LOGE("Failed to register rx_queue notification callback");
    }

    //register_handler(tx_badge, "lwip_tx_irq_from_ethernet", tx_done_notify, data);
    //register_handler(rx_badge, "lwip_rx_irq_from_ethernet", rx_queue_notify, data);

    LWIP_MEMPOOL_INIT(RX_POOL);
    /* Pre allocate buffers */
    rx_avail->write_idx = 0;   
    for (int i = 0; i < NUM_BUFFERS - 1; i++) {
        void *buf = ps_dma_alloc(
            &io_ops->dma_manager,
            BUFFER_SIZE,
            64,
            1,
            PS_MEM_NORMAL
        );
        assert(buf);
        memset(buf, 0, BUFFER_SIZE);
        ZF_LOGF_IF(buf == NULL, "Failed to allocate DMA memory for pending rx ring");

        ethernet_buffer_t *buffer = &data->buffer_metadata[i];

        *buffer = (ethernet_buffer_t) {
            .buffer = buf,
            .dma_addr = ENCODE_DMA_ADDRESS(buf),
            .size = BUFFER_SIZE,
            .origin = ORIGIN_RX_QUEUE,
            .allocated = false,
            .in_async_use = false,
        };
        /* Now add buffer to the available RX ring */
        rx_avail->buffers[rx_avail->write_idx % RING_SIZE] = buffer;
        rx_avail_release();
        rx_avail->write_idx++;
    }

    /* Allocate tx rings */
    data->num_available_tx = 0;
    for (int i = 0; i < NUM_BUFFERS - 1; i++) {
        void *buf = ps_dma_alloc(
            &io_ops->dma_manager,
            BUFFER_SIZE,
            64,
            1,
            PS_MEM_NORMAL
        );
        ZF_LOGF_IF(!buf, "Failed to allocate buffer for pending TX ring.");
        memset(buf, 0, BUFFER_SIZE);

        ethernet_buffer_t *buffer = &data->buffer_metadata[NUM_BUFFERS + i];
        *buffer = (ethernet_buffer_t) {
            .buffer = buf,
            .dma_addr = ENCODE_DMA_ADDRESS(buf),
            .size = BUFFER_SIZE,
            .origin = ORIGIN_TX_QUEUE,
            .allocated = false,
            .in_async_use = false,
        };

        data->available_tx[i] = buffer;
        data->num_available_tx++;
    }

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
    return 0;    
}