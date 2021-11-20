/*
 * Copyright 2020, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */

#include <autoconf.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <camkes/dma.h>
#include <camkes/dataport.h>
#include <camkes/io.h>
#include <camkes/irq.h>

#include <platsupport/io.h>
#include <platsupport/irq.h>
#include <platsupport/interface_registration.h>
#include <ethdrivers/raw.h>
#include <ethdrivers/intel.h>
#include <sel4utils/sel4_zf_logif.h>
#include <lwip-ethernet-async.h>

#include <utils/util.h>
#include <ring.h>

#define BUF_SIZE 2048
#define RING_DEQUEUED 1
#define RING_ERR -1


typedef struct data {
    struct eth_driver *eth_driver;
    /* mac address */
    uint8_t hw_mac[6];
    ps_io_ops_t *io_ops;

    /* Pointers to shared buffers */
    ring_t *rx_avail;
    ring_t *rx_used;
    ring_t *tx_avail;
    ring_t *tx_used;

    notify_fn client_rx_notify;
    notify_fn client_tx_notify;
} server_data_t;

static register_cb_fn reg_tx_cb;

/* This can be useful as a debugging tool when concerned about packet corruption. */
/* 
static void checksum(unsigned char *buffer, unsigned int len) {
    unsigned int csum;
    unsigned char *p;
    unsigned int i;
    for (p = buffer, i=len, csum=0; i > 0; csum += *p++, --i);
    printf("check sum = %zu\n", csum);
}
*/

static inline int ring_enqueue(ring_t *ring, uintptr_t buffer, unsigned int len, unsigned int index)
{
    if ((ring->write_idx - ring->read_idx + 1) % RING_SIZE) {
        ring->buffers[ring->write_idx % RING_SIZE].encoded_addr = buffer;
        ring->buffers[ring->write_idx % RING_SIZE].len = len;
        ring->buffers[ring->write_idx % RING_SIZE].idx = index;
        ring->write_idx++;
        THREAD_MEMORY_RELEASE();
        return 0;
    }

    ZF_LOGE("Ring full");
    return RING_ERR; 
}

/* Returns 0 if ring is empty. 1 otherwise. */
static int ring_dequeue(ring_t *ring, uintptr_t *addr, unsigned int *len, void **cookie)
{
    if (!((ring->write_idx - ring->read_idx) % RING_SIZE)) {
        ZF_LOGW("Ring is empty");
        return 0;
    }

    *addr = ring->buffers[ring->read_idx % RING_SIZE].encoded_addr;
    *len = ring->buffers[ring->read_idx % RING_SIZE].len;
    *cookie = &ring->buffers[ring->read_idx % RING_SIZE];

    THREAD_MEMORY_RELEASE();
    ring->read_idx++;

    return RING_DEQUEUED;
}

/* Packets have been transferred or dropped. */
static void eth_tx_complete(void *iface, void *cookie)
{   
    ZF_LOGW("Packets have been transferred or dropped");
    server_data_t *state = iface;

    buff_desc_t *desc = cookie;

    int err = ring_enqueue(state->tx_avail, desc->encoded_addr, desc->len, desc->idx);
    ZF_LOGF_IF(err, "lwip_eth_send: Error while enqueuing available buffer, tx available queue full");

    /* notify client */
    state->client_tx_notify();
}

static uintptr_t eth_allocate_rx_buf(void *iface, size_t buf_size, void **cookie)
{
    if (buf_size > BUF_SIZE) {
        return 0;
    }
    server_data_t *state = iface;

    uintptr_t addr;
    unsigned int len;

    /* Try to grab a buffer from the available ring */
    if (!ring_dequeue(state->rx_avail, &addr, &len, cookie)) {
        ZF_LOGE("RX Available ring is empty. No more buffers available");
        return 0;
    }

    buff_desc_t *desc = *cookie;
    ZF_LOGW("encoded addr = %p, length = %d, index = %d", desc->encoded_addr, len, desc->idx);

    void *decoded_buf = DECODE_DMA_ADDRESS(addr);
    ZF_LOGF_IF(decoded_buf == NULL, "Decoded DMA buffer is NULL");

    /* Invalidate the memory */
    ps_dma_cache_invalidate(&state->io_ops->dma_manager, decoded_buf, buf_size);
    uintptr_t phys = ps_dma_pin(&state->io_ops->dma_manager, decoded_buf, buf_size);

    ZF_LOGW("phys: %p", phys);

    return phys;
}

static void eth_rx_complete(void *iface, unsigned int num_bufs, void **cookies, unsigned int *lens)
{
    server_data_t *state = iface;
    ring_t *rx_used = state->rx_used;
    
    for (int i = 0; i < num_bufs; i++) {
        /* Add buffers to used rx ring. */
        buff_desc_t *desc = cookies[i];
        ZF_LOGW("encoded addr = %p, length = %d, index = %d", desc->encoded_addr, lens[i], desc->idx);
        int err = ring_enqueue(state->rx_used, desc->encoded_addr, lens[i], desc->idx);

        if (err) {
            ZF_LOGE("Queue is full. Disabling RX IRQs.");
            /* TODO inform driver to disable RX IRQs */
        }
    }

    /* Notify the client */
    state->client_rx_notify();
}

static struct raw_iface_callbacks ethdriver_callbacks = {
    .tx_complete = eth_tx_complete,
    .rx_complete = eth_rx_complete,
    .allocate_rx_buf = eth_allocate_rx_buf
};

/* We have packets that need to be sent */
static void tx_send(void *iface)
{
    ZF_LOGW("We have packets that need to be sent");
    server_data_t *state = iface;

    uintptr_t buffer;
    unsigned int len;
    void *cookie;

    while(ring_dequeue(state->tx_used, &buffer, &len, &cookie)) {
        void *decoded_buf = DECODE_DMA_ADDRESS(buffer);
        ZF_LOGF_IF(decoded_buf == NULL, "Decoded DMA buffer is NULL");

        uintptr_t phys = ps_dma_pin(&state->io_ops->dma_manager, decoded_buf, len);
        ps_dma_cache_clean(&state->io_ops->dma_manager, decoded_buf, len);

        int err = state->eth_driver->i_fn.raw_tx(state->eth_driver, 1, &phys, &len, cookie);
        if (err != ETHIF_TX_ENQUEUED) {
            eth_tx_complete(state, cookie);
        }
    }

    int error = reg_tx_cb(tx_send, state);
    ZF_LOGF_IF(error, "Unable to register transmit callback handler");
}

static void client_get_mac(uint8_t *b1, uint8_t *b2, uint8_t *b3, uint8_t *b4, uint8_t *b5, uint8_t *b6, void *cookie)
{
    server_data_t *state = cookie;
    *b1 = state->hw_mac[0];
    *b2 = state->hw_mac[1];
    *b3 = state->hw_mac[2];
    *b4 = state->hw_mac[3];
    *b5 = state->hw_mac[4];
    *b6 = state->hw_mac[5];
}

static int hardware_interface_searcher(void *cookie, void *interface_instance, char **properties)
{

    server_data_t *state = cookie;
    state->eth_driver = interface_instance;
    return PS_INTERFACE_FOUND_MATCH;
}

static void server_init_tx(server_data_t *state, void *tx_available, void *tx_used, register_cb_fn reg_tx)
{
    int error = reg_tx(tx_send, state);
    if (error) {
        ZF_LOGE("Unable to register handler");
    }

    state->tx_avail = (ring_t *)tx_available;
    state->tx_used = (ring_t *)tx_used;
    
    reg_tx_cb = reg_tx;
}

static void server_init_rx(server_data_t *state, void *rx_available, void *rx_used, register_cb_fn reg_rx)
{
    state->rx_avail = (ring_t *)rx_available;
    state->rx_used = (ring_t *)rx_used;
   
    // TODO: set up notification channel from client to server when rx_queue is empty. 

}

int lwip_ethernet_async_server_init(ps_io_ops_t *io_ops, register_get_mac_server_fn register_get_mac_fn,
                void *rx_available, void *rx_used, void *tx_available, void *tx_used, 
                register_cb_fn reg_rx_cb, register_cb_fn reg_tx_cb, 
                notify_fn rx_notify, notify_fn tx_notify)
{
    server_data_t *data;
    int error = ps_calloc(&io_ops->malloc_ops, 1, sizeof(*data), (void **)&data);
    ZF_LOGF_IF(error, "Failed to calloc server data");
    data->io_ops = io_ops;

    server_init_rx(data, rx_available, rx_used, reg_rx_cb);
    server_init_tx(data, tx_available, tx_used, reg_tx_cb);

    data->client_rx_notify = rx_notify;
    data->client_tx_notify = tx_notify;

    error = ps_interface_find(&io_ops->interface_registration_ops,
                              PS_ETHERNET_INTERFACE, hardware_interface_searcher, data);
    if (error) {
        ZF_LOGF("Unable to find an ethernet device");
    }

    data->eth_driver->cb_cookie = data;
    data->eth_driver->i_cb = ethdriver_callbacks;

    error = trace_extra_point_register_name(0, "eth_rx_complete");
    ZF_LOGF_IF(error, "Failed to register extra trace point 0");
    error = trace_extra_point_register_name(1, "eth_tx_complete");
    ZF_LOGF_IF(error, "Failed to register extra trace point 1");

    data->eth_driver->i_fn.get_mac(data->eth_driver, data->hw_mac);
    data->eth_driver->i_fn.raw_poll(data->eth_driver);

    register_get_mac_fn(client_get_mac, data);
    return 0;
}
