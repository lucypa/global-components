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
#define ERR_QUEUE_FULL 1

typedef struct data {
    struct eth_driver *eth_driver;
    /* mac address */
    uint8_t hw_mac[6];
    ps_io_ops_t *io_ops;

    /* Pointers to shared buffers */
    dataport_t *tx;
    dataport_t *rx;

    rx_notify_fn client_rx_notify;
    tx_notify_fn client_tx_notify;
} server_data_t;

static register_cb_fn reg_tx_cb;

/* Packets have been transferred or dropped. */
static void eth_tx_complete(void *iface, void *cookie)
{   
    server_data_t *state = iface;
    ring_t *tx_avail = state->tx->available;

    if ((tx_avail->write_idx - tx_avail->read_idx + 1) % RING_SIZE) {
        ZF_LOGF("lwip_eth_send: Error while enqueuing available buffer, tx available queue full");
    } else {
        tx_avail->buffer[tx_avail->write_idx % RING_SIZE] = cookie;
        COMPILER_MEMORY_RELEASE();
        tx_avail->write_idx++;
        /* notify client */
        state->client_tx_notify();
    }
}

static uintptr_t eth_allocate_rx_buf(void *iface, size_t buf_size, void **cookie)
{
    ZF_LOGW("Eth_allocate_rx_buf");

    if (buf_size > BUF_SIZE) {
        return 0;
    }
    server_data_t *state = iface;

    ring_t *rx_avail = state->rx->available;
 
    /* Try to grab a buffer from the available ring */
    if (!(rx_avail->write_idx - rx_avail->read_idx % RING_SIZE)) {
        ZF_LOGW("rx_avail write idx = %d, rx_avail read idx = %d", rx_avail->write_idx, rx_avail->read_idx);
        ZF_LOGF("RX Available ring is empty. No more buffers available");
        return 0;
    }

    void *buffer = rx_avail->buffer[rx_avail->read_idx % RING_SIZE];
    *cookie = buffer; 
    COMPILER_MEMORY_RELEASE();
    rx_avail->read_idx++;

    void *decoded_buf = DECODE_DMA_ADDRESS(buffer);
    ZF_LOGF_IF(decoded_buf == NULL, "Decoded DMA buffer is NULL");

    /* Invalidate the memory */
    ps_dma_cache_invalidate(&state->io_ops->dma_manager, decoded_buf, buf_size);
    uintptr_t phys = ps_dma_pin(&state->io_ops->dma_manager, decoded_buf, buf_size);
    return phys;
}

static int eth_rx_complete(void *iface, unsigned int num_bufs, void **cookies, unsigned int *lens)
{
    server_data_t *state = iface;
    ring_t *rx_used = state->rx->used;

    for (int i = 0; i < num_bufs; i++) {
        /* Add buffers to used rx ring. */
        if (!(rx_used->write_idx - rx_used->read_idx + 1) % RING_SIZE) {
            rx_used->buffer[rx_used->write_idx % RING_SIZE] = cookies[i];
            rx_used->buffer[rx_used->write_idx % RING_SIZE] = lens[i];
            COMPILER_MEMORY_RELEASE();
            rx_used->write_idx++;
        } else {
            ZF_LOGE("Queue is full. Disabling RX IRQs.");
            /* inform driver to disable RX IRQs */
            return ERR_QUEUE_FULL;
        }
        // DOES THIS NEED TO BE HERE?
        COMPILER_MEMORY_ACQUIRE(); 
    }

    /* Notify the client */
    state->client_rx_notify();

    return 0;
}

static struct raw_iface_callbacks ethdriver_callbacks = {
    .tx_complete = eth_tx_complete,
    .rx_complete = eth_rx_complete,
    .allocate_rx_buf = eth_allocate_rx_buf
};

/* We have packets that need to be sent */
static void tx_send(void *cookie)
{
    server_data_t *state = cookie;
    ring_t *tx_used = state->tx->used;
    /* Grab buffers from used tx ring */
    while (tx_used->write_idx - tx_used->read_idx % RING_SIZE) {
        void *buffer = tx_used->buffer[tx_used->read_idx % RING_SIZE];
        size_t len = tx_used->len[tx_used->read_idx % RING_SIZE];
        COMPILER_MEMORY_RELEASE();
        tx_used->read_idx++;

        void *decoded_buf = DECODE_DMA_ADDRESS(buffer);
        ZF_LOGF_IF(decoded_buf == NULL, "Decoded DMA buffer is NULL");

        uintptr_t phys = ps_dma_pin(&state->io_ops->dma_manager, decoded_buf, len);
        ps_dma_cache_clean(&state->io_ops->dma_manager, decoded_buf, len);

        // TODO: THIS CAN'T HANDLE CHAINED BUFFERS.
        int err = state->eth_driver->i_fn.raw_tx(state->eth_driver, 1, &phys, &len, buffer);
        if (err != ETHIF_TX_ENQUEUED) eth_tx_complete(state, buffer);
    
        // DOES THIS NEED TO BE HERE?
        COMPILER_MEMORY_ACQUIRE();
    }

    reg_tx_cb(tx_send, state);
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

static void server_init_tx(server_data_t *state, void *tx_dataport_buf, register_cb_fn reg_tx)
{
    int error = reg_tx(tx_send, state);
    if (error) {
        ZF_LOGE("Unable to register handler");
    }

    state->tx = (dataport_t *)tx_dataport_buf;
    
    reg_tx_cb = reg_tx;
}

static void server_init_rx(server_data_t *state, void *rx_dataport_buf, register_cb_fn reg_rx)
{

    //seL4_Word rx_badge;
    /*int error = register_handler(rx_badge, "lwip_rx_irq", rx, state);
    if (error) {
        ZF_LOGE("Unable to register handler");
    }*/
    ZF_LOGW("server_init_rx");
    state->rx = (dataport_t *)rx_dataport_buf;
    ZF_LOGW("Rx available write_idx = %d", state->rx->available->write_idx);
    
    // TODO: set up notification channel from client to server when rx_queue is empty. 

    //rx_release();
}

int lwip_ethernet_async_server_init(ps_io_ops_t *io_ops, register_get_mac_server_fn register_get_mac_fn,
                void *rx_dataport_buf, void *tx_dataport_buf, register_cb_fn reg_rx_cb, register_cb_fn reg_tx_cb, 
                rx_notify_fn rx_notify, tx_notify_fn tx_notify)
{
    ZF_LOGW("HELLO server\n"); 
    server_data_t *data;
    int error = ps_calloc(&io_ops->malloc_ops, 1, sizeof(*data), (void **)&data);
    ZF_LOGF_IF(error, "Failed to calloc server data");
    data->io_ops = io_ops;

    /*error = ps_calloc(&io_ops->malloc_ops, 1, sizeof(struct dataport), (void **)&data->tx);
    ZF_LOGF_IF(error, "Failed to calloc dataport tx");
    error = ps_calloc(&io_ops->malloc_ops, 1, sizeof(struct dataport), (void **)&data->rx);
    ZF_LOGF_IF(error, "Failed to calloc dataport rx");*/

    server_init_rx(data, rx_dataport_buf, reg_rx_cb);
    server_init_tx(data, tx_dataport_buf, reg_tx_cb);

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

    ZF_LOGW("Finished lwip_ethernet_async_server_init");
    return 0;
}
