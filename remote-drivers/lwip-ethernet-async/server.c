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
} server_data_t;

/* Packets have been transferred or dropped. */
static void eth_tx_complete(void *iface, void *cookie)
{   
    server_data_t *state = iface;
    ring_t *tx_avail = state->tx->available;

    if ((tx_avail->write_idx - tx_avail->read_idx + 1) % RING_SIZE) {
        ZF_LOGF("lwip_eth_send: Error while enqueuing available buffer, tx available queue full");
    } else {
        tx_avail->buffers[tx_avail->write_idx % RING_SIZE] = cookie;
        COMPILER_MEMORY_RELEASE();
        tx_avail->write_idx++;
        /* notify client */
        seL4_Signal(tx_avail->notify_badge);
    }
}

static uintptr_t eth_allocate_rx_buf(void *iface, size_t buf_size, void **cookie)
{
    ZF_LOGW("Eth_allocate_rx_buf");

    if (buf_size > BUF_SIZE) {
        return 0;
    }
    server_data_t *state = iface;

    COMPILER_MEMORY_ACQUIRE();
    volatile ring_t *rx_avail = state->rx->available;
 
    /* Try to grab a buffer from the available ring */
    if (!(rx_avail->write_idx - rx_avail->read_idx % RING_SIZE)) {
        ZF_LOGW("rx_avail write idx = %d, rx_avail read idx = %d", rx_avail->write_idx, rx_avail->read_idx);
        ZF_LOGF("RX Available ring is empty. No more buffers available");
        return 0;
    }

    ethernet_buffer_t *buffer = rx_avail->buffers[rx_avail->read_idx % RING_SIZE];
    COMPILER_MEMORY_RELEASE();
    rx_avail->read_idx++;

    void *decoded_buf = DECODE_DMA_ADDRESS(buffer);
    ZF_LOGF_IF(decoded_buf == NULL, "Decoded DMA buffer is NULL");

    *cookie = buffer; 
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
        // Add buffers to used rx ring. 
        ethernet_buffer_t *buffer = cookies[i];
        buffer->len = lens[i];

        if (!(rx_used->write_idx - rx_used->read_idx + 1) % RING_SIZE) {
            rx_used->buffers[rx_used->write_idx % RING_SIZE] = buffer;
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
    seL4_Signal(rx_used->notify_badge);

    return 0;
}

static struct raw_iface_callbacks ethdriver_callbacks = {
    .tx_complete = eth_tx_complete,
    .rx_complete = eth_rx_complete,
    .allocate_rx_buf = eth_allocate_rx_buf
};

/* We have packets that need to be sent */
static void tx_send(seL4_Word badge, void *cookie)
{
    server_data_t *state = cookie;
    ring_t *tx_used = state->tx->used;
    /* Grab buffers from used tx ring */
    while (tx_used->write_idx - tx_used->read_idx % RING_SIZE) {
        ethernet_buffer_t *buffer = tx_used->buffers[tx_used->read_idx % RING_SIZE];
        COMPILER_MEMORY_RELEASE();
        tx_used->read_idx++;

        void *decoded_buf = DECODE_DMA_ADDRESS(buffer);
        ZF_LOGF_IF(decoded_buf == NULL, "Decoded DMA buffer is NULL");

        uintptr_t phys = ps_dma_pin(&state->io_ops->dma_manager, decoded_buf, buffer->len);
        ps_dma_cache_clean(&state->io_ops->dma_manager, decoded_buf, buffer->len);

        // TODO: THIS CAN'T HANDLE CHAINED BUFFERS.
        int err = state->eth_driver->i_fn.raw_tx(state->eth_driver, 1, &phys, &buffer->len, buffer);
        if (err != ETHIF_TX_ENQUEUED) eth_tx_complete(state, buffer);
    
        // DOES THIS NEED TO BE HERE?
        COMPILER_MEMORY_ACQUIRE();
    }
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

static void server_init_tx(server_data_t *state, void *tx_dataport_buf, register_callback_handler_fn_t register_handler)
{
    seL4_Word tx_badge;
    int error = register_handler(tx_badge, "lwip_tx_irq", tx_send, state);
    if (error) {
        ZF_LOGE("Unable to register handler");
    }

    state->tx = (dataport_t *)tx_dataport_buf;
   
    ring_t *tx_used = state->tx->used;
    tx_used->notify_badge = tx_badge;
}

static void server_init_rx(server_data_t *state, void *rx_dataport_buf, register_callback_handler_fn_t register_handler)
{

    //seL4_Word rx_badge;
    /*int error = register_handler(rx_badge, "lwip_rx_irq", rx, state);
    if (error) {
        ZF_LOGE("Unable to register handler");
    }*/

    state->rx = (dataport_t *)rx_dataport_buf;
    
    // TODO: set up notification channel from client to server when rx_queue is empty. 

    //rx_release();
}

int lwip_ethernet_async_server_init(ps_io_ops_t *io_ops, register_get_mac_server_fn register_get_mac_fn,
                void *rx_dataport_buf, void *tx_dataport_buf, register_callback_handler_fn_t register_handler)
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

    server_init_rx(data, rx_dataport_buf, register_handler);
    server_init_tx(data, tx_dataport_buf, register_handler);

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
