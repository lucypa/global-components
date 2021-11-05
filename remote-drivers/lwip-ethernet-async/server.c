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

typedef struct data {
    struct eth_driver *eth_driver;
    /* mac address */
    uint8_t hw_mac[6];
    ps_io_ops_t *io_ops;
} server_data_t;

server_data_t *data;

/* Packets have been transferred or dropped. */
static void eth_tx_complete(void *iface, void *cookie)
{   
    if ((tx_avail->write - tx_avail->read + 1) % RING_SIZE) {
        ZF_LOGF("lwip_eth_send: Error while enqueuing available buffer, tx available queue full");
    } else {
        tx_avail->buffers[tx_avail->write_idx % RING_SIZE] = cookie;
        tx_avail_release();
        tx_avail->write_idx++;
        /* notify client */
        tx_done_notify();
    }
}

/* We have packets that need to be sent */
static void tx_send_notify(void)
{
    /* Grab buffers from used tx ring, 
    dma cache clean, uintptr_t phys = dma_pin */
    while (tx_used->write_idx - tx_used->read_idx % RING_SIZE) {
        ethernet_buffer_t *buffer = tx_used->buffers[tx->used->read_idx % RING_SIZE];
        tx_used_release();
        tx_used->read_idx++;

        void *decoded_buf = DECODE_DMA_ADDRESS(buffer);
        ZF_LOGF_IF(decoded_buf == NULL, "Decoded DMA buffer is NULL");

        uintptr_t phys = ps_dma_pin(&data->io_ops->dma_manager, decoded_buf, buffer->lens);
        ps_dma_cache_clean(&data->io_ops->dma_manager, decoded_buf, buffer->lens);

        // TODO: THIS CAN'T HANDLE CHAINED BUFFERS.
        int err = data->eth_driver->i_fn.raw_tx(data->eth_driver, 1, &phys, buffer->lens, buffer);
        if (err != ETHIF_TX_ENQUEUED) eth_tx_complete(data, buffer);
    
        // DOES THIS NEED TO BE HERE?
        tx_used_acquire();
    }
    
}

static uintprtr_t eth_allocate_rx_buf(void *iface, size_t buf_size, void **cookie)
{
    if (buf_size > BUF_SIZE) {
        return 0;
    }
    server_data_t *state = iface;
 
    /* Try to grab a buffer from the available ring */
    if (!(rx_avail->write_idx - rx_avail->read_idx % RING_SIZE)) {
        ZF_LOGF("RX Available ring is empty. No more buffers available");
        return 0;
    }

    ethernet_buffer_t *buffer = rx_avail->buffers[rx_avail->read_idx % RING_SIZE];
    rx_avail_release();
    rx_avail->read_idx++;

    void *decoded_buf = DECODE_DMA_ADDRESS(buffer);
    ZF_LOGF_IF(decoded_buf == NULL, "Decoded DMA buffer is NULL");

    *cookie = buffer. 
    /* Invalidate the memory */
    ps_dma_cache_invalidate(&state->io_ops->dma_manager, decoded_buf, buf_size);
    uintptr_t phys = ps_dma_pin(&state->io_ops->dma_manager, decoded_buf, buf_size);
    return phys;
}

static void eth_rx_complete(void *iface, unsigned int num_bufs, void **cookies, unsigned int *lens)
{
    server_data_t *state = iface;
    for (int i = 0; i < num_bufs; i++) {
        // Add buffers to used rx ring. 
        ethernet_buffer_t *buffer = cookies[i];
        buffer->len = lens[i];
        rx_used_acquire();
        if (!(rx_used->write_idx - rx_used->read_idx + 1) % RING_SIZE) {
            rx_used->buffers[rx_used->write_idx % RING_SIZE] = buffer;
            rx_used_release();
            rx_used->write_idx++;
        } else {
            ZF_LOGE("Queue is full. Dropping packet.");
            // DO WE PUT IT BACK IN THE AVAILABLE QUEUE?
            /* Disable RX IRQS? */
            break;
        }
    }

    /* Notify the client */
    rx_queue_notify();

    return;
}

static struct raw_iface_callbacks ethdriver_callbacks = {
    .tx_complete = eth_tx_complete,
    .rx_complete = eth_rx_complete,
    .allocate_rx_buf = eth_allocate_rx_buf
};

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

int lwip_ethernet_async_server_init(ps_io_ops_t *io_ops, register_callback_handler_fn_t register_handler, 
    register_get_mac_server_fn register_get_mac_fn)
{
    int error = ps_calloc(&io_ops->malloc_ops, 1, sizeof(*data), (void **)&data);
    data->io_ops = io_ops;


    error = ps_interface_find(&io_ops->interface_registration_ops,
                              PS_ETHERNET_INTERFACE, hardware_interface_searcher, data);
    if (error) {
        ZF_LOGF("Unable to find an ethernet device");
    }

    data->eth_driver->cb_cookie = data;
    data->eth_driver->i_cb = ethdriver_callbacks;

    seL4_Word tx_badge;
    seL4_Word rx_badge;


    error = register_handler(tx_badge, "lwip_tx_irq", tx_send_notify, data);
    if (error) {
        ZF_LOGE("Unable to register handler");
    }
    /*error = register_handler(rx_badge, "lwip_rx_irq", rx_queue_notify, data);
    if (error) {
        ZF_LOGE("Unable to register handler");
    }
    rx_queue_notify(rx_badge, data);*/

    /*error = trace_extra_point_register_name(0, "eth_rx_complete");
    ZF_LOGF_IF(error, "Failed to register extra trace point 0");
    error = trace_extra_point_register_name(1, "eth_tx_complete");
    ZF_LOGF_IF(error, "Failed to register extra trace point 1");*/


    data->eth_driver->i_fn.get_mac(data->eth_driver, data->hw_mac);
    data->eth_driver->i_fn.raw_poll(data->eth_driver);

    register_get_mac_fn(client_get_mac, data);
    return 0;
}
