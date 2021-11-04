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

#define _VAR_STRINGIZE(...) #__VA_ARGS__
#define VAR_STRINGIZE(...) _VAR_STRINGIZE(__VA_ARGS__)

import <lwip-ethernet-async.camkes>;

#define lwip_ethernet_async_client_interfaces(name) \
    uses lwip_ethernet_async_control name##_control; \
    dataport Buf name##_dma_pool; \
    include "ring.h"; \
    dataport ring_t rx_avail; \
    dataport ring_t rx_used; \
    provides Notify rx_queue; \
    dataport ring_t tx_avail; \
    provides Notify tx_done; \
    dataport ring_t tx_used; \
    uses Notify tx_send; \
    emits Init name##_init1; \
    consumes Init name##_init2;

#define lwip_ethernet_async_server_interfaces(name) \
    provides lwip_ethernet_async_control name##_control; \
    dataport Buf name##_dma_pool; \
    include "ring.h"; \
    dataport ring_t rx_avail; \
    dataport ring_t rx_used; \
    uses Notify rx_queue; \
    dataport ring_t tx_avail; \
    uses Notify tx_done; \
    dataport ring_t tx_used; \
    provides Notify tx_send; \
    emits Init name##_init1; \
    consumes Init name##_init2;

#define lwip_ethernet_async_connections(name, client, driver) \
    connection seL4RPCNoThreads name##_eth_driver_conn(from client.name##_control, to driver.name##_control); \
    connection seL4RPCCall notification(from client.rx_queue, to driver.rx_queue); \
    connection seL4RPCCall notification(from client.tx_done, to driver.tx_done); \
    connection seL4RPCCall notification(from driver.tx_used, to client.tx_used); \
    connection seL4SharedData d1(from client.rx_avail, to driver.rx_avail); \
    connection seL4SharedData d2(from client.rx_used, to driver.rx_used); \
    connection seL4SharedData d3(from client.tx_avail, to driver.tx_avail); \
    connection seL4SharedData d4(from client.tx_used, to driver.tx_used); \
    connection seL4DMASharedData name##_dma(from client.name##_dma_pool, to driver.name##_dma_pool); \
    connection LwipEthernetAsyncClientInit name##_client_init(from client.name##_init1, to client.name##_init2); \
    connection LwipEthernetAsyncServerInit name##_server_init(from driver.name##_init1, to driver.name##_init2);

#define lwip_ethernet_async_configurations(name, client, driver) \
    name##_dma.size = 0x400000; \
    name##_dma.controller = VAR_STRINGIZE(client.name##_dma_pool); \
    name##_server_init.connection_name = VAR_STRINGIZE(name); \
    name##_client_init.connection_name = VAR_STRINGIZE(name);
