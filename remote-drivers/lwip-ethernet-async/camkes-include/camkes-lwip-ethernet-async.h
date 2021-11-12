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

import <std_connector.camkes>;
import <global-connectors.camkes>;
import <lwip-ethernet-async.camkes>;

#define lwip_ethernet_async_client_interfaces(name) \
    uses lwip_ethernet_async_control name##_control; \
    dataport Buf name##_dma_pool; \
    emits Signal s; \
    include "ring.h"; \
    dataport dataport_t rx; \
    consumes Notification rx_done; \
    dataport dataport_t tx; \
    emits Notification tx_ready; \
    consumes Notification tx_done; \
    emits Init name##_init1; \
    consumes Init name##_init2;

#define lwip_ethernet_async_server_interfaces(name) \
    provides lwip_ethernet_async_control name##_control; \
    dataport Buf name##_dma_pool; \
    consumes Signal s; \
    include "ring.h"; \
    dataport dataport_t rx_buf; \
    emits Notification rx_done; \
    dataport dataport_t tx_buf; \
    emits Notification tx_done; \
    consumes Notification tx_ready; \
    emits Init name##_init1; \
    consumes Init name##_init2;

#define lwip_ethernet_async_connections(name, client, driver) \
    connection seL4RPCNoThreads name##_eth_driver_conn(from client.name##_control, to driver.name##_control); \
    connection seL4Notification init_done(from client.s, to driver.s); \
    connection seL4SharedData d1(from client.rx, to driver.rx_buf); \
    connection seL4SharedData d3(from client.tx, to driver.tx_buf); \
    connection seL4Notification tx_ready(from client.tx_ready, to driver.tx_ready); \
    connection seL4Notification rx_done(from driver.rx_done, to client.rx_done); \
    connection seL4Notification tx_done(from driver.tx_done, to client.tx_done); \
    connection seL4DMASharedData name##_dma(from client.name##_dma_pool, to driver.name##_dma_pool); \
    connection LwipEthernetAsyncClientInit name##_client_init(from client.name##_init1, to client.name##_init2); \
    connection LwipEthernetAsyncServerInit name##_server_init(from driver.name##_init1, to driver.name##_init2);

#define lwip_ethernet_async_configurations(name, client, driver) \
    name##_dma.size = 0x400000; \
    name##_dma.controller = VAR_STRINGIZE(client.name##_dma_pool); \
    name##_server_init.connection_name = VAR_STRINGIZE(name); \
    name##_client_init.connection_name = VAR_STRINGIZE(name);
