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

#include <lwip-ethernet-async.h>
#include <camkes.h>

/*- set connection_name = configuration[me.parent.name].get('connection_name') -*/

static void *instance_cookie;
static int init_client_pre(ps_io_ops_t *io_ops) {

    int error = lwip_ethernet_async_client_init(io_ops, /*? connection_name ?*/_control_mac, 
                    &instance_cookie, &rx, &tx, rx_done_reg_callback, tx_done_reg_callback, NULL, tx_ready_emit);

    return error;
}

CAMKES_PRE_INIT_MODULE_DEFINE(/*? connection_name ?*/_client_setup_pre, init_client_pre);

static int init_client_post(ps_io_ops_t *io_ops) {  
    return 0;
}
CAMKES_POST_INIT_MODULE_DEFINE(/*? connection_name ?*/_client_setup_late, init_client_post);
