/*
 * Copyright 2017, Data61
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

#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdio.h>
#include <sel4/sel4.h>
#include <sel4/arch/constants.h>
#include <camkes.h>
#include <platsupport/time_manager.h>
#include <platsupport/local_time_manager.h>
#include <utils/util.h>
#include <sel4utils/sel4_zf_logif.h>
#include <simple/simple.h>
#include <camkes/io.h>

#include "time_server.h"
#include "plat.h"

/* ltimer for accessing timer devices */
static ltimer_t ltimer;
/* time manager for timeout multiplexing */
static time_manager_t time_manager;

/* declare the memory needed for the clients
 * this field tracks which timeouts have triggered
 * for a specific client */
uint32_t *client_state = NULL;

/* Prototype for this function is not generated by the camkes templates yet */
seL4_Word the_timer_get_sender_id();
void the_timer_emit(unsigned int);
int the_timer_largest_badge(void);

static inline uint64_t current_time_ns() {
    uint64_t time;
    int error = ltimer_get_time(&ltimer, &time);
    ZF_LOGF_IF(error, "Failed to get time");
    return time;
}

static inline unsigned int get_time_token(int cid, int tid)
{
    return (unsigned int) cid * timers_per_client + tid;
}

static int signal_client(uintptr_t token) {

    int cid = ((int) token) / timers_per_client;
    int tid = ((int) token) % timers_per_client;

    assert(client_state != NULL);

    client_state[cid] |= BIT(tid);
    the_timer_emit(cid + 1);

    return 0;
}

void time_server_irq_handle(irq_ack_fn irq_acknowledge) {
    int error = time_server_lock();
    ZF_LOGF_IF(error, "Failed to lock time server");

    error = irq_acknowledge();
    ZF_LOGF_IF(error, "irq acknowledge failed");

    error = tm_update(&time_manager);
    ZF_LOGF_IF(error, "Failed to update time manager");

    error = time_server_unlock();
    ZF_LOGF_IF(error, "Failed to unlock time server");
}

static int _oneshot_relative(int cid, int tid, uint64_t ns) {
    if (tid >= timers_per_client || tid < 0) {
        ZF_LOGE("invalid tid, 0 >= %d >= %d\n", tid, timers_per_client);
        return -1;
    }

    int error = time_server_lock();
    ZF_LOGF_IF(error, "Failed to lock time server");

    unsigned int id = get_time_token(cid, tid);
    error = tm_register_rel_cb(&time_manager, ns, id, signal_client, (uintptr_t) id);
    ZF_LOGF_IF(error, "Failed to set timeout");

    error = time_server_unlock();
    ZF_LOGF_IF(error, "Failed to unlock time server");
    return 0;
}

static int _oneshot_absolute(int cid, int tid, uint64_t ns) {
    if (tid >= timers_per_client || tid < 0) {
        ZF_LOGE("invalid tid, 0 >= %d >= %d\n", tid, timers_per_client);
        return -1;
    }

    int error = time_server_lock();
    ZF_LOGF_IF(error, "Failed to lock time server");

    unsigned int token = get_time_token(cid, tid);

    error = tm_register_abs_cb(&time_manager, ns, token, signal_client, (uintptr_t) token);
    if (error == ETIME) {
        signal_client(token);
        error = 0;
    }
    ZF_LOGF_IF(error, "Failed to set timeout");

    error = time_server_unlock();
    ZF_LOGF_IF(error, "Failed to unlock time server");
    return 0;
}

static int _periodic(int cid, int tid, uint64_t ns) {
    if (tid >= timers_per_client || tid < 0) {
        ZF_LOGE("invalid tid, 0 >= %d >= %d\n", tid, timers_per_client);
        return -1;
    }

    int error = time_server_lock();
    ZF_LOGF_IF(error, "Failed to lock time server");

    unsigned int token = get_time_token(cid, tid);
    error = tm_register_periodic_cb(&time_manager, ns, 0, token, signal_client, (uintptr_t) token);
    ZF_LOGF_IF(error, "Failed to set timeout");

    error = time_server_unlock();
    ZF_LOGF_IF(error, "Failed to unlock time server");
    return 0;
}

static int _stop(int cid, int tid) {
    if (tid >= timers_per_client || tid < 0) {
        ZF_LOGE("invalid tid, 0 >= %d >= %d\n", tid, timers_per_client);
        return -1;
    }
    int error = time_server_lock();
    ZF_LOGF_IF(error, "Failed to lock time server");

    error = tm_deregister_cb(&time_manager, get_time_token(cid, tid));
    ZF_LOGF_IF(error, "Failed to deregister callback");

    error = time_server_unlock();
    ZF_LOGF_IF(error, "Failed to unlock time server");
    return 0;
}

static unsigned int _completed(int cid) {
    int error = time_server_lock();
    ZF_LOGF_IF(error, "Failed to lock time server");

    assert(client_state != NULL);
    unsigned int ret = client_state[cid];
    client_state[cid] = 0;

    error = time_server_unlock();
    ZF_LOGF_IF(error, "Failed to unlock time server");

    return ret;
}

static uint64_t _time(int cid) {
    return current_time_ns();
}

/* substract 1 from the badge as we started counting badges at 1
 * to avoid using the 0 badge */
int the_timer_oneshot_relative(int id, uint64_t ns) {
    return _oneshot_relative(the_timer_get_sender_id() - 1, id, ns);
}

int the_timer_oneshot_absolute(int id, uint64_t ns) {
    return _oneshot_absolute(the_timer_get_sender_id() - 1, id, ns);
}

int the_timer_periodic(int id, uint64_t ns) {
    return _periodic(the_timer_get_sender_id() - 1, id, ns);
}

int the_timer_stop(int id) {
    return _stop(the_timer_get_sender_id() - 1, id);
}

unsigned int the_timer_completed() {
    return _completed(the_timer_get_sender_id() - 1);
}

uint64_t the_timer_time() {
    return _time(the_timer_get_sender_id() - 1);
}

void post_init() {
    int error = time_server_lock();
    ZF_LOGF_IF(error, "Failed to lock timer server");

    ps_io_ops_t ops;
    error = camkes_io_ops(&ops);
    ZF_LOGF_IF(error, "Failed to get camkes_io_ops");

    error = ps_calloc(&ops.malloc_ops, the_timer_largest_badge(), sizeof(*client_state), (void **) &client_state);
    ZF_LOGF_IF(error, "Failed to allocate client state")

    error = ltimer_default_init(&ltimer, ops);
    ZF_LOGF_IF(error, "Failed to init timer");

    plat_post_init(&ltimer);

    int num_timers = timers_per_client * the_timer_largest_badge();
    tm_init(&time_manager, &ltimer, &ops, num_timers);
    for (unsigned int i = 0; i < num_timers; i++) {
        error = tm_alloc_id_at(&time_manager, i);
        ZF_LOGF_IF(error, "Failed to alloc id at %u\n", i);
    }

    error = time_server_unlock();
    ZF_LOGF_IF(error, "Failed to unlock timer server");

    set_putchar(putchar_putchar);
}
