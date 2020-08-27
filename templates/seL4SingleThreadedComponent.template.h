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

#include <sel4/sel4.h>


typedef int (*camkes_module_init_fn_t)(ps_io_ops_t *io_ops);

#define CAMKES_ENV_INIT_MODULE_DEFINE(name, init_func)                   \
    static_assert(init_func != NULL, "Supplied init_func is NULL!");            \
    USED SECTION("_env_init") camkes_module_init_fn_t name = init_func;

#define CAMKES_PRE_INIT_MODULE_DEFINE(name, init_func)                   \
    static_assert(init_func != NULL, "Supplied init_func is NULL!");            \
    USED SECTION("_pre_init") camkes_module_init_fn_t name = init_func;

#define CAMKES_POST_INIT_MODULE_DEFINE(name, init_func)                   \
    static_assert(init_func != NULL, "Supplied init_func is NULL!");            \
    USED SECTION("_post_init") camkes_module_init_fn_t name = init_func;

int trace_extra_point_register_name(int tp_id, const char *name);

void trace_extra_point__wipe_all(void);

void trace_extra_point_start(int tp_id);

void trace_extra_point_end(int tp_id, int count);

/* Function for registering notification event handlers under a certain badge value */
int single_threaded_component_register_handler(seL4_Word badge, const char* name, void (*callback_handler)(seL4_Word, void *), void * cookie);

