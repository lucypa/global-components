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
#ifndef _RING_H_
#define _RING_H_

#include <sel4/sel4.h>
#include <stdint.h>
#include <stddef.h>

#define RING_SIZE 512
#define BUFFER_SIZE 2048

typedef struct buff_desc {
    uintptr_t encoded_addr; /* encoded dma addresses */
    unsigned int len; /* associated memory lengths */
    unsigned int idx; /* index into client side metadata */
} buff_desc_t;

typedef struct ring {
    buff_desc_t buffers[RING_SIZE]; 
    uint32_t write_idx;
    uint32_t read_idx;
} ring_t;


/* the reader always and only  modifies the read index, the writer the write index.  
Reads/writes of a small integer are atomic.
Next slot to read is read % size; add one after reading.  Likewise, next slot to 
write is (write % size); increment write after writing. */

/* 
 *Empty = !!((write - read ) % size)
 *Full = !!((write - read + 1)%size) 
*/

#endif
