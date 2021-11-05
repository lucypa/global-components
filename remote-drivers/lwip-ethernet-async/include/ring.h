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

#define RING_SIZE 512 // number of buffer slots in ring queues. 
#define BUFFER_SIZE 2048

typedef struct ethernet_buffer {
    /* The acutal underlying memory of the buffer */
    unsigned char *buffer;
    /* length of data stored */
    size_t len;
    /* The encoded DMA address */
    uintptr_t dma_addr;
    /* The physical size of the buffer */
    size_t size;
    /* Whether the buffer has been allocated */
    bool allocated;
    /* Whether the buffer is in use by the ethernet device */
    bool in_async_use;
    /* Queue from which the buffer was allocated */
    char origin;
} ethernet_buffer_t;

typedef struct ring {
    ethernet_buffer_t *buffers[RING_SIZE];
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
