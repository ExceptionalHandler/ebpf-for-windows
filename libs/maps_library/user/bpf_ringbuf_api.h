// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "bpf_maps_api.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
struct bpf_ring_buffer;

/**
 * @brief Ring buffer sample callback function type
 * @param ctx User context passed to bpf_ringbuf_new
 * @param data Pointer to sample data
 * @param size Size of sample data in bytes
 * @return 0 to continue processing, non-zero to stop
 */
typedef int (*bpf_ring_buffer_sample_fn)(void* ctx, void* data, size_t size);

/**
 * @brief Ring buffer options
 */
struct bpf_ring_buffer_opts {
    size_t sz;      // Size of this structure (for versioning)
    uint32_t flags; // Reserved, must be 0
};

/**
 * @brief Create a new ring buffer consumer
 * @param map_fd File descriptor of ring buffer map
 * @param sample_cb Callback function to invoke for each sample
 * @param ctx User context to pass to callback
 * @param opts Options (can be NULL for defaults)
 * @return Pointer to ring buffer object, or NULL on failure
 */
struct bpf_ring_buffer*
bpf_ringbuf_new(
    bpf_map_fd_t map_fd,
    bpf_ring_buffer_sample_fn sample_cb,
    void* ctx,
    const struct bpf_ring_buffer_opts* opts);

/**
 * @brief Poll ring buffer for new events
 * @param rb Ring buffer object
 * @param timeout_ms Timeout in milliseconds (-1 for infinite, 0 for non-blocking)
 * @return Number of events processed, or negative error code
 */
int
bpf_ringbuf_poll(struct bpf_ring_buffer* rb, int timeout_ms);

/**
 * @brief Consume available events from ring buffer without waiting
 * @param rb Ring buffer object
 * @return Number of events processed, or negative error code
 */
int
bpf_ringbuf_consume(struct bpf_ring_buffer* rb);

/**
 * @brief Free ring buffer consumer
 * @param rb Ring buffer object to free
 */
void
bpf_ringbuf_free(struct bpf_ring_buffer* rb);

#ifdef __cplusplus
}
#endif
