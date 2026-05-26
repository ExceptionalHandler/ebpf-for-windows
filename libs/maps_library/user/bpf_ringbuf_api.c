// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_ringbuf_api.h"
#include "../common/bpf_maps_protocol.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Forward declare device IOCTL function from bpf_maps_device.c
extern int bpf_maps_device_ioctl(
    DWORD ioctl_code,
    void* input_buffer,
    DWORD input_size,
    void* output_buffer,
    DWORD output_size,
    DWORD* bytes_returned);

// Forward declare map descriptor structure and getter from bpf_maps_api.c
typedef struct _bpf_map_descriptor
{
    bpf_map_fd_t fd;
    uint64_t handle;
    uint32_t key_size;
    uint32_t value_size;
    bpf_map_type_t type;
} bpf_map_descriptor_t;

extern bpf_map_descriptor_t* get_map_descriptor(bpf_map_fd_t fd);

// Ring buffer record structures (from ebpf_ring_buffer_record.h)
#define EBPF_RINGBUF_LOCK_BIT (1U << 31)
#define EBPF_RINGBUF_DISCARD_BIT (1U << 30)

typedef struct _ebpf_ring_buffer_record
{
    struct
    {
        uint32_t length;      // High 2 bits are lock,discard
        uint32_t page_offset; // Offset of the record from the start of the data buffer, in pages
    } header;
    uint8_t data[1];
} ebpf_ring_buffer_record_t;

// Ring buffer shared memory structures
typedef struct _ebpf_ring_buffer_consumer_page
{
    volatile uint64_t consumer_offset;
} ebpf_ring_buffer_consumer_page_t;

typedef struct _ebpf_ring_buffer_producer_page
{
    volatile uint64_t producer_offset;
} ebpf_ring_buffer_producer_page_t;

// Ring buffer mapping info
typedef struct _bpf_ring_mapping
{
    ebpf_ring_buffer_consumer_page_t* consumer_page;
    ebpf_ring_buffer_producer_page_t* producer_page;
    uint8_t* data;
    size_t data_size;
    bpf_ring_buffer_sample_fn sample_fn;
    void* sample_context;
} bpf_ring_mapping_t;

// Ring buffer object
struct bpf_ring_buffer
{
    bpf_map_fd_t map_fd;
    HANDLE wait_handle;
    bpf_ring_mapping_t mapping;
};

// Helper functions for ring buffer records
static bool _record_is_locked(const ebpf_ring_buffer_record_t* record)
{
    return (ReadUInt32Acquire(&record->header.length) & EBPF_RINGBUF_LOCK_BIT) != 0;
}

static bool _record_is_discarded(const ebpf_ring_buffer_record_t* record)
{
    return (ReadUInt32NoFence(&record->header.length) & EBPF_RINGBUF_DISCARD_BIT) != 0;
}

static uint32_t _record_length(const ebpf_ring_buffer_record_t* record)
{
    return ReadUInt32NoFence(&record->header.length) & ~(EBPF_RINGBUF_LOCK_BIT | EBPF_RINGBUF_DISCARD_BIT);
}

static uint32_t _record_total_size(const ebpf_ring_buffer_record_t* record)
{
    return (_record_length(record) + sizeof(record->header) + 7) & ~7;
}

static const ebpf_ring_buffer_record_t* _next_record(
    const uint8_t* buffer,
    size_t buffer_length,
    size_t consumer,
    size_t producer)
{
    if (producer == consumer) {
        return NULL;
    }
    return (const ebpf_ring_buffer_record_t*)(buffer + consumer % buffer_length);
}

// Process ring buffer records
static int process_ring_records(bpf_ring_mapping_t* mapping)
{
    int records_processed = 0;
    uint8_t* data = mapping->data;
    size_t data_size = mapping->data_size;
    void* ctx = mapping->sample_context;

    uint64_t consumer_offset = ReadULong64Acquire(&mapping->consumer_page->consumer_offset);
    uint64_t producer_offset = ReadULong64Acquire(&mapping->producer_page->producer_offset);

    while (true) {
        const ebpf_ring_buffer_record_t* record = _next_record(
            data, data_size, consumer_offset, producer_offset);

        if (record == NULL) {
            break;
        }

        if (_record_is_locked(record)) {
            break;
        }

        uint32_t record_size = _record_total_size(record);

        if (_record_is_discarded(record)) {
            consumer_offset += record_size;
            WriteULong64Release(&mapping->consumer_page->consumer_offset, consumer_offset);
            continue;
        }

        uint32_t data_length = _record_length(record);

        int result = mapping->sample_fn(ctx, (void*)record->data, data_length);

        consumer_offset += record_size;
        WriteULong64Release(&mapping->consumer_page->consumer_offset, consumer_offset);

        records_processed++;

        if (result != 0) {
            break;
        }
    }

    return records_processed;
}

struct bpf_ring_buffer*
bpf_ringbuf_new(
    bpf_map_fd_t map_fd,
    bpf_ring_buffer_sample_fn sample_cb,
    void* ctx,
    const struct bpf_ring_buffer_opts* opts)
{
    if (map_fd == BPF_MAP_FD_INVALID || sample_cb == NULL) {
        return NULL;
    }

    // Get the map descriptor to retrieve the kernel handle
    bpf_map_descriptor_t* desc = get_map_descriptor(map_fd);
    if (desc == NULL) {
        return NULL;
    }

    // Allocate ring buffer structure
    struct bpf_ring_buffer* rb = (struct bpf_ring_buffer*)malloc(sizeof(struct bpf_ring_buffer));
    if (rb == NULL) {
        return NULL;
    }

    memset(rb, 0, sizeof(*rb));
    rb->map_fd = map_fd;
    rb->mapping.sample_fn = sample_cb;
    rb->mapping.sample_context = ctx;

    // Create event handle for signaling new data (manual reset, initially non-signaled)
    rb->wait_handle = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (rb->wait_handle == NULL) {
        free(rb);
        return NULL;
    }

    // Map the ring buffer memory via IOCTL (send handle, not fd)
    bpf_map_ringbuf_map_request_t map_request;
    bpf_map_ringbuf_map_reply_t map_reply;
    map_request.map_handle = desc->handle;

    DWORD bytes_returned = 0;
    int result = bpf_maps_device_ioctl(
        IOCTL_BPF_MAP_RINGBUF_MAP,
        &map_request, sizeof(map_request),
        &map_reply, sizeof(map_reply),
        &bytes_returned);

    if (result != 0 || bytes_returned != sizeof(map_reply)) {
        CloseHandle(rb->wait_handle);
        free(rb);
        return NULL;
    }

    rb->mapping.consumer_page = (ebpf_ring_buffer_consumer_page_t*)(uintptr_t)map_reply.consumer_address;
    rb->mapping.producer_page = (ebpf_ring_buffer_producer_page_t*)(uintptr_t)map_reply.producer_address;
    rb->mapping.data = (uint8_t*)(uintptr_t)map_reply.data_address;
    rb->mapping.data_size = map_reply.data_size;

    // Set the wait handle on the map so the kernel can signal it (send handle, not fd)
    bpf_map_set_wait_handle_request_t wait_request;
    wait_request.map_handle = desc->handle;
    wait_request.event_handle = (uint64_t)(uintptr_t)rb->wait_handle;

    result = bpf_maps_device_ioctl(
        IOCTL_BPF_MAP_SET_WAIT_HANDLE,
        &wait_request, sizeof(wait_request),
        NULL, 0,
        &bytes_returned);

    if (result != 0) {
        CloseHandle(rb->wait_handle);
        free(rb);
        return NULL;
    }

    return rb;
}

int
bpf_ringbuf_poll(struct bpf_ring_buffer* rb, int timeout_ms)
{
    if (rb == NULL) {
        return -1;
    }

    DWORD wait_result = WaitForSingleObject(rb->wait_handle, timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms);

    if (wait_result == WAIT_TIMEOUT) {
        return 0;
    }

    if (wait_result != WAIT_OBJECT_0) {
        return -1;
    }

    return bpf_ringbuf_consume(rb);
}

int
bpf_ringbuf_consume(struct bpf_ring_buffer* rb)
{
    if (rb == NULL) {
        return -1;
    }

    return process_ring_records(&rb->mapping);
}

void
bpf_ringbuf_free(struct bpf_ring_buffer* rb)
{
    if (rb != NULL) {
        // Close the event handle
        if (rb->wait_handle != NULL) {
            CloseHandle(rb->wait_handle);
        }
        // Note: We should also unmap memory here, but for now we just free the structure
        free(rb);
    }
}
