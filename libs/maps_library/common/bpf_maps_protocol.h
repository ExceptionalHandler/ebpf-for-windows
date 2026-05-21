// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "bpf_maps_common.h"

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// IOCTL codes for BPF map operations
#define IOCTL_BPF_MAP_CREATE \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_BPF_MAP_LOOKUP \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_BPF_MAP_UPDATE \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_BPF_MAP_DELETE \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_BPF_MAP_GET_NEXT_KEY \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_BPF_MAP_CLOSE \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Sample-specific: fetch the handle of the driver-owned process map.
#define IOCTL_BPF_GET_PROCESS_MAP \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Sample-specific: fetch the handle of the driver-owned process events ring buffer.
#define IOCTL_BPF_GET_PROCESS_RINGBUF \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x911, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _bpf_get_process_map_reply {
    uint64_t map_handle;
    uint32_t key_size;
    uint32_t value_size;
} bpf_get_process_map_reply_t;

typedef struct _bpf_get_process_ringbuf_reply {
    uint64_t map_handle;
} bpf_get_process_ringbuf_reply_t;

// Process event structure written to ring buffer
typedef struct _process_event {
    uint32_t pid;
    uint64_t start_time;  // FILETIME
} process_event_t;

// Protocol structures

// Map create operation
typedef struct _bpf_map_create_request {
    bpf_map_definition_t definition;
    uint32_t name_length;
    char name[1];  // Variable length
} bpf_map_create_request_t;

typedef struct _bpf_map_create_reply {
    uint64_t map_handle;
} bpf_map_create_reply_t;

// Map lookup operation
typedef struct _bpf_map_lookup_request {
    uint64_t map_handle;
    uint32_t key_size;
    uint8_t key[1];  // Variable length
} bpf_map_lookup_request_t;

typedef struct _bpf_map_lookup_reply {
    uint32_t value_size;
    uint8_t value[1];  // Variable length
} bpf_map_lookup_reply_t;

// Map update operation
typedef struct _bpf_map_update_request {
    uint64_t map_handle;
    uint64_t flags;  // BPF_ANY, BPF_NOEXIST, BPF_EXIST
    uint32_t key_size;
    uint32_t value_size;
    uint8_t data[1];  // key followed by value (variable length)
} bpf_map_update_request_t;

// Map delete operation
typedef struct _bpf_map_delete_request {
    uint64_t map_handle;
    uint32_t key_size;
    uint8_t key[1];  // Variable length
} bpf_map_delete_request_t;

// Map get next key operation
typedef struct _bpf_map_get_next_key_request {
    uint64_t map_handle;
    uint32_t key_size;
    uint8_t key[1];  // Variable length (can be all zeros for first key)
} bpf_map_get_next_key_request_t;

typedef struct _bpf_map_get_next_key_reply {
    uint32_t key_size;
    uint8_t key[1];  // Variable length
} bpf_map_get_next_key_reply_t;

// Map close operation
typedef struct _bpf_map_close_request {
    uint64_t map_handle;
} bpf_map_close_request_t;

#ifdef __cplusplus
}
#endif
