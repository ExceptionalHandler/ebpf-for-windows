// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include <stdint.h>

// In kernel mode, use the existing eBPF types
#ifdef _KERNEL_MODE
#include "ebpf_structs.h"
// Just use the existing eBPF types directly
#define bpf_map_type_t bpf_map_type
#define bpf_map_definition_t ebpf_map_definition_in_memory_t
#else
// In user mode, define our own types

#ifdef __cplusplus
extern "C" {
#endif

// Map types (from Linux BPF)
typedef enum _bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_QUEUE = 22,
    BPF_MAP_TYPE_STACK = 23,
    BPF_MAP_TYPE_RINGBUF = 27,
} bpf_map_type_t;

// Map definition
typedef struct _bpf_map_definition {
    uint32_t type;          // Map type
    uint32_t key_size;      // Size of key in bytes
    uint32_t value_size;    // Size of value in bytes
    uint32_t max_entries;   // Maximum number of entries
    uint32_t flags;         // Map flags
} bpf_map_definition_t;

// Result codes
typedef enum _bpf_map_result {
    BPF_MAP_SUCCESS = 0,
    BPF_MAP_ERROR_INVALID_ARGUMENT = 1,
    BPF_MAP_ERROR_NO_MEMORY = 2,
    BPF_MAP_ERROR_NOT_FOUND = 3,
    BPF_MAP_ERROR_ALREADY_EXISTS = 4,
    BPF_MAP_ERROR_NOT_SUPPORTED = 5,
    BPF_MAP_ERROR_DEVICE_IO = 6,
} bpf_map_result_t;

#ifdef __cplusplus
}
#endif

#endif // _KERNEL_MODE
