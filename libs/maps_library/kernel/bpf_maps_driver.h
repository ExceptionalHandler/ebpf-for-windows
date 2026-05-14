// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

// Don't include ntddk.h here - let eBPF platform headers handle it
// The caller (driver) should include Windows headers before this
#ifndef _KERNEL_MODE
#include <ntddk.h>
#endif

#include "../common/bpf_maps_common.h"
#include "../common/bpf_maps_config.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations - use the eBPF types directly when available
#ifndef _EBPF_MAPS_H
typedef struct _ebpf_core_map ebpf_map_t;
#endif

// Library initialization/termination
_Must_inspect_result_
NTSTATUS
bpf_maps_library_init(void);

void
bpf_maps_library_close_context(void* context);

void
bpf_maps_library_cleanup(void);

// Kernel-mode map operations (direct API - bypasses IOCTL layer)
_Must_inspect_result_
NTSTATUS
bpf_map_create_km(
    _In_ uint32_t type,
    _In_opt_ const char* name,
    _In_ uint32_t name_length,
    _In_ uint32_t key_size,
    _In_ uint32_t value_size,
    _In_ uint32_t max_entries,
    _Out_ uint64_t* map_handle);

_Must_inspect_result_
NTSTATUS
bpf_map_lookup_elem_km(
    _In_ uint64_t map_handle,
    _In_reads_bytes_(key_size) const void* key,
    _In_ uint32_t key_size,
    _Out_writes_bytes_(value_size) void* value,
    _In_ uint32_t value_size);

_Must_inspect_result_
NTSTATUS
bpf_map_update_elem_km(
    _In_ uint64_t map_handle,
    _In_reads_bytes_(key_size) const void* key,
    _In_ uint32_t key_size,
    _In_reads_bytes_(value_size) const void* value,
    _In_ uint32_t value_size,
    _In_ uint64_t flags);

_Must_inspect_result_
NTSTATUS
bpf_map_delete_elem_km(
    _In_ uint64_t map_handle,
    _In_reads_bytes_(key_size) const void* key,
    _In_ uint32_t key_size);

_Must_inspect_result_
NTSTATUS
bpf_map_get_next_key_km(
    _In_ uint64_t map_handle,
    _In_reads_bytes_opt_(key_size) const void* key,
    _In_ uint32_t key_size,
    _Out_writes_bytes_(next_key_size) void* next_key,
    _In_ uint32_t next_key_size);

_Must_inspect_result_
NTSTATUS
bpf_map_close_km(
    _In_ uint64_t map_handle);

// IOCTL handler for drivers that expose user-mode interface
_Must_inspect_result_
NTSTATUS
bpf_maps_handle_ioctl(
    _In_ ULONG ioctl_code,
    _In_reads_bytes_opt_(input_length) PVOID input_buffer,
    _In_ ULONG input_length,
    _Out_writes_bytes_opt_(output_length) PVOID output_buffer,
    _In_ ULONG output_length,
    _Out_ PULONG bytes_returned);

#ifdef __cplusplus
}
#endif
