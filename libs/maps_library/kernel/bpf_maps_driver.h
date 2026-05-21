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

// WDF initialization utility
// Include WDF headers if not already included
#ifndef _WDFDEVICE_H_
// Forward declarations for when WDF headers are not included
typedef void* WDFDEVICE;
typedef void* PWDFDEVICE_INIT;
typedef void (*PFN_WDF_IO_QUEUE_IO_DEVICE_CONTROL)(void*, void*, size_t, size_t, unsigned long);
typedef void (*PFN_WDF_DRIVER_UNLOAD)(void*);
#endif

typedef struct _bpf_maps_wdf_config
{
    const wchar_t* device_name;
    const wchar_t* symbolic_link;
    void* io_device_control_callback;  // PFN_WDF_IO_QUEUE_IO_DEVICE_CONTROL
    void* unload_callback;  // PFN_WDF_DRIVER_UNLOAD
} bpf_maps_wdf_config_t;

_Must_inspect_result_
NTSTATUS
bpf_maps_wdf_initialize(
    _In_ void* DriverObject,  // PDRIVER_OBJECT
    _In_ void* RegistryPath,  // PUNICODE_STRING
    _In_ const bpf_maps_wdf_config_t* config,
    _Out_ void** device_out,  // WDFDEVICE*
    _Out_ void** device_object_out);  // DEVICE_OBJECT**

#ifdef __cplusplus
}
#endif
