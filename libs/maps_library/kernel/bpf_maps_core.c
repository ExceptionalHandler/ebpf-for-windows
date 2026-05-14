// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// This file provides a wrapper around the existing eBPF maps implementation
// It includes the full ebpf_maps.c functionality and exposes a simplified API

#define EBPF_FILE_ID EBPF_FILE_ID_MAPS

// Include eBPF platform headers first to get kernel headers in right order
#include "ebpf_platform.h"
#include "ebpf_core_structs.h"
#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_maps.h"
#include "ebpf_random.h"
#include "ebpf_object.h"
#include "cxplat.h"

// Include our header last
#include "bpf_maps_driver.h"

// Helper to convert our map types to eBPF map types
static ebpf_result_t
_bpf_to_ebpf_result(NTSTATUS status)
{
    if (NT_SUCCESS(status)) {
        return EBPF_SUCCESS;
    }

    switch (status) {
    case STATUS_NO_MEMORY:
        return EBPF_NO_MEMORY;
    case STATUS_INVALID_PARAMETER:
        return EBPF_INVALID_ARGUMENT;
    case STATUS_NOT_FOUND:
        return EBPF_OBJECT_NOT_FOUND;
    case STATUS_OBJECT_NAME_COLLISION:
        return EBPF_OBJECT_ALREADY_EXISTS;
    default:
        return EBPF_FAILED;
    }
}

static NTSTATUS
_ebpf_to_ntstatus(ebpf_result_t result)
{
    switch (result) {
    case EBPF_SUCCESS:
        return STATUS_SUCCESS;
    case EBPF_NO_MEMORY:
        return STATUS_NO_MEMORY;
    case EBPF_INVALID_ARGUMENT:
        return STATUS_INVALID_PARAMETER;
    case EBPF_OBJECT_NOT_FOUND:
        return STATUS_NOT_FOUND;
    case EBPF_OBJECT_ALREADY_EXISTS:
        return STATUS_OBJECT_NAME_COLLISION;
    case EBPF_OPERATION_NOT_SUPPORTED:
        return STATUS_NOT_SUPPORTED;
    default:
        return STATUS_UNSUCCESSFUL;
    }
}

// Global initialization state
static BOOLEAN g_maps_library_initialized = FALSE;
static KSPIN_LOCK g_init_lock;

NTSTATUS
bpf_maps_library_init(void)
{
    NTSTATUS status = STATUS_SUCCESS;
    ebpf_result_t result;

    if (g_maps_library_initialized) {
        return STATUS_SUCCESS;
    }
    // Initialize platform
    result = ebpf_platform_initiate();
    if (result != EBPF_SUCCESS) {
        status = _ebpf_to_ntstatus(result);
        goto Done;
    }
    result = ebpf_random_initiate();
    if (result != EBPF_SUCCESS) {
        status = _ebpf_to_ntstatus(result);
        ebpf_platform_terminate();
        goto Done;
    }
    // Initialize epoch subsystem
    result = ebpf_epoch_initiate();
    if (result != EBPF_SUCCESS) {
        status = _ebpf_to_ntstatus(result);
        ebpf_random_terminate();
        ebpf_platform_terminate();
        goto Done;
    }

    result = ebpf_maps_initiate();
    if (result != EBPF_SUCCESS) {
        goto Done;
        ebpf_epoch_terminate();
        ebpf_random_terminate();
        ebpf_platform_terminate();
    }

     // Initialize object tracking
    result = ebpf_object_tracking_initiate();
    if (result != EBPF_SUCCESS) {
        status = _ebpf_to_ntstatus(result);
        ebpf_maps_terminate();
        ebpf_epoch_terminate();
        ebpf_random_terminate();
        ebpf_platform_terminate();
        goto Done;
    }
    // Initialize handle table
    result = ebpf_handle_table_initiate();
    if (result != EBPF_SUCCESS) {
        status = _ebpf_to_ntstatus(result);
        ebpf_object_tracking_terminate();
        ebpf_maps_terminate();
        ebpf_epoch_terminate();
        ebpf_random_terminate();
        ebpf_platform_terminate();
        goto Done;
    }

    g_maps_library_initialized = TRUE;

Done:

    return status;
}

void
bpf_maps_library_close_context(_In_opt_ void* context)
{
    if (!context) {
        return;
    }

    ebpf_epoch_state_t epoch_state = {0};
    ebpf_epoch_enter(&epoch_state);

    ebpf_core_object_t* object = (ebpf_core_object_t*)context;
    EBPF_OBJECT_RELEASE_REFERENCE_INDIRECT_USER((&object->base));

    ebpf_epoch_exit(&epoch_state);
}

void
bpf_maps_library_cleanup(void)
{
    if (!g_maps_library_initialized) {
        return;
    }
    ebpf_handle_table_terminate();
    ebpf_object_tracking_terminate();
    ebpf_maps_terminate();
    ebpf_epoch_terminate();
    ebpf_random_terminate();
    ebpf_platform_terminate();

    g_maps_library_initialized = FALSE;

}

NTSTATUS
bpf_map_create_km(
    _In_ uint32_t type,
    _In_opt_ const char* name,
    _In_ uint32_t name_length,
    _In_ uint32_t key_size,
    _In_ uint32_t value_size,
    _In_ uint32_t max_entries,
    _Out_ uint64_t* map_handle)
{
    ebpf_result_t result;
    ebpf_map_t* map = NULL;
    cxplat_utf8_string_t map_name = {0};
    ebpf_map_definition_in_memory_t map_def = {0};
    ebpf_handle_t handle = ebpf_handle_invalid;

    if (!g_maps_library_initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (map_handle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Set up map name
    if (name && name_length > 0) {
        map_name.value = (uint8_t*)name;
        map_name.length = name_length;
    }

    // Set up map definition
    map_def.type = type;
    map_def.key_size = key_size;
    map_def.value_size = value_size;
    map_def.max_entries = max_entries;
    map_def.inner_map_id = 0;
    map_def.pinning = LIBBPF_PIN_NONE;

    // Create the map
    result = ebpf_map_create(&map_name, &map_def, ebpf_handle_invalid, &map);
    if (result != EBPF_SUCCESS) {
        return _ebpf_to_ntstatus(result);
    }

    // Create a handle for the map. 
    //ToDo: Use correct symblic name
    result = ebpf_handle_create(&handle, (ebpf_base_object_t*)map);
    if (result != EBPF_SUCCESS) {
        // Release the map object reference
        EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)map);
        return _ebpf_to_ntstatus(result);
    }

    // Release our reference - handle now owns the map
    EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)map);

    *map_handle = (uint64_t)handle;
    return STATUS_SUCCESS;
}

NTSTATUS
bpf_map_lookup_elem_km(
    _In_ uint64_t map_handle,
    _In_reads_bytes_(key_size) const void* key,
    _In_ uint32_t key_size,
    _Out_writes_bytes_(value_size) void* value,
    _In_ uint32_t value_size)
{
    ebpf_result_t result;
    ebpf_map_t* map = NULL;
    ebpf_object_type_t object_type;

    if (!g_maps_library_initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (key == NULL || value == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Get the map object from the handle
    result = EBPF_OBJECT_REFERENCE_BY_HANDLE(
        (ebpf_handle_t)map_handle,
        EBPF_OBJECT_MAP,
        (ebpf_core_object_t**)&map);

    if (result != EBPF_SUCCESS) {
        return _ebpf_to_ntstatus(result);
    }

    // Perform the lookup
    result = ebpf_map_find_entry(map, key_size, (const uint8_t*)key, value_size, (uint8_t*)value, 0);

    // Release the map reference
    EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)map);

    return _ebpf_to_ntstatus(result);
}

NTSTATUS
bpf_map_update_elem_km(
    _In_ uint64_t map_handle,
    _In_reads_bytes_(key_size) const void* key,
    _In_ uint32_t key_size,
    _In_reads_bytes_(value_size) const void* value,
    _In_ uint32_t value_size,
    _In_ uint64_t flags)
{
    ebpf_result_t result;
    ebpf_map_t* map = NULL;
    ebpf_map_option_t option;

    if (!g_maps_library_initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (key == NULL || value == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Convert flags to map option
    switch (flags) {
    case 0: // BPF_ANY
        option = EBPF_ANY;
        break;
    case 1: // BPF_NOEXIST
        option = EBPF_NOEXIST;
        break;
    case 2: // BPF_EXIST
        option = EBPF_EXIST;
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    // Get the map object from the handle
    result = EBPF_OBJECT_REFERENCE_BY_HANDLE(
        (ebpf_handle_t)map_handle,
        EBPF_OBJECT_MAP,
        (ebpf_core_object_t**)&map);

    if (result != EBPF_SUCCESS) {
        return _ebpf_to_ntstatus(result);
    }

    // Perform the update
    result = ebpf_map_update_entry(
        map,
        key_size,
        (const uint8_t*)key,
        value_size,
        (const uint8_t*)value,
        option,
        0);

    // Release the map reference
    EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)map);

    return _ebpf_to_ntstatus(result);
}

NTSTATUS
bpf_map_delete_elem_km(
    _In_ uint64_t map_handle,
    _In_reads_bytes_(key_size) const void* key,
    _In_ uint32_t key_size)
{
    ebpf_result_t result;
    ebpf_map_t* map = NULL;

    if (!g_maps_library_initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (key == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Get the map object from the handle
    result = EBPF_OBJECT_REFERENCE_BY_HANDLE(
        (ebpf_handle_t)map_handle,
        EBPF_OBJECT_MAP,
        (ebpf_core_object_t**)&map);

    if (result != EBPF_SUCCESS) {
        return _ebpf_to_ntstatus(result);
    }

    // Perform the delete
    result = ebpf_map_delete_entry(map, key_size, (const uint8_t*)key, 0);

    // Release the map reference
    EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)map);

    return _ebpf_to_ntstatus(result);
}

NTSTATUS
bpf_map_get_next_key_km(
    _In_ uint64_t map_handle,
    _In_reads_bytes_opt_(key_size) const void* key,
    _In_ uint32_t key_size,
    _Out_writes_bytes_(next_key_size) void* next_key,
    _In_ uint32_t next_key_size)
{
    ebpf_result_t result;
    ebpf_map_t* map = NULL;

    if (!g_maps_library_initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (next_key == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (key_size != next_key_size) {
        return STATUS_INVALID_PARAMETER;
    }

    // Get the map object from the handle
    result = EBPF_OBJECT_REFERENCE_BY_HANDLE(
        (ebpf_handle_t)map_handle,
        EBPF_OBJECT_MAP,
        (ebpf_core_object_t**)&map);

    if (result != EBPF_SUCCESS) {
        return _ebpf_to_ntstatus(result);
    }

    // Perform the get next key
    result = ebpf_map_next_key(map, key_size, (const uint8_t*)key, (uint8_t*)next_key);

    // Release the map reference
    EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)map);

    return _ebpf_to_ntstatus(result);
}

NTSTATUS
bpf_map_close_km(
    _In_ uint64_t map_handle)
{
    ebpf_result_t result;

    if (!g_maps_library_initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    // Close the handle (this releases the map object reference)
    result = ebpf_handle_close((ebpf_handle_t)map_handle);

    return _ebpf_to_ntstatus(result);
}
