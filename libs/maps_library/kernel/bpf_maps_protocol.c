// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_MAPS

// Include ntifs.h BEFORE ntddk.h to avoid PEPROCESS/PETHREAD redefinition errors
#include <ntifs.h>
#include <ntddk.h>
#include "ebpf_tracelog.h"
#include "bpf_maps_driver.h"
#include "../common/bpf_maps_protocol.h"

NTSTATUS
bpf_maps_handle_ioctl(
    _In_ ULONG ioctl_code,
    _In_reads_bytes_opt_(input_length) PVOID input_buffer,
    _In_ ULONG input_length,
    _Out_writes_bytes_opt_(output_length) PVOID output_buffer,
    _In_ ULONG output_length,
    _Out_ PULONG bytes_returned)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (bytes_returned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *bytes_returned = 0;

    switch (ioctl_code) {
    case IOCTL_BPF_MAP_CREATE: {
        bpf_map_create_request_t* request = (bpf_map_create_request_t*)input_buffer;
        bpf_map_create_reply_t* reply = (bpf_map_create_reply_t*)output_buffer;

        if (input_length < sizeof(bpf_map_create_request_t) ||
            output_length < sizeof(bpf_map_create_reply_t)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (request == NULL || reply == NULL) {
            return STATUS_INVALID_PARAMETER;
        }

        status = bpf_map_create_km(
            request->definition.type,
            request->name_length > 0 ? request->name : NULL,
            request->name_length,
            request->definition.key_size,
            request->definition.value_size,
            request->definition.max_entries,
            &reply->map_handle);

        if (NT_SUCCESS(status)) {
            *bytes_returned = sizeof(bpf_map_create_reply_t);
        }

        break;
    }

    case IOCTL_BPF_MAP_LOOKUP: {
        bpf_map_lookup_request_t* request = (bpf_map_lookup_request_t*)input_buffer;
        bpf_map_lookup_reply_t* reply = (bpf_map_lookup_reply_t*)output_buffer;

        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Protocol: IOCTL_BPF_MAP_LOOKUP received");

        if (input_length < sizeof(bpf_map_lookup_request_t) ||
            output_length < sizeof(bpf_map_lookup_reply_t)) {
            EBPF_LOG_MESSAGE_UINT64_UINT64(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_MAP,
                "Protocol: LOOKUP buffer too small",
                input_length,
                output_length);
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (request == NULL || reply == NULL) {
            EBPF_LOG_MESSAGE(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_MAP,
                "Protocol: LOOKUP null buffer");
            return STATUS_INVALID_PARAMETER;
        }

        // Calculate actual sizes based on variable-length data
        ULONG expected_input_size = FIELD_OFFSET(bpf_map_lookup_request_t, key) + request->key_size ;
        if (input_length < expected_input_size) {
            EBPF_LOG_MESSAGE_UINT64_UINT64(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_MAP,
                "Protocol: LOOKUP input too small for key",
                input_length,
                expected_input_size);
            return STATUS_BUFFER_TOO_SMALL;
        }

        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Protocol: LOOKUP calling bpf_map_lookup_elem_km, handle and key_size",
            request->map_handle,
            request->key_size);

        status = bpf_map_lookup_elem_km(
            request->map_handle,
            request->key,
            request->key_size,
            reply->value,
            output_length - FIELD_OFFSET(bpf_map_lookup_reply_t, value));

        if (NT_SUCCESS(status)) {
            // Get the actual value size from the map
            reply->value_size = output_length - FIELD_OFFSET(bpf_map_lookup_reply_t, value);
            *bytes_returned = FIELD_OFFSET(bpf_map_lookup_reply_t, value) + reply->value_size;
            EBPF_LOG_MESSAGE_UINT64(
                EBPF_TRACELOG_LEVEL_INFO,
                EBPF_TRACELOG_KEYWORD_MAP,
                "Protocol: LOOKUP succeeded, bytes_returned",
                *bytes_returned);
        } else {
            EBPF_LOG_NTSTATUS_API_FAILURE(
                EBPF_TRACELOG_KEYWORD_MAP,
                "bpf_map_lookup_elem_km",
                status);
        }

        break;
    }

    case IOCTL_BPF_MAP_UPDATE: {
        bpf_map_update_request_t* request = (bpf_map_update_request_t*)input_buffer;

        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Protocol: IOCTL_BPF_MAP_UPDATE received");

        if (input_length < sizeof(bpf_map_update_request_t)) {
            EBPF_LOG_MESSAGE_UINT64(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_MAP,
                "Protocol: UPDATE buffer too small",
                input_length);
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (request == NULL) {
            EBPF_LOG_MESSAGE(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_MAP,
                "Protocol: UPDATE null buffer");
            return STATUS_INVALID_PARAMETER;
        }

        // Validate buffer size includes key + value
        ULONG expected_input_size = sizeof(bpf_map_update_request_t) +
                                    request->key_size +
                                    request->value_size - 1;
        if (input_length < expected_input_size) {
            EBPF_LOG_MESSAGE_UINT64_UINT64(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_MAP,
                "Protocol: UPDATE input too small",
                input_length,
                expected_input_size);
            return STATUS_BUFFER_TOO_SMALL;
        }

        // Key is at data[0], value follows immediately after key
        const void* key = request->data;
        const void* value = request->data + request->key_size;

        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_MAP,
            "Protocol: UPDATE calling bpf_map_update_elem_km, handle and key_size",
            request->map_handle,
            request->key_size);

        status = bpf_map_update_elem_km(
            request->map_handle,
            key,
            request->key_size,
            value,
            request->value_size,
            request->flags);

        if (NT_SUCCESS(status)) {
            EBPF_LOG_MESSAGE(
                EBPF_TRACELOG_LEVEL_INFO,
                EBPF_TRACELOG_KEYWORD_MAP,
                "Protocol: UPDATE succeeded");
        } else {
            EBPF_LOG_NTSTATUS_API_FAILURE(
                EBPF_TRACELOG_KEYWORD_MAP,
                "bpf_map_update_elem_km",
                status);
        }

        // No reply data for update
        *bytes_returned = 0;

        break;
    }

    case IOCTL_BPF_MAP_DELETE: {
        bpf_map_delete_request_t* request = (bpf_map_delete_request_t*)input_buffer;

        if (input_length < sizeof(bpf_map_delete_request_t)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (request == NULL) {
            return STATUS_INVALID_PARAMETER;
        }

        ULONG expected_input_size = sizeof(bpf_map_delete_request_t) + request->key_size - 1;
        if (input_length < expected_input_size) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        status = bpf_map_delete_elem_km(
            request->map_handle,
            request->key,
            request->key_size);

        // No reply data for delete
        *bytes_returned = 0;

        break;
    }

    case IOCTL_BPF_MAP_GET_NEXT_KEY: {
        bpf_map_get_next_key_request_t* request = (bpf_map_get_next_key_request_t*)input_buffer;
        bpf_map_get_next_key_reply_t* reply = (bpf_map_get_next_key_reply_t*)output_buffer;

        if (input_length < sizeof(bpf_map_get_next_key_request_t) ||
            output_length < sizeof(bpf_map_get_next_key_reply_t)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (request == NULL || reply == NULL) {
            return STATUS_INVALID_PARAMETER;
        }

        ULONG expected_input_size = sizeof(bpf_map_get_next_key_request_t) + request->key_size - 1;
        if (input_length < expected_input_size) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        // Check if key is all zeros (meaning get first key - pass NULL)
        BOOLEAN is_first_key = TRUE;
        for (ULONG i = 0; i < request->key_size; i++) {
            if (request->key[i] != 0) {
                is_first_key = FALSE;
                break;
            }
        }

        status = bpf_map_get_next_key_km(
            request->map_handle,
            is_first_key ? NULL : request->key,
            request->key_size,
            reply->key,
            output_length - FIELD_OFFSET(bpf_map_get_next_key_reply_t, key));

        if (NT_SUCCESS(status)) {
            reply->key_size = request->key_size;
            *bytes_returned = FIELD_OFFSET(bpf_map_get_next_key_reply_t, key) + reply->key_size;
        }

        break;
    }

    case IOCTL_BPF_MAP_CLOSE: {
        bpf_map_close_request_t* request = (bpf_map_close_request_t*)input_buffer;

        if (input_length < sizeof(bpf_map_close_request_t)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (request == NULL) {
            return STATUS_INVALID_PARAMETER;
        }

        status = bpf_map_close_km(request->map_handle);

        // No reply data for close
        *bytes_returned = 0;

        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return status;
}
