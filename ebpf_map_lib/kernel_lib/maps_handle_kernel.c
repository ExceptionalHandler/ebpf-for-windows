// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Simplified handle mechanism for maps library
// Uses direct object pointers instead of Windows file handles

#define EBPF_FILE_ID EBPF_FILE_ID_MAPS_HANDLE

#include "maps_handle.h"
#include "ebpf_object.h"
#include "ebpf_tracelog.h"
#include "ebpf_core_structs.h"

static const uint32_t _maps_object_marker = 'eobj';

bool
_maps_object_compare(_In_ const ebpf_base_object_t* object, _In_ const void* context)
{
    ebpf_assert(context != NULL);
    __analysis_assume(context != NULL);

    if (object->marker != _maps_object_marker) {
        return false;
    }

    ebpf_core_object_t* local_object = (ebpf_core_object_t*)object;
    ebpf_object_type_t object_type = *((ebpf_object_type_t*)context);

    return (local_object->type == object_type);
}

_Must_inspect_result_ ebpf_result_t
maps_handle_table_initiate(void)
{
    return EBPF_SUCCESS;
}

void
maps_handle_table_terminate(void)
{
    // No-op: no global state to clean up
}

_Must_inspect_result_ ebpf_result_t
maps_handle_create(_Out_ maps_handle_t* handle, _Inout_ struct _ebpf_base_object* object)
{
    EBPF_LOG_ENTRY();

    if (handle == NULL || object == NULL) {
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    // Set the marker so compare function can validate it
    object->marker = _maps_object_marker;

    // Acquire reference on the object
    EBPF_OBJECT_ACQUIRE_REFERENCE_INDIRECT(object);

    // Handle is just the object pointer cast to uint64_t
    *handle = (maps_handle_t)object;

    EBPF_LOG_MESSAGE_UINT64(
        EBPF_TRACELOG_LEVEL_VERBOSE,
        EBPF_TRACELOG_KEYWORD_MAP,
        "maps_handle_create: created handle",
        *handle);

    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

_Must_inspect_result_ ebpf_result_t
maps_handle_close(maps_handle_t handle)
{
    EBPF_LOG_ENTRY();

    if (handle == 0) {
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    EBPF_LOG_MESSAGE_UINT64(
        EBPF_TRACELOG_LEVEL_VERBOSE,
        EBPF_TRACELOG_KEYWORD_MAP,
        "maps_handle_close: closing handle",
        handle);

    // Cast handle back to object pointer and release reference
    struct _ebpf_base_object* object = (struct _ebpf_base_object*)handle;
    EBPF_OBJECT_RELEASE_REFERENCE_INDIRECT(object);

    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

_IRQL_requires_max_(PASSIVE_LEVEL) ebpf_result_t
maps_reference_base_object_by_handle(
    maps_handle_t handle,
    _In_opt_ maps_compare_object_t compare_function,
    _In_opt_ const void* context,
    _Outptr_ struct _ebpf_base_object** object,
    uint32_t file_id,
    uint32_t line)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    struct _ebpf_base_object* local_object;

    if (handle == 0 || object == NULL) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // Cast handle to object pointer
    local_object = (struct _ebpf_base_object*)handle;

    // Validate object if compare function provided
    if (compare_function) {
        if (!compare_function(local_object, context)) {
            return_value = EBPF_INVALID_OBJECT;
            goto Done;
        }
    }

    // Acquire reference with tracking
    local_object->acquire_reference(local_object, false, file_id, line);
    *object = local_object;
    return_value = EBPF_SUCCESS;

    EBPF_LOG_MESSAGE_UINT64(
        EBPF_TRACELOG_LEVEL_VERBOSE,
        EBPF_TRACELOG_KEYWORD_MAP,
        "maps_reference_base_object_by_handle: referenced object",
        handle);

Done:
    EBPF_RETURN_RESULT(return_value);
}
