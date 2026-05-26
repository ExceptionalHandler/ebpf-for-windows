// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_result.h"
#include "ebpf_windows.h"

typedef uint64_t maps_handle_t;

typedef bool (*maps_compare_object_t)(_In_ const void* object, _In_ const void* context);

bool
_maps_object_compare(_In_ const struct _ebpf_base_object* object, _In_ const void* context);

_Must_inspect_result_ ebpf_result_t
maps_handle_table_initiate(void);

void
maps_handle_table_terminate(void);

_Must_inspect_result_ ebpf_result_t
maps_handle_create(_Out_ maps_handle_t* handle, _Inout_ struct _ebpf_base_object* object);

_Must_inspect_result_ ebpf_result_t
maps_handle_close(maps_handle_t handle);

_IRQL_requires_max_(PASSIVE_LEVEL) ebpf_result_t
maps_reference_base_object_by_handle(
    maps_handle_t handle,
    _In_opt_ maps_compare_object_t compare_function,
    _In_opt_ const void* context,
    _Outptr_ struct _ebpf_base_object** object,
    uint32_t file_id,
    uint32_t line);
