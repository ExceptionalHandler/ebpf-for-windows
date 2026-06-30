// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Implementation of bpf_program_lib. See bpf_program_lib.h for the conceptual model.
 *
 * Flow:
 *   1. bpf_program_lib_initiate() registers an NMR provider under the caller's NPI id.
 *   2. When a bpf2c client driver loads and calls NmrRegisterClient + NmrClientAttachProvider,
 *      NMR invokes _provider_attach_client(), handing us the client's metadata_table.
 *   3. We enumerate the client's programs, pick the first one, resolve its helper imports against
 *      the static registry, and publish the bound program.
 *   4. The host calls bpf_program_lib_invoke() to call the program function directly.
 */

#include "bpf_program_lib.h"
#include "ebpf_tracelog.h"

#include <ntddk.h>
#include <netioddk.h>

#define BPF_PROGRAM_LIB_POOL_TAG 'lpfb'

// Module id for the provider registration. The value is not meaningful for matching (the bpf2c
// client matches on NPI id only), but NMR requires a module id.
static const NPI_MODULEID _bpf_program_lib_module_id = {
    sizeof(NPI_MODULEID),
    MIT_GUID,
    {/* 8f9a1b2c-3d4e-5f60-7182-93a4b5c6d7e8 */
     0x8f9a1b2c,
     0x3d4e,
     0x5f60,
     {0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8}}};

typedef struct _bpf_program_lib_state
{
    HANDLE nmr_provider_handle;
    NPI_PROVIDER_CHARACTERISTICS characteristics;
    GUID npi_id;

    bpf_helper_registry_entry_t* registry;
    size_t registry_count;

    // New program_data mode (alternative to registry)
    const ebpf_program_data_t* program_data;
    bool use_program_data; // true = use program_data, false = use registry

    // Single-program demo: protected by a simple interlocked publish.
    bpf_loaded_program_t loaded_program;
    volatile LONG program_loaded; // 0 = none bound, 1 = bound.
} bpf_program_lib_state_t;

static bpf_program_lib_state_t _state = {0};

/**
 * @brief Look up a helper implementation address ("import resolution").
 *
 * Supports two modes:
 * 1. Legacy registry mode: simple array lookup
 * 2. program_data mode: lookup in ebpf_program_data_t structures (like ebpf_core.c)
 */
static helper_function_t
_bpf_program_lib_lookup_helper(uint32_t helper_id)
{
    if (_state.use_program_data && _state.program_data != NULL) {
        // New mode: look up in ebpf_program_data_t structures
        const ebpf_program_data_t* program_data = _state.program_data;

        // Check global helpers (helper_id < EBPF_MAX_GENERAL_HELPER_FUNCTION)
        if (helper_id < EBPF_MAX_GENERAL_HELPER_FUNCTION) {
            if (program_data->global_helper_function_addresses != NULL &&
                program_data->program_info != NULL) {
                for (size_t i = 0; i < program_data->program_info->count_of_global_helpers; i++) {
                    if (program_data->program_info->global_helper_prototype[i].helper_id == helper_id) {
                        return (helper_function_t)program_data->global_helper_function_addresses
                            ->helper_function_address[i];
                    }
                }
            }
        } else {
            // Program-type-specific helpers (helper_id >= EBPF_MAX_GENERAL_HELPER_FUNCTION)
            if (program_data->program_type_specific_helper_function_addresses != NULL &&
                program_data->program_info != NULL) {
                for (size_t i = 0; i < program_data->program_info->count_of_program_type_specific_helpers; i++) {
                    if (program_data->program_info->program_type_specific_helper_prototype[i].helper_id == helper_id) {
                        return (helper_function_t)program_data->program_type_specific_helper_function_addresses
                            ->helper_function_address[i];
                    }
                }
            }
        }
        return NULL;
    } else {
        // Legacy mode: simple registry lookup
        for (size_t i = 0; i < _state.registry_count; i++) {
            if (_state.registry[i].helper_id == helper_id) {
                return _state.registry[i].address;
            }
        }
        return NULL;
    }
}

/**
 * @brief Resolve every helper the program references against the static registry and build the
 * runtime context's helper_data array.
 */
static NTSTATUS
_bpf_program_lib_resolve_helpers(_In_ const program_entry_t* program, _Inout_ bpf_loaded_program_t* loaded)
{
    uint16_t helper_count = program->helper_count;

    EBPF_LOG_MESSAGE_UINT64(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: _resolve_helpers ENTRY, helper_count",
        (uint64_t)helper_count);

    loaded->helper_count = helper_count;
    loaded->helper_data = NULL;
    loaded->runtime_context.helper_data = NULL;

    if (helper_count == 0) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: no helpers to resolve (count=0)");
        return STATUS_SUCCESS;
    }

    helper_function_data_t* helper_data = (helper_function_data_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(helper_function_data_t) * helper_count, BPF_PROGRAM_LIB_POOL_TAG);
    if (helper_data == NULL) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: helper resolution FAILED - ExAllocatePool returned NULL");
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(helper_data, sizeof(helper_function_data_t) * helper_count);

    EBPF_LOG_MESSAGE_UINT64(
        EBPF_TRACELOG_LEVEL_VERBOSE,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: allocated helper_data array at",
        (uint64_t)helper_data);

    // The helpers array is a versioned/strided array; stride by header.total_size.
    size_t helper_entry_size = program->helpers[0].header.total_size;

    EBPF_LOG_MESSAGE_UINT64(
        EBPF_TRACELOG_LEVEL_VERBOSE,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: helper_entry_size (stride)",
        (uint64_t)helper_entry_size);

    for (uint16_t i = 0; i < helper_count; i++) {
        const helper_function_entry_t* entry =
            (const helper_function_entry_t*)ARRAY_ELEMENT_INDEX(program->helpers, i, helper_entry_size);

        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: resolving helper (index, helper_id)",
            (uint64_t)i,
            (uint64_t)entry->helper_id);

        helper_function_t address = _bpf_program_lib_lookup_helper(entry->helper_id);
        if (address == NULL) {
            // The program imports a helper the host does not provide: fail the load, just like a
            // DLL failing to resolve an import.
            EBPF_LOG_MESSAGE_UINT64(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_BASE,
                "bpf_program_lib: helper resolution FAILED - helper_id not found in registry",
                (uint64_t)entry->helper_id);
            ExFreePool(helper_data);
            return STATUS_PROCEDURE_NOT_FOUND;
        }

        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_VERBOSE,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: helper resolved (index, address)",
            (uint64_t)i,
            (uint64_t)address);

        helper_data[i].header = (ebpf_native_module_header_t)EBPF_NATIVE_HELPER_FUNCTION_DATA_HEADER;
        helper_data[i].address = address;
        helper_data[i].tail_call = false; // Layer 1: no tail calls.
    }

    loaded->helper_data = helper_data;
    loaded->runtime_context.helper_data = helper_data;

    EBPF_LOG_MESSAGE_UINT64(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: all helpers resolved successfully (count)",
        (uint64_t)helper_count);

    return STATUS_SUCCESS;
}

/**
 * @brief NMR provider attach callback. Called when a bpf2c client driver attaches.
 *
 * The client's metadata_table arrives as client_dispatch.
 */
static NTSTATUS
_bpf_program_lib_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_result_maybenull_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch)
{
    UNREFERENCED_PARAMETER(nmr_binding_handle);
    UNREFERENCED_PARAMETER(provider_context);
    UNREFERENCED_PARAMETER(client_binding_context);

    NTSTATUS status;
    const metadata_table_t* table = (const metadata_table_t*)client_dispatch;
    program_entry_t* programs = NULL;
    size_t program_count = 0;
    bpf_loaded_program_t loaded = {0};

    *provider_binding_context = NULL;
    *provider_dispatch = NULL;

    EBPF_LOG_MESSAGE(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: _provider_attach_client ENTRY");

    // Log client module ID if available
    if (client_registration_instance != NULL && client_registration_instance->ModuleId != NULL) {
        if (client_registration_instance->ModuleId->Type == MIT_GUID) {
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_INFO,
                EBPF_TRACELOG_KEYWORD_BASE,
                "bpf_program_lib: client module GUID",
                &client_registration_instance->ModuleId->Guid);
        } else {
            EBPF_LOG_MESSAGE_UINT64(
                EBPF_TRACELOG_LEVEL_WARNING,
                EBPF_TRACELOG_KEYWORD_BASE,
                "bpf_program_lib: client module ID type (not GUID)",
                (uint64_t)client_registration_instance->ModuleId->Type);
        }
    }

    // Requirement #4: only one bpf2c client may be loaded at a time.
    if (InterlockedCompareExchange(&_state.program_loaded, 1, 0) != 0) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: attach REJECTED - program already loaded");
        return STATUS_INVALID_DEVICE_STATE;
    }

    EBPF_LOG_MESSAGE(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: program_loaded flag set successfully");

    if (table == NULL) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: attach FAILED - metadata_table is NULL");
        status = STATUS_INVALID_PARAMETER;
        goto Error;
    }

    EBPF_LOG_MESSAGE_UINT64(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: metadata_table pointer, calling table->programs()",
        (uint64_t)table);

    table->programs(&programs, &program_count);

    EBPF_LOG_MESSAGE_UINT64_UINT64(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: programs() returned (program_count, programs_ptr)",
        (uint64_t)program_count,
        (uint64_t)programs);

    if (program_count == 0 || programs == NULL) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: attach FAILED - no programs found (count, ptr)",
            (uint64_t)program_count,
            (uint64_t)programs);
        status = STATUS_NOT_FOUND;
        goto Error;
    }

    // Pick the first program (single-program demo). programs is a strided array but we only need [0].
    {
        const program_entry_t* program = programs; // index 0 -> base pointer.

        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: program[0] (function_ptr, helper_count)",
            (uint64_t)program->function,
            (uint64_t)program->helper_count);

        if (program->function == NULL) {
            EBPF_LOG_MESSAGE(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_BASE,
                "bpf_program_lib: attach FAILED - program function pointer is NULL");
            status = STATUS_INVALID_PARAMETER;
            goto Error;
        }

        status = _bpf_program_lib_resolve_helpers(program, &loaded);
        if (!NT_SUCCESS(status)) {
            EBPF_LOG_MESSAGE_NTSTATUS(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_BASE,
                "bpf_program_lib: attach FAILED - helper resolution failed",
                status);
            goto Error;
        }

        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: helper resolution succeeded");

        loaded.function = program->function;
        loaded.runtime_context.map_data = NULL;                     // Layer 1: no maps.
        loaded.runtime_context.global_variable_section_data = NULL; // Layer 1: no globals.
    }

    // Publish the bound program.
    _state.loaded_program = loaded;

    EBPF_LOG_MESSAGE(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: attach SUCCESS - program bound and published");

    return STATUS_SUCCESS;

Error:
    EBPF_LOG_MESSAGE_NTSTATUS(
        EBPF_TRACELOG_LEVEL_ERROR,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: attach ERROR path - rolling back",
        status);
    // Roll back the "loaded" flag so a subsequent valid client can attach.
    InterlockedExchange(&_state.program_loaded, 0);
    return status;
}

static NTSTATUS
_bpf_program_lib_provider_detach_client(_In_ void* provider_binding_context)
{
    UNREFERENCED_PARAMETER(provider_binding_context);

    EBPF_LOG_MESSAGE(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: _provider_detach_client ENTRY");

    // Free helper_data and clear the bound program. The bpf2c client is detaching/unloading.
    if (InterlockedCompareExchange(&_state.program_loaded, 0, 1) == 1) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: detaching - freeing helper_data and clearing loaded program");
        if (_state.loaded_program.helper_data != NULL) {
            ExFreePool(_state.loaded_program.helper_data);
        }
        RtlZeroMemory(&_state.loaded_program, sizeof(_state.loaded_program));
    } else {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_WARNING,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: detach called but no program was loaded");
    }

    EBPF_LOG_MESSAGE(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: _provider_detach_client EXIT (success)");

    // No asynchronous references are held against the program, so detach completes synchronously.
    return STATUS_SUCCESS;
}

static void
_bpf_program_lib_provider_cleanup_binding_context(_In_ void* provider_binding_context)
{
    UNREFERENCED_PARAMETER(provider_binding_context);
}

NTSTATUS
bpf_program_lib_initiate(
    _In_ const GUID* npi_id,
    _In_reads_(registry_count) bpf_helper_registry_entry_t* registry,
    size_t registry_count)
{
    EBPF_LOG_MESSAGE(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: bpf_program_lib_initiate ENTRY");

    EBPF_LOG_MESSAGE_GUID(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: NPI ID",
        npi_id);

    EBPF_LOG_MESSAGE_UINT64(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: registry_count",
        (uint64_t)registry_count);

    if (_state.nmr_provider_handle != NULL) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: initiate FAILED - already initiated");
        return STATUS_INVALID_DEVICE_STATE;
    }

    _state.npi_id = *npi_id;
    _state.registry = registry;
    _state.registry_count = registry_count;
    _state.program_data = NULL;
    _state.use_program_data = false;
    _state.program_loaded = 0;

    NPI_PROVIDER_CHARACTERISTICS* characteristics = &_state.characteristics;
    RtlZeroMemory(characteristics, sizeof(*characteristics));
    characteristics->Length = sizeof(NPI_PROVIDER_CHARACTERISTICS);
    characteristics->ProviderAttachClient = _bpf_program_lib_provider_attach_client;
    characteristics->ProviderDetachClient = _bpf_program_lib_provider_detach_client;
    characteristics->ProviderCleanupBindingContext = _bpf_program_lib_provider_cleanup_binding_context;
    characteristics->ProviderRegistrationInstance.Size = sizeof(NPI_REGISTRATION_INSTANCE);
    characteristics->ProviderRegistrationInstance.NpiId = &_state.npi_id;
    characteristics->ProviderRegistrationInstance.ModuleId = &_bpf_program_lib_module_id;

    NTSTATUS status = NmrRegisterProvider(characteristics, NULL, &_state.nmr_provider_handle);

    if (NT_SUCCESS(status)) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: NmrRegisterProvider SUCCESS, handle",
            (uint64_t)_state.nmr_provider_handle);
    } else {
        EBPF_LOG_MESSAGE_NTSTATUS(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: NmrRegisterProvider FAILED",
            status);
    }

    return status;
}

void
bpf_program_lib_terminate(void)
{
    if (_state.nmr_provider_handle != NULL) {
        NTSTATUS status = NmrDeregisterProvider(_state.nmr_provider_handle);
        if (status == STATUS_PENDING) {
            NmrWaitForProviderDeregisterComplete(_state.nmr_provider_handle);
        }
        _state.nmr_provider_handle = NULL;
    }

    // Provider deregistration drives detach for any attached client, which frees helper_data.
    // Guard in case no client ever attached.
    if (_state.loaded_program.helper_data != NULL) {
        ExFreePool(_state.loaded_program.helper_data);
        _state.loaded_program.helper_data = NULL;
    }
    RtlZeroMemory(&_state.loaded_program, sizeof(_state.loaded_program));
    _state.program_loaded = 0;
}

_Ret_maybenull_ const bpf_loaded_program_t*
bpf_program_lib_get_loaded_program(void)
{
    if (InterlockedCompareExchange(&_state.program_loaded, 1, 1) != 1) {
        return NULL;
    }
    return &_state.loaded_program;
}

uint64_t
bpf_program_lib_invoke(_In_opt_ const bpf_loaded_program_t* program, _Inout_ void* context)
{
    if (program == NULL) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_WARNING,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: invoke called with NULL program");
        return 0;
    }
    if (program->function == NULL) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_program_lib: invoke called with NULL function pointer");
        return 0;
    }

    EBPF_LOG_MESSAGE_UINT64_UINT64(
        EBPF_TRACELOG_LEVEL_VERBOSE,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: invoking program (function_ptr, context_ptr)",
        (uint64_t)program->function,
        (uint64_t)context);

    uint64_t result = program->function(context, &program->runtime_context);

    EBPF_LOG_MESSAGE_UINT64(
        EBPF_TRACELOG_LEVEL_VERBOSE,
        EBPF_TRACELOG_KEYWORD_BASE,
        "bpf_program_lib: program returned",
        result);

    return result;
}
