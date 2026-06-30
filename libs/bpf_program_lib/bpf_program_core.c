// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Implementation of general eBPF helper functions for use with bpf_program_lib.
 *
 * This file contains implementations of all the general eBPF helper functions
 * that were originally part of _ebpf_general_helpers in ebpf_core.c, renamed
 * with the _bpf_program prefix for use in the bpf_program_lib library.
 */

#include "bpf_program_lib.h"
#include "ebpf_tracelog.h"
#include "ebpf_maps.h"
#include "ebpf_program.h"
#include "ebpf_random.h"

#include <errno.h>
#include <stdlib.h>
#include <ntddk.h>
#pragma warning(push)
#pragma warning(disable : 28196)
#include <ntstrsafe.h>
#pragma warning(pop)

#define EBPF_NS_PER_FILETIME 100
#define EBPF_FILETIME_PER_MS 10000

// Pick a limit on string size based on the size of the eBPF stack.
#define MAX_PRINTK_STRING_SIZE 512

// Only integers are currently supported.
#define PRINTK_SPECIFIER_CHARS "diux"

// Forward declarations
static void*
_bpf_program_map_find_element(ebpf_map_t* map, const uint8_t* key);
static int64_t
_bpf_program_map_update_element(ebpf_map_t* map, const uint8_t* key, const uint8_t* value, uint64_t flags);
static int64_t
_bpf_program_map_delete_element(ebpf_map_t* map, const uint8_t* key);
static void*
_bpf_program_map_find_and_delete_element(_Inout_ ebpf_map_t* map, _In_ const uint8_t* key);
static int64_t
_bpf_program_tail_call(void* ctx, ebpf_map_t* map, uint32_t index);
static uint64_t
_bpf_program_get_time_since_boot_ns();
static uint64_t
_bpf_program_get_time_ns();
static long
_bpf_program_trace_printk2(_In_reads_(fmt_size) const char* fmt, size_t fmt_size);
static long
_bpf_program_trace_printk3(_In_reads_(fmt_size) const char* fmt, size_t fmt_size, uint64_t arg3);
static long
_bpf_program_trace_printk4(_In_reads_(fmt_size) const char* fmt, size_t fmt_size, uint64_t arg3, uint64_t arg4);
static long
_bpf_program_trace_printk5(
    _In_reads_(fmt_size) const char* fmt, size_t fmt_size, uint64_t arg3, uint64_t arg4, uint64_t arg5);
static int
_bpf_program_ring_buffer_output(
    _Inout_ ebpf_map_t* map, _In_reads_bytes_(length) uint8_t* data, size_t length, uint64_t flags);
static int
_bpf_program_map_push_elem(_Inout_ ebpf_map_t* map, _In_ const uint8_t* value, uint64_t flags);
static int
_bpf_program_map_pop_elem(_Inout_ ebpf_map_t* map, _Out_ uint8_t* value);
static int
_bpf_program_map_peek_elem(_Inout_ ebpf_map_t* map, _Out_ uint8_t* value);
static uint64_t
_bpf_program_get_pid_tgid();
static uint64_t
_bpf_program_get_current_logon_id(_In_ const void* ctx);
static int32_t
_bpf_program_is_current_admin(_In_ const void* ctx);
static int32_t
_bpf_program_memcpy_s(
    _Out_writes_(destination_size) void* destination,
    size_t destination_size,
    _In_reads_(source_size) const void* source,
    size_t source_size);
static int32_t
_bpf_program_memcmp_s(
    _In_reads_(buffer1_length) const void* buffer1,
    size_t buffer1_length,
    _In_reads_(buffer2_length) const void* buffer2,
    size_t buffer2_length);
static uintptr_t
_bpf_program_memset(_Out_writes_(length) void* buffer, size_t length, int value);
static int32_t
_bpf_program_memmove_s(
    _Out_writes_(destination_length) void* destination,
    size_t destination_length,
    _In_reads_(source_length) const void* source,
    size_t source_length);
static uint64_t
_bpf_program_get_time_since_boot_ms();
static uint64_t
_bpf_program_get_time_ms();
static int
_bpf_program_perf_event_output(
    _In_ void* ctx, _Inout_ ebpf_map_t* map, uint64_t flags, _In_reads_bytes_(length) uint8_t* data, size_t length);
static uint64_t
_bpf_program_get_current_process_start_key(
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    uint64_t dummy_param5,
    _In_ const void* ctx);
static int64_t
_bpf_program_get_current_thread_create_time(
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    uint64_t dummy_param5,
    _In_ const void* ctx);
static errno_t
_bpf_program_strncpy_s(
    _Out_writes_(dest_size) char* dest, size_t dest_size, _In_reads_(count) const char* src, size_t count);
static errno_t
_bpf_program_strncat_s(
    _Out_writes_(dest_size) char* dest, size_t dest_size, _In_reads_(count) const char* src, size_t count);
static size_t
_bpf_program_strlen_s(_In_reads_(str_size) const char* str, size_t str_size);

int
_bpf_program_csum_diff(
    _In_reads_bytes_opt_(from_size) const void* from,
    int from_size,
    _In_reads_bytes_opt_(to_size) const void* to,
    int to_size,
    int seed);
    //
// Static helper registry and program data structures (mimicking ebpf_core.c's pattern).
//
// The demo program (program.c) calls no helper functions: it only reads its context and returns
// the parity of the process id. The registry is therefore empty. To let a loaded program call a
// helper, add an entry here mapping its helper id to a host implementation.
//

// Helper function prototypes (empty for now)
static const ebpf_helper_function_prototype_t* _prog_core_global_helper_prototype = NULL;
static const uint32_t _prog_core_global_helper_count = 0;

// Helper function addresses (empty for now)
static const void* _prog_core_general_helpers[] = {

    // Map related helpers.
    (void*)&_bpf_program_map_find_element,
    (void*)&_bpf_program_map_update_element,
    (void*)&_bpf_program_map_delete_element,
    (void*)&_bpf_program_map_find_and_delete_element,
    // Tail call.
    (void*)&_bpf_program_tail_call,
    // Utility functions.
    (void*)&ebpf_random_uint32,
    (void*)&_bpf_program_get_time_since_boot_ns,
    (void*)&ebpf_get_current_cpu,
    (void*)&_bpf_program_get_time_ns,
    (void*)&_bpf_program_csum_diff,
    // Ring buffer output.
    (void*)&_bpf_program_ring_buffer_output,
    (void*)&_bpf_program_trace_printk2,
    (void*)&_bpf_program_trace_printk3,
    (void*)&_bpf_program_trace_printk4,
    (void*)&_bpf_program_trace_printk5,
    (void*)&_bpf_program_map_push_elem,
    (void*)&_bpf_program_map_pop_elem,
    (void*)&_bpf_program_map_peek_elem,
    (void*)&_bpf_program_get_pid_tgid,
    (void*)&_bpf_program_get_current_logon_id,
    (void*)&_bpf_program_is_current_admin,
    (void*)&_bpf_program_memcpy_s,
    (void*)&_bpf_program_memcmp_s,
    (void*)&_bpf_program_memset,
    (void*)&_bpf_program_memmove_s,
    // No default implementation of bpf_get_socket_cookie
    (void*)NULL, // bpf_get_socket_cookie
    (void*)&_bpf_program_strncpy_s,
    (void*)&_bpf_program_strncat_s,
    (void*)&_bpf_program_strlen_s,
    (void*)&_bpf_program_get_time_since_boot_ms,
    (void*)&_bpf_program_get_time_ms,
    // Perf event array (perf buffer) output.
    (void*)&_bpf_program_perf_event_output,
    (void*)&_bpf_program_get_current_process_start_key,
    (void*)&_bpf_program_get_current_thread_create_time,
};

// Helper registry: maps helper_id to function address.
// Array index corresponds to (helper_id - 1), since helper IDs start at 1.
bpf_helper_registry_entry_t _prog_core_helper_registry[] = {
    {BPF_FUNC_map_lookup_elem, (helper_function_t)&_bpf_program_map_find_element},                 // helper_id 1
    {BPF_FUNC_map_update_elem, (helper_function_t)&_bpf_program_map_update_element},               // helper_id 2
    {BPF_FUNC_map_delete_elem, (helper_function_t)&_bpf_program_map_delete_element},               // helper_id 3
    {BPF_FUNC_map_lookup_and_delete_elem, (helper_function_t)&_bpf_program_map_find_and_delete_element},     // helper_id 4
    {BPF_FUNC_tail_call, (helper_function_t)&_bpf_program_tail_call},                                       // helper_id 5
    {BPF_FUNC_get_prandom_u32, (helper_function_t)&ebpf_random_uint32},                                     // helper_id 6
    {BPF_FUNC_ktime_get_boot_ns, (helper_function_t)&_bpf_program_get_time_since_boot_ns},                 // helper_id 7
    {BPF_FUNC_get_smp_processor_id, (helper_function_t)&ebpf_get_current_cpu},                             // helper_id 8
    {BPF_FUNC_ktime_get_ns, (helper_function_t)&_bpf_program_get_time_ns},                                 // helper_id 9
    {BPF_FUNC_csum_diff, (helper_function_t)&_bpf_program_csum_diff},                                      // helper_id 10
    {BPF_FUNC_ringbuf_output, (helper_function_t)&_bpf_program_ring_buffer_output},                        // helper_id 11
    {BPF_FUNC_trace_printk2, (helper_function_t)&_bpf_program_trace_printk2},                              // helper_id 12
    {BPF_FUNC_trace_printk3, (helper_function_t)&_bpf_program_trace_printk3},                              // helper_id 13
    {BPF_FUNC_trace_printk4, (helper_function_t)&_bpf_program_trace_printk4},                              // helper_id 14
    {BPF_FUNC_trace_printk5, (helper_function_t)&_bpf_program_trace_printk5},                              // helper_id 15
    {BPF_FUNC_map_push_elem, (helper_function_t)&_bpf_program_map_push_elem},                              // helper_id 16
    {BPF_FUNC_map_pop_elem, (helper_function_t)&_bpf_program_map_pop_elem},                                // helper_id 17
    {BPF_FUNC_map_peek_elem, (helper_function_t)&_bpf_program_map_peek_elem},                              // helper_id 18
    {BPF_FUNC_get_current_pid_tgid, (helper_function_t)&_bpf_program_get_pid_tgid},                        // helper_id 19
    {BPF_FUNC_get_current_logon_id, (helper_function_t)&_bpf_program_get_current_logon_id},                // helper_id 20
    {BPF_FUNC_is_current_admin, (helper_function_t)&_bpf_program_is_current_admin},                        // helper_id 21
    {BPF_FUNC_memcpy_s, (helper_function_t)&_bpf_program_memcpy_s},                                        // helper_id 22
    {BPF_FUNC_memcmp_s, (helper_function_t)&_bpf_program_memcmp_s},                                        // helper_id 23
    {BPF_FUNC_memset, (helper_function_t)&_bpf_program_memset},                                            // helper_id 24
    {BPF_FUNC_memmove_s, (helper_function_t)&_bpf_program_memmove_s},                                      // helper_id 25
    {BPF_FUNC_get_socket_cookie, (helper_function_t)NULL},                                                 // helper_id 26
    {BPF_FUNC_strncpy_s, (helper_function_t)&_bpf_program_strncpy_s},                                      // helper_id 27
    {BPF_FUNC_strncat_s, (helper_function_t)&_bpf_program_strncat_s},                                      // helper_id 28
    {BPF_FUNC_strnlen_s, (helper_function_t)&_bpf_program_strlen_s},                                       // helper_id 29
    {BPF_FUNC_ktime_get_boot_ms, (helper_function_t)&_bpf_program_get_time_since_boot_ms},                 // helper_id 30
    {BPF_FUNC_ktime_get_ms, (helper_function_t)&_bpf_program_get_time_ms},                                 // helper_id 31
    {BPF_FUNC_perf_event_output, (helper_function_t)&_bpf_program_perf_event_output},                      // helper_id 32
    {BPF_FUNC_get_current_process_start_key, (helper_function_t)&_bpf_program_get_current_process_start_key},     // helper_id 33
    {BPF_FUNC_get_current_thread_create_time, (helper_function_t)&_bpf_program_get_current_thread_create_time},   // helper_id 34
};


bpf_helper_registry_entry_t*
getRegistry()
{
    return (bpf_helper_registry_entry_t*)_prog_core_helper_registry;
}

//
// Map-related helper functions
//

static void*
_bpf_program_map_find_element(ebpf_map_t* map, const uint8_t* key)
{
    ebpf_result_t retval;
    uint8_t* value;
    retval = ebpf_map_find_entry(map, 0, key, sizeof(&value), (uint8_t*)&value, EBPF_MAP_FLAG_HELPER);
    if (retval != EBPF_SUCCESS) {
        return NULL;
    } else {
        return value;
    }
}

static int64_t
_bpf_program_map_update_element(ebpf_map_t* map, const uint8_t* key, const uint8_t* value, uint64_t flags)
{
    return -ebpf_map_update_entry(map, 0, key, 0, value, flags, EBPF_MAP_FLAG_HELPER);
}

static int64_t
_bpf_program_map_delete_element(ebpf_map_t* map, const uint8_t* key)
{
    return -ebpf_map_delete_entry(map, 0, key, EBPF_MAP_FLAG_HELPER);
}

static void*
_bpf_program_map_find_and_delete_element(_Inout_ ebpf_map_t* map, _In_ const uint8_t* key)
{
    ebpf_result_t retval;
    uint8_t* value;
    retval = ebpf_map_find_entry(
        map, 0, key, sizeof(&value), (uint8_t*)&value, EBPF_MAP_FLAG_HELPER | EBPF_MAP_FIND_FLAG_DELETE);
    if (retval != EBPF_SUCCESS) {
        return NULL;
    } else {
        return value;
    }
}

static int
_bpf_program_map_push_elem(_Inout_ ebpf_map_t* map, _In_ const uint8_t* value, uint64_t flags)
{
    return -ebpf_map_push_entry(map, 0, value, (int)flags | EBPF_MAP_FLAG_HELPER);
}

static int
_bpf_program_map_pop_elem(_Inout_ ebpf_map_t* map, _Out_ uint8_t* value)
{
    return -ebpf_map_pop_entry(map, 0, value, EBPF_MAP_FLAG_HELPER);
}

static int
_bpf_program_map_peek_elem(_Inout_ ebpf_map_t* map, _Out_ uint8_t* value)
{
    return -ebpf_map_peek_entry(map, 0, value, EBPF_MAP_FLAG_HELPER);
}

//
// Tail call
//

static int64_t
_bpf_program_tail_call(void* context, ebpf_map_t* map, uint32_t index)
{
    // Get program from map[index].
    ebpf_program_t* callee = ebpf_map_get_program_from_entry(map, sizeof(index), (uint8_t*)&index);
    if (callee == NULL) {
        return -EBPF_INVALID_ARGUMENT;
    }
    return -ebpf_program_set_tail_call(context, callee);
}

//
// Utility functions
//

static uint32_t
_bpf_program_random_uint32()
{
    return ebpf_random_uint32();
}

static uint64_t
_bpf_program_get_time_since_boot_ns()
{
    // cxplat_query_time_since_boot_precise returns time elapsed since
    // boot in units of 100 ns.
    return cxplat_query_time_since_boot_precise(true) * EBPF_NS_PER_FILETIME;
}

static uint32_t
_bpf_program_get_current_cpu()
{
    return ebpf_get_current_cpu();
}

static uint64_t
_bpf_program_get_time_ns()
{
    // cxplat_query_time_since_boot_precise returns time elapsed since
    // boot in units of 100 ns.
    return cxplat_query_time_since_boot_precise(false) * EBPF_NS_PER_FILETIME;
}

int
_bpf_program_csum_diff(
    _In_reads_bytes_opt_(from_size) const void* from,
    int from_size,
    _In_reads_bytes_opt_(to_size) const void* to,
    int to_size,
    int seed)
{
    int csum_diff = -EINVAL;

    if ((from_size % 4 != 0) || (to_size % 4 != 0)) {
        // size of buffers should be a multiple of 4.
        goto Exit;
    }

    csum_diff = seed;
    if (to != NULL) {
        for (int i = 0; i < to_size / 2; i++) {
            csum_diff += (uint16_t)(*((uint16_t*)to + i));
        }
    }
    if (from != NULL) {
        for (int i = 0; i < from_size / 2; i++) {
            csum_diff += (uint16_t)(~*((uint16_t*)from + i));
        }
    }

    // Adding 16-bit unsigned integers or their one's complement will produce a positive 32-bit integer,
    // unless the length of the buffers is so long, that the signed 32 bit output overflows and produces a negative
    // result.
    if (csum_diff < 0) {
        csum_diff = -EINVAL;
    }
Exit:
    return csum_diff;
}

static uint64_t
_bpf_program_get_time_since_boot_ms()
{
    // cxplat_query_time_since_boot_approximate returns time elapsed since
    // boot in units of 100 ns.
    return cxplat_query_time_since_boot_approximate(true) / EBPF_FILETIME_PER_MS;
}

static uint64_t
_bpf_program_get_time_ms()
{
    // cxplat_query_time_since_boot_approximate returns time elapsed since
    // boot in units of 100 ns.
    return cxplat_query_time_since_boot_approximate(false) / EBPF_FILETIME_PER_MS;
}

//
// Ring buffer output
//

static int
_bpf_program_ring_buffer_output(
    _Inout_ ebpf_map_t* map, _In_reads_bytes_(length) uint8_t* data, size_t length, uint64_t flags)
{
    // This function implements bpf_ringbuf_output helper function, which returns negative error in case of failure.
    UNREFERENCED_PARAMETER(flags);
    return -ebpf_ring_buffer_map_output(map, data, length);
}

//
// Trace printk functions
//

static long
_bpf_program_trace_printk(_In_reads_(fmt_size) const char* fmt, size_t fmt_size, int arg_count, ...)
{
    if (fmt_size > MAX_PRINTK_STRING_SIZE - 1) {
        // Disallow large fmt_size values.
        return -1;
    }

    // If the provider is not enabled, don't bother with the rest.
    if (!TraceLoggingProviderEnabled(ebpf_tracelog_provider, EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_PRINTK)) {
        return 0;
    }

    // Make a copy of the original format string.
    char* output = (char*)ExAllocatePoolUninitialized(NonPagedPoolNx, fmt_size + 1, 'pfbe');
    if (output == NULL) {
        return -1;
    }
    memcpy(output, fmt, fmt_size);

    // Make sure the output is null-terminated, and
    // remove the newline if present.
    // A well-formed input should be null terminated,
    // so look at the next-to-last byte.
    char* end = output + fmt_size - 2;
    if (*end != '\n') {
        end++;
    }
    *end = '\0';

    /* Validate format string.
     * The conversion specifiers are limited to:
     * %d, %i, %u, %x, %ld, %li, %lu, %lx, %lld, %lli, %llu, %llx.
     * No modifier (size of field, padding with zeroes, etc.) is available.
     */
    long bytes_written = -1;
    const char* p;
    int specifier_count = 0;
    for (p = output; *p; p++) {
        if (*p != '%') {
            continue;
        }
        if (p[1] == 0) {
            break;
        }
        if (p[1] == '%') {
            // Allow a %% escape.
            p++;
            continue;
        }

        // We found a specifier.  Verify that it is in the legal set.
        if (strchr(PRINTK_SPECIFIER_CHARS, p[1])) {
            // We found a legal one character specifier.
            p++;
            specifier_count++;
            continue;
        }

        if (p[1] != 'l' || p[2] == 0) {
            break;
        }
        if (strchr(PRINTK_SPECIFIER_CHARS, p[2])) {
            // We found a legal two character specifier.
            p += 2;
            specifier_count++;
            continue;
        }

        if (p[2] != 'l' || p[3] == 0) {
            break;
        }
        if (strchr(PRINTK_SPECIFIER_CHARS, p[3])) {
            // We found a legal three character specifier.
            p += 3;
            specifier_count++;
            continue;
        }
        break;
    }

    if ((*p == 0) && (arg_count == specifier_count)) {
        va_list arg_list;
        va_start(arg_list, arg_count);
        bytes_written = ebpf_platform_printk(output, arg_list);
        va_end(arg_list);
    }

    ExFreePool(output);
    return bytes_written;
}

long
_bpf_program_trace_printk2(_In_reads_(fmt_size) const char* fmt, size_t fmt_size)
{
    return _bpf_program_trace_printk(fmt, fmt_size, 0);
}

long
_bpf_program_trace_printk3(_In_reads_(fmt_size) const char* fmt, size_t fmt_size, uint64_t arg3)
{
    return _bpf_program_trace_printk(fmt, fmt_size, 1, arg3);
}

long
_bpf_program_trace_printk4(_In_reads_(fmt_size) const char* fmt, size_t fmt_size, uint64_t arg3, uint64_t arg4)
{
    return _bpf_program_trace_printk(fmt, fmt_size, 2, arg3, arg4);
}

long
_bpf_program_trace_printk5(
    _In_reads_(fmt_size) const char* fmt, size_t fmt_size, uint64_t arg3, uint64_t arg4, uint64_t arg5)
{
    return _bpf_program_trace_printk(fmt, fmt_size, 3, arg3, arg4, arg5);
}

//
// Process/thread related functions
//

static uint64_t
_bpf_program_get_pid_tgid()
{
    return ((uint64_t)ebpf_platform_process_id() << 32) | ebpf_platform_thread_id();
}

static uint64_t
_bpf_program_get_current_logon_id(_In_ const void* ctx)
{
    uint64_t logon_id = 0;

    UNREFERENCED_PARAMETER(ctx);

    if (!ebpf_is_preemptible()) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_CORE, "get_current_logon_id: Called at DISPATCH.");

        return 0;
    }

    ebpf_result_t result = ebpf_platform_get_authentication_id(&logon_id);
    if (result != EBPF_SUCCESS) {
        return 0;
    }

    return logon_id;
}

static int32_t
_bpf_program_is_current_admin(_In_ const void* ctx)
{
    // TODO: Issue# 1871 - Implement this function.
    UNREFERENCED_PARAMETER(ctx);

    return -1;
}

//
// Memory manipulation functions
//

static int32_t
_bpf_program_memcpy_s(
    _Out_writes_(destination_size) void* destination,
    size_t destination_size,
    _In_reads_(source_size) const void* source,
    size_t source_size)
{
    if (source_size > destination_size) {
        return -EINVAL;
    }
    return memcpy_s(destination, destination_size, source, source_size);
}

static uintptr_t
_bpf_program_memset(_Out_writes_(length) void* buffer, size_t length, int value)
{
    return (uintptr_t)memset(buffer, value, length);
}

static int32_t
_bpf_program_memcmp_s(
    _In_reads_(buffer1_length) const void* buffer1,
    size_t buffer1_length,
    _In_reads_(buffer2_length) const void* buffer2,
    size_t buffer2_length)
{
    int32_t result = memcmp(buffer1, buffer2, buffer1_length < buffer2_length ? buffer1_length : buffer2_length);

    if (result == 0) {
        if (buffer1_length < buffer2_length) {
            result = -1;
        } else if (buffer1_length > buffer2_length) {
            result = 1;
        }
    } else {
        result = result < 0 ? -1 : 1;
    }
    return result;
}

static int32_t
_bpf_program_memmove_s(
    _Out_writes_(destination_length) void* destination,
    size_t destination_length,
    _In_reads_(source_length) const void* source,
    size_t source_length)
{
    if (source_length > destination_length) {
        return -EINVAL;
    }
    return memmove_s(destination, destination_length, source, source_length);
}

//
// String manipulation functions
//

static errno_t
_bpf_program_strncpy_s(
    _Out_writes_(dest_size) char* dest, size_t dest_size, _In_reads_(count) const char* src, size_t count)
{
    return RtlStringCbCopyNExA(dest, dest_size, src, count, NULL, NULL, STRSAFE_FILL_BEHIND_NULL | 0);
}

static errno_t
_bpf_program_strncat_s(
    _Out_writes_(dest_size) char* dest, size_t dest_size, _In_reads_(count) const char* src, size_t count)
{
    return RtlStringCbCatNExA(dest, dest_size, src, count, NULL, NULL, STRSAFE_FILL_BEHIND_NULL | 0);
}

static size_t
_bpf_program_strlen_s(_In_reads_(str_size) const char* str, size_t str_size)
{
    size_t length = 0;

    NTSTATUS Status = RtlStringCbLengthA(str, str_size, &length);

    if (NT_ERROR(Status)) {
        if (str == NULL) {
            // Null pointer: return 0.
            return 0;
        }

        // no null found; match the behavior of strlen_s and return the buffer length.
        return str_size;
    }

    return length;
}

//
// Perf event output
//

static int
_bpf_program_perf_event_output(
    _In_ void* ctx, _Inout_ ebpf_map_t* map, uint64_t flags, _In_reads_bytes_(length) uint8_t* data, size_t length)
{
    return -ebpf_perf_event_array_map_output_with_capture(ctx, map, flags, data, length);
}

//
// Process/thread tracking
//

static uint64_t
_bpf_program_get_current_process_start_key(
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    uint64_t dummy_param5,
    _In_ const void* ctx)
{
    UNREFERENCED_PARAMETER(dummy_param1);
    UNREFERENCED_PARAMETER(dummy_param2);
    UNREFERENCED_PARAMETER(dummy_param3);
    UNREFERENCED_PARAMETER(dummy_param4);
    UNREFERENCED_PARAMETER(dummy_param5);
    UNREFERENCED_PARAMETER(ctx);

    return PsGetProcessStartKey(IoGetCurrentProcess());
}

static int64_t
_bpf_program_get_current_thread_create_time(
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    uint64_t dummy_param5,
    _In_ const void* ctx)
{
    UNREFERENCED_PARAMETER(dummy_param1);
    UNREFERENCED_PARAMETER(dummy_param2);
    UNREFERENCED_PARAMETER(dummy_param3);
    UNREFERENCED_PARAMETER(dummy_param4);
    UNREFERENCED_PARAMETER(dummy_param5);
    UNREFERENCED_PARAMETER(ctx);

    return PsGetThreadCreateTime(KeGetCurrentThread());
}
