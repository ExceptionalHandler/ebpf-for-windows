// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"
#include "ebpf_protocol.h"

#include <windows.h>
#include <ip2string.h>
#include <io.h>
#include <iostream>
#include <string>
#include <thread>

#define EBPF_RINGBUF_LOCK_BIT (1U << 31)
#define EBPF_RINGBUF_DISCARD_BIT (1U << 30)

const char* connect_map = "connect::connect_map";
const char* program_path = "connect::program";
const char* program_link = "connect::program_link";

// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once


typedef struct _connect_info
{
    uint64_t time;
    uint32_t pid;
    uint32_t tid;
    uint32_t dst_address;
    uint16_t dst_port;
    uint32_t src_address;
    uint16_t src_port;
    uint32_t protocol;
    uint64_t socket_cookie;
} connect_info;


typedef struct _ebpf_ring_buffer_record
{
    // This struct should match the linux ring buffer record structure for future mmap compatibility (see #4163).
    struct
    {
        uint32_t length;      ///< High 2 bits are lock,discard.
        uint32_t page_offset; ///< Currently unused.
    } header;
    uint8_t data[1];
} ebpf_ring_buffer_record_t;


/**
 * @brief Locate the next record in the ring buffer's data buffer and
 * advance consumer offset.
 *
 * @param[in] buffer Pointer to the start of the ring buffer's data buffer.
 * @param[in] buffer_length Length of the ring buffer's data buffer.
 * @param[in] consumer Consumer offset.
 * @param[in] producer Producer offset.
 * @return Pointer to the next record or NULL if no more records.
 */
inline const ebpf_ring_buffer_record_t*
ebpf_ring_buffer_next_record(_In_ const uint8_t* buffer, size_t buffer_length, size_t consumer, size_t producer)
{
    if (producer < consumer) {
        return nullptr;
    }
    if (producer == consumer) {
        return NULL;
    }
    return (ebpf_ring_buffer_record_t*)(buffer + consumer % buffer_length);
}

inline const bool
ebpf_ring_buffer_record_is_locked(_In_ const ebpf_ring_buffer_record_t* record)
{
    // Uses read-acquire to ensure that if the record is unlocked and not discarded that the data is visible.
    return (ReadUInt32Acquire(&record->header.length) & EBPF_RINGBUF_LOCK_BIT) != 0;
}

inline const uint32_t
ebpf_ring_buffer_record_length(_In_ const ebpf_ring_buffer_record_t* record)
{
    return ReadUInt32NoFence(&record->header.length) & ~(EBPF_RINGBUF_LOCK_BIT | EBPF_RINGBUF_DISCARD_BIT);
}

inline const bool
ebpf_ring_buffer_record_is_discarded(_In_ const ebpf_ring_buffer_record_t* record)
{
    // We check the lock bit using read-acquire before checking for discard, so we can use no-fence here.
    return (ReadUInt32NoFence(&record->header.length) & EBPF_RINGBUF_DISCARD_BIT) != 0;
}

inline const uint32_t
ebpf_ring_buffer_record_total_size(_In_ const ebpf_ring_buffer_record_t* record)
{
    return (ebpf_ring_buffer_record_length(record) + EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data) + 7) & ~7;
}

int
load(int argc, char** argv)
{
    ebpf_result_t result;
    bpf_object* object = nullptr;
    bpf_program* program = nullptr;
    bpf_link* link = nullptr;
    fd_t program_fd;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    object = bpf_object__open("C:\\git\\hubble-fgs\\bpf\\windows\\NetDemo.sys");
    if (object == nullptr) {
        printf("\nAm here\n");
        fprintf(stderr, "Failed to open connect_monitor eBPF program\n");
        return 1;
    }

    result = ebpf_object_set_execution_type(object, EBPF_EXECUTION_NATIVE);
    if (result != EBPF_SUCCESS) {
        fprintf(stderr, "Failed to set execution type\n");
        return 1;
    }
    program = bpf_object__next_program(object, nullptr);
    if (bpf_object__load(object) < 0) {
        fprintf(stderr, "Failed to load  eBPF program\n");
        size_t log_buffer_size;
        fprintf(stderr, "%s", bpf_program__log_buf(program, &log_buffer_size));
        bpf_object__close(object);
        return 1;
    }
    program_fd = bpf_program__fd(program);

    fd_t connect_ringbuf_fd = bpf_object__find_map_fd_by_name(object, "connect_map");
    if (connect_ringbuf_fd <= 0) {
        fprintf(stderr, "Failed to find eBPF map : %s\n", connect_map);
        return 1;
    }
    
    if (bpf_obj_pin(connect_ringbuf_fd, connect_map) < 0) {
        fprintf(stderr, "Failed to pin eBPF program connect map: %d\n", errno);
        return 1;
    }
    

    
    result = ebpf_program_attach(program, nullptr, nullptr, 0, &link);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to attach eBPF program\n");
        return 1;
    }

    if (bpf_link__pin(link, program_link) < 0) {
        fprintf(stderr, "Failed to pin eBPF link: %d\n", errno);
        return 1;
    }

    if (bpf_program__pin(program, program_path) < 0) {
        fprintf(stderr, "Failed to pin eBPF program: %d\n", errno);
        return 1;
    }
    return 0;
}

int
unload(int argc, char** argv)
{
    ebpf_result_t result;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    result = ebpf_object_unpin(program_path);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF program: %d\n", result);
    }
    result = ebpf_object_unpin(program_link);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF link: %d\n", result);
    }
    result = ebpf_object_unpin(connect_map);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF command map: %d\n", result);
    }
    
    return 1;
}



std::string
AddressToString(void const* address, uint32_t len)
{
    char result[64];
    if (len == 4) {
        RtlIpv4AddressToStringA((in_addr const*)address, result);
    } else {
        RtlIpv6AddressToStringA((in6_addr const*)address, result);
    }
    return result;
}

const char*
ProtocolToString(uint32_t protocol)
{
    switch (protocol) {
    case IPPROTO_UDP:
        return "UDP";
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_ICMP:
        return "ICMP";
    case IPPROTO_PUP:
        return "PUP";
    case IPPROTO_RAW:
        return "RAW";
    case IPPROTO_IGMP:
        return "IGMP";
    }
    return "<Unknown>";
}

std::string
FormatTime(uint64_t time)
{
    static const auto boot = std::chrono::system_clock::now() - std::chrono::milliseconds(GetTickCount64());
    const auto tp = boot + std::chrono::milliseconds(time);

    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    tm timeInfo;
    char result[64];
    localtime_s(&timeInfo, &t);
    strftime(result, sizeof(result), "%Y-%m-%d %H:%M:%S", &timeInfo);
    return result;
}


int
connect_callback(_Inout_ void* ctx, _In_opt_ void* data, size_t size)
{
    char path[65520] = {};
    if ((!data) || (!size)) {
        fprintf(stderr, "NO data in data var\n");
    }
    UNREFERENCED_PARAMETER(ctx);
    connect_info* ci = reinterpret_cast<connect_info*>(data);
    printf(
        "%s PID: %6u TID: %6u Type: %-4s Dst Address: %s:%d Src Address: %s:%d\n",
        FormatTime(ci->time).c_str(),
        ci->pid,
        ci->tid,
        ProtocolToString(ci->protocol),
        AddressToString(&ci->dst_address, 4).c_str(),
        ntohs(ci->dst_port),
        AddressToString(&ci->src_address, 4).c_str(),
        ntohs(ci->src_port));
    return 0;
}


#ifndef OK

HANDLE hSync = INVALID_HANDLE_VALUE;
HANDLE hASync = INVALID_HANDLE_VALUE;

uint32_t
invoke_ioctl(void* request, DWORD dwReqSize, void* response, DWORD dwRespSize, OVERLAPPED* overlapped = nullptr)
{
    uint32_t return_value = ERROR_SUCCESS;
    DWORD actual_reply_size;
    uint32_t request_size = dwReqSize;
    void* request_ptr = request;
    uint32_t reply_size = dwRespSize;
    void* reply_ptr = response;
    bool variable_reply_size = false;
    bool success = false;

    HANDLE hDevice = INVALID_HANDLE_VALUE;

    if (!overlapped) {
        if (hSync == INVALID_HANDLE_VALUE) {
            hSync = CreateFileW(L"\\\\.\\EbpfIoDevice", GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, 0);
            if (hSync == INVALID_HANDLE_VALUE) {
                printf("\nCreate Sync device failed. Error = %d\n", GetLastError());
                goto Exit;
            }
            hDevice = hSync;
        }
    } else {
        if (hASync == INVALID_HANDLE_VALUE) {
            hASync = CreateFileW(
                L"\\\\.\\EbpfIoDevice",
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                CREATE_ALWAYS,
                FILE_FLAG_OVERLAPPED,
                0);
            if (hASync == INVALID_HANDLE_VALUE) {
                printf("\nCreate Sync device failed. Error = %d\n", GetLastError());
                goto Exit;
            }
        }
        hDevice = hASync;
    }
    if (hDevice == INVALID_HANDLE_VALUE) {
        return_value = ERROR_ACCESS_DENIED;
        goto Exit;
    }

    success = DeviceIoControl(
        hDevice,
        CTL_CODE(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS),
        request_ptr,
        request_size,
        reply_ptr,
        reply_size,
        &actual_reply_size,
        overlapped);

    if (!success) {
        return_value = GetLastError();
        printf("\nDevice io control failed. Error = %d\n", GetLastError());
        goto Exit;
    }

    if (actual_reply_size != reply_size && !variable_reply_size) {
        printf("\nDevice io control incorrect reply. ");
        return_value = ERROR_INVALID_PARAMETER;
        goto Exit;
    }

Exit:
    return (return_value);
}

HANDLE hOverlappedEvent = INVALID_HANDLE_VALUE;

HANDLE
GetOverlappedEvent()
{
    if (hOverlappedEvent == INVALID_HANDLE_VALUE) {
        hOverlappedEvent = CreateEvent(NULL, false, false, NULL);
        ResetEvent(hOverlappedEvent);
    }
    return hOverlappedEvent;
}

void
RecvEvents2()
{
    
    fd_t ringBuf_fd = bpf_obj_get((char*)connect_map);
    if (ringBuf_fd == ebpf_fd_invalid) {
        fprintf(stderr, "Failed to get  up eBPF ringbuf\n");
        return;
    }
    uint32_t result = EBPF_SUCCESS;

    ebpf_handle_t map_handle = _get_osfhandle(ringBuf_fd);
    if (map_handle == ebpf_handle_invalid) {
        fprintf(stderr, "Failed to get  ringbuf handle.\n");
        return;
    }
    bpf_map_info info = {0};

    uint32_t info_size = sizeof(info);
    auto err = bpf_obj_get_info_by_fd(ringBuf_fd, &info, &info_size);
    if (err) {
        fprintf(stderr, "Failed to get  map info.\n");
        return;
    }
    int ring_buffer_size = info.max_entries;

    HANDLE ring_buffer_map_handle;

    if (!DuplicateHandle(
            (GetCurrentProcess()),
            (HANDLE)map_handle,
            GetCurrentProcess(),
            &ring_buffer_map_handle,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS)) {
        fprintf(stderr, "Failed to dup map handle . Err = %d\n", GetLastError());
        return;
    }

    // Get user-mode address to ring buffer shared data.
    ebpf_operation_map_query_buffer_request_t query_buffer_request{
        sizeof(query_buffer_request),
        ebpf_operation_id_t::EBPF_OPERATION_MAP_QUERY_BUFFER,
        (ebpf_handle_t)ring_buffer_map_handle};
    ebpf_operation_map_query_buffer_reply_t query_buffer_reply{};

    result = invoke_ioctl(
        &query_buffer_request, sizeof(query_buffer_request), &query_buffer_reply, sizeof(query_buffer_reply));
    if (result != EBPF_SUCCESS) {
        fprintf(stderr, "Failed do device io control . Err = %d\n", result);
        return;
    }
    uint8_t* buffer = reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(query_buffer_reply.buffer_address));

    // Issue the async query IOCTL.
    ebpf_operation_map_async_query_request_t async_query_request{
        sizeof(async_query_request),
        ebpf_operation_id_t::EBPF_OPERATION_MAP_ASYNC_QUERY,
        (ebpf_handle_t)ring_buffer_map_handle,
        (uint32_t)query_buffer_reply.consumer_offset};

    do {
        ebpf_operation_map_async_query_reply_t async_reply;
        OVERLAPPED overlapped{};
        overlapped.hEvent = GetOverlappedEvent();
        result = invoke_ioctl(
            &async_query_request, sizeof(async_query_request), &async_reply, sizeof(async_reply), &overlapped);
        if (result == ERROR_IO_PENDING) {
            result = EBPF_SUCCESS;
        }
        if (result != EBPF_SUCCESS) {
            fprintf(stderr, "Failed do device io control 2 . Err = %d\n", result);
            return;
        }
        DWORD dwWait = WaitForSingleObject(overlapped.hEvent, INFINITE);
        if (dwWait != WAIT_OBJECT_0) {
            fprintf(stderr, "Failed waiting for overlapped io.  . Err = %d\n", dwWait);
            return;
        }
        ResetEvent(overlapped.hEvent);

        ebpf_map_async_query_result_t* async_query_result = &(async_reply.async_query_result);
        size_t consumer = async_query_result->consumer;
        size_t producer = async_query_result->producer;
        for (;;) {
            auto record = ebpf_ring_buffer_next_record((const uint8_t*)buffer, ring_buffer_size, consumer, producer);

            if (record == nullptr) {
                // No more records.
                break;
            }

            if (ebpf_ring_buffer_record_is_locked(record)) {
                // Record is locked. Wait for the record to be unlocked.
                break;
            }

            if (!ebpf_ring_buffer_record_is_discarded(record)) {
                int callback_result = connect_callback(
                    NULL,
                    const_cast<void*>(reinterpret_cast<const void*>(record->data)),
                    record->header.length - EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data));
                if (callback_result != 0) {
                    break;
                }
            }

            consumer += ebpf_ring_buffer_record_total_size(record);
        }
        async_query_request.consumer_offset = consumer;

    } while (result == EBPF_SUCCESS);
}

#endif

std::atomic_bool end = false;
void
RecvEvents()
{
    fd_t ringBuf_fd = bpf_obj_get((char*)connect_map);
    if (ringBuf_fd == ebpf_fd_invalid) {
        fprintf(stderr, "Failed to get  up eBPF ringbuf\n");
        return;
    }

    auto ring = ring_buffer__new(ringBuf_fd, connect_callback, nullptr, nullptr);
    if (ring == nullptr) {
        fprintf(stderr, "Failed to create ring buf manager\n");
        return;
    }
    while (!end) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    ring_buffer__free(ring);
}

int
getEvents(int argc, char** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    std::thread th(RecvEvents2);
    th.detach();
    MessageBox(NULL, L"STOP", L"STOP?", MB_OK);
    end = true;
    return 0;
}

typedef int (*operation_t)(int argc, char** argv);
struct
{
    const char* name;
    const char* help;
    operation_t operation;
} commands[]{
    {"load", "load\tLoad the connect monitor eBPF program", load},
    {"unload", "unload\tUnload the connect monitor eBPF program", unload},
    {"getEvents", "stats\tShow Events of connections being launched", getEvents}};

void
print_usage(char* path)
{
    fprintf(stderr, "Usage: %s command\n", path);
    for (auto& cmd : commands) {
        fprintf(stderr, "\t%s\n", cmd.name);
    }
}

int
main(int argc, char** argv)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    for (const auto& cmd : commands) {
        if (_stricmp(cmd.name, argv[1]) == 0) {
            return cmd.operation(argc - 2, argv + 2);
        }
    }
    print_usage(argv[0]);
    return 1;
}
