// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"
#include "ebpf_protocol.h"

#include <windows.h>
#include <io.h>
#include <iostream>
#include <ip2string.h>
#include <string>
#include <thread>
#include "monitor.h"

#define EBPF_RINGBUF_LOCK_BIT (1U << 31)
#define EBPF_RINGBUF_DISCARD_BIT (1U << 30)

const char* connect_program_path = "connect::program";
const char* connect_program_link = "connect::program_link";

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Ws2_32.lib")

#pragma once

int
loadConnect()
{
    ebpf_result_t result;
    bpf_object* object = nullptr;
    bpf_program* program = nullptr;
    bpf_link* link = nullptr;
    fd_t program_fd;
    
    object = bpf_object__open("C:\\Program Files\\Tetragon\\BPF\\tcp_connect.sys");
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

    result = ebpf_program_attach(program, &EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT, nullptr, 0, &link);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to attach eBPF program\n");
        return 1;
    }

    if (bpf_link__pin(link, connect_program_link) < 0) {
        fprintf(stderr, "Failed to pin eBPF link: %d\n", errno);
        return 1;
    }

    if (bpf_program__pin(program, connect_program_path) < 0) {
        fprintf(stderr, "Failed to pin eBPF program: %d\n", errno);
        return 1;
    }
    return 0;
}

int
unloadConnect()
{
    ebpf_result_t result;

    result = ebpf_object_unpin(connect_program_path);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF program: %d\n", result);
    }
    result = ebpf_object_unpin(connect_program_link);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF link: %d\n", result);
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
connection_callback(_Inout_ void* ctx, _In_opt_ void* data, size_t size)
{
    if ((!data) || (!size)) {
        fprintf(stderr, "NO data in data var\n");
    }
    UNREFERENCED_PARAMETER(ctx);
    msg_ip_event* msg = reinterpret_cast<msg_ip_event*>(data);
    printf(
        " PID: %6u Type: %-4s Dst Address: %s:%d Src Address: %s:%d\n",
        //FormatTime(ci->time).c_str(),
        msg->key.pid,
        ProtocolToString(msg->tuple.proto),
        AddressToString(&msg->tuple.daddr[0], 4).c_str(),
        ntohs(msg->tuple.dport),
        AddressToString(&msg->tuple.saddr[0], 4).c_str(),
        ntohs(msg->tuple.sport));
    return 0;
}