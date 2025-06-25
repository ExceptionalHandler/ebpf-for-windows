// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_protocol.h"
#include "ebpf_api.h"


#include <windows.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <io.h>
#include <iostream>
#include <string> 
#include <thread>
#include "monitor.h"

#pragma comment(lib, "Secur32.lib")

const char* process_map = "process::process_map";
const char* command_map = "process::command_map";
const char* program_path = "process::program";
const char* program_link = "process::program_link";

extern const char* process_ringbuf;

fd_t image_fd = 0;
fd_t cmd_fd = 0;

#ifdef __cplusplus
extern "C"
{
#endif
    //
    // Attach Types.
    //

    /** @brief Attach type for handling process creation and destruction events.
     *
     * Program type: \ref EBPF_ATTACH_TYPE_PROCESS
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_PROCESS = {
        0x66e20687, 0x9805, 0x4458, {0xa0, 0xdb, 0x38, 0xe2, 0x20, 0xd3, 0x16, 0x85}};

    //
    // Program Types.
    //

#define EBPF_PROGRAM_TYPE_PROCESS_GUID                                                 \
    {                                                                                  \
        0x22ea7b37, 0x1043, 0x4d0d, { 0xb6, 0x0d, 0xca, 0xfa, 0x1c, 0x7b, 0x63, 0x8e } \
    }

    /** @brief Program type for handling process creation and destruction events.
     *
     * eBPF program prototype: \ref process_md_t
     *
     * Attach type(s): \ref EBPF_ATTACH_TYPE_PRCOESS
     *
     * Helpers available: see bpf_helpers.h
     */
    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_PROCESS = EBPF_PROGRAM_TYPE_PROCESS_GUID;

#ifdef __cplusplus
}
#endif


int
loadProcess()
{
    ebpf_result_t result;
    bpf_object* object = nullptr;
    bpf_program* program = nullptr;
    bpf_link* link = nullptr;
    fd_t program_fd;

    object = bpf_object__open("C:\\Program Files\\Tetragon\\BPF\\process_monitor.sys");
    if (object == nullptr) {
        printf("\nAm here\n");
        fprintf(stderr, "Failed to open process_monitor eBPF program\n");
        return 1;
    }

    result = ebpf_object_set_execution_type(object, EBPF_EXECUTION_NATIVE);
    if (result != EBPF_SUCCESS) {
        fprintf(stderr, "Failed to set execution type\n");
        return 1;
    }
    program = bpf_object__next_program(object, nullptr);
    if (bpf_object__load(object) < 0) {
        fprintf(stderr, "Failed to load process_monitor eBPF program\n");
        size_t log_buffer_size;
        fprintf(stderr, "%s", bpf_program__log_buf(program, &log_buffer_size));
        bpf_object__close(object);
        return 1;
    }
    program_fd = bpf_program__fd(program);

    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");
    if (process_map_fd <= 0) {
        fprintf(stderr, "Failed to find eBPF map : %s\n", process_map);
        return 1;
    }
    fd_t command_map_fd = bpf_object__find_map_fd_by_name(object, "command_map");
    if (command_map_fd <= 0) {
        fprintf(stderr, "Failed to find eBPF map : %s\n", command_map);
        return 1;
    }
    fd_t process_ringbuf_fd = bpf_object__find_map_fd_by_name(object, "process_ringbuf");
    if (process_ringbuf_fd <= 0) {
        fprintf(stderr, "Failed to find eBPF map : %s\n", process_ringbuf);
        return 1;
    }
    if (bpf_obj_pin(process_map_fd, process_map) < 0) {
        fprintf(stderr, "Failed to pin eBPF program process map: %d\n", errno);
        return 1;
    }
    if (bpf_obj_pin(command_map_fd, command_map) < 0) {
        fprintf(stderr, "Failed to pin eBPF program command map: %d\n", errno);
        return 1;
    }
    if (bpf_obj_pin(process_ringbuf_fd, process_ringbuf) < 0) {
        fprintf(stderr, "Failed to pin eBPF program process_ringbuf: %d\n", errno);
        return 1;
    }

    program = bpf_object__next_program(object, nullptr);
    if (program == nullptr) {
        fprintf(stderr, "Failed to find eBPF program from object.\n");
        return 1;
    }
    result = ebpf_program_attach(program, &EBPF_ATTACH_TYPE_PROCESS, nullptr, 0, &link);
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
unloadProcess()
{
    ebpf_result_t result;

    result = ebpf_object_unpin(program_path);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF program: %d\n", result);
    }
    result = ebpf_object_unpin(program_link);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF link: %d\n", result);
    }
    result = ebpf_object_unpin(command_map);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF command map: %d\n", result);
    }
    result = ebpf_object_unpin(process_map);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF process map: %d\n", result);
    }
    result = ebpf_object_unpin(process_ringbuf);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF ringbuf map: %d\n", result);
    }
    return 1;
}

int
process_creation_callback(_Inout_ void* ctx, _In_opt_ void* data, size_t size)
{
    char path[65520] = {};
    if ((!data) || (!size)) {
        fprintf(stderr, "NO data in data var\n");
    }
    UNREFERENCED_PARAMETER(ctx);
    uint8_t op = ((uint8_t*)data)[0];
   
    if (op == 5) {
        process_create_info* process_createinfo = reinterpret_cast<process_create_info*>(data);
        auto pid = process_createinfo->process_id;
        int err = bpf_map_lookup_elem(cmd_fd, &pid, &path);
        if (err) {
            printf("\nFailed getting image path\n");
        }
        else {
            SECURITY_LOGON_SESSION_DATA* datar = NULL;

            LsaGetLogonSessionData((PLUID) & (process_createinfo->user_luid), &datar);

            LPSTR strSid = nullptr;
            if (!ConvertSidToStringSidA(datar->Sid, &strSid)) {
                printf("ConvertSidToStringSid failed. Error: %d ", GetLastError());
            }
            printf(
                "\nLaunched PID = %d, Parent = %d. user = %llu Path = %S. UserName = %S . Sid = %s\n",
                process_createinfo->process_id,
                process_createinfo->parent_process_id,
                process_createinfo->user_luid,
                (wchar_t*)path, 
                 datar->UserName.Buffer, 
                strSid);
            bpf_map_delete_elem(cmd_fd, &pid);
        }
        
    } else if( op == 7) {
        process_exit_info *process_exitinfo = reinterpret_cast<process_exit_info*>(data);

        printf(
            "\n Stopped PID = %d. Exit Code = %d", process_exitinfo->process_id, process_exitinfo->process_exit_code);
    } else {
        printf("\n Unknop op %d",op);

    }
    return 0;
}

void
preRecvProcess()
{
    image_fd = bpf_obj_get((char*)process_map);
    if (image_fd == ebpf_fd_invalid) {
        fprintf(stderr, "Failed to get  up eBPF process map\n");
        return;
    }
    cmd_fd = bpf_obj_get((char*)command_map);
    if (cmd_fd == ebpf_fd_invalid) {
        fprintf(stderr, "Failed to get  up eBPF cmd map\n");
        return;
    }
}
