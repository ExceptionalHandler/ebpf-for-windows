// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>
#include "bpf_maps_api.h"
#include "../../../libs/maps_library/common/bpf_maps_protocol.h"

// Must match the symbolic link the sample driver creates.
#define SAMPLE_DEVICE_NAME L"\\\\.\\BpfMapsDevice"

static int
fetch_process_map_fd(bpf_map_fd_t* out_fd)
{
    HANDLE device = CreateFileW(
        SAMPLE_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (device == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to open %ls (error %lu)\n", SAMPLE_DEVICE_NAME, GetLastError());
        return -1;
    }

    bpf_get_process_map_reply_t reply = {0};
    DWORD bytes_returned = 0;
    BOOL ok = DeviceIoControl(
        device,
        IOCTL_BPF_GET_PROCESS_MAP,
        NULL, 0,
        &reply, sizeof(reply),
        &bytes_returned,
        NULL);
    CloseHandle(device);

    if (!ok || bytes_returned != sizeof(reply)) {
        fprintf(stderr, "IOCTL_BPF_GET_PROCESS_MAP failed (error %lu)\n", GetLastError());
        return -1;
    }

    return bpf_map_register_handle(
        reply.map_handle, reply.key_size, reply.value_size,
        BPF_MAP_TYPE_HASH, out_fd);
}

static int
fetch_process_ringbuf_fd(bpf_map_fd_t* out_fd)
{
    HANDLE device = CreateFileW(
        SAMPLE_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (device == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to open %ls (error %lu)\n", SAMPLE_DEVICE_NAME, GetLastError());
        return -1;
    }

    bpf_get_process_ringbuf_reply_t reply = {0};
    DWORD bytes_returned = 0;
    BOOL ok = DeviceIoControl(
        device,
        IOCTL_BPF_GET_PROCESS_RINGBUF,
        NULL, 0,
        &reply, sizeof(reply),
        &bytes_returned,
        NULL);
    CloseHandle(device);

    if (!ok || bytes_returned != sizeof(reply)) {
        fprintf(stderr, "IOCTL_BPF_GET_PROCESS_RINGBUF failed (error %lu)\n", GetLastError());
        return -1;
    }

    return bpf_map_register_handle(
        reply.map_handle, 0, 0,
        BPF_MAP_TYPE_RINGBUF, out_fd);
}

static void
format_filetime(uint64_t filetime, char* buffer, size_t buffer_size)
{
    FILETIME ft;
    SYSTEMTIME st, local_st;

    ft.dwLowDateTime = (DWORD)filetime;
    ft.dwHighDateTime = (DWORD)(filetime >> 32);

    if (FileTimeToSystemTime(&ft, &st) &&
        SystemTimeToTzSpecificLocalTime(NULL, &st, &local_st)) {
        snprintf(buffer, buffer_size, "%04d-%02d-%02d %02d:%02d:%02d",
                 local_st.wYear, local_st.wMonth, local_st.wDay,
                 local_st.wHour, local_st.wMinute, local_st.wSecond);
    } else {
        snprintf(buffer, buffer_size, "Unknown");
    }
}

int main(int argc, char* argv[])
{
    printf("Process Monitor - Listening for process creation events...\n");
    printf("Press Ctrl+C to exit\n\n");

    // Point the map library at the sample driver's device.
    if (bpf_maps_set_device_name(SAMPLE_DEVICE_NAME) != 0) {
        fprintf(stderr, "bpf_maps_set_device_name failed\n");
        return 1;
    }

    // Fetch the driver-owned process map
    bpf_map_fd_t map_fd = BPF_MAP_FD_INVALID;
    if (fetch_process_map_fd(&map_fd) != 0) {
        fprintf(stderr, "Could not obtain process map handle. Is the driver loaded?\n");
        return 1;
    }

    // Fetch the driver-owned ring buffer
    bpf_map_fd_t ringbuf_fd = BPF_MAP_FD_INVALID;
    if (fetch_process_ringbuf_fd(&ringbuf_fd) != 0) {
        fprintf(stderr, "Could not obtain ring buffer handle. Is the driver loaded?\n");
        return 1;
    }

    printf("Connected to driver. Monitoring process events...\n\n");

    // Poll the ring buffer for events
    while (1) {
        process_event_t event;
        int rc = bpf_map_lookup_elem(ringbuf_fd, NULL, &event);

        if (rc == 0) {
            // Got an event - look up the process path
            wchar_t image_path[520] = {0};
            rc = bpf_map_lookup_elem(map_fd, &event.pid, image_path);

            char time_str[64];
            format_filetime(event.start_time, time_str, sizeof(time_str));

            if (rc == 0) {
                printf("PID: %5u | Start Time: %s | Path: %ls\n",
                       event.pid, time_str, image_path);
            } else {
                printf("PID: %5u | Start Time: %s | Path: <not found>\n",
                       event.pid, time_str);
            }
            fflush(stdout);
        } else {
            // No events available - sleep briefly
            Sleep(100);
        }
    }

    return 0;
}
