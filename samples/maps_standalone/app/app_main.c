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

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        printf("Looks up the image path for <pid> in the driver's process map.\n");
        return 1;
    }

    uint32_t pid = (uint32_t)strtoul(argv[1], NULL, 0);

    // Point the map library at the sample driver's device.
    if (bpf_maps_set_device_name(SAMPLE_DEVICE_NAME) != 0) {
        fprintf(stderr, "bpf_maps_set_device_name failed\n");
        return 1;
    }

    // Fetch the driver-owned map and register its handle as a local fd.
    bpf_map_fd_t fd = BPF_MAP_FD_INVALID;
    if (fetch_process_map_fd(&fd) != 0) {
        fprintf(stderr, "Could not obtain process map handle. Is the driver loaded?\n");
        return 1;
    }

    // Look up the image path for the requested PID.
    wchar_t image_path[260] = {0};  // value_size is 520 bytes = 260 WCHAR
    int rc = bpf_map_lookup_elem(fd, &pid, image_path);
    if (rc != 0) {
        printf("PID %u: not found in process map\n", pid);
        return 2;
    }

    printf("PID %u: %ls\n", pid, image_path);
    return 0;
}
