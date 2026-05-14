// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include <windows.h>
#include "bpf_maps_api.h"
#include "../common/bpf_maps_config.h"
#include "../common/bpf_maps_protocol.h"

// Global device handle (lazy initialized)
static HANDLE g_device_handle = INVALID_HANDLE_VALUE;
static SRWLOCK g_device_lock = SRWLOCK_INIT;
static wchar_t g_device_name[256] = BPF_MAPS_DEVICE_NAME_USER;

int bpf_maps_device_init(void)
{
    AcquireSRWLockExclusive(&g_device_lock);

    if (g_device_handle == INVALID_HANDLE_VALUE) {
        g_device_handle = CreateFileW(
            g_device_name,
            GENERIC_READ | GENERIC_WRITE,
            0,                      // No sharing
            NULL,                   // Default security
            OPEN_EXISTING,          // Must exist
            FILE_ATTRIBUTE_NORMAL,  // Normal attributes
            NULL);                  // No template
    }

    BOOL success = (g_device_handle != INVALID_HANDLE_VALUE);
    ReleaseSRWLockExclusive(&g_device_lock);

    return success ? 0 : -1;
}

void bpf_maps_device_cleanup(void)
{
    AcquireSRWLockExclusive(&g_device_lock);

    if (g_device_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(g_device_handle);
        g_device_handle = INVALID_HANDLE_VALUE;
    }

    ReleaseSRWLockExclusive(&g_device_lock);
}

int bpf_maps_device_ioctl(
    DWORD ioctl_code,
    void* input_buffer,
    DWORD input_size,
    void* output_buffer,
    DWORD output_size,
    DWORD* bytes_returned)
{
    // Initialize device if not already done
    if (g_device_handle == INVALID_HANDLE_VALUE) {
        if (bpf_maps_device_init() != 0) {
            return -1;
        }
    }

    BOOL success = DeviceIoControl(
        g_device_handle,
        ioctl_code,
        input_buffer,
        input_size,
        output_buffer,
        output_size,
        bytes_returned,
        NULL);  // Synchronous

    return success ? 0 : -1;
}

int bpf_maps_set_device_name(const wchar_t* device_name)
{
    if (!device_name) {
        return -1;
    }

    AcquireSRWLockExclusive(&g_device_lock);

    if (g_device_handle != INVALID_HANDLE_VALUE) {
        // Already initialized, can't change
        ReleaseSRWLockExclusive(&g_device_lock);
        return -1;
    }

    wcsncpy_s(g_device_name, 256, device_name, _TRUNCATE);

    ReleaseSRWLockExclusive(&g_device_lock);
    return 0;
}
