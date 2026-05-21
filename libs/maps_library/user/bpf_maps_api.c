// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bpf_maps_api.h"
#include "../common/bpf_maps_protocol.h"

// Forward declarations for device I/O
int bpf_maps_device_ioctl(
    DWORD ioctl_code,
    void* input_buffer,
    DWORD input_size,
    void* output_buffer,
    DWORD output_size,
    DWORD* bytes_returned);

// Map descriptor to track FD -> handle mapping
typedef struct _bpf_map_descriptor {
    bpf_map_fd_t fd;
    uint64_t handle;
    uint32_t key_size;
    uint32_t value_size;
    bpf_map_type_t type;
} bpf_map_descriptor_t;

// Simple map descriptor table (for demo; production should use dynamic allocation)
#define MAX_MAPS 256
static bpf_map_descriptor_t g_map_table[MAX_MAPS];
static SRWLOCK g_map_table_lock = SRWLOCK_INIT;
static int g_next_fd = 1;

// Helper: Find free slot in map table
static bpf_map_fd_t alloc_map_fd(uint64_t handle, uint32_t key_size, uint32_t value_size, bpf_map_type_t type)
{
    AcquireSRWLockExclusive(&g_map_table_lock);

    for (int i = 0; i < MAX_MAPS; i++) {
        if (g_map_table[i].fd == BPF_MAP_FD_INVALID) {
            g_map_table[i].fd = g_next_fd++;
            g_map_table[i].handle = handle;
            g_map_table[i].key_size = key_size;
            g_map_table[i].value_size = value_size;
            g_map_table[i].type = type;

            bpf_map_fd_t fd = g_map_table[i].fd;
            ReleaseSRWLockExclusive(&g_map_table_lock);
            return fd;
        }
    }

    ReleaseSRWLockExclusive(&g_map_table_lock);
    return BPF_MAP_FD_INVALID;
}

// Helper: Get map descriptor by FD
static bpf_map_descriptor_t* get_map_descriptor(bpf_map_fd_t fd)
{
    AcquireSRWLockShared(&g_map_table_lock);

    for (int i = 0; i < MAX_MAPS; i++) {
        if (g_map_table[i].fd == fd) {
            ReleaseSRWLockShared(&g_map_table_lock);
            return &g_map_table[i];
        }
    }

    ReleaseSRWLockShared(&g_map_table_lock);
    return NULL;
}

// Helper: Free map descriptor
static void free_map_fd(bpf_map_fd_t fd)
{
    AcquireSRWLockExclusive(&g_map_table_lock);

    for (int i = 0; i < MAX_MAPS; i++) {
        if (g_map_table[i].fd == fd) {
            g_map_table[i].fd = BPF_MAP_FD_INVALID;
            g_map_table[i].handle = 0;
            break;
        }
    }

    ReleaseSRWLockExclusive(&g_map_table_lock);
}

// Initialize map table
static void init_map_table(void)
{
    static int initialized = 0;
    if (!initialized) {
        for (int i = 0; i < MAX_MAPS; i++) {
            g_map_table[i].fd = BPF_MAP_FD_INVALID;
            g_map_table[i].handle = 0;
        }
        initialized = 1;
    }
}

int bpf_map_create(
    bpf_map_type_t type,
    const char* name,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    uint32_t flags,
    bpf_map_fd_t* fd)
{
    if (!fd) {
        return -1;
    }

    init_map_table();

    // Build request
    uint32_t name_len = name ? (uint32_t)strlen(name) + 1 : 1;
    uint32_t request_size = sizeof(bpf_map_create_request_t) + name_len - 1;

    bpf_map_create_request_t* request = (bpf_map_create_request_t*)malloc(request_size);
    if (!request) {
        return -1;
    }

    request->definition.type = type;
    request->definition.key_size = key_size;
    request->definition.value_size = value_size;
    request->definition.max_entries = max_entries;
    request->definition.flags = flags;
    request->name_length = name_len;

    if (name) {
        strcpy_s(request->name, name_len, name);
    } else {
        request->name[0] = '\0';
    }

    // Send IOCTL
    bpf_map_create_reply_t reply = {0};
    DWORD bytes_returned = 0;

    int result = bpf_maps_device_ioctl(
        IOCTL_BPF_MAP_CREATE,
        request,
        request_size,
        &reply,
        sizeof(reply),
        &bytes_returned);

    free(request);

    if (result != 0 || bytes_returned != sizeof(reply)) {
        return -1;
    }

    // Allocate FD
    *fd = alloc_map_fd(reply.map_handle, key_size, value_size, type);
    if (*fd == BPF_MAP_FD_INVALID) {
        // TODO: Send close IOCTL to kernel
        return -1;
    }

    return 0;
}

int bpf_map_lookup_elem(
    bpf_map_fd_t fd,
    const void* key,
    void* value)
{
    if (!key || !value) {
        return -1;
    }

    bpf_map_descriptor_t* desc = get_map_descriptor(fd);
    if (!desc) {
        return -1;
    }

    // Build request
    uint32_t request_size = offsetof(bpf_map_lookup_request_t, key) + desc->key_size ;
    bpf_map_lookup_request_t* request = (bpf_map_lookup_request_t*)malloc(request_size);
    if (!request) {
        return -1;
    }

    request->map_handle = desc->handle;
    request->key_size = desc->key_size;
    memcpy(request->key, key, desc->key_size);

    // Allocate reply buffer
    uint32_t reply_size = offsetof(bpf_map_lookup_reply_t, value) + desc->value_size ;
    bpf_map_lookup_reply_t* reply = (bpf_map_lookup_reply_t*)malloc(reply_size);
    if (!reply) {
        free(request);
        return -1;
    }
    printf("\nReply Size = %d\n", reply_size);

    // Send IOCTL
    DWORD bytes_returned = 0;
    int result = bpf_maps_device_ioctl(
        IOCTL_BPF_MAP_LOOKUP,
        request,
        request_size,
        reply,
        reply_size,
        &bytes_returned);

    if (result == 0 && bytes_returned >= sizeof(bpf_map_lookup_reply_t)) {
        // Copy value
        memcpy(value, reply->value, desc->value_size);
    } else {
        result = -1;
    }

    free(request);
    free(reply);

    return result;
}

int bpf_map_update_elem(
    bpf_map_fd_t fd,
    const void* key,
    const void* value,
    uint64_t flags)
{
    if (!key || !value) {
        return -1;
    }

    bpf_map_descriptor_t* desc = get_map_descriptor(fd);
    if (!desc) {
        return -1;
    }

    // Build request (key + value in data field)
    uint32_t request_size = sizeof(bpf_map_update_request_t) + desc->key_size + desc->value_size - 1;
    bpf_map_update_request_t* request = (bpf_map_update_request_t*)malloc(request_size);
    if (!request) {
        return -1;
    }

    request->map_handle = desc->handle;
    request->flags = flags;
    request->key_size = desc->key_size;
    request->value_size = desc->value_size;

    // Copy key and value
    memcpy(request->data, key, desc->key_size);
    memcpy(request->data + desc->key_size, value, desc->value_size);

    // Send IOCTL (no reply for update)
    DWORD bytes_returned = 0;
    int result = bpf_maps_device_ioctl(
        IOCTL_BPF_MAP_UPDATE,
        request,
        request_size,
        NULL,
        0,
        &bytes_returned);

    free(request);

    return result;
}

int bpf_map_delete_elem(
    bpf_map_fd_t fd,
    const void* key)
{
    if (!key) {
        return -1;
    }

    bpf_map_descriptor_t* desc = get_map_descriptor(fd);
    if (!desc) {
        return -1;
    }

    // Build request
    uint32_t request_size = sizeof(bpf_map_delete_request_t) + desc->key_size - 1;
    bpf_map_delete_request_t* request = (bpf_map_delete_request_t*)malloc(request_size);
    if (!request) {
        return -1;
    }

    request->map_handle = desc->handle;
    request->key_size = desc->key_size;
    memcpy(request->key, key, desc->key_size);

    // Send IOCTL (no reply for delete)
    DWORD bytes_returned = 0;
    int result = bpf_maps_device_ioctl(
        IOCTL_BPF_MAP_DELETE,
        request,
        request_size,
        NULL,
        0,
        &bytes_returned);

    free(request);

    return result;
}

int bpf_map_get_next_key(
    bpf_map_fd_t fd,
    const void* key,
    void* next_key)
{
    if (!next_key) {
        return -1;
    }

    bpf_map_descriptor_t* desc = get_map_descriptor(fd);
    if (!desc) {
        return -1;
    }

    // Build request
    uint32_t request_size = sizeof(bpf_map_get_next_key_request_t) + desc->key_size - 1;
    bpf_map_get_next_key_request_t* request = (bpf_map_get_next_key_request_t*)malloc(request_size);
    if (!request) {
        return -1;
    }

    request->map_handle = desc->handle;
    request->key_size = desc->key_size;

    // If key is NULL, use zeros (get first key)
    if (key) {
        memcpy(request->key, key, desc->key_size);
    } else {
        memset(request->key, 0, desc->key_size);
    }

    // Allocate reply buffer
    uint32_t reply_size = sizeof(bpf_map_get_next_key_reply_t) + desc->key_size - 1;
    bpf_map_get_next_key_reply_t* reply = (bpf_map_get_next_key_reply_t*)malloc(reply_size);
    if (!reply) {
        free(request);
        return -1;
    }

    // Send IOCTL
    DWORD bytes_returned = 0;
    int result = bpf_maps_device_ioctl(
        IOCTL_BPF_MAP_GET_NEXT_KEY,
        request,
        request_size,
        reply,
        reply_size,
        &bytes_returned);

    if (result == 0 && bytes_returned >= sizeof(bpf_map_get_next_key_reply_t)) {
        // Copy next key
        memcpy(next_key, reply->key, desc->key_size);
    } else {
        result = -1;
    }

    free(request);
    free(reply);

    return result;
}

int bpf_map_register_handle(
    uint64_t handle,
    uint32_t key_size,
    uint32_t value_size,
    bpf_map_type_t type,
    bpf_map_fd_t* fd)
{
    if (fd == NULL || handle == 0) {
        return -1;
    }

    init_map_table();

    *fd = alloc_map_fd(handle, key_size, value_size, type);
    return (*fd == BPF_MAP_FD_INVALID) ? -1 : 0;
}

void bpf_map_close(bpf_map_fd_t fd)
{
    bpf_map_descriptor_t* desc = get_map_descriptor(fd);
    if (!desc) {
        return;
    }

    // Send close IOCTL
    bpf_map_close_request_t request;
    request.map_handle = desc->handle;

    DWORD bytes_returned = 0;
    bpf_maps_device_ioctl(
        IOCTL_BPF_MAP_CLOSE,
        &request,
        sizeof(request),
        NULL,
        0,
        &bytes_returned);

    // Free FD
    free_map_fd(fd);
}
