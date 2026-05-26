// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "../common/bpf_maps_common.h"

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Map file descriptor type
typedef int bpf_map_fd_t;
#define BPF_MAP_FD_INVALID (-1)

// Update flags
#define BPF_ANY     0   // Create or update
#define BPF_NOEXIST 1   // Create only (fail if exists)
#define BPF_EXIST   2   // Update only (fail if not exists)

// API functions

/**
 * @brief Create a new BPF map
 * @param type Map type (hash, array, etc.)
 * @param name Map name (optional, can be NULL)
 * @param key_size Size of keys in bytes
 * @param value_size Size of values in bytes
 * @param max_entries Maximum number of entries
 * @param flags Map creation flags
 * @param fd Output: file descriptor for the created map
 * @return 0 on success, negative error code on failure
 */
int bpf_map_create(
    bpf_map_type_t type,
    const char* name,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    uint32_t flags,
    bpf_map_fd_t* fd);

/**
 * @brief Look up an element in a BPF map
 * @param fd Map file descriptor
 * @param key Pointer to key data
 * @param value Pointer to buffer to receive value data
 * @return 0 on success, negative error code on failure (including not found)
 */
int bpf_map_lookup_elem(
    bpf_map_fd_t fd,
    const void* key,
    void* value);

/**
 * @brief Update or create an element in a BPF map
 * @param fd Map file descriptor
 * @param key Pointer to key data
 * @param value Pointer to value data
 * @param flags Update flags (BPF_ANY, BPF_NOEXIST, BPF_EXIST)
 * @return 0 on success, negative error code on failure
 */
int bpf_map_update_elem(
    bpf_map_fd_t fd,
    const void* key,
    const void* value,
    uint64_t flags);

/**
 * @brief Delete an element from a BPF map
 * @param fd Map file descriptor
 * @param key Pointer to key data
 * @return 0 on success, negative error code on failure
 */
int bpf_map_delete_elem(
    bpf_map_fd_t fd,
    const void* key);

/**
 * @brief Get the next key in a BPF map (for iteration)
 * @param fd Map file descriptor
 * @param key Pointer to current key (NULL to get first key)
 * @param next_key Pointer to buffer to receive next key
 * @return 0 on success, negative error code on failure (including no more keys)
 */
int bpf_map_get_next_key(
    bpf_map_fd_t fd,
    const void* key,
    void* next_key);

/**
 * @brief Close a BPF map file descriptor
 * @param fd Map file descriptor to close
 */
void bpf_map_close(
    bpf_map_fd_t fd);

/**
 * @brief Set the device name for map operations (optional, runtime configuration)
 * @param device_name Wide string device name (e.g., L"\\\\.\\MyDevice")
 * @return 0 on success, -1 if device already opened
 */
int bpf_maps_set_device_name(
    const wchar_t* device_name);

/**
 * @brief Register an externally-created kernel map handle as a user-mode fd so
 *        that the existing bpf_map_lookup_elem / update / delete / get_next_key
 *        APIs can operate on it. Used when the driver created the map and wants
 *        to hand its handle off to user-mode.
 * @param handle The kernel map handle (as returned to user-mode by the driver).
 * @param key_size Key size the map was created with.
 * @param value_size Value size the map was created with.
 * @param type Map type the map was created with.
 * @param fd Output: fd that can be passed to the other bpf_map_* APIs.
 * @return 0 on success, -1 on failure.
 */
int bpf_map_register_handle(
    uint64_t handle,
    uint32_t key_size,
    uint32_t value_size,
    bpf_map_type_t type,
    bpf_map_fd_t* fd);

#ifdef __cplusplus
}
#endif
