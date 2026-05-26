// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

// Device name configuration (can be overridden at build time via preprocessor defines)

// User-mode Win32 device name
#ifndef BPF_MAPS_DEVICE_NAME_USER
#define BPF_MAPS_DEVICE_NAME_USER L"\\\\.\\BpfMapsDevice"
#endif

// Kernel-mode device name
#ifndef BPF_MAPS_DEVICE_NAME_KERNEL
#define BPF_MAPS_DEVICE_NAME_KERNEL L"\\Device\\BpfMapsDevice"
#endif

// Symbolic link for user-mode access
#ifndef BPF_MAPS_SYMBOLIC_LINK
#define BPF_MAPS_SYMBOLIC_LINK L"\\GLOBAL??\\BpfMapsDevice"
#endif
