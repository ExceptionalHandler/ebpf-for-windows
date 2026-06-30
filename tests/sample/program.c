// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

//
// Simplified process-monitor eBPF program.
//
// This is a stripped-down version of
//   C:\git\ntosebpfext\tools\process_monitor_bpf\process_monitor.c
// with the maps, per-CPU scratch space, ring buffer, image-path/command-line capture, and all
// helper calls removed. It keeps only the essential shape: a "process" program that receives a
// process_md_t for each process create/delete.
//
// This program deliberately calls NO helper functions. The process program type exposes only a
// single helper (bpf_process_get_image_path); general helpers such as bpf_printk are not usable
// for this type and would fail verification ("invalid helper function id"). Instead, the program
// simply returns the parity of the process id (1 if odd, 0 if even), and hookdrv traces both the
// pid and this return value from its process-creation callback.
//
// The full version depends on ntosebpfext.sys (which provides the EBPF_PROGRAM_TYPE_PROCESS hook
// and the process_md_t context). To keep this sample self-contained within ebpf-for-windows, the
// minimal context declarations from ntosebpfext's ebpf_ntos_hooks.h are inlined below.
//

#include "bpf_helpers.h"

typedef enum _process_operation
{
    PROCESS_OPERATION_CREATE, ///< Process creation.
    PROCESS_OPERATION_DELETE, ///< Process deletion.
} process_operation_t;

// Process program context (subset of ntosebpfext's process_md_t, kept in the same field order).
typedef struct _process_md
{
    uint8_t* command_start;            ///< Pointer to start of the command line as UTF-16 string.
    uint8_t* command_end;              ///< Pointer to end of the command line as UTF-16 string.
    uint64_t process_id;               ///< Process ID.
    uint64_t parent_process_id;        ///< Parent process ID.
    uint64_t creating_process_id;      ///< Creating process ID.
    uint64_t creating_thread_id;       ///< Creating thread ID.
    uint64_t creation_time;            ///< Process creation time (as a FILETIME).
    uint64_t exit_time;                ///< Process exit time (FILETIME). Set only for PROCESS_OPERATION_DELETE.
    uint32_t process_exit_code;        ///< Process exit status. Set only for PROCESS_OPERATION_DELETE.
    process_operation_t operation : 8; ///< Operation to do.
} process_md_t;

typedef int
process_hook_t(process_md_t* context);

// The following line is optional, but is used to verify that the ProcessMonitor prototype is
// correct, or the compiler would complain when the function is actually defined below.
process_hook_t ProcessMonitor;

SEC("process")
int
ProcessMonitor(process_md_t* ctx)
{
    // Return the parity of the process id: 1 if odd, 0 if even. hookdrv traces the pid and this
    // return value. No helper functions are called, so the program verifies for the process type.
    return (int)(ctx->process_id & 1);
}
