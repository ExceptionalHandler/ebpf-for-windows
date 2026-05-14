// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Include ntifs.h first - required by ebpf_tracelog.h dependencies
#include <ntifs.h>
#include <ntddk.h>

// Disable warning 4062 for WDF headers (unhandled enumerator in switch)
#pragma warning(push)
#pragma warning(disable: 4062)
#include <wdf.h>
#pragma warning(pop)

#include "bpf_maps_driver.h"
#include "../../../libs/maps_library/common/bpf_maps_protocol.h"
#include "ebpf_tracelog.h"

#define PROCESS_MAP_MAX_ENTRIES 4096
#define PROCESS_IMAGE_MAX_BYTES 520  // 260 WCHARs, matches MAX_PATH

static uint64_t g_process_map_handle = 0;
static BOOLEAN g_process_callback_registered = FALSE;

// Device object pointer required by eBPF runtime
static DEVICE_OBJECT* _bpf_maps_driver_device_object = NULL;

_Ret_notnull_ DEVICE_OBJECT*
ebpf_driver_get_device_object(void)
{
    return _bpf_maps_driver_device_object;
}

// Custom device name (can be overridden at build time)
#ifndef BPF_MAPS_DEVICE_NAME_KERNEL
#define BPF_MAPS_DEVICE_NAME_KERNEL L"\\Device\\BpfMapsDevice"
#endif

#ifndef BPF_MAPS_SYMBOLIC_LINK
#define BPF_MAPS_SYMBOLIC_LINK L"\\DosDevices\\BpfMapsDevice"
#endif

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD DriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;
EVT_WDF_FILE_CLOSE EvtFileClose;

static void
ProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    uint32_t pid = (uint32_t)(ULONG_PTR)ProcessId;
    uint8_t image_path[PROCESS_IMAGE_MAX_BYTES];

    if (CreateInfo != NULL) {
        // Process creation: copy image path into fixed buffer, store in map.
        RtlZeroMemory(image_path, sizeof(image_path));
        if (CreateInfo->ImageFileName != NULL && CreateInfo->ImageFileName->Buffer != NULL) {
            USHORT copy_bytes = CreateInfo->ImageFileName->Length;
            if (copy_bytes > sizeof(image_path) - sizeof(WCHAR)) {
                copy_bytes = sizeof(image_path) - sizeof(WCHAR);
            }
            RtlCopyMemory(image_path, CreateInfo->ImageFileName->Buffer, copy_bytes);
        }

        NTSTATUS status = bpf_map_update_elem_km(
            g_process_map_handle,
            &pid, sizeof(pid),
            image_path, sizeof(image_path),
            0);  // BPF_ANY
        if (!NT_SUCCESS(status)) {
            EBPF_LOG_NTSTATUS_API_FAILURE(
                EBPF_TRACELOG_KEYWORD_MAP,
                "bpf_map_update_elem_km",
                status);
        } else {
            EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "HO Gaya Ho Gaya?")
        }
    } else {
        // Process exit: remove entry.
        (void)bpf_map_delete_elem_km(g_process_map_handle, &pid, sizeof(pid));
    }
}



void
EvtFileClose(_In_ WDFFILEOBJECT FileObject)
{
    FILE_OBJECT* file_object = WdfFileObjectWdmGetFileObject(FileObject);

    EBPF_LOG_MESSAGE_UINT64(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "EvtFileClose: Releasing eBPF object reference from FsContext2",
        (uint64_t)file_object->FsContext2);

    bpf_maps_library_close_context(file_object->FsContext2);
    file_object->FsContext2 = NULL;
}

// The C runtime queries the file type via GetFileType when creating a file
// descriptor. GetFileType queries volume information to get device type via
// FileFsDeviceInformation information class.
NTSTATUS
_ebpf_driver_query_volume_information(_In_ WDFDEVICE device, _Inout_ IRP* irp)
{
    NTSTATUS status;
    IO_STACK_LOCATION* irp_stack_location;
    UNREFERENCED_PARAMETER(device);
    irp_stack_location = IoGetCurrentIrpStackLocation(irp);

    switch (irp_stack_location->Parameters.QueryVolume.FsInformationClass) {
    case FileFsDeviceInformation:
        if (irp_stack_location->Parameters.DeviceIoControl.OutputBufferLength < sizeof(FILE_FS_DEVICE_INFORMATION)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            FILE_FS_DEVICE_INFORMATION* device_info = (FILE_FS_DEVICE_INFORMATION*)irp->AssociatedIrp.SystemBuffer;
            device_info->DeviceType = FILE_DEVICE_NULL;
            device_info->Characteristics = 0;
            status = STATUS_SUCCESS;
        }
        break;
    default:
        status = STATUS_NOT_SUPPORTED;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, 0);
    return status;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver = NULL;
    PWDFDEVICE_INIT device_init = NULL;
    WDFDEVICE device = NULL;
    WDF_IO_QUEUE_CONFIG queue_config;
    WDFQUEUE queue = NULL;
    UNICODE_STRING device_name;
    UNICODE_STRING symbolic_link;
    NTSTATUS trace_status;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_FILEOBJECT_CONFIG file_object_config;

    // Initialize trace logging (best effort - don't fail driver load if tracing unavailable)
    trace_status = ebpf_trace_initiate();
    if (!NT_SUCCESS(trace_status)) {
        // Fall back to KdPrint for this critical error
        KdPrint(("BPF Maps Driver: WARNING - Failed to initialize trace logging: 0x%08X\n", trace_status));
        // Continue driver initialization - tracing is not critical
    }

    EBPF_LOG_ENTRY();

    status = bpf_maps_library_init();
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(
            EBPF_TRACELOG_KEYWORD_BASE,
            "bpf_maps_library_init",
            status);
        return status;
    }

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = DriverUnload;

    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(
            EBPF_TRACELOG_KEYWORD_API,
            "WdfDriverCreate",
            status);
        bpf_maps_library_cleanup();
        ebpf_trace_terminate();

        return status;
    }

    device_init = WdfControlDeviceInitAllocate(driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (device_init == NULL) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_API,
            "WdfControlDeviceInitAllocate failed");
        bpf_maps_library_cleanup();
        ebpf_trace_terminate();

        return STATUS_INSUFFICIENT_RESOURCES;
    }
    WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_NULL);
    WdfDeviceInitSetCharacteristics(device_init, FILE_DEVICE_SECURE_OPEN, FALSE);
    WdfDeviceInitSetCharacteristics(device_init, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);
    RtlInitUnicodeString(&device_name, BPF_MAPS_DEVICE_NAME_KERNEL);
    status = WdfDeviceInitAssignName(device_init, &device_name);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(
            EBPF_TRACELOG_KEYWORD_API,
            "WdfDeviceInitAssignName",
            status);
        WdfDeviceInitFree(device_init);
        bpf_maps_library_cleanup();
        ebpf_trace_terminate();

        return status;
    }

    // Configure file object cleanup to properly release eBPF object references
    WDF_FILEOBJECT_CONFIG_INIT(&file_object_config, WDF_NO_EVENT_CALLBACK, EvtFileClose, WDF_NO_EVENT_CALLBACK);
    WdfDeviceInitSetFileObjectConfig(device_init, &file_object_config, WDF_NO_OBJECT_ATTRIBUTES);

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.SynchronizationScope = WdfSynchronizationScopeNone;

    status = WdfDeviceCreate(&device_init, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(
            EBPF_TRACELOG_KEYWORD_API,
            "WdfDeviceCreate",
            status);
        WdfDeviceInitFree(device_init);
        bpf_maps_library_cleanup();
        ebpf_trace_terminate();

        return status;
    }

    _bpf_maps_driver_device_object = WdfDeviceWdmGetDeviceObject(device);

    RtlInitUnicodeString(&symbolic_link, BPF_MAPS_SYMBOLIC_LINK);
    status = WdfDeviceCreateSymbolicLink(device, &symbolic_link);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(
            EBPF_TRACELOG_KEYWORD_API,
            "WdfDeviceCreateSymbolicLink",
            status);
        bpf_maps_library_cleanup();
        ebpf_trace_terminate();

        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue_config, WdfIoQueueDispatchSequential);
    queue_config.EvtIoDeviceControl = EvtIoDeviceControl;

    status = WdfIoQueueCreate(device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(
            EBPF_TRACELOG_KEYWORD_API,
            "WdfIoQueueCreate",
            status);
        bpf_maps_library_cleanup();
        ebpf_trace_terminate();

        return status;
    }

    WdfControlFinishInitializing(device);

    // Create the process-tracking map.
    status = bpf_map_create_km(
        1,  // BPF_MAP_TYPE_HASH
        "process_map", sizeof("process_map") - 1,
        sizeof(uint32_t),
        PROCESS_IMAGE_MAX_BYTES,
        PROCESS_MAP_MAX_ENTRIES,
        &g_process_map_handle);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(
            EBPF_TRACELOG_KEYWORD_MAP,
            "bpf_map_create_km",
            status);
        WdfObjectDelete(device);
        bpf_maps_library_cleanup();
        ebpf_trace_terminate();

        return status;
    }

    //// Register the process creation/exit callback.
    //status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);
    //if (!NT_SUCCESS(status)) {
    //    EBPF_LOG_NTSTATUS_API_FAILURE(
    //        EBPF_TRACELOG_KEYWORD_API,
    //        "PsSetCreateProcessNotifyRoutineEx",
    //        status);
    //   (void)bpf_map_close_km(g_process_map_handle);
    //    g_process_map_handle = 0;
    //    bpf_maps_library_cleanup();
    //    ebpf_trace_terminate();

    //    return status;
    //}
    //g_process_callback_registered = TRUE;

    EBPF_LOG_MESSAGE(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "BPF Maps Driver loaded successfully");

    EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "Returning Zero")

    return STATUS_SUCCESS;
}

void
DriverUnload(
    _In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);

    EBPF_LOG_ENTRY();

    // Clear device object pointer to prevent access during teardown
    _bpf_maps_driver_device_object = NULL;

    EBPF_LOG_MESSAGE(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "DriverUnload: Step 1 - Unregistering process callback");

    // Unregister the callback BEFORE closing the map so no in-flight
    // callback can touch a stale map handle.
   /* if (g_process_callback_registered) {
        (void)PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
        g_process_callback_registered = FALSE;
    }*/

    EBPF_LOG_MESSAGE(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "DriverUnload: Step 2 - Closing map handle");

    if (g_process_map_handle != 0) {
        (void)bpf_map_close_km(g_process_map_handle);
        g_process_map_handle = 0;
    }

    EBPF_LOG_MESSAGE(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "DriverUnload: Step 3 - Cleaning up maps library");

    bpf_maps_library_cleanup();

    EBPF_LOG_MESSAGE(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_BASE,
        "BPF Maps Driver unloaded");

    ebpf_trace_terminate();
}

void
EvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode)
{

    NTSTATUS status = STATUS_SUCCESS;
    PVOID input_buffer = NULL;
    PVOID output_buffer = NULL;
    size_t input_length = 0;
    size_t output_length = 0;
    ULONG bytes_returned = 0;

    UNREFERENCED_PARAMETER(Queue);
    EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "In device io control");

    // Get input buffer if present
    if (InputBufferLength > 0) {
        status = WdfRequestRetrieveInputBuffer(
            Request,
            InputBufferLength,
            &input_buffer,
            &input_length);

        if (!NT_SUCCESS(status)) {
            EBPF_LOG_NTSTATUS_API_FAILURE(
                EBPF_TRACELOG_KEYWORD_API,
                "WdfRequestRetrieveInputBuffer",
                status);
            WdfRequestComplete(Request, status);
            return;
        }
    }



    //// Get output buffer if present
    //if (OutputBufferLength > 0) {
    //    status = WdfRequestRetrieveOutputBuffer(
    //        Request,
    //        OutputBufferLength,
    //        &output_buffer,
    //        &output_length);

    //    if (!NT_SUCCESS(status)) {
    //        EBPF_LOG_NTSTATUS_API_FAILURE(
    //            EBPF_TRACELOG_KEYWORD_API,
    //            "WdfRequestRetrieveOutputBuffer",
    //            status);
    //        WdfRequestComplete(Request, status);
    //        return;
    //    }
    //}

    //// Sample-specific IOCTL: hand the driver-owned process map's handle to user mode.
    //if (IoControlCode == IOCTL_BPF_GET_PROCESS_MAP) {
    //    if (output_buffer == NULL || output_length < sizeof(bpf_get_process_map_reply_t)) {
    //        status = STATUS_BUFFER_TOO_SMALL;
    //    } else if (g_process_map_handle == 0) {
    //        status = STATUS_DEVICE_NOT_READY;
    //    } else {
    //        bpf_get_process_map_reply_t* reply = (bpf_get_process_map_reply_t*)output_buffer;
    //        reply->map_handle = g_process_map_handle;
    //        reply->key_size = sizeof(uint32_t);
    //        reply->value_size = PROCESS_IMAGE_MAX_BYTES;
    //        bytes_returned = sizeof(*reply);
    //        status = STATUS_SUCCESS;
    //    }
    //    WdfRequestCompleteWithInformation(Request, status, bytes_returned);
    //    return;
    //}

    ////// Delegate everything else to the maps library IOCTL handler
    //status = bpf_maps_handle_ioctl(
    //    IoControlCode,
    //    input_buffer,
    //    (ULONG)input_length,
    //    output_buffer,
    //    (ULONG)output_length,
    //    &bytes_returned);

    // Complete the request
    WdfRequestCompleteWithInformation(Request, status, bytes_returned);
}
