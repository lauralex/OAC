/**
 * @file main.c
 * @brief Main driver code for OAC6.
 *
 * This file contains the entry point and initialization code for the OAC6 kernel-mode driver.
 * It sets up the device object, symbolic link, and IRP handlers. It also includes IOCTL
 * definitions for communication with user-mode applications.
 *
 * The driver provides functionalities such as CR3 thrashing and NMI stack walking, which can be
 * triggered via IOCTLs. It also initializes a WFP-based network monitor and manages internal
 * structures.
 *
 * Note: This code is intended for educational purposes only. Unauthorized use or distribution
 * of this code may violate local laws and regulations.
 */

#include "cr3_thrasher.h"
#include "internals.h"
#include "stackwalk.h"
#include "wfp_monitor.h"

 // =================================================================================================
 // == IOCTL Definitions
 // =================================================================================================
#define IOCTL_TEST_COMMUNICATION          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRIGGER_CR3_THRASH          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNLOAD_DRIVER               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRIGGER_NMI_STACKWALK       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INITIALIZE_WFP_MONITOR      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DEINITIALIZE_WFP_MONITOR    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)


// =================================================================================================
// == Function Prototypes
// =================================================================================================

// The function that performs the actual driver initialization.
NTSTATUS DriverInitialize(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

// Standard IRP and Unload handlers.
VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
);
NTSTATUS IrpCreateCloseHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
);
NTSTATUS IrpDeviceIoCtlHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
);


// =================================================================================================
// == Global Variables
// =================================================================================================

const wchar_t* G_DRIVER_NAME = L"\\Driver\\OAC6"; // For IoCreateDriver. Can be NULL for stealth.
const wchar_t* G_DEVICE_NAME = L"\\Device\\OAC6";
const wchar_t* G_SYMLINK_NAME = L"\\DosDevices\\OAC6";

// Global state to track if the WFP component is currently initialized.
BOOLEAN G_IsWfpInitialized = FALSE;


// =================================================================================================
// == Driver Entry & Initialization
// =================================================================================================

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[+] kdmapper has called DriverEntry\n");

    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, G_DRIVER_NAME);

    // Call the undocumented function IoCreateDriver.
    // This will create our DRIVER_OBJECT and call our DriverInitialize function.
    NTSTATUS status = IoCreateDriver(&driverName, &DriverInitialize);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[-] IoCreateDriver failed: 0x%X\n", status);
    }
    else
    {
        DbgPrint("[+] IoCreateDriver succeeded\n");
    }

    return status;
}

// This function is called by IoCreateDriver to perform driver initialization.
NTSTATUS NTAPI DriverInitialize(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS       status = STATUS_SUCCESS;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName = { 0 };
    UNICODE_STRING symbolicLinkName = { 0 };

    RtlInitUnicodeString(&deviceName, G_DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLinkName, G_SYMLINK_NAME);

    DbgPrint("[+] DriverInitialize called by IoCreateDriver\n");

    // Create the device object.
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[-] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    DbgPrint("[+] Device object created successfully\n");

    // Create a symbolic link so user-mode applications can find the device.
    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[-] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    DbgPrint("[+] Symbolic link created successfully\n");

    // Set up the driver unload routine and IRP handlers.
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;

    // Clear the initialization flag to allow I/O.
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    // Initialize internal structures.
    InitializeInternals();

    DbgPrint("[+] Driver initialized successfully. WFP monitor is ready to be activated via IOCTL.\n");
    return status;
}

//
// IRP Handlers and Unload Routine
//

VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING symbolicLinkName = { 0 };
    RtlInitUnicodeString(&symbolicLinkName, G_SYMLINK_NAME);
    DbgPrint("[+] DriverUnload called\n");

    // Deinitialize the NMI handler if it was initialized.
    DeinitializeNmiHandler();

    // Ensure WFP is cleaned up if it was left active. This is a critical cleanup step.
    if (G_IsWfpInitialized)
    {
        DbgPrint("[*] WFP was active during unload. De-initializing now.\n");
        DeinitializeWfpMonitor();
        G_IsWfpInitialized = FALSE;
    }

    // Delete the symbolic link.
    IoDeleteSymbolicLink(&symbolicLinkName);
    DbgPrint("[+] Symbolic link deleted\n");

    // Delete the device object.
    if (DriverObject->DeviceObject)
    {
        IoDeleteDevice(DriverObject->DeviceObject);
        DbgPrint("[+] Device object deleted\n");
    }

    // Delete the driver object itself.
    IoDeleteDriver(DriverObject);

    DbgPrint("[+] Driver unloaded successfully\n");
}

NTSTATUS IrpCreateCloseHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[+] IrpCreateCloseHandler called\n");
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS IrpDeviceIoCtlHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
)
{
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS           status = STATUS_SUCCESS;
    ULONG_PTR          information = 0;

    if (!irpStack)
    {
        status = STATUS_UNSUCCESSFUL;
    }
    else
    {
        switch (irpStack->Parameters.DeviceIoControl.IoControlCode)
        {
        case IOCTL_TEST_COMMUNICATION:
            DbgPrint("[+] IOCTL_TEST_COMMUNICATION received\n");
            break;

        case IOCTL_TRIGGER_CR3_THRASH:
            DbgPrint("[+] IOCTL_TRIGGER_CR3_THRASH received\n");
            TriggerCr3Thrash();
            break;

        case IOCTL_TRIGGER_NMI_STACKWALK:
            DbgPrint("[+] IOCTL_TRIGGER_NMI_STACKWALK received\n");
            TriggerNmiStackwalk();
            break;

        case IOCTL_INITIALIZE_WFP_MONITOR:
            DbgPrint("[+] IOCTL_INITIALIZE_WFP_MONITOR received\n");
            if (G_IsWfpInitialized)
            {
                DbgPrint("[*] WFP monitor is already initialized.\n");
                status = STATUS_SUCCESS; // Or a custom status like STATUS_ALREADY_INITIALIZED
            }
            else
            {
                status = InitializeWfpMonitor(DeviceObject);
                if (NT_SUCCESS(status))
                {
                    G_IsWfpInitialized = TRUE;
                }
            }
            break;

        case IOCTL_DEINITIALIZE_WFP_MONITOR:
            DbgPrint("[+] IOCTL_DEINITIALIZE_WFP_MONITOR received\n");
            if (!G_IsWfpInitialized)
            {
                DbgPrint("[*] WFP monitor is not currently initialized.\n");
            }
            else
            {
                DeinitializeWfpMonitor();
                G_IsWfpInitialized = FALSE;
            }
            break;

        case IOCTL_UNLOAD_DRIVER:
            DbgPrint("[+] IOCTL_UNLOAD_DRIVER received\n");
            // CRITICAL: Complete the request back to user-mode BEFORE unloading.
            Irp->IoStatus.Status = status;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            // Now that the client's request is complete, proceed with cleanup.
            DriverUnload(DeviceObject->DriverObject);
            return status; // Exit without completing the request again.

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}