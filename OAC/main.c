#include "cr3_thrasher.h"
#include "internals.h"
#include "stackwalk.h"

// =================================================================================================
// == IOCTL Definitions
// =================================================================================================
#define IOCTL_TEST_COMMUNICATION        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRIGGER_CR3_THRASH        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNLOAD_DRIVER             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRIGGER_NMI_STACKWALK     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)


// =================================================================================================
// == Function Prototypes
// =================================================================================================

// The function that performs the actual driver initialization.
NTSTATUS DriverInitialize(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
);

// Standard IRP and Unload handlers.
VOID DriverUnload(
    IN PDRIVER_OBJECT DriverObject
);
NTSTATUS IrpCreateCloseHandler(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP           Irp
);
NTSTATUS IrpDeviceIoCtlHandler(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP           Irp
);


// =================================================================================================
// == Global Variables
// =================================================================================================

const wchar_t* G_DRIVER_NAME  = L"\\Driver\\OAC6"; // For IoCreateDriver. Can be NULL for stealth.
const wchar_t* G_DEVICE_NAME  = L"\\Device\\OAC6";
const wchar_t* G_SYMLINK_NAME = L"\\DosDevices\\OAC6";


// =================================================================================================
// == Driver Entry & Initialization
// =================================================================================================

NTSTATUS DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[+] kdmapper has called DriverEntry\n");

    // We can provide a driver name, or NULL for stealth
    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, G_DRIVER_NAME);

    // Call the undocumented function IoCreateDriver.
    // This will create our DRIVER_OBJECT and call our DriverInitialize function.
    NTSTATUS status = IoCreateDriver(&driverName, &DriverInitialize);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[-] IoCreateDriver failed: 0x%X\n", status);
        return status;
    }
    else
    {
        DbgPrint("[+] IoCreateDriver succeeded\n");
    }

    return status;
}

// This function is called by IoCreateDriver to perform driver initialization.
// All initialization code should be done here.
NTSTATUS NTAPI DriverInitialize(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS       status           = STATUS_SUCCESS;
    PDEVICE_OBJECT deviceObject     = NULL;
    UNICODE_STRING deviceName       = {0};
    UNICODE_STRING symbolicLinkName = {0};

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

    // Set up the driver unload routine.
    DriverObject->DriverUnload = DriverUnload;
    // Set up the IRP handlers.
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;

    // Clear the initialization flag to allow I/O.
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[+] Driver initialized successfully\n");
    return status;
}

//
// IRP Handlers and Unload Routine
//

// This will be called when the driver is to be unloaded (e.g., by another kernel component).
// It's good practice to have a cleanup routine.
VOID DriverUnload(
    IN PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING symbolicLinkName = {0};
    RtlInitUnicodeString(&symbolicLinkName, G_SYMLINK_NAME);
    DbgPrint("[+] DriverUnload called\n");

    // Deinitialize the NMI handler if it was initialized.
    DeinitializeNmiHandler();

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

// Handler for when a user-mode application opens/closes a handle to the device.
NTSTATUS IrpCreateCloseHandler(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[+] IrpCreateCloseHandler called\n");
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Handler for receiving IOCTLs from user-mode applications.
NTSTATUS IrpDeviceIoCtlHandler(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpStack    = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS           status      = STATUS_SUCCESS;
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
            // Just a test IOCTL to verify communication.
            break;
        case IOCTL_TRIGGER_CR3_THRASH:
            DbgPrint("[+] IOCTL_TRIGGER_CR3_THRASH received\n");

            TriggerCr3Thrash();
            break;
        case IOCTL_TRIGGER_NMI_STACKWALK:
            DbgPrint("[+] IOCTL_TRIGGER_NMI_STACKWALK received\n");

            TriggerNmiStackwalk();
            break;
        case IOCTL_UNLOAD_DRIVER:
            DbgPrint("[+] IOCTL_UNLOAD_DRIVER received\n");

            // CRITICAL: We must complete the request back to user-mode BEFORE we
            // delete the device, otherwise the I/O manager will crash trying
            // to complete a request for a non-existent device.
            Irp->IoStatus.Status      = status;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            // Now that the user-mode app has it answer, we can proceed with cleanup.
            DriverUnload(DeviceObject->DriverObject);

            // Note: The driver code is still in memory, but it is now disconnected.
            return status;
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}
