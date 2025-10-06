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
    UNICODE_STRING DriverName;
    RtlInitUnicodeString(&DriverName, G_DRIVER_NAME);

    // Call the undocumented function IoCreateDriver.
    // This will create our DRIVER_OBJECT and call our DriverInitialize function.
    NTSTATUS Status = IoCreateDriver(&DriverName, &DriverInitialize);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[-] IoCreateDriver failed: 0x%X\n", Status);
        return Status;
    }
    else
    {
        DbgPrint("[+] IoCreateDriver succeeded\n");
    }

    return Status;
}

// This function is called by IoCreateDriver to perform driver initialization.
// All initialization code should be done here.
NTSTATUS NTAPI DriverInitialize(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS       Status           = STATUS_SUCCESS;
    PDEVICE_OBJECT DeviceObject     = NULL;
    UNICODE_STRING DeviceName       = {0};
    UNICODE_STRING SymbolicLinkName = {0};

    RtlInitUnicodeString(&DeviceName, G_DEVICE_NAME);
    RtlInitUnicodeString(&SymbolicLinkName, G_SYMLINK_NAME);

    DbgPrint("[+] DriverInitialize called by IoCreateDriver\n");

    // Create the device object.
    Status = IoCreateDevice(
        DriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &DeviceObject
    );

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[-] IoCreateDevice failed: 0x%X\n", Status);
        return Status;
    }

    DbgPrint("[+] Device object created successfully\n");

    // Create a symbolic link so user-mode applications can find the device.
    Status = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[-] IoCreateSymbolicLink failed: 0x%X\n", Status);
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    DbgPrint("[+] Symbolic link created successfully\n");

    // Set up the driver unload routine.
    DriverObject->DriverUnload = DriverUnload;
    // Set up the IRP handlers.
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;

    // Initialize internal structures and state.
    InitializeInternals();

    // Clear the initialization flag to allow I/O.
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[+] Driver initialized successfully\n");
    return Status;
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
    UNICODE_STRING SymbolicLinkName = {0};
    RtlInitUnicodeString(&SymbolicLinkName, G_SYMLINK_NAME);
    DbgPrint("[+] DriverUnload called\n");

    // Deinitialize the NMI handler if it was initialized.
    DeinitializeNmiHandler();

    // Delete the symbolic link.
    IoDeleteSymbolicLink(&SymbolicLinkName);
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

    PIO_STACK_LOCATION IrpStack    = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS           Status      = STATUS_SUCCESS;
    ULONG_PTR          Information = 0;

    if (!IrpStack)
    {
        Status = STATUS_UNSUCCESSFUL;
    }
    else
    {
        switch (IrpStack->Parameters.DeviceIoControl.IoControlCode)
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
            Irp->IoStatus.Status      = Status;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            // Now that the user-mode app has it answer, we can proceed with cleanup.
            DriverUnload(DeviceObject->DriverObject);

            // Note: The driver code is still in memory, but it is now disconnected.
            return Status;
        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    Irp->IoStatus.Status      = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}
