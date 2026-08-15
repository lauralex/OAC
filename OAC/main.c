#include <ntifs.h>
#include <wdmsec.h>
#include <initguid.h>

#include "..\shared\oac_protocol.h"
#include "compat.h"
#include "cpu_snapshot.h"
#include "protection.h"
#include "scanner.h"
#include "telemetry.h"

#define OAC_DEVICE_NAME L"\\Device\\OAC"
#define OAC_DOS_DEVICE_NAME L"\\DosDevices\\OAC"

DEFINE_GUID(GUID_DEVCLASS_OAC,
    0x8f69af54, 0x6284, 0x4f94, 0xa0, 0x49, 0x21, 0x96, 0x75, 0x9b, 0x9a, 0xd2);

static UNICODE_STRING g_DeviceName;
static UNICODE_STRING g_DosDeviceName;
static PDEVICE_OBJECT g_DeviceObject;
static BOOLEAN g_DosLinkCreated;
static BOOLEAN g_TelemetryInitialized;
static BOOLEAN g_ScannerInitialized;
static BOOLEAN g_CpuSnapshotInitialized;
static BOOLEAN g_ProtectionInitialized;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD OacDriverUnload;
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLEANUP)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH OacCreateClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH OacDeviceControl;

static NTSTATUS OacCompleteIrp(
    _Inout_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS OacUnsupportedRequest(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return OacCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

NTSTATUS OacCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return OacCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

static BOOLEAN OacIsTrustedClient(VOID)
{
    return OacIsTrustedClientProcess(PsGetCurrentProcess());
}

NTSTATUS OacDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    PVOID buffer;
    ULONG inputLength;
    ULONG outputLength;
    ULONG code;
    ULONG bytesWritten = 0;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    UNREFERENCED_PARAMETER(DeviceObject);
    stack = IoGetCurrentIrpStackLocation(Irp);
    buffer = Irp->AssociatedIrp.SystemBuffer;
    inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    code = stack->Parameters.DeviceIoControl.IoControlCode;

    if (code != IOCTL_OAC_PING && !OacIsTrustedClient() &&
        (code != IOCTL_OAC_CONFIGURE ||
         OacTrustedClientProcessId() != NULL))
    {
        return OacCompleteIrp(Irp, STATUS_ACCESS_DENIED, 0);
    }

    switch (code)
    {
    case IOCTL_OAC_PING:
        if (buffer == NULL || outputLength < sizeof(OAC_STATUS_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlZeroMemory(buffer, sizeof(OAC_STATUS_RESPONSE));
        ((POAC_STATUS_RESPONSE)buffer)->Version = OAC_PROTOCOL_VERSION;
        ((POAC_STATUS_RESPONSE)buffer)->Size = sizeof(OAC_STATUS_RESPONSE);
        bytesWritten = sizeof(OAC_STATUS_RESPONSE);
        status = STATUS_SUCCESS;
        break;

    case IOCTL_OAC_CONFIGURE:
        if (buffer == NULL || inputLength != sizeof(OAC_CONFIG_REQUEST))
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = OacConfigureProtection(
            (const OAC_CONFIG_REQUEST*)buffer,
            PsGetCurrentProcessId());
        break;

    case IOCTL_OAC_RUN_KERNEL_SCAN:
        if (buffer == NULL || inputLength != sizeof(OAC_SCAN_REQUEST))
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = OacRunKernelScan((const OAC_SCAN_REQUEST*)buffer);
        break;

    case IOCTL_OAC_GET_FINDINGS:
        if (buffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = OacReadFindings(
            (POAC_FINDINGS_RESPONSE)buffer,
            outputLength,
            &bytesWritten);
        break;

    case IOCTL_OAC_CPU_SNAPSHOT:
        if (buffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = OacCaptureCpuSnapshot(
            (POAC_CPU_RESPONSE)buffer,
            outputLength,
            &bytesWritten);
        break;

    case IOCTL_OAC_GET_STATUS:
        if (buffer == NULL || outputLength < sizeof(OAC_STATUS_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            POAC_STATUS_RESPONSE response = (POAC_STATUS_RESPONSE)buffer;
            RtlZeroMemory(response, sizeof(*response));
            response->Version = OAC_PROTOCOL_VERSION;
            response->Size = sizeof(*response);
            response->Capabilities = OAC_CAP_HANDLE_PROTECTION |
                OAC_CAP_IMAGE_TELEMETRY |
                OAC_CAP_CPU_SNAPSHOT |
                OAC_CAP_DRIVER_GATE |
                OacScannerCapabilities();
            response->ConfigurationFlags = OacConfigurationFlags();
            response->ProtectedProcessId = HandleToULong(OacProtectedProcessId());
            response->ClientProcessId = HandleToULong(OacTrustedClientProcessId());
            response->FindingsWritten = OacTelemetryWritten();
            response->FindingsDropped = OacTelemetryDropped();
            response->PostStartLoads = OacPostStartLoads();
            response->DriverGateTrips = OacDriverGateTrips();
            bytesWritten = sizeof(*response);
            status = STATUS_SUCCESS;
        }
        break;

    default:
        break;
    }

    return OacCompleteIrp(Irp, status, bytesWritten);
}

static VOID OacCleanup(VOID)
{
    if (g_ProtectionInitialized)
    {
        OacProtectionShutdown();
        g_ProtectionInitialized = FALSE;
    }
    if (g_CpuSnapshotInitialized)
    {
        OacCpuSnapshotShutdown();
        g_CpuSnapshotInitialized = FALSE;
    }
    if (g_ScannerInitialized)
    {
        OacScannerShutdown();
        g_ScannerInitialized = FALSE;
    }
    if (g_DosLinkCreated)
    {
        (VOID)IoDeleteSymbolicLink(&g_DosDeviceName);
        g_DosLinkCreated = FALSE;
    }
    if (g_DeviceObject != NULL)
    {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
    if (g_TelemetryInitialized)
    {
        OacTelemetryShutdown();
        g_TelemetryInitialized = FALSE;
    }
}

VOID OacDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    OacCleanup();
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);
    RtlInitUnicodeString(&g_DeviceName, OAC_DEVICE_NAME);
    RtlInitUnicodeString(&g_DosDeviceName, OAC_DOS_DEVICE_NAME);

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
    {
        /* One default handler intentionally covers every unsupported major code. */
#pragma warning(suppress: 28169)
        DriverObject->MajorFunction[i] = OacUnsupportedRequest;
    }
    DriverObject->MajorFunction[IRP_MJ_CREATE] = OacCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = OacCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = OacCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OacDeviceControl;
    DriverObject->DriverUnload = OacDriverUnload;

    OacCompatibilityInitialize();

    status = OacTelemetryInitialize();
    if (!NT_SUCCESS(status)) goto Failure;
    g_TelemetryInitialized = TRUE;

    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        TRUE,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
        &GUID_DEVCLASS_OAC,
        &g_DeviceObject);
    if (!NT_SUCCESS(status)) goto Failure;
    g_DeviceObject->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&g_DosDeviceName, &g_DeviceName);
    if (!NT_SUCCESS(status)) goto Failure;
    g_DosLinkCreated = TRUE;

    status = OacScannerInitialize(DriverObject);
    if (!NT_SUCCESS(status)) goto Failure;
    g_ScannerInitialized = TRUE;

    status = OacCpuSnapshotInitialize();
    if (!NT_SUCCESS(status)) goto Failure;
    g_CpuSnapshotInitialized = TRUE;

    status = OacProtectionInitialize(DriverObject);
    if (!NT_SUCCESS(status)) goto Failure;
    g_ProtectionInitialized = TRUE;

    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    OacReportFinding(OacSeverityInfo, OacCategoryGeneral, NULL, NULL,
        NULL, OAC_PROTOCOL_VERSION,
        L"OAC driver initialized with signed-load security model");
    return STATUS_SUCCESS;

Failure:
    OacCleanup();
    return status;
}
