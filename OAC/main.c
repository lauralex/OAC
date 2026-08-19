#include <ntifs.h>
#include <wdmsec.h>
#include <initguid.h>

#include "..\shared\oac_protocol.h"
#include "..\shared\protocol\oac_v5.h"
#include "..\shared\protocol\oac_validate.h"
#include "..\shared\protocol\oac_test.h"
#include "compat.h"
#include "cpu_snapshot.h"
#include "evidence.h"
#include "protection.h"
#include "scanner.h"
#include "session.h"
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
static BOOLEAN g_EvidenceInitialized;
static BOOLEAN g_ScannerInitialized;
static BOOLEAN g_CpuSnapshotInitialized;
static BOOLEAN g_ProtectionInitialized;
static BOOLEAN g_SessionInitialized;
static BOOLEAN g_LabMode;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD OacDriverUnload;
_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH OacCreate;
_Dispatch_type_(IRP_MJ_CLEANUP)
DRIVER_DISPATCH OacCleanupFile;
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH OacClose;
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

NTSTATUS OacCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    return OacCompleteIrp(Irp, OacSessionCreate(DeviceObject, Irp), 0);
}

NTSTATUS OacCleanupFile(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PEPROCESS owner = NULL;
    NTSTATUS status;

    status = OacSessionCleanup(DeviceObject, stack->FileObject, &owner);
    if (owner != NULL)
    {
        OacProtectionRevokeController(owner);
        ObDereferenceObject(owner);
    }
    return OacCompleteIrp(Irp, status, 0);
}

NTSTATUS OacClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PEPROCESS owner = NULL;
    NTSTATUS status;

    status = OacSessionCleanup(
        DeviceObject,
        stack->FileObject,
        &owner);
    if (owner != NULL)
    {
        OacProtectionRevokeController(owner);
        ObDereferenceObject(owner);
    }
    if (NT_SUCCESS(status))
    {
        status = OacSessionClose(DeviceObject, stack->FileObject);
    }
    return OacCompleteIrp(
        Irp,
        status,
        0);
}

static ULONG OacV5Capabilities(VOID)
{
    return OAC_V5_CAP_SESSION_CONTROL | OAC_V5_CAP_LAUNCH_TICKET |
        OAC_V5_CAP_SESSION_LIVENESS | OAC_V5_CAP_TYPED_EVENTS |
        OAC_V5_CAP_PAGED_SNAPSHOTS;
}

static VOID OacInitializeV5Response(
    _Out_ POAC_V5_RESPONSE_HEADER Header,
    _In_ ULONG Size,
    _In_ ULONGLONG RequestId,
    _In_ OAC_V5_MESSAGE_TYPE MessageType,
    _In_opt_ const OAC_SESSION_SNAPSHOT* Snapshot)
{
    Header->Version = OAC_V5_VERSION;
    Header->Size = Size;
    Header->RequestId = RequestId;
    Header->MessageType = MessageType;
    if (Snapshot != NULL)
    {
        Header->SessionId = Snapshot->SessionId;
        Header->Generation = Snapshot->Generation;
    }
    Header->Status = STATUS_SUCCESS;
    Header->Reason = OAC_V5_REASON_NONE;
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
    OAC_SESSION_LEASE lease = { 0 };

    stack = IoGetCurrentIrpStackLocation(Irp);
    buffer = Irp->AssociatedIrp.SystemBuffer;
    inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    code = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (code)
    {
    case IOCTL_OAC_PING:
        if (inputLength != 0)
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
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
        if (!OacSessionLabMode(DeviceObject))
        {
            status = STATUS_NOT_SUPPORTED;
            break;
        }
        if (buffer == NULL || inputLength != sizeof(OAC_CONFIG_REQUEST))
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = OacSessionAcquireDiagnostic(
            DeviceObject,
            stack->FileObject,
            &lease);
        if (!NT_SUCCESS(status))
        {
            OAC_SESSION_SNAPSHOT snapshot;
            status = OacSessionClaim(
                DeviceObject,
                stack->FileObject,
                OAC_V5_SESSION_DIAGNOSTIC,
                FALSE,
                &snapshot);
            if (NT_SUCCESS(status))
            {
                status = OacSessionAcquireDiagnostic(
                    DeviceObject,
                    stack->FileObject,
                    &lease);
            }
        }
        if (NT_SUCCESS(status))
        {
            status = OacConfigureProtection(
                (const OAC_CONFIG_REQUEST*)buffer,
                PsGetCurrentProcessId(),
                &lease);
        }
        break;

    case IOCTL_OAC_RUN_KERNEL_SCAN:
        if (!OacSessionLabMode(DeviceObject))
        {
            status = STATUS_NOT_SUPPORTED;
            break;
        }
        if (buffer == NULL || inputLength != sizeof(OAC_SCAN_REQUEST))
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = OacSessionAcquireDiagnostic(
            DeviceObject,
            stack->FileObject,
            &lease);
        if (NT_SUCCESS(status))
        {
            status = OacRunKernelScan((const OAC_SCAN_REQUEST*)buffer);
        }
        break;

    case IOCTL_OAC_GET_FINDINGS:
        if (!OacSessionLabMode(DeviceObject))
        {
            status = STATUS_NOT_SUPPORTED;
            break;
        }
        if (inputLength != 0)
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        if (buffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = OacSessionAcquireDiagnostic(
            DeviceObject,
            stack->FileObject,
            &lease);
        if (NT_SUCCESS(status))
        {
            status = OacReadFindings(
                (POAC_FINDINGS_RESPONSE)buffer,
                outputLength,
                &bytesWritten);
        }
        break;

    case IOCTL_OAC_CPU_SNAPSHOT:
        if (!OacSessionLabMode(DeviceObject))
        {
            status = STATUS_NOT_SUPPORTED;
            break;
        }
        if (inputLength != 0)
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        if (buffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = OacSessionAcquireDiagnostic(
            DeviceObject,
            stack->FileObject,
            &lease);
        if (NT_SUCCESS(status))
        {
            status = OacCaptureCpuSnapshot(
                buffer,
                outputLength,
                &bytesWritten);
        }
        break;

    case IOCTL_OAC_GET_STATUS:
        if (!OacSessionLabMode(DeviceObject))
        {
            status = STATUS_NOT_SUPPORTED;
            break;
        }
        if (inputLength != 0)
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        if (buffer == NULL || outputLength < sizeof(OAC_STATUS_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            POAC_STATUS_RESPONSE response = (POAC_STATUS_RESPONSE)buffer;
            status = OacSessionAcquireDiagnostic(
                DeviceObject,
                stack->FileObject,
                &lease);
            if (!NT_SUCCESS(status)) break;
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

    case IOCTL_OAC_V5_NEGOTIATE:
        if (buffer == NULL || outputLength > OAC_V5_MAX_OUTPUT_SIZE ||
            OacV5ValidateNegotiateRequest(
                (const OAC_V5_NEGOTIATE_REQUEST*)buffer,
                inputLength) != OAC_V5_VALID)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(OAC_V5_NEGOTIATE_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            const ULONGLONG requestId =
                ((const OAC_V5_NEGOTIATE_REQUEST*)buffer)->Header.RequestId;
            POAC_V5_NEGOTIATE_RESPONSE response =
                (POAC_V5_NEGOTIATE_RESPONSE)buffer;
            status = OacSessionMarkNegotiated(
                DeviceObject,
                stack->FileObject);
            if (!NT_SUCCESS(status)) break;
            RtlZeroMemory(response, sizeof(*response));
            OacInitializeV5Response(
                &response->Header,
                sizeof(*response),
                requestId,
                OAC_V5_MESSAGE_NEGOTIATE,
                NULL);
            response->MinimumVersion = OAC_V5_VERSION;
            response->SelectedVersion = OAC_V5_VERSION;
            response->MaximumVersion = OAC_V5_VERSION;
            response->Capabilities = OacV5Capabilities();
            response->MaximumInputSize = OAC_V5_MAX_INPUT_SIZE;
            response->MaximumOutputSize = OAC_V5_MAX_OUTPUT_SIZE;
            response->MaximumEventCount =
                OAC_EVIDENCE_MAX_RECORDS_PER_PAGE;
            response->ProtocolFlags = OAC_V5_PROTOCOL_STRICT_LENGTHS |
                OAC_V5_PROTOCOL_TYPED_EVENTS;
            if (OacSessionLabMode(DeviceObject))
            {
                response->ProtocolFlags |= OAC_V5_PROTOCOL_V4_DIAGNOSTIC;
            }
            bytesWritten = sizeof(*response);
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_OAC_V5_CLAIM_SESSION:
        if (buffer == NULL || outputLength > OAC_V5_MAX_OUTPUT_SIZE ||
            OacV5ValidateClaimRequest(
                (const OAC_V5_CLAIM_REQUEST*)buffer,
                inputLength) != OAC_V5_VALID)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(OAC_V5_CLAIM_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            const ULONGLONG requestId =
                ((const OAC_V5_CLAIM_REQUEST*)buffer)->Header.RequestId;
            const ULONG mode =
                ((const OAC_V5_CLAIM_REQUEST*)buffer)->Mode;
            OAC_SESSION_SNAPSHOT snapshot;
            POAC_V5_CLAIM_RESPONSE response;

            status = OacSessionClaim(
                DeviceObject,
                stack->FileObject,
                mode,
                TRUE,
                &snapshot);
            if (!NT_SUCCESS(status)) break;
            response = (POAC_V5_CLAIM_RESPONSE)buffer;
            RtlZeroMemory(response, sizeof(*response));
            OacInitializeV5Response(
                &response->Header,
                sizeof(*response),
                requestId,
                OAC_V5_MESSAGE_CLAIM_SESSION,
                &snapshot);
            response->State = snapshot.State;
            response->Capabilities = OacV5Capabilities();
            bytesWritten = sizeof(*response);
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_OAC_ARM_LAUNCH:
        if (buffer == NULL || outputLength > OAC_V5_MAX_OUTPUT_SIZE ||
            OacValidateArmLaunchRequest(
                (const OAC_ARM_LAUNCH_REQUEST*)buffer,
                inputLength) != OAC_V5_VALID)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(OAC_ARM_LAUNCH_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            const OAC_ARM_LAUNCH_REQUEST request =
                *(const OAC_ARM_LAUNCH_REQUEST*)buffer;
            OAC_SESSION_SNAPSHOT snapshot;
            OAC_LAUNCH_ID launchId;
            ULONGLONG expirationInterruptTime100ns;
            POAC_ARM_LAUNCH_RESPONSE response;

            status = OacSessionAcquireV5(
                DeviceObject,
                stack->FileObject,
                &request.Header,
                &lease);
            if (!NT_SUCCESS(status)) break;
            status = OacSessionArmLaunch(
                &lease,
                request.TimeToLiveMilliseconds,
                request.CanonicalNtPath,
                request.CanonicalNtPathLength,
                request.CanonicalDosDevicePath,
                request.CanonicalDosDevicePathLength,
                &launchId,
                &expirationInterruptTime100ns,
                &snapshot);
            if (!NT_SUCCESS(status)) break;
            response = (POAC_ARM_LAUNCH_RESPONSE)buffer;
            RtlZeroMemory(response, sizeof(*response));
            OacInitializeV5Response(
                &response->Header,
                sizeof(*response),
                request.Header.RequestId,
                OAC_MESSAGE_ARM_LAUNCH,
                &snapshot);
            response->LaunchId = launchId;
            response->ExpirationInterruptTime100ns =
                expirationInterruptTime100ns;
            response->State = snapshot.State;
            bytesWritten = sizeof(*response);
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_OAC_CANCEL_LAUNCH:
        if (buffer == NULL || outputLength > OAC_V5_MAX_OUTPUT_SIZE ||
            OacValidateCancelLaunchRequest(
                (const OAC_CANCEL_LAUNCH_REQUEST*)buffer,
                inputLength) != OAC_V5_VALID)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(OAC_CANCEL_LAUNCH_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            const OAC_CANCEL_LAUNCH_REQUEST request =
                *(const OAC_CANCEL_LAUNCH_REQUEST*)buffer;
            OAC_SESSION_SNAPSHOT snapshot;
            POAC_CANCEL_LAUNCH_RESPONSE response;

            status = OacSessionAcquireV5(
                DeviceObject,
                stack->FileObject,
                &request.Header,
                &lease);
            if (!NT_SUCCESS(status)) break;
            status = OacSessionCancelLaunch(
                &lease,
                &request.LaunchId,
                &snapshot);
            if (!NT_SUCCESS(status)) break;
            response = (POAC_CANCEL_LAUNCH_RESPONSE)buffer;
            RtlZeroMemory(response, sizeof(*response));
            OacInitializeV5Response(
                &response->Header,
                sizeof(*response),
                request.Header.RequestId,
                OAC_MESSAGE_CANCEL_LAUNCH,
                &snapshot);
            response->Header.Flags = OAC_V5_RESPONSE_REVOKED;
            response->State = snapshot.State;
            bytesWritten = sizeof(*response);
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_OAC_CONFIRM_TARGET:
        if (buffer == NULL || outputLength > OAC_V5_MAX_OUTPUT_SIZE ||
            OacValidateConfirmTargetRequest(
                (const OAC_CONFIRM_TARGET_REQUEST*)buffer,
                inputLength) != OAC_V5_VALID)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(OAC_CONFIRM_TARGET_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            const OAC_CONFIRM_TARGET_REQUEST request =
                *(const OAC_CONFIRM_TARGET_REQUEST*)buffer;
            OAC_SESSION_SNAPSHOT snapshot;
            POAC_CONFIRM_TARGET_RESPONSE response;

            status = OacSessionAcquireV5(
                DeviceObject,
                stack->FileObject,
                &request.Header,
                &lease);
            if (!NT_SUCCESS(status)) break;
            status = OacSessionConfirmTarget(
                &lease,
                &request.LaunchId,
                request.TargetProcessHandle,
                &snapshot);
            if (!NT_SUCCESS(status)) break;
            response = (POAC_CONFIRM_TARGET_RESPONSE)buffer;
            RtlZeroMemory(response, sizeof(*response));
            OacInitializeV5Response(
                &response->Header,
                sizeof(*response),
                request.Header.RequestId,
                OAC_MESSAGE_CONFIRM_TARGET,
                &snapshot);
            response->TargetProcessId = snapshot.TargetProcessId;
            response->State = snapshot.State;
            OacEvidencePublish(
                &snapshot.SessionId,
                snapshot.Generation,
                OAC_V5_RULE_TARGET_BOUND,
                OAC_V5_EVENT_SESSION_STATE_CHANGED,
                OAC_V5_OBSERVATION_INFO,
                OAC_V5_POLICY_NOT_EVALUATED,
                OAC_V5_CONFIDENCE_HIGH,
                OAC_V5_CATEGORY_PROCESS,
                (HANDLE)(ULONG_PTR)snapshot.TargetProcessId,
                NULL,
                NULL,
                0,
                OAC_V5_EVIDENCE_KERNEL_SOURCE);
            bytesWritten = sizeof(*response);
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_OAC_V5_REVOKE_SESSION:
        if (buffer == NULL || outputLength > OAC_V5_MAX_OUTPUT_SIZE ||
            OacValidateRevokeSessionRequest(
                (const OAC_REVOKE_SESSION_REQUEST*)buffer,
                inputLength) != OAC_V5_VALID)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(OAC_REVOKE_SESSION_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            const OAC_REVOKE_SESSION_REQUEST request =
                *(const OAC_REVOKE_SESSION_REQUEST*)buffer;
            OAC_SESSION_SNAPSHOT snapshot;
            POAC_REVOKE_SESSION_RESPONSE response;
            PEPROCESS revokedOwner = NULL;

            status = OacSessionAcquireV5Status(
                DeviceObject,
                stack->FileObject,
                &request.Header,
                &lease);
            if (!NT_SUCCESS(status)) break;
            status = OacSessionRevoke(
                &lease,
                request.RevokeReason,
                &snapshot,
                &revokedOwner);
            if (!NT_SUCCESS(status)) break;
            if (revokedOwner != NULL)
            {
                OacProtectionRevokeController(revokedOwner);
                ObDereferenceObject(revokedOwner);
            }
            OacEvidencePublish(
                &snapshot.SessionId,
                snapshot.Generation,
                OAC_V5_RULE_SESSION_REVOKED,
                OAC_V5_EVENT_REVOCATION,
                OAC_V5_OBSERVATION_INFO,
                OAC_V5_POLICY_NOT_EVALUATED,
                OAC_V5_CONFIDENCE_HIGH,
                OAC_V5_CATEGORY_SERVICE,
                PsGetCurrentProcessId(),
                PsGetCurrentThreadId(),
                NULL,
                request.RevokeReason,
                OAC_V5_EVIDENCE_KERNEL_SOURCE);

            response = (POAC_REVOKE_SESSION_RESPONSE)buffer;
            RtlZeroMemory(response, sizeof(*response));
            OacInitializeV5Response(
                &response->Header,
                sizeof(*response),
                request.Header.RequestId,
                OAC_V5_MESSAGE_REVOKE_SESSION,
                &snapshot);
            response->Header.Flags = OAC_V5_RESPONSE_REVOKED;
            response->State = snapshot.State;
            response->RevokeReason = snapshot.RevokeReason;
            response->SessionLossSequence = snapshot.SessionLossSequence;
            response->LastSessionLossReason =
                snapshot.LastSessionLossReason;
            bytesWritten = sizeof(*response);
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_OAC_READ_EVIDENCE:
        if (buffer == NULL || outputLength > OAC_V5_MAX_OUTPUT_SIZE ||
            OacValidateEvidenceReadRequest(
                (const OAC_EVIDENCE_READ_REQUEST*)buffer,
                inputLength) != OAC_V5_VALID)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        {
            const OAC_EVIDENCE_READ_REQUEST request =
                *(const OAC_EVIDENCE_READ_REQUEST*)buffer;
            OAC_SESSION_SNAPSHOT snapshot;
            POAC_EVIDENCE_READ_RESPONSE response =
                (POAC_EVIDENCE_READ_RESPONSE)buffer;

            status = OacSessionAcquireV5Status(
                DeviceObject,
                stack->FileObject,
                &request.Header,
                &lease);
            if (!NT_SUCCESS(status)) break;
            status = OacSessionSnapshot(&lease, &snapshot);
            if (!NT_SUCCESS(status)) break;
            status = OacEvidenceRead(
                &request,
                snapshot.State >= OAC_V5_SESSION_REVOKED,
                response,
                outputLength,
                &bytesWritten);
            if (!NT_SUCCESS(status)) break;
            OacInitializeV5Response(
                &response->Header,
                bytesWritten,
                request.Header.RequestId,
                OAC_MESSAGE_READ_EVIDENCE,
                &snapshot);
        }
        break;

    case IOCTL_OAC_MANAGE_SNAPSHOT:
        if (buffer == NULL || outputLength > OAC_V5_MAX_OUTPUT_SIZE ||
            OacValidateSnapshotRequest(
                (const OAC_SNAPSHOT_REQUEST*)buffer,
                inputLength) != OAC_V5_VALID)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        {
            const OAC_SNAPSHOT_REQUEST request =
                *(const OAC_SNAPSHOT_REQUEST*)buffer;
            OAC_SESSION_SNAPSHOT snapshot;
            POAC_SNAPSHOT_RESPONSE response =
                (POAC_SNAPSHOT_RESPONSE)buffer;

            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            {
                status = STATUS_INVALID_DEVICE_STATE;
                break;
            }
            status = OacSessionAcquireV5Status(
                DeviceObject,
                stack->FileObject,
                &request.Header,
                &lease);
            if (!NT_SUCCESS(status)) break;
            status = OacSessionSnapshot(&lease, &snapshot);
            if (!NT_SUCCESS(status)) break;
            status = OacEvidenceManageSnapshot(
                &request,
                snapshot.State >= OAC_V5_SESSION_REVOKED,
                response,
                outputLength,
                &bytesWritten);
            if (!NT_SUCCESS(status)) break;
            OacInitializeV5Response(
                &response->Header,
                bytesWritten,
                request.Header.RequestId,
                OAC_MESSAGE_MANAGE_SNAPSHOT,
                &snapshot);
        }
        break;

    case IOCTL_OAC_TEST_INJECT_EVIDENCE:
        if (!OacSessionLabMode(DeviceObject) || buffer == NULL ||
            outputLength != 0 ||
            OacValidateTestEvidenceRequest(
                (const OAC_TEST_INJECT_EVIDENCE_REQUEST*)buffer,
                inputLength) != OAC_V5_VALID)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        {
            const OAC_TEST_INJECT_EVIDENCE_REQUEST request =
                *(const OAC_TEST_INJECT_EVIDENCE_REQUEST*)buffer;
            ULONG index;

            status = OacSessionAcquireV5(
                DeviceObject,
                stack->FileObject,
                &request.Header,
                &lease);
            if (!NT_SUCCESS(status)) break;
            if (!OacSessionLeaseIsDiagnostic(&lease))
            {
                status = STATUS_ACCESS_DENIED;
                break;
            }
            for (index = 0; index < request.Count; ++index)
            {
                OacEvidencePublish(
                    &request.Header.SessionId,
                    request.Header.Generation,
                    request.RuleId,
                    request.EventType,
                    request.ObservationSeverity,
                    request.PolicySeverity,
                    request.Confidence,
                    request.Category,
                    PsGetCurrentProcessId(),
                    PsGetCurrentThreadId(),
                    NULL,
                    index,
                    request.EvidenceFlags);
            }
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_OAC_V5_GET_STATUS:
        if (buffer == NULL || outputLength > OAC_V5_MAX_OUTPUT_SIZE ||
            OacV5ValidateStatusRequest(
                (const OAC_V5_STATUS_REQUEST*)buffer,
                inputLength) != OAC_V5_VALID)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < sizeof(OAC_V5_STATUS_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            const OAC_V5_REQUEST_HEADER requestHeader =
                ((const OAC_V5_STATUS_REQUEST*)buffer)->Header;
            OAC_SESSION_SNAPSHOT snapshot;
            POAC_V5_STATUS_RESPONSE response;
            ULONG configurationFlags;

            status = OacSessionAcquireV5Status(
                DeviceObject,
                stack->FileObject,
                &requestHeader,
                &lease);
            if (!NT_SUCCESS(status)) break;
            status = OacSessionSnapshot(&lease, &snapshot);
            if (!NT_SUCCESS(status)) break;
            response = (POAC_V5_STATUS_RESPONSE)buffer;
            RtlZeroMemory(response, sizeof(*response));
            OacInitializeV5Response(
                &response->Header,
                sizeof(*response),
                requestHeader.RequestId,
                OAC_V5_MESSAGE_GET_STATUS,
                &snapshot);
            response->State = snapshot.State;
            if (snapshot.State >= OAC_V5_SESSION_REVOKED)
            {
                response->Header.Flags |= OAC_V5_RESPONSE_REVOKED;
            }
            response->Capabilities = OacV5Capabilities();
            configurationFlags = OacConfigurationFlags();
            if ((configurationFlags & OAC_CONFIG_ENABLE_IMAGE_LOG) != 0)
            {
                response->ConfigurationFlags |= OAC_V5_CONFIG_IMAGE_LOG;
            }
            if ((configurationFlags & OAC_CONFIG_DRIVER_GATE) != 0)
            {
                response->ConfigurationFlags |= OAC_V5_CONFIG_DRIVER_GATE;
            }
            response->RevokeReason = snapshot.RevokeReason;
            response->ServiceProcessId = snapshot.ServiceProcessId;
            response->TargetProcessId = snapshot.TargetProcessId;
            OacEvidenceEventCounters(
                &response->EventsWritten,
                &response->EventsDropped);
            response->PostStartLoads = OacPostStartLoads();
            response->DriverGateTrips = OacDriverGateTrips();
            response->SessionLossSequence = snapshot.SessionLossSequence;
            response->LastSessionLossReason =
                snapshot.LastSessionLossReason;
            bytesWritten = sizeof(*response);
            status = STATUS_SUCCESS;
        }
        break;

    default:
        break;
    }

    OacSessionRelease(&lease);
    return OacCompleteIrp(Irp, status, bytesWritten);
}

static BOOLEAN OacReadLabMode(_In_ PUNICODE_STRING RegistryPath)
{
    static const UNICODE_STRING parametersName =
        RTL_CONSTANT_STRING(L"Parameters");
    static const UNICODE_STRING valueName =
        RTL_CONSTANT_STRING(L"LabMode");
    OBJECT_ATTRIBUTES attributes;
    HANDLE serviceKey = NULL;
    HANDLE parametersKey = NULL;
    UCHAR valueBuffer[
        FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION value =
        (PKEY_VALUE_PARTIAL_INFORMATION)valueBuffer;
    ULONG returnedLength = 0;
    NTSTATUS status;
    BOOLEAN enabled = FALSE;

    InitializeObjectAttributes(
        &attributes,
        RegistryPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    status = ZwOpenKey(&serviceKey, KEY_QUERY_VALUE, &attributes);
    if (!NT_SUCCESS(status)) goto Exit;
    InitializeObjectAttributes(
        &attributes,
        (PUNICODE_STRING)&parametersName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        serviceKey,
        NULL);
    status = ZwOpenKey(&parametersKey, KEY_QUERY_VALUE, &attributes);
    if (!NT_SUCCESS(status)) goto Exit;
    status = ZwQueryValueKey(
        parametersKey,
        (PUNICODE_STRING)&valueName,
        KeyValuePartialInformation,
        value,
        sizeof(valueBuffer),
        &returnedLength);
    if (NT_SUCCESS(status) && value->Type == REG_DWORD &&
        value->DataLength == sizeof(ULONG))
    {
        enabled = *(UNALIGNED ULONG*)value->Data == 1;
    }

Exit:
    if (parametersKey != NULL) ZwClose(parametersKey);
    if (serviceKey != NULL) ZwClose(serviceKey);
    return enabled;
}

static NTSTATUS OacApplyDeviceSecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ BOOLEAN LabMode)
{
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    UCHAR systemSidBuffer[SECURITY_MAX_SID_SIZE];
    UCHAR serviceSidBuffer[SECURITY_MAX_SID_SIZE];
    UCHAR adminSidBuffer[SECURITY_MAX_SID_SIZE];
    PSID systemSid = (PSID)systemSidBuffer;
    PSID serviceSid = (PSID)serviceSidBuffer;
    PSID adminSid = (PSID)adminSidBuffer;
    SECURITY_DESCRIPTOR descriptor;
    PACL dacl = NULL;
    ULONG daclSize;
    HANDLE deviceHandle = NULL;
    NTSTATUS status;

    status = RtlInitializeSid(systemSid, &ntAuthority, 1);
    if (!NT_SUCCESS(status)) return status;
    *RtlSubAuthoritySid(systemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;
    status = OacSessionBuildServiceSid(
        serviceSid,
        sizeof(serviceSidBuffer));
    if (!NT_SUCCESS(status)) return status;
    status = RtlInitializeSid(adminSid, &ntAuthority, 2);
    if (!NT_SUCCESS(status)) return status;
    *RtlSubAuthoritySid(adminSid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid(adminSid, 1) = DOMAIN_ALIAS_RID_ADMINS;

    daclSize = sizeof(ACL) +
        (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(systemSid)) +
        (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(serviceSid));
    if (LabMode)
    {
        daclSize += sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) +
            RtlLengthSid(adminSid);
    }
    dacl = (PACL)OacAllocatePool(TRUE, daclSize, 'dCaO');
    if (dacl == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    status = RtlCreateAcl(dacl, daclSize, ACL_REVISION);
    if (!NT_SUCCESS(status)) goto Exit;
    status = RtlAddAccessAllowedAceEx(
        dacl,
        ACL_REVISION,
        0,
        GENERIC_ALL,
        systemSid);
    if (!NT_SUCCESS(status)) goto Exit;
    status = RtlAddAccessAllowedAceEx(
        dacl,
        ACL_REVISION,
        0,
        GENERIC_ALL,
        serviceSid);
    if (!NT_SUCCESS(status)) goto Exit;
    if (LabMode)
    {
        status = RtlAddAccessAllowedAceEx(
            dacl,
            ACL_REVISION,
            0,
            GENERIC_ALL,
            adminSid);
        if (!NT_SUCCESS(status)) goto Exit;
    }

    status = RtlCreateSecurityDescriptor(
        &descriptor,
        SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) goto Exit;
    status = RtlSetDaclSecurityDescriptor(&descriptor, TRUE, dacl, FALSE);
    if (!NT_SUCCESS(status)) goto Exit;
    status = ObOpenObjectByPointer(
        DeviceObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        WRITE_DAC,
        NULL,
        KernelMode,
        &deviceHandle);
    if (!NT_SUCCESS(status)) goto Exit;
    status = ZwSetSecurityObject(
        deviceHandle,
        DACL_SECURITY_INFORMATION,
        &descriptor);

Exit:
    if (deviceHandle != NULL) ZwClose(deviceHandle);
    if (dacl != NULL) ExFreePoolWithTag(dacl, 'dCaO');
    return status;
}

static VOID OacCleanup(VOID)
{
    if (g_ProtectionInitialized)
    {
        OacProtectionShutdown();
        g_ProtectionInitialized = FALSE;
    }
    if (g_SessionInitialized && g_DeviceObject != NULL)
    {
        OacSessionShutdown(g_DeviceObject);
        g_SessionInitialized = FALSE;
    }
    if (g_EvidenceInitialized)
    {
        OacEvidenceShutdown();
        g_EvidenceInitialized = FALSE;
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

    RtlInitUnicodeString(&g_DeviceName, OAC_DEVICE_NAME);
    RtlInitUnicodeString(&g_DosDeviceName, OAC_DOS_DEVICE_NAME);

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
    {
        /* One default handler intentionally covers every unsupported major code. */
#pragma warning(suppress: 28169)
        DriverObject->MajorFunction[i] = OacUnsupportedRequest;
    }
    DriverObject->MajorFunction[IRP_MJ_CREATE] = OacCreate;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = OacCleanupFile;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = OacClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OacDeviceControl;
    DriverObject->DriverUnload = OacDriverUnload;

    OacCompatibilityInitialize();
    g_LabMode = OacReadLabMode(RegistryPath);

    status = OacTelemetryInitialize();
    if (!NT_SUCCESS(status)) goto Failure;
    g_TelemetryInitialized = TRUE;

    status = OacEvidenceInitialize();
    if (!NT_SUCCESS(status)) goto Failure;
    g_EvidenceInitialized = TRUE;

    status = IoCreateDeviceSecure(
        DriverObject,
        sizeof(OAC_DEVICE_EXTENSION),
        &g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        g_LabMode
            ? &SDDL_DEVOBJ_SYS_ALL_ADM_ALL
            : &SDDL_DEVOBJ_SYS_ALL,
        &GUID_DEVCLASS_OAC,
        &g_DeviceObject);
    if (!NT_SUCCESS(status)) goto Failure;
    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    OacSessionInitialize(g_DeviceObject, g_LabMode);
    g_SessionInitialized = TRUE;

    status = OacApplyDeviceSecurity(g_DeviceObject, g_LabMode);
    if (!NT_SUCCESS(status)) goto Failure;

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
