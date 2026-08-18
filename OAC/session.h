#pragma once

#include <ntifs.h>
#include "..\shared\protocol\oac_v5.h"

typedef struct OAC_SESSION_LEASE_TAG
{
    PVOID Session;
} OAC_SESSION_LEASE, *POAC_SESSION_LEASE;

typedef enum OAC_SESSION_PROCESS_CREATE_RESULT_TAG
{
    OacSessionProcessCreateIgnored = 0,
    OacSessionProcessCreateBound = 1,
    OacSessionProcessCreateDenied = 2
} OAC_SESSION_PROCESS_CREATE_RESULT;

typedef struct OAC_SESSION_SNAPSHOT_TAG
{
    OAC_V5_SESSION_ID SessionId;
    ULONGLONG Generation;
    ULONG State;
    ULONG RevokeReason;
    ULONGLONG ServiceProcessId;
    ULONGLONG TargetProcessId;
    ULONGLONG SessionLossSequence;
    ULONG LastSessionLossReason;
} OAC_SESSION_SNAPSHOT, *POAC_SESSION_SNAPSHOT;

typedef struct OAC_DEVICE_EXTENSION_TAG
{
    EX_PUSH_LOCK SessionLock;
    PVOID ActiveSession;
    volatile LONG64 NextGeneration;
    ULONGLONG SessionLossSequence;
    ULONG LastSessionLossReason;
    BOOLEAN LabMode;
    BOOLEAN Stopping;
} OAC_DEVICE_EXTENSION, *POAC_DEVICE_EXTENSION;

NTSTATUS OacSessionBuildServiceSid(
    _Out_writes_bytes_(SidBufferSize) PSID Sid,
    _In_ ULONG SidBufferSize);

VOID OacSessionInitialize(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ BOOLEAN LabMode);

VOID OacSessionShutdown(_In_ PDEVICE_OBJECT DeviceObject);

NTSTATUS OacSessionCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp);

NTSTATUS OacSessionCleanup(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFILE_OBJECT FileObject,
    _Outptr_result_maybenull_ PEPROCESS* RevokedOwner);

NTSTATUS OacSessionClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFILE_OBJECT FileObject);

BOOLEAN OacSessionLabMode(_In_ PDEVICE_OBJECT DeviceObject);

NTSTATUS OacSessionMarkNegotiated(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFILE_OBJECT FileObject);

NTSTATUS OacSessionClaim(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFILE_OBJECT FileObject,
    _In_ ULONG Mode,
    _In_ BOOLEAN RequireNegotiation,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot);

NTSTATUS OacSessionAcquireV5(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFILE_OBJECT FileObject,
    _In_ const OAC_V5_REQUEST_HEADER* Header,
    _Out_ POAC_SESSION_LEASE Lease);

NTSTATUS OacSessionAcquireV5Status(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFILE_OBJECT FileObject,
    _In_ const OAC_V5_REQUEST_HEADER* Header,
    _Out_ POAC_SESSION_LEASE Lease);

NTSTATUS OacSessionAcquireDiagnostic(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFILE_OBJECT FileObject,
    _Out_ POAC_SESSION_LEASE Lease);

VOID OacSessionRelease(_Inout_ POAC_SESSION_LEASE Lease);

NTSTATUS OacSessionSnapshot(
    _In_ const OAC_SESSION_LEASE* Lease,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot);

NTSTATUS OacSessionRevoke(
    _In_ const OAC_SESSION_LEASE* Lease,
    _In_ OAC_V5_REVOKE_REASON RevokeReason,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot,
    _Outptr_result_maybenull_ PEPROCESS* RevokedOwner);

NTSTATUS OacSessionBindTarget(
    _In_ const OAC_SESSION_LEASE* Lease,
    _In_opt_ PEPROCESS TargetProcess,
    _In_opt_ HANDLE TargetProcessId);

NTSTATUS OacSessionArmLaunch(
    _In_ const OAC_SESSION_LEASE* Lease,
    _In_ ULONG TimeToLiveMilliseconds,
    _In_reads_(CanonicalNtPathLength) const WCHAR* CanonicalNtPath,
    _In_ ULONG CanonicalNtPathLength,
    _In_reads_(CanonicalDosDevicePathLength)
        const WCHAR* CanonicalDosDevicePath,
    _In_ ULONG CanonicalDosDevicePathLength,
    _Out_ POAC_LAUNCH_ID LaunchId,
    _Out_ PULONGLONG ExpirationInterruptTime100ns,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot);

NTSTATUS OacSessionCancelLaunch(
    _In_ const OAC_SESSION_LEASE* Lease,
    _In_ const OAC_LAUNCH_ID* LaunchId,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot);

NTSTATUS OacSessionConfirmTarget(
    _In_ const OAC_SESSION_LEASE* Lease,
    _In_ const OAC_LAUNCH_ID* LaunchId,
    _In_ ULONGLONG TargetProcessHandle,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot);

OAC_SESSION_PROCESS_CREATE_RESULT OacSessionNotifyProcessCreate(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PEPROCESS CreatorProcess,
    _In_ HANDLE CreatorProcessId,
    _In_opt_ PCUNICODE_STRING ImageFileName,
    _In_ BOOLEAN FileOpenNameAvailable);

BOOLEAN OacSessionIsControllerProcess(_In_ PEPROCESS Process);

BOOLEAN OacSessionIsTargetProcess(_In_ PEPROCESS Process);

HANDLE OacSessionTargetProcessId(VOID);

VOID OacSessionNotifyProcessExit(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId);
