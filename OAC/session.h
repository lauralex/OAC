#pragma once

#include <ntifs.h>
#include "..\shared\protocol\oac_v5.h"

typedef struct OAC_SESSION_LEASE_TAG
{
    PVOID Session;
} OAC_SESSION_LEASE, *POAC_SESSION_LEASE;

typedef struct OAC_SESSION_SNAPSHOT_TAG
{
    OAC_V5_SESSION_ID SessionId;
    ULONGLONG Generation;
    ULONG State;
    ULONG RevokeReason;
    ULONGLONG ServiceProcessId;
    ULONGLONG TargetProcessId;
} OAC_SESSION_SNAPSHOT, *POAC_SESSION_SNAPSHOT;

typedef struct OAC_DEVICE_EXTENSION_TAG
{
    EX_PUSH_LOCK SessionLock;
    PVOID ActiveSession;
    volatile LONG64 NextGeneration;
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

NTSTATUS OacSessionBindTarget(
    _In_ const OAC_SESSION_LEASE* Lease,
    _In_opt_ PEPROCESS TargetProcess,
    _In_opt_ HANDLE TargetProcessId);

BOOLEAN OacSessionIsControllerProcess(_In_ PEPROCESS Process);

VOID OacSessionNotifyProcessExit(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId);
