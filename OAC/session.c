#include "session.h"
#include "compat.h"

#include <bcrypt.h>

#define OAC_FILE_POOL_TAG 'fCaO'
#define OAC_SESSION_POOL_TAG 'sCaO'
#define OAC_FILE_CONTEXT_MAGIC 0x4643414FUL
#define OAC_TOKEN_GROUP_ENABLED 0x00000004UL
#define OAC_TOKEN_GROUP_DENY_ONLY 0x00000010UL

typedef struct OAC_SESSION_TAG OAC_SESSION, *POAC_SESSION;

typedef struct OAC_FILE_CONTEXT_TAG
{
    ULONG Magic;
    volatile LONG CleanupStarted;
    BOOLEAN ServiceOwner;
    ULONG NegotiatedVersion;
    PEPROCESS OpenProcess;
    POAC_SESSION Session;
} OAC_FILE_CONTEXT, *POAC_FILE_CONTEXT;

struct OAC_SESSION_TAG
{
    volatile LONG References;
    EX_RUNDOWN_REF IoRundown;
    PDEVICE_OBJECT DeviceObject;
    PFILE_OBJECT ControlFile;
    PEPROCESS ServiceProcess;
    PEPROCESS TargetProcess;
    OAC_V5_SESSION_ID SessionId;
    ULONGLONG Generation;
    HANDLE ServiceProcessId;
    HANDLE TargetProcessId;
    ULONG Mode;
    ULONG State;
    ULONG RevokeReason;
    BOOLEAN Cleaned;
    BOOLEAN ServiceExited;
};

static PDEVICE_OBJECT g_SessionDevice;

static const ULONG g_ServiceSidParts[] =
{
    SECURITY_SERVICE_ID_BASE_RID,
    1726785755UL,
    3364470821UL,
    2652420548UL,
    2779146334UL,
    590817200UL
};

NTSTATUS OacSessionBuildServiceSid(
    _Out_writes_bytes_(SidBufferSize) PSID Sid,
    _In_ ULONG SidBufferSize)
{
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    ULONG index;
    NTSTATUS status;

    if (Sid == NULL ||
        SidBufferSize < RtlLengthRequiredSid(
            (ULONG)RTL_NUMBER_OF(g_ServiceSidParts)))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = RtlInitializeSid(
        Sid,
        &authority,
        (UCHAR)RTL_NUMBER_OF(g_ServiceSidParts));
    if (!NT_SUCCESS(status)) return status;
    for (index = 0; index < RTL_NUMBER_OF(g_ServiceSidParts); ++index)
    {
        *RtlSubAuthoritySid(Sid, index) = g_ServiceSidParts[index];
    }
    return STATUS_SUCCESS;
}

static POAC_DEVICE_EXTENSION OacExtension(_In_ PDEVICE_OBJECT DeviceObject)
{
    return (POAC_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
}

static VOID OacLockExclusive(_Inout_ PEX_PUSH_LOCK Lock)
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(Lock);
}

static VOID OacUnlockExclusive(_Inout_ PEX_PUSH_LOCK Lock)
{
    ExReleasePushLockExclusive(Lock);
    KeLeaveCriticalRegion();
}

static VOID OacLockShared(_Inout_ PEX_PUSH_LOCK Lock)
{
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(Lock);
}

static VOID OacUnlockShared(_Inout_ PEX_PUSH_LOCK Lock)
{
    ExReleasePushLockShared(Lock);
    KeLeaveCriticalRegion();
}

static BOOLEAN OacSidPresent(
    _In_reads_opt_(SidCount) const SID_AND_ATTRIBUTES* Sids,
    _In_ ULONG SidCount,
    _In_ PSID ExpectedSid,
    _In_ BOOLEAN RequireEnabledGroup)
{
    ULONG index;

    if (Sids == NULL) return FALSE;
    for (index = 0; index < SidCount; ++index)
    {
        const ULONG attributes = Sids[index].Attributes;

        if (RtlEqualSid(Sids[index].Sid, ExpectedSid) &&
            (!RequireEnabledGroup ||
                ((attributes & OAC_TOKEN_GROUP_ENABLED) != 0 &&
                 (attributes & OAC_TOKEN_GROUP_DENY_ONLY) == 0)))
        {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN OacIsServiceProcess(VOID)
{
    UCHAR sidBuffer[SECURITY_MAX_SID_SIZE];
    PACCESS_TOKEN token;
    PTOKEN_GROUPS_AND_PRIVILEGES identity = NULL;
    PSID serviceSid = (PSID)sidBuffer;
    NTSTATUS status;
    BOOLEAN groupFound = FALSE;
    BOOLEAN restrictedFound = FALSE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return FALSE;
    status = OacSessionBuildServiceSid(serviceSid, sizeof(sidBuffer));
    if (!NT_SUCCESS(status)) return FALSE;

    token = PsReferencePrimaryToken(PsGetCurrentProcess());
    /* This supported aggregate class carries both normal and restricting SIDs. */
    status = SeQueryInformationToken(
        token,
        TokenGroupsAndPrivileges,
        (PVOID*)&identity);
    if (NT_SUCCESS(status) && identity != NULL)
    {
        groupFound = OacSidPresent(
            identity->Sids,
            identity->SidCount,
            serviceSid,
            TRUE);
        restrictedFound = OacSidPresent(
            identity->RestrictedSids,
            identity->RestrictedSidCount,
            serviceSid,
            FALSE);
    }
    if (identity != NULL) ExFreePool(identity);
    PsDereferencePrimaryToken(token);
    return groupFound && restrictedFound;
}

static NTSTATUS OacGenerateSessionId(_Out_ POAC_V5_SESSION_ID SessionId)
{
    NTSTATUS status;
    ULONG attempts;

    for (attempts = 0; attempts != 4; ++attempts)
    {
        status = BCryptGenRandom(
            NULL,
            (PUCHAR)SessionId,
            sizeof(*SessionId),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!NT_SUCCESS(status)) return status;
        if (SessionId->High != 0 || SessionId->Low != 0)
        {
            return STATUS_SUCCESS;
        }
    }
    return STATUS_UNSUCCESSFUL;
}

static VOID OacSessionReleaseReference(_Inout_ POAC_SESSION Session)
{
    if (InterlockedDecrement(&Session->References) == 0)
    {
        NT_ASSERT(Session->ControlFile == NULL);
        NT_ASSERT(Session->ServiceProcess == NULL);
        NT_ASSERT(Session->TargetProcess == NULL);
        ExFreePoolWithTag(Session, OAC_SESSION_POOL_TAG);
    }
}

static VOID OacReleaseControlObjects(_Inout_ POAC_SESSION Session)
{
    PFILE_OBJECT fileObject;
    PEPROCESS serviceProcess;

    fileObject = (PFILE_OBJECT)InterlockedExchangePointer(
        (PVOID volatile*)&Session->ControlFile,
        NULL);
    serviceProcess = (PEPROCESS)InterlockedExchangePointer(
        (PVOID volatile*)&Session->ServiceProcess,
        NULL);
    if (fileObject != NULL) ObDereferenceObject(fileObject);
    if (serviceProcess != NULL) ObDereferenceObject(serviceProcess);
}

static VOID OacRetireIfEligible(
    _Inout_ POAC_DEVICE_EXTENSION Extension,
    _Inout_ POAC_SESSION Session,
    _Out_ PBOOLEAN DeviceReferenceReleased)
{
    *DeviceReferenceReleased = FALSE;
    if ((Session->Cleaned || Session->ServiceExited) &&
        Session->TargetProcess == NULL &&
        Extension->ActiveSession == Session)
    {
        Extension->ActiveSession = NULL;
        *DeviceReferenceReleased = TRUE;
    }
}

static POAC_FILE_CONTEXT OacGetFileContext(_In_ PFILE_OBJECT FileObject)
{
    POAC_FILE_CONTEXT context = (POAC_FILE_CONTEXT)FileObject->FsContext;

    if (context == NULL || context->Magic != OAC_FILE_CONTEXT_MAGIC)
    {
        return NULL;
    }
    return context;
}

static BOOLEAN OacSessionAcceptsControl(_In_ ULONG State)
{
    return State == OAC_V5_SESSION_CLAIMED ||
        State == OAC_V5_SESSION_LAUNCH_PENDING ||
        State == OAC_V5_SESSION_TARGET_BOUND ||
        State == OAC_V5_SESSION_MONITORING;
}

VOID OacSessionInitialize(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ BOOLEAN LabMode)
{
    POAC_DEVICE_EXTENSION extension = OacExtension(DeviceObject);

    RtlZeroMemory(extension, sizeof(*extension));
    ExInitializePushLock(&extension->SessionLock);
    extension->LabMode = LabMode;
    g_SessionDevice = DeviceObject;
}

VOID OacSessionShutdown(_In_ PDEVICE_OBJECT DeviceObject)
{
    POAC_DEVICE_EXTENSION extension = OacExtension(DeviceObject);
    POAC_SESSION session;
    PEPROCESS targetProcess = NULL;

    OacLockExclusive(&extension->SessionLock);
    extension->Stopping = TRUE;
    session = (POAC_SESSION)extension->ActiveSession;
    extension->ActiveSession = NULL;
    if (session != NULL)
    {
        session->State = OAC_V5_SESSION_CLOSING;
        session->RevokeReason = OAC_V5_REVOKE_DRIVER_STOP;
        targetProcess = (PEPROCESS)InterlockedExchangePointer(
            (PVOID volatile*)&session->TargetProcess,
            NULL);
        session->TargetProcessId = NULL;
    }
    OacUnlockExclusive(&extension->SessionLock);

    if (session != NULL)
    {
        OacReleaseControlObjects(session);
        if (targetProcess != NULL) ObDereferenceObject(targetProcess);
        OacSessionReleaseReference(session);
    }
    g_SessionDevice = NULL;
}

NTSTATUS OacSessionCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    POAC_DEVICE_EXTENSION extension = OacExtension(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    POAC_FILE_CONTEXT context;
    BOOLEAN serviceOwner;

    if (stack->FileObject == NULL || stack->FileObject->FileName.Length != 0)
    {
        return STATUS_OBJECT_NAME_INVALID;
    }
    if (extension->Stopping) return STATUS_DELETE_PENDING;

    serviceOwner = OacIsServiceProcess();
    if (!extension->LabMode && !serviceOwner)
    {
        return STATUS_ACCESS_DENIED;
    }

    context = (POAC_FILE_CONTEXT)OacAllocatePool(
        FALSE,
        sizeof(*context),
        OAC_FILE_POOL_TAG);
    if (context == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(context, sizeof(*context));
    context->Magic = OAC_FILE_CONTEXT_MAGIC;
    context->ServiceOwner = serviceOwner;
    context->OpenProcess = PsGetCurrentProcess();
    ObReferenceObject(context->OpenProcess);
    stack->FileObject->FsContext = context;
    return STATUS_SUCCESS;
}

NTSTATUS OacSessionCleanup(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFILE_OBJECT FileObject,
    _Outptr_result_maybenull_ PEPROCESS* RevokedOwner)
{
    POAC_DEVICE_EXTENSION extension = OacExtension(DeviceObject);
    POAC_FILE_CONTEXT context = OacGetFileContext(FileObject);
    POAC_SESSION session;
    BOOLEAN releaseDeviceReference = FALSE;

    *RevokedOwner = NULL;
    if (context == NULL) return STATUS_SUCCESS;
    if (InterlockedCompareExchange(&context->CleanupStarted, 1, 0) != 0)
    {
        return STATUS_SUCCESS;
    }

    OacLockExclusive(&extension->SessionLock);
    session = context->Session;
    if (session == NULL)
    {
        OacUnlockExclusive(&extension->SessionLock);
        return STATUS_SUCCESS;
    }
    if (session->ServiceProcess != NULL)
    {
        ObReferenceObject(session->ServiceProcess);
        *RevokedOwner = session->ServiceProcess;
    }
    session->Cleaned = TRUE;
    session->State = OAC_V5_SESSION_CLOSING;
    if (session->RevokeReason == OAC_V5_REVOKE_NONE)
    {
        session->RevokeReason = OAC_V5_REVOKE_FILE_CLEANUP;
    }
    OacRetireIfEligible(
        extension,
        session,
        &releaseDeviceReference);
    OacUnlockExclusive(&extension->SessionLock);

    ExRundownCompleted(&session->IoRundown);
    ExWaitForRundownProtectionRelease(&session->IoRundown);
    OacReleaseControlObjects(session);
    if (releaseDeviceReference) OacSessionReleaseReference(session);
    return STATUS_SUCCESS;
}

NTSTATUS OacSessionClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFILE_OBJECT FileObject)
{
    POAC_FILE_CONTEXT context = OacGetFileContext(FileObject);
    POAC_SESSION session;
    PEPROCESS owner = NULL;

    if (context == NULL) return STATUS_SUCCESS;
    (VOID)OacSessionCleanup(DeviceObject, FileObject, &owner);
    if (owner != NULL) ObDereferenceObject(owner);
    FileObject->FsContext = NULL;
    context->Magic = 0;
    session = context->Session;
    context->Session = NULL;
    if (session != NULL) OacSessionReleaseReference(session);
    if (context->OpenProcess != NULL)
    {
        ObDereferenceObject(context->OpenProcess);
        context->OpenProcess = NULL;
    }
    ExFreePoolWithTag(context, OAC_FILE_POOL_TAG);
    return STATUS_SUCCESS;
}

BOOLEAN OacSessionLabMode(_In_ PDEVICE_OBJECT DeviceObject)
{
    return OacExtension(DeviceObject)->LabMode;
}

NTSTATUS OacSessionMarkNegotiated(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFILE_OBJECT FileObject)
{
    POAC_DEVICE_EXTENSION extension = OacExtension(DeviceObject);
    POAC_FILE_CONTEXT context = OacGetFileContext(FileObject);
    NTSTATUS status;

    if (context == NULL)
    {
        return STATUS_FILE_CLOSED;
    }

    OacLockExclusive(&extension->SessionLock);
    if (context->CleanupStarted != 0)
    {
        status = STATUS_FILE_CLOSED;
    }
    else if (context->OpenProcess != PsGetCurrentProcess())
    {
        status = STATUS_ACCESS_DENIED;
    }
    else if (context->Session != NULL)
    {
        status = STATUS_INVALID_DEVICE_STATE;
    }
    else
    {
        context->NegotiatedVersion = OAC_V5_VERSION;
        status = STATUS_SUCCESS;
    }
    OacUnlockExclusive(&extension->SessionLock);
    return status;
}

NTSTATUS OacSessionClaim(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFILE_OBJECT FileObject,
    _In_ ULONG Mode,
    _In_ BOOLEAN RequireNegotiation,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot)
{
    POAC_DEVICE_EXTENSION extension = OacExtension(DeviceObject);
    POAC_FILE_CONTEXT context = OacGetFileContext(FileObject);
    POAC_SESSION session;
    NTSTATUS status;
    LONG64 generation;

    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    if (context == NULL || context->CleanupStarted != 0)
    {
        return STATUS_FILE_CLOSED;
    }
    if (context->OpenProcess != PsGetCurrentProcess())
    {
        return STATUS_ACCESS_DENIED;
    }
    if (RequireNegotiation && context->NegotiatedVersion != OAC_V5_VERSION)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!RequireNegotiation && context->NegotiatedVersion != 0)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (Mode == OAC_V5_SESSION_PRODUCTION)
    {
        if (!context->ServiceOwner || !OacIsServiceProcess())
        {
            return STATUS_ACCESS_DENIED;
        }
    }
    else if (Mode == OAC_V5_SESSION_DIAGNOSTIC)
    {
        if (!extension->LabMode) return STATUS_NOT_SUPPORTED;
    }
    else
    {
        return STATUS_INVALID_PARAMETER;
    }

    session = (POAC_SESSION)OacAllocatePool(
        FALSE,
        sizeof(*session),
        OAC_SESSION_POOL_TAG);
    if (session == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(session, sizeof(*session));
    status = OacGenerateSessionId(&session->SessionId);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(session, OAC_SESSION_POOL_TAG);
        return status;
    }
    generation = InterlockedIncrement64(&extension->NextGeneration);
    if (generation <= 0)
    {
        ExFreePoolWithTag(session, OAC_SESSION_POOL_TAG);
        return STATUS_INTEGER_OVERFLOW;
    }

    session->References = 2;
    ExInitializeRundownProtection(&session->IoRundown);
    session->DeviceObject = DeviceObject;
    session->ControlFile = FileObject;
    ObReferenceObject(FileObject);
    session->ServiceProcess = context->OpenProcess;
    ObReferenceObject(session->ServiceProcess);
    session->ServiceProcessId = PsGetCurrentProcessId();
    session->Generation = (ULONGLONG)generation;
    session->Mode = Mode;
    session->State = OAC_V5_SESSION_CLAIMED;

    OacLockExclusive(&extension->SessionLock);
    if (extension->Stopping)
    {
        status = STATUS_DELETE_PENDING;
    }
    else if (context->CleanupStarted != 0)
    {
        status = STATUS_FILE_CLOSED;
    }
    else if ((RequireNegotiation &&
              context->NegotiatedVersion != OAC_V5_VERSION) ||
             (!RequireNegotiation && context->NegotiatedVersion != 0))
    {
        status = STATUS_INVALID_DEVICE_STATE;
    }
    else if (context->Session != NULL || extension->ActiveSession != NULL)
    {
        status = STATUS_DEVICE_BUSY;
    }
    else
    {
        context->Session = session;
        extension->ActiveSession = session;
        Snapshot->SessionId = session->SessionId;
        Snapshot->Generation = session->Generation;
        Snapshot->State = session->State;
        Snapshot->ServiceProcessId =
            HandleToULong(session->ServiceProcessId);
        status = STATUS_SUCCESS;
    }
    OacUnlockExclusive(&extension->SessionLock);

    if (!NT_SUCCESS(status))
    {
        OacReleaseControlObjects(session);
        session->References = 1;
        OacSessionReleaseReference(session);
        return status;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS OacSessionAcquireCore(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFILE_OBJECT FileObject,
    _In_opt_ const OAC_V5_REQUEST_HEADER* Header,
    _In_ BOOLEAN Diagnostic,
    _In_ BOOLEAN AllowRevoked,
    _Out_ POAC_SESSION_LEASE Lease)
{
    POAC_DEVICE_EXTENSION extension = OacExtension(DeviceObject);
    POAC_FILE_CONTEXT context = OacGetFileContext(FileObject);
    POAC_SESSION session;
    NTSTATUS status = STATUS_ACCESS_DENIED;

    Lease->Session = NULL;
    if (context == NULL || context->CleanupStarted != 0)
    {
        return STATUS_FILE_CLOSED;
    }

    OacLockShared(&extension->SessionLock);
    session = context->Session;
    if (session == NULL || extension->ActiveSession != session ||
        session->ControlFile != FileObject ||
        session->ServiceProcess != PsGetCurrentProcess() ||
        session->Cleaned ||
        (!OacSessionAcceptsControl(session->State) &&
         !(AllowRevoked && session->State == OAC_V5_SESSION_REVOKED)))
    {
        status = STATUS_ACCESS_DENIED;
    }
    else if (Diagnostic &&
        (session->Mode != OAC_V5_SESSION_DIAGNOSTIC ||
         context->NegotiatedVersion != 0))
    {
        status = STATUS_ACCESS_DENIED;
    }
    else if (!Diagnostic &&
        (context->NegotiatedVersion != OAC_V5_VERSION ||
         Header == NULL ||
         Header->SessionId.High != session->SessionId.High ||
         Header->SessionId.Low != session->SessionId.Low ||
         Header->Generation != session->Generation))
    {
        status = STATUS_ACCESS_DENIED;
    }
    else if (!ExAcquireRundownProtection(&session->IoRundown))
    {
        status = STATUS_FILE_CLOSED;
    }
    else
    {
        Lease->Session = session;
        status = STATUS_SUCCESS;
    }
    OacUnlockShared(&extension->SessionLock);
    return status;
}

NTSTATUS OacSessionAcquireV5(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFILE_OBJECT FileObject,
    _In_ const OAC_V5_REQUEST_HEADER* Header,
    _Out_ POAC_SESSION_LEASE Lease)
{
    return OacSessionAcquireCore(
        DeviceObject,
        FileObject,
        Header,
        FALSE,
        FALSE,
        Lease);
}

NTSTATUS OacSessionAcquireV5Status(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFILE_OBJECT FileObject,
    _In_ const OAC_V5_REQUEST_HEADER* Header,
    _Out_ POAC_SESSION_LEASE Lease)
{
    return OacSessionAcquireCore(
        DeviceObject,
        FileObject,
        Header,
        FALSE,
        TRUE,
        Lease);
}

NTSTATUS OacSessionAcquireDiagnostic(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFILE_OBJECT FileObject,
    _Out_ POAC_SESSION_LEASE Lease)
{
    return OacSessionAcquireCore(
        DeviceObject,
        FileObject,
        NULL,
        TRUE,
        FALSE,
        Lease);
}

VOID OacSessionRelease(_Inout_ POAC_SESSION_LEASE Lease)
{
    POAC_SESSION session = (POAC_SESSION)Lease->Session;

    Lease->Session = NULL;
    if (session != NULL) ExReleaseRundownProtection(&session->IoRundown);
}

NTSTATUS OacSessionSnapshot(
    _In_ const OAC_SESSION_LEASE* Lease,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot)
{
    POAC_SESSION session = (POAC_SESSION)Lease->Session;
    POAC_DEVICE_EXTENSION extension;

    if (session == NULL) return STATUS_INVALID_PARAMETER;
    extension = OacExtension(session->DeviceObject);
    OacLockShared(&extension->SessionLock);
    Snapshot->SessionId = session->SessionId;
    Snapshot->Generation = session->Generation;
    Snapshot->State = session->State;
    Snapshot->RevokeReason = session->RevokeReason;
    Snapshot->ServiceProcessId = HandleToULong(session->ServiceProcessId);
    Snapshot->TargetProcessId = HandleToULong(session->TargetProcessId);
    OacUnlockShared(&extension->SessionLock);
    return STATUS_SUCCESS;
}

NTSTATUS OacSessionBindTarget(
    _In_ const OAC_SESSION_LEASE* Lease,
    _In_opt_ PEPROCESS TargetProcess,
    _In_opt_ HANDLE TargetProcessId)
{
    POAC_SESSION session = (POAC_SESSION)Lease->Session;
    POAC_DEVICE_EXTENSION extension;
    NTSTATUS status;

    if (session == NULL ||
        ((TargetProcess == NULL) != (TargetProcessId == NULL)))
    {
        return STATUS_INVALID_PARAMETER;
    }
    extension = OacExtension(session->DeviceObject);
    OacLockExclusive(&extension->SessionLock);
    if (session->Cleaned || extension->ActiveSession != session)
    {
        status = STATUS_FILE_CLOSED;
    }
    else if (session->TargetProcess != NULL &&
        session->TargetProcess != TargetProcess)
    {
        status = STATUS_INVALID_DEVICE_STATE;
    }
    else
    {
        if (TargetProcess != NULL && session->TargetProcess == NULL)
        {
            ObReferenceObject(TargetProcess);
            session->TargetProcess = TargetProcess;
        }
        session->TargetProcessId = TargetProcessId;
        status = STATUS_SUCCESS;
    }
    OacUnlockExclusive(&extension->SessionLock);
    return status;
}

BOOLEAN OacSessionIsControllerProcess(_In_ PEPROCESS Process)
{
    PDEVICE_OBJECT deviceObject = g_SessionDevice;
    POAC_DEVICE_EXTENSION extension;
    POAC_SESSION session;
    BOOLEAN matches = FALSE;

    if (deviceObject == NULL || Process == NULL) return FALSE;
    extension = OacExtension(deviceObject);
    OacLockShared(&extension->SessionLock);
    session = (POAC_SESSION)extension->ActiveSession;
    if (session != NULL && !session->Cleaned &&
        OacSessionAcceptsControl(session->State) &&
        session->ServiceProcess == Process)
    {
        matches = TRUE;
    }
    OacUnlockShared(&extension->SessionLock);
    return matches;
}

VOID OacSessionNotifyProcessExit(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId)
{
    PDEVICE_OBJECT deviceObject = g_SessionDevice;
    POAC_DEVICE_EXTENSION extension;
    POAC_SESSION session;
    PEPROCESS targetProcess = NULL;
    BOOLEAN releaseDeviceReference = FALSE;
    BOOLEAN releaseControlObjects = FALSE;

    if (deviceObject == NULL) return;
    extension = OacExtension(deviceObject);
    OacLockExclusive(&extension->SessionLock);
    session = (POAC_SESSION)extension->ActiveSession;
    if (session != NULL)
    {
        InterlockedIncrement(&session->References);
        if (session->ServiceProcess == Process)
        {
            session->ServiceExited = TRUE;
            releaseControlObjects = TRUE;
            if (session->State < OAC_V5_SESSION_REVOKED)
            {
                session->State = OAC_V5_SESSION_REVOKED;
                session->RevokeReason = OAC_V5_REVOKE_SERVICE_EXIT;
            }
        }
        if (session->TargetProcess == Process)
        {
            targetProcess = session->TargetProcess;
            session->TargetProcess = NULL;
            session->TargetProcessId = NULL;
            if (session->State < OAC_V5_SESSION_REVOKED)
            {
                session->State = OAC_V5_SESSION_REVOKED;
                session->RevokeReason = OAC_V5_REVOKE_TARGET_EXIT;
            }
        }
        OacRetireIfEligible(
            extension,
            session,
            &releaseDeviceReference);
    }
    OacUnlockExclusive(&extension->SessionLock);

    UNREFERENCED_PARAMETER(ProcessId);
    if (targetProcess != NULL) ObDereferenceObject(targetProcess);
    if (releaseControlObjects) OacReleaseControlObjects(session);
    if (releaseDeviceReference) OacSessionReleaseReference(session);
    if (session != NULL) OacSessionReleaseReference(session);
}
