#include "session.h"
#include "compat.h"
#include "evidence.h"
#include "protection.h"
#include "..\shared\protocol\oac_validate.h"

#include <bcrypt.h>

#define OAC_FILE_POOL_TAG 'fCaO'
#define OAC_SESSION_POOL_TAG 'sCaO'
#define OAC_FILE_CONTEXT_MAGIC 0x4643414FUL
#define OAC_TOKEN_GROUP_ENABLED 0x00000004UL
#define OAC_TOKEN_GROUP_DENY_ONLY 0x00000010UL
#define OAC_100NS_PER_MILLISECOND 10000ULL

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

typedef struct OAC_PENDING_LAUNCH_TAG
{
    OAC_LAUNCH_ID LaunchId;
    ULONGLONG ExpirationInterruptTime100ns;
    ULONG CanonicalNtPathLength;
    ULONG CanonicalDosDevicePathLength;
    WCHAR CanonicalNtPath[OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS];
    WCHAR CanonicalDosDevicePath[OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS];
} OAC_PENDING_LAUNCH, *POAC_PENDING_LAUNCH;

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
    ULONG ConfigurationFlags;
    OAC_V5_SCAN_ID LastCompletedScanId;
    OAC_PENDING_LAUNCH PendingLaunch;
    OAC_LAUNCH_ID BoundLaunchId;
    UCHAR ManifestSha256[OAC_V5_MANIFEST_DIGEST_SIZE];
    UCHAR BackendBindingSha256[OAC_V5_BACKEND_BINDING_DIGEST_SIZE];
    BOOLEAN Cleaned;
    BOOLEAN ServiceExited;
    BOOLEAN SessionLossRecorded;
    BOOLEAN EndpointScanInProgress;
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

static NTSTATUS OacGenerateLaunchId(_Out_ POAC_LAUNCH_ID LaunchId)
{
    NTSTATUS status;
    ULONG attempts;

    for (attempts = 0; attempts != 4; ++attempts)
    {
        status = BCryptGenRandom(
            NULL,
            (PUCHAR)LaunchId,
            sizeof(*LaunchId),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!NT_SUCCESS(status)) return status;
        if (LaunchId->High != 0 || LaunchId->Low != 0)
        {
            return STATUS_SUCCESS;
        }
    }
    return STATUS_UNSUCCESSFUL;
}

static BOOLEAN OacLaunchIdsEqual(
    _In_ const OAC_LAUNCH_ID* Left,
    _In_ const OAC_LAUNCH_ID* Right)
{
    return Left->High == Right->High && Left->Low == Right->Low;
}

static VOID OacClearPendingLaunch(_Inout_ POAC_SESSION Session)
{
    (VOID)RtlSecureZeroMemory(
        &Session->PendingLaunch,
        sizeof(Session->PendingLaunch));
}

static VOID OacClearBoundLaunch(_Inout_ POAC_SESSION Session)
{
    (VOID)RtlSecureZeroMemory(
        &Session->BoundLaunchId,
        sizeof(Session->BoundLaunchId));
}

static VOID OacClearLaunchState(_Inout_ POAC_SESSION Session)
{
    OacClearPendingLaunch(Session);
    OacClearBoundLaunch(Session);
}

static VOID OacFillSnapshotLocked(
    _In_ const OAC_SESSION* Session,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot)
{
    Snapshot->SessionId = Session->SessionId;
    Snapshot->Generation = Session->Generation;
    Snapshot->State = Session->State;
    Snapshot->RevokeReason = Session->RevokeReason;
    Snapshot->ServiceProcessId =
        (ULONGLONG)(ULONG_PTR)Session->ServiceProcessId;
    Snapshot->TargetProcessId =
        (ULONGLONG)(ULONG_PTR)Session->TargetProcessId;
    Snapshot->SessionLossSequence =
        OacExtension(Session->DeviceObject)->SessionLossSequence;
    Snapshot->LastSessionLossReason =
        OacExtension(Session->DeviceObject)->LastSessionLossReason;
    Snapshot->Mode = Session->Mode;
    Snapshot->ConfigurationFlags = Session->ConfigurationFlags;
    Snapshot->LastCompletedScanId = Session->LastCompletedScanId;
    RtlCopyMemory(
        Snapshot->ManifestSha256,
        Session->ManifestSha256,
        sizeof(Snapshot->ManifestSha256));
    RtlCopyMemory(
        Snapshot->BackendBindingSha256,
        Session->BackendBindingSha256,
        sizeof(Snapshot->BackendBindingSha256));
}

static BOOLEAN OacRecordSessionLossLocked(
    _Inout_ POAC_DEVICE_EXTENSION Extension,
    _Inout_ POAC_SESSION Session,
    _In_ OAC_V5_REVOKE_REASON RevokeReason)
{
    if (Session->SessionLossRecorded) return FALSE;
    if (Extension->SessionLossSequence != ~0ULL)
    {
        ++Extension->SessionLossSequence;
    }
    Extension->LastSessionLossReason = RevokeReason;
    Session->SessionLossRecorded = TRUE;
    return TRUE;
}

static VOID OacPublishSessionLoss(
    _In_ const OAC_V5_SESSION_ID* SessionId,
    _In_ ULONGLONG Generation,
    _In_ OAC_V5_REVOKE_REASON RevokeReason,
    _In_opt_ HANDLE ServiceProcessId)
{
    OacEvidencePublish(
        SessionId,
        Generation,
        OAC_V5_RULE_SESSION_LOST,
        OAC_V5_EVENT_REVOCATION,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_V5_POLICY_NOT_EVALUATED,
        OAC_V5_CONFIDENCE_HIGH,
        OAC_V5_CATEGORY_SERVICE,
        ServiceProcessId,
        NULL,
        NULL,
        RevokeReason,
        OAC_V5_EVIDENCE_KERNEL_SOURCE);
}

static VOID OacApplyEvidenceLossLocked(
    _Inout_ POAC_DEVICE_EXTENSION Extension,
    _Inout_ POAC_SESSION Session)
{
    /* Callback publishers only latch queue loss under the evidence spin lock.
     * Session operations apply the production revocation here, under the
     * existing session lock, so callbacks never wait on a push lock. */
    if (!OacEvidenceHasAlertLoss(
            &Session->SessionId,
            Session->Generation))
    {
        return;
    }
    if (Session->Mode == OAC_V5_SESSION_PRODUCTION &&
        Session->State < OAC_V5_SESSION_REVOKED)
    {
        OacClearLaunchState(Session);
        Session->State = OAC_V5_SESSION_REVOKED;
        Session->RevokeReason = OAC_V5_REVOKE_EVIDENCE_LOSS;
        OacRecordSessionLossLocked(
            Extension,
            Session,
            OAC_V5_REVOKE_EVIDENCE_LOSS);
    }
}

static VOID OacRevokeLaunchLocked(
    _Inout_ POAC_SESSION Session,
    _In_ OAC_V5_REVOKE_REASON RevokeReason)
{
    OacClearLaunchState(Session);
    if (Session->State < OAC_V5_SESSION_REVOKED)
    {
        Session->State = OAC_V5_SESSION_REVOKED;
        Session->RevokeReason = RevokeReason;
    }
}

static BOOLEAN OacExpirePendingLaunchLocked(
    _Inout_ POAC_SESSION Session,
    _In_ ULONGLONG Now100ns)
{
    if (Session->State == OAC_V5_SESSION_LAUNCH_PENDING &&
        Now100ns >= Session->PendingLaunch.ExpirationInterruptTime100ns)
    {
        OacRevokeLaunchLocked(Session, OAC_REVOKE_LAUNCH_EXPIRED);
        return TRUE;
    }
    return FALSE;
}

static VOID OacSessionReleaseReference(_Inout_ POAC_SESSION Session)
{
    if (InterlockedDecrement(&Session->References) == 0)
    {
        NT_ASSERT(Session->ControlFile == NULL);
        NT_ASSERT(Session->ServiceProcess == NULL);
        NT_ASSERT(Session->TargetProcess == NULL);
        OacClearLaunchState(Session);
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
        OacRecordSessionLossLocked(
            extension,
            session,
            OAC_V5_REVOKE_DRIVER_STOP);
        session->State = OAC_V5_SESSION_CLOSING;
        if (session->RevokeReason == OAC_V5_REVOKE_NONE)
        {
            session->RevokeReason = OAC_V5_REVOKE_DRIVER_STOP;
        }
        OacClearLaunchState(session);
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
    BOOLEAN publishSessionLoss = FALSE;
    OAC_V5_SESSION_ID evidenceSessionId = { 0 };
    ULONGLONG evidenceGeneration = 0;
    HANDLE serviceProcessId = NULL;

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
    publishSessionLoss = OacRecordSessionLossLocked(
        extension,
        session,
        OAC_V5_REVOKE_FILE_CLEANUP);
    if (publishSessionLoss)
    {
        evidenceSessionId = session->SessionId;
        evidenceGeneration = session->Generation;
        serviceProcessId = session->ServiceProcessId;
    }
    session->State = OAC_V5_SESSION_CLOSING;
    if (session->RevokeReason == OAC_V5_REVOKE_NONE)
    {
        session->RevokeReason = OAC_V5_REVOKE_FILE_CLEANUP;
    }
    OacClearLaunchState(session);
    OacRetireIfEligible(
        extension,
        session,
        &releaseDeviceReference);
    OacUnlockExclusive(&extension->SessionLock);

    if (publishSessionLoss)
    {
        OacPublishSessionLoss(
            &evidenceSessionId,
            evidenceGeneration,
            OAC_V5_REVOKE_FILE_CLEANUP,
            serviceProcessId);
    }

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
    _In_reads_opt_(OAC_V5_BACKEND_BINDING_DIGEST_SIZE)
        const UCHAR* BackendBindingSha256,
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
        if (!context->ServiceOwner || !OacIsServiceProcess() ||
            BackendBindingSha256 == NULL ||
            OacV5BufferIsZero(
                BackendBindingSha256,
                OAC_V5_BACKEND_BINDING_DIGEST_SIZE))
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
    if (Mode == OAC_V5_SESSION_PRODUCTION)
    {
        RtlCopyMemory(
            session->BackendBindingSha256,
            BackendBindingSha256,
            sizeof(session->BackendBindingSha256));
    }

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
        OacEvidenceBeginSession(
            &session->SessionId,
            session->Generation,
            session->Mode);
        Snapshot->SessionId = session->SessionId;
        Snapshot->Generation = session->Generation;
        Snapshot->State = session->State;
        Snapshot->ServiceProcessId =
            (ULONGLONG)(ULONG_PTR)session->ServiceProcessId;
        Snapshot->Mode = session->Mode;
        RtlCopyMemory(
            Snapshot->BackendBindingSha256,
            session->BackendBindingSha256,
            sizeof(Snapshot->BackendBindingSha256));
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

    OacLockExclusive(&extension->SessionLock);
    session = context->Session;
    if (session != NULL && extension->ActiveSession == session)
    {
        OacApplyEvidenceLossLocked(extension, session);
    }
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
    OacUnlockExclusive(&extension->SessionLock);
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

BOOLEAN OacSessionLeaseIsDiagnostic(
    _In_ const OAC_SESSION_LEASE* Lease)
{
    const POAC_SESSION session = Lease != NULL
        ? (POAC_SESSION)Lease->Session
        : NULL;
    return session != NULL &&
        session->Mode == OAC_V5_SESSION_DIAGNOSTIC;
}

NTSTATUS OacSessionSnapshot(
    _In_ const OAC_SESSION_LEASE* Lease,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot)
{
    POAC_SESSION session = (POAC_SESSION)Lease->Session;
    POAC_DEVICE_EXTENSION extension;

    if (session == NULL) return STATUS_INVALID_PARAMETER;
    extension = OacExtension(session->DeviceObject);
    OacLockExclusive(&extension->SessionLock);
    OacApplyEvidenceLossLocked(extension, session);
    (VOID)OacExpirePendingLaunchLocked(session, KeQueryInterruptTime());
    OacFillSnapshotLocked(session, Snapshot);
    OacUnlockExclusive(&extension->SessionLock);
    return STATUS_SUCCESS;
}

NTSTATUS OacSessionBeginEndpointScan(
    _In_ const OAC_SESSION_LEASE* Lease)
{
    POAC_SESSION session;
    POAC_DEVICE_EXTENSION extension;
    NTSTATUS status;

    if (Lease == NULL) return STATUS_INVALID_PARAMETER;
    session = (POAC_SESSION)Lease->Session;
    if (session == NULL) return STATUS_INVALID_PARAMETER;

    extension = OacExtension(session->DeviceObject);
    OacLockExclusive(&extension->SessionLock);
    OacApplyEvidenceLossLocked(extension, session);
    if (session->Cleaned || extension->ActiveSession != session)
    {
        status = STATUS_FILE_CLOSED;
    }
    else if (session->Mode != OAC_V5_SESSION_PRODUCTION)
    {
        status = STATUS_NOT_SUPPORTED;
    }
    else if (session->State != OAC_V5_SESSION_CLAIMED ||
        session->EndpointScanInProgress ||
        session->ConfigurationFlags != OAC_V5_CONFIG_FLAGS ||
        session->LastCompletedScanId != 0)
    {
        status = STATUS_INVALID_DEVICE_STATE;
    }
    else
    {
        session->EndpointScanInProgress = TRUE;
        status = STATUS_SUCCESS;
    }
    OacUnlockExclusive(&extension->SessionLock);
    return status;
}

NTSTATUS OacSessionFinishEndpointScan(
    _In_ const OAC_SESSION_LEASE* Lease,
    _In_ OAC_V5_SCAN_ID ScanId,
    _In_ BOOLEAN Complete,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot)
{
    POAC_SESSION session;
    POAC_DEVICE_EXTENSION extension;
    NTSTATUS status;

    if (Lease == NULL || Snapshot == NULL || (Complete && ScanId == 0))
        return STATUS_INVALID_PARAMETER;
    session = (POAC_SESSION)Lease->Session;
    if (session == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));

    extension = OacExtension(session->DeviceObject);
    OacLockExclusive(&extension->SessionLock);
    OacApplyEvidenceLossLocked(extension, session);
    if (session->Cleaned || extension->ActiveSession != session)
    {
        status = STATUS_FILE_CLOSED;
    }
    else if (session->Mode != OAC_V5_SESSION_PRODUCTION ||
        session->State != OAC_V5_SESSION_CLAIMED ||
        !session->EndpointScanInProgress)
    {
        status = STATUS_INVALID_DEVICE_STATE;
    }
    else
    {
        session->EndpointScanInProgress = FALSE;
        if (Complete)
        {
            session->LastCompletedScanId = ScanId;
        }
        else
        {
            session->ConfigurationFlags = 0;
            session->LastCompletedScanId = 0;
        }
        OacFillSnapshotLocked(session, Snapshot);
        status = STATUS_SUCCESS;
    }
    OacUnlockExclusive(&extension->SessionLock);
    return status;
}

NTSTATUS OacSessionConfigureEndpoint(
    _In_ const OAC_SESSION_LEASE* Lease,
    _In_ ULONG ConfigurationFlags,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot)
{
    POAC_SESSION session;
    POAC_DEVICE_EXTENSION extension;
    NTSTATUS status;

    if (Lease == NULL || Snapshot == NULL || ConfigurationFlags == 0 ||
        (ConfigurationFlags & ~OAC_V5_CONFIG_FLAGS) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    session = (POAC_SESSION)Lease->Session;
    if (session == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));

    extension = OacExtension(session->DeviceObject);
    OacLockExclusive(&extension->SessionLock);
    OacApplyEvidenceLossLocked(extension, session);
    if (session->Cleaned || extension->ActiveSession != session)
    {
        status = STATUS_FILE_CLOSED;
    }
    else if (session->Mode != OAC_V5_SESSION_PRODUCTION)
    {
        status = STATUS_NOT_SUPPORTED;
    }
    else if (session->State != OAC_V5_SESSION_CLAIMED ||
        session->EndpointScanInProgress ||
        session->ConfigurationFlags != 0 ||
        session->LastCompletedScanId != 0)
    {
        status = STATUS_INVALID_DEVICE_STATE;
    }
    else
    {
        session->ConfigurationFlags = ConfigurationFlags;
        OacFillSnapshotLocked(session, Snapshot);
        status = STATUS_SUCCESS;
    }
    OacUnlockExclusive(&extension->SessionLock);
    return status;
}

NTSTATUS OacSessionRevoke(
    _In_ const OAC_SESSION_LEASE* Lease,
    _In_ OAC_V5_REVOKE_REASON RevokeReason,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot,
    _Outptr_result_maybenull_ PEPROCESS* RevokedOwner)
{
    POAC_SESSION session;
    POAC_DEVICE_EXTENSION extension;
    NTSTATUS status;

    if (Lease == NULL || Snapshot == NULL || RevokedOwner == NULL ||
        RevokeReason != OAC_V5_REVOKE_REQUESTED)
    {
        return STATUS_INVALID_PARAMETER;
    }
    session = (POAC_SESSION)Lease->Session;
    if (session == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    *RevokedOwner = NULL;

    extension = OacExtension(session->DeviceObject);
    OacLockExclusive(&extension->SessionLock);
    OacApplyEvidenceLossLocked(extension, session);
    if (session->Cleaned || extension->ActiveSession != session)
    {
        status = STATUS_FILE_CLOSED;
    }
    else if (session->State == OAC_V5_SESSION_REVOKED)
    {
        OacFillSnapshotLocked(session, Snapshot);
        status = STATUS_SUCCESS;
    }
    else if (!OacSessionAcceptsControl(session->State))
    {
        status = STATUS_INVALID_DEVICE_STATE;
    }
    else
    {
        if (session->ServiceProcess != NULL)
        {
            ObReferenceObject(session->ServiceProcess);
            *RevokedOwner = session->ServiceProcess;
        }
        OacClearLaunchState(session);
        session->State = OAC_V5_SESSION_REVOKED;
        session->RevokeReason = RevokeReason;
        OacRecordSessionLossLocked(extension, session, RevokeReason);
        OacFillSnapshotLocked(session, Snapshot);
        status = STATUS_SUCCESS;
    }
    OacUnlockExclusive(&extension->SessionLock);
    return status;
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
    OacApplyEvidenceLossLocked(extension, session);
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

NTSTATUS OacSessionArmLaunch(
    _In_ const OAC_SESSION_LEASE* Lease,
    _In_ ULONG TimeToLiveMilliseconds,
    _In_reads_(OAC_V5_MANIFEST_DIGEST_SIZE) const UCHAR* ManifestSha256,
    _In_reads_(CanonicalNtPathLength) const WCHAR* CanonicalNtPath,
    _In_ ULONG CanonicalNtPathLength,
    _In_reads_(CanonicalDosDevicePathLength)
        const WCHAR* CanonicalDosDevicePath,
    _In_ ULONG CanonicalDosDevicePathLength,
    _Out_ POAC_LAUNCH_ID LaunchId,
    _Out_ PULONGLONG ExpirationInterruptTime100ns,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot)
{
    POAC_SESSION session;
    POAC_DEVICE_EXTENSION extension;
    OAC_LAUNCH_ID generatedId = { 0 };
    ULONGLONG now100ns;
    ULONGLONG expirationInterruptTime100ns;
    NTSTATUS status;

    if (Lease == NULL || LaunchId == NULL ||
        ExpirationInterruptTime100ns == NULL ||
        Snapshot == NULL || ManifestSha256 == NULL ||
        OacV5BufferIsZero(
            ManifestSha256,
            OAC_V5_MANIFEST_DIGEST_SIZE) || CanonicalNtPath == NULL ||
        CanonicalDosDevicePath == NULL ||
        TimeToLiveMilliseconds < OAC_LAUNCH_MIN_TTL_MS ||
        TimeToLiveMilliseconds > OAC_LAUNCH_MAX_TTL_MS ||
        CanonicalNtPathLength == 0 ||
        CanonicalNtPathLength >= OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS ||
        CanonicalDosDevicePathLength == 0 ||
        CanonicalDosDevicePathLength >=
            OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS)
    {
        return STATUS_INVALID_PARAMETER;
    }

    session = (POAC_SESSION)Lease->Session;
    if (session == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(LaunchId, sizeof(*LaunchId));
    *ExpirationInterruptTime100ns = 0;
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));

    status = OacGenerateLaunchId(&generatedId);
    if (!NT_SUCCESS(status))
    {
        (VOID)RtlSecureZeroMemory(&generatedId, sizeof(generatedId));
        return status;
    }
    now100ns = KeQueryInterruptTime();
    expirationInterruptTime100ns = now100ns +
        ((ULONGLONG)TimeToLiveMilliseconds * OAC_100NS_PER_MILLISECOND);
    if (expirationInterruptTime100ns <= now100ns)
    {
        (VOID)RtlSecureZeroMemory(&generatedId, sizeof(generatedId));
        return STATUS_INTEGER_OVERFLOW;
    }

    extension = OacExtension(session->DeviceObject);
    OacLockExclusive(&extension->SessionLock);
    OacApplyEvidenceLossLocked(extension, session);
    if (session->Cleaned || extension->ActiveSession != session)
    {
        status = STATUS_FILE_CLOSED;
    }
    else if (session->Mode != OAC_V5_SESSION_PRODUCTION)
    {
        status = STATUS_NOT_SUPPORTED;
    }
    else if (session->State != OAC_V5_SESSION_CLAIMED)
    {
        status = STATUS_INVALID_DEVICE_STATE;
    }
    else if (session->EndpointScanInProgress ||
        session->LastCompletedScanId == 0 ||
        session->ConfigurationFlags != OAC_V5_CONFIG_FLAGS ||
        OacDriverGateTrips() != 0)
    {
        status = STATUS_INVALID_DEVICE_STATE;
    }
    else
    {
        OacClearLaunchState(session);
        RtlCopyMemory(
            session->ManifestSha256,
            ManifestSha256,
            sizeof(session->ManifestSha256));
        session->PendingLaunch.LaunchId = generatedId;
        session->PendingLaunch.ExpirationInterruptTime100ns =
            expirationInterruptTime100ns;
        session->PendingLaunch.CanonicalNtPathLength =
            CanonicalNtPathLength;
        session->PendingLaunch.CanonicalDosDevicePathLength =
            CanonicalDosDevicePathLength;
        RtlCopyMemory(
            session->PendingLaunch.CanonicalNtPath,
            CanonicalNtPath,
            CanonicalNtPathLength * sizeof(WCHAR));
        RtlCopyMemory(
            session->PendingLaunch.CanonicalDosDevicePath,
            CanonicalDosDevicePath,
            CanonicalDosDevicePathLength * sizeof(WCHAR));
        session->State = OAC_V5_SESSION_LAUNCH_PENDING;
        *LaunchId = generatedId;
        *ExpirationInterruptTime100ns = expirationInterruptTime100ns;
        OacFillSnapshotLocked(session, Snapshot);
        status = STATUS_SUCCESS;
    }
    OacUnlockExclusive(&extension->SessionLock);
    (VOID)RtlSecureZeroMemory(&generatedId, sizeof(generatedId));
    return status;
}

NTSTATUS OacSessionCancelLaunch(
    _In_ const OAC_SESSION_LEASE* Lease,
    _In_ const OAC_LAUNCH_ID* LaunchId,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot)
{
    POAC_SESSION session;
    POAC_DEVICE_EXTENSION extension;
    NTSTATUS status;

    if (Lease == NULL || LaunchId == NULL || Snapshot == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    session = (POAC_SESSION)Lease->Session;
    if (session == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));

    extension = OacExtension(session->DeviceObject);
    OacLockExclusive(&extension->SessionLock);
    OacApplyEvidenceLossLocked(extension, session);
    if (session->Cleaned || extension->ActiveSession != session)
    {
        status = STATUS_FILE_CLOSED;
    }
    else if (session->Mode != OAC_V5_SESSION_PRODUCTION)
    {
        status = STATUS_NOT_SUPPORTED;
    }
    else if (OacExpirePendingLaunchLocked(
        session,
        KeQueryInterruptTime()))
    {
        status = STATUS_TIMEOUT;
    }
    else if (session->State != OAC_V5_SESSION_LAUNCH_PENDING)
    {
        status = STATUS_INVALID_DEVICE_STATE;
    }
    else if (!OacLaunchIdsEqual(
        &session->PendingLaunch.LaunchId,
        LaunchId))
    {
        status = STATUS_ACCESS_DENIED;
    }
    else
    {
        OacRevokeLaunchLocked(
            session,
            OAC_REVOKE_LAUNCH_CANCELLED);
        OacFillSnapshotLocked(session, Snapshot);
        status = STATUS_SUCCESS;
    }
    OacUnlockExclusive(&extension->SessionLock);
    return status;
}

NTSTATUS OacSessionConfirmTarget(
    _In_ const OAC_SESSION_LEASE* Lease,
    _In_ const OAC_LAUNCH_ID* LaunchId,
    _In_ ULONGLONG TargetProcessHandle,
    _Out_ POAC_SESSION_SNAPSHOT Snapshot)
{
    POAC_SESSION session;
    POAC_DEVICE_EXTENSION extension;
    PEPROCESS targetProcess = NULL;
    NTSTATUS referenceStatus;
    NTSTATUS status;

    if (Lease == NULL || LaunchId == NULL || Snapshot == NULL ||
        TargetProcessHandle == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    session = (POAC_SESSION)Lease->Session;
    if (session == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));

    referenceStatus = ObReferenceObjectByHandle(
        (HANDLE)(ULONG_PTR)TargetProcessHandle,
        0,
        *PsProcessType,
        UserMode,
        (PVOID*)&targetProcess,
        NULL);

    extension = OacExtension(session->DeviceObject);
    OacLockExclusive(&extension->SessionLock);
    OacApplyEvidenceLossLocked(extension, session);
    if (session->Cleaned || extension->ActiveSession != session)
    {
        status = STATUS_FILE_CLOSED;
    }
    else if (session->Mode != OAC_V5_SESSION_PRODUCTION)
    {
        status = STATUS_NOT_SUPPORTED;
    }
    else if (session->State != OAC_V5_SESSION_TARGET_BOUND)
    {
        status = STATUS_INVALID_DEVICE_STATE;
    }
    else if (!NT_SUCCESS(referenceStatus) ||
        !OacLaunchIdsEqual(&session->BoundLaunchId, LaunchId) ||
        session->TargetProcess != targetProcess)
    {
        OacRevokeLaunchLocked(
            session,
            OAC_REVOKE_TARGET_CONFIRMATION_FAILED);
        status = NT_SUCCESS(referenceStatus)
            ? STATUS_ACCESS_DENIED
            : referenceStatus;
    }
    else
    {
        OacClearBoundLaunch(session);
        session->State = OAC_V5_SESSION_MONITORING;
        OacFillSnapshotLocked(session, Snapshot);
        status = STATUS_SUCCESS;
    }
    OacUnlockExclusive(&extension->SessionLock);

    if (targetProcess != NULL) ObDereferenceObject(targetProcess);
    return status;
}

static BOOLEAN OacStoredPathMatches(
    _In_reads_(ExpectedPathLength) const WCHAR* ExpectedPath,
    _In_ ULONG ExpectedPathLength,
    _In_ PCUNICODE_STRING ImageFileName)
{
    UNICODE_STRING expectedPath;
    ULONG expectedLength = ExpectedPathLength * sizeof(WCHAR);

    if (expectedLength > MAXUSHORT ||
        ImageFileName->Length != (USHORT)expectedLength)
    {
        return FALSE;
    }
    expectedPath.Buffer = (PWCH)ExpectedPath;
    expectedPath.Length = (USHORT)expectedLength;
    expectedPath.MaximumLength = (USHORT)expectedLength;
    return RtlEqualUnicodeString(&expectedPath, ImageFileName, TRUE);
}

static BOOLEAN OacDosDevicePathMatches(
    _In_ const OAC_SESSION* Session,
    _In_ PCUNICODE_STRING ImageFileName)
{
    const WCHAR* expected = Session->PendingLaunch.CanonicalDosDevicePath;
    ULONG expectedCharacters =
        Session->PendingLaunch.CanonicalDosDevicePathLength;
    ULONG observedCharacters = ImageFileName->Length / sizeof(WCHAR);
    UNICODE_STRING expectedSuffix;
    UNICODE_STRING observedSuffix;

    if (OacStoredPathMatches(
            expected,
            expectedCharacters,
            ImageFileName))
    {
        return TRUE;
    }
    if ((ImageFileName->Length % sizeof(WCHAR)) != 0 ||
        expectedCharacters <= 4)
    {
        return FALSE;
    }

    expectedSuffix.Buffer = (PWCH)&expected[4];
    expectedSuffix.Length = (USHORT)(
        (expectedCharacters - 4) * sizeof(WCHAR));
    expectedSuffix.MaximumLength = expectedSuffix.Length;
    observedSuffix = *ImageFileName;
    if (observedCharacters == expectedCharacters &&
        ImageFileName->Buffer[0] == L'\\' &&
        ImageFileName->Buffer[1] == L'\\' &&
        ImageFileName->Buffer[2] == L'?' &&
        ImageFileName->Buffer[3] == L'\\')
    {
        observedSuffix.Buffer = &ImageFileName->Buffer[4];
        observedSuffix.Length = (USHORT)(
            (observedCharacters - 4) * sizeof(WCHAR));
        observedSuffix.MaximumLength = observedSuffix.Length;
    }
    else if (observedCharacters != expectedCharacters - 4)
    {
        return FALSE;
    }
    return RtlEqualUnicodeString(&expectedSuffix, &observedSuffix, TRUE);
}

static BOOLEAN OacPendingPathMatches(
    _In_ const OAC_SESSION* Session,
    _In_opt_ PCUNICODE_STRING ImageFileName)
{
    if (ImageFileName == NULL || ImageFileName->Buffer == NULL)
    {
        return FALSE;
    }
    /* PS_CREATE_NOTIFY_INFO may expose the exact image-open name in either
     * volume-device or DOS-device form. Both expected spellings come from the
     * same service-locked file handle and are compared case-insensitively. */
    return OacStoredPathMatches(
            Session->PendingLaunch.CanonicalNtPath,
            Session->PendingLaunch.CanonicalNtPathLength,
            ImageFileName) ||
        OacDosDevicePathMatches(Session, ImageFileName);
}

OAC_SESSION_PROCESS_CREATE_RESULT OacSessionNotifyProcessCreate(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PEPROCESS CreatorProcess,
    _In_ HANDLE CreatorProcessId,
    _In_opt_ PCUNICODE_STRING ImageFileName,
    _In_ BOOLEAN FileOpenNameAvailable)
{
    PDEVICE_OBJECT deviceObject = g_SessionDevice;
    POAC_DEVICE_EXTENSION extension;
    POAC_SESSION session;
    OAC_LAUNCH_DECISION decision;
    OAC_SESSION_PROCESS_CREATE_RESULT result =
        OacSessionProcessCreateIgnored;
    BOOLEAN creatorMatches;
    BOOLEAN nameAvailable;
    BOOLEAN pathMatches;

    if (deviceObject == NULL || Process == NULL || CreatorProcess == NULL)
    {
        return OacSessionProcessCreateIgnored;
    }
    extension = OacExtension(deviceObject);
    OacLockExclusive(&extension->SessionLock);
    session = (POAC_SESSION)extension->ActiveSession;
    if (session == NULL)
    {
        OacUnlockExclusive(&extension->SessionLock);
        return OacSessionProcessCreateIgnored;
    }
    OacApplyEvidenceLossLocked(extension, session);

    creatorMatches = !session->Cleaned && !session->ServiceExited &&
        session->ServiceProcess == CreatorProcess &&
        session->ServiceProcessId == CreatorProcessId;
    nameAvailable = FileOpenNameAvailable && ImageFileName != NULL &&
        ImageFileName->Buffer != NULL;
    pathMatches = nameAvailable && OacPendingPathMatches(
        session,
        ImageFileName);
    decision = OacDecideLaunchCandidate(
        session->State,
        KeQueryInterruptTime(),
        session->PendingLaunch.ExpirationInterruptTime100ns,
        creatorMatches,
        nameAvailable,
        pathMatches);

    if (decision == OAC_LAUNCH_CONSUME_BIND)
    {
        if (session->TargetProcess != NULL)
        {
            OacRevokeLaunchLocked(
                session,
                OAC_REVOKE_LAUNCH_MISMATCH);
            result = OacSessionProcessCreateDenied;
        }
        else
        {
            ObReferenceObject(Process);
            session->TargetProcess = Process;
            session->TargetProcessId = ProcessId;
            session->BoundLaunchId = session->PendingLaunch.LaunchId;
            OacClearPendingLaunch(session);
            session->State = OAC_V5_SESSION_TARGET_BOUND;
            result = OacSessionProcessCreateBound;
        }
    }
    else if (decision == OAC_LAUNCH_REVOKE_EXPIRED)
    {
        OacRevokeLaunchLocked(session, OAC_REVOKE_LAUNCH_EXPIRED);
        result = OacSessionProcessCreateDenied;
    }
    else if (decision == OAC_LAUNCH_REVOKE_MISMATCH)
    {
        OacRevokeLaunchLocked(session, OAC_REVOKE_LAUNCH_MISMATCH);
        result = OacSessionProcessCreateDenied;
    }
    else if (decision == OAC_LAUNCH_DENY_SERVICE_CREATION_AFTER_BIND)
    {
        result = OacSessionProcessCreateDenied;
    }
    OacUnlockExclusive(&extension->SessionLock);
    return result;
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
        (session->Mode != OAC_V5_SESSION_PRODUCTION ||
         !OacEvidenceHasAlertLoss(
             &session->SessionId,
             session->Generation)) &&
        OacSessionAcceptsControl(session->State) &&
        session->ServiceProcess == Process)
    {
        matches = TRUE;
    }
    OacUnlockShared(&extension->SessionLock);
    return matches;
}

BOOLEAN OacSessionIsTargetProcess(_In_ PEPROCESS Process)
{
    OAC_V5_SESSION_ID sessionId;
    ULONGLONG generation;

    return OacSessionCaptureTargetEvidenceIdentity(
        Process,
        NULL,
        &sessionId,
        &generation);
}

ULONG OacSessionConfigurationFlags(VOID)
{
    PDEVICE_OBJECT deviceObject = g_SessionDevice;
    POAC_DEVICE_EXTENSION extension;
    POAC_SESSION session;
    ULONG flags = 0;

    if (deviceObject == NULL) return 0;
    extension = OacExtension(deviceObject);
    OacLockShared(&extension->SessionLock);
    session = (POAC_SESSION)extension->ActiveSession;
    if (session != NULL && !session->Cleaned &&
        session->Mode == OAC_V5_SESSION_PRODUCTION)
    {
        flags = session->ConfigurationFlags;
    }
    OacUnlockShared(&extension->SessionLock);
    return flags;
}

BOOLEAN OacSessionCaptureEvidenceIdentity(
    _Out_ POAC_V5_SESSION_ID SessionId,
    _Out_ PULONGLONG Generation)
{
    PDEVICE_OBJECT deviceObject = g_SessionDevice;
    POAC_DEVICE_EXTENSION extension;
    POAC_SESSION session;
    BOOLEAN captured = FALSE;

    if (SessionId == NULL || Generation == NULL)
        return FALSE;
    RtlZeroMemory(SessionId, sizeof(*SessionId));
    *Generation = 0;
    if (deviceObject == NULL) return FALSE;

    extension = OacExtension(deviceObject);
    OacLockShared(&extension->SessionLock);
    session = (POAC_SESSION)extension->ActiveSession;
    if (session != NULL && !session->Cleaned)
    {
        *SessionId = session->SessionId;
        *Generation = session->Generation;
        captured = TRUE;
    }
    OacUnlockShared(&extension->SessionLock);
    return captured;
}

BOOLEAN OacSessionCaptureTargetEvidenceIdentity(
    _In_opt_ PEPROCESS Process,
    _In_opt_ HANDLE ProcessId,
    _Out_ POAC_V5_SESSION_ID SessionId,
    _Out_ PULONGLONG Generation)
{
    PDEVICE_OBJECT deviceObject = g_SessionDevice;
    POAC_DEVICE_EXTENSION extension;
    POAC_SESSION session;
    BOOLEAN matches = FALSE;

    if (SessionId == NULL || Generation == NULL)
        return FALSE;
    RtlZeroMemory(SessionId, sizeof(*SessionId));
    *Generation = 0;
    if (deviceObject == NULL || (Process == NULL && ProcessId == NULL))
        return FALSE;

    extension = OacExtension(deviceObject);
    OacLockShared(&extension->SessionLock);
    session = (POAC_SESSION)extension->ActiveSession;
    if (session != NULL && session->TargetProcess != NULL &&
        (Process == NULL || session->TargetProcess == Process) &&
        (ProcessId == NULL || session->TargetProcessId == ProcessId))
    {
        *SessionId = session->SessionId;
        *Generation = session->Generation;
        matches = TRUE;
    }
    OacUnlockShared(&extension->SessionLock);
    return matches;
}

HANDLE OacSessionTargetProcessId(VOID)
{
    PDEVICE_OBJECT deviceObject = g_SessionDevice;
    POAC_DEVICE_EXTENSION extension;
    POAC_SESSION session;
    HANDLE processId = NULL;

    if (deviceObject == NULL) return NULL;
    extension = OacExtension(deviceObject);
    OacLockShared(&extension->SessionLock);
    session = (POAC_SESSION)extension->ActiveSession;
    if (session != NULL && session->TargetProcess != NULL)
    {
        processId = session->TargetProcessId;
    }
    OacUnlockShared(&extension->SessionLock);
    return processId;
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
    BOOLEAN publishSessionLoss = FALSE;
    OAC_V5_SESSION_ID evidenceSessionId = { 0 };
    ULONGLONG evidenceGeneration = 0;

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
            publishSessionLoss = OacRecordSessionLossLocked(
                extension,
                session,
                OAC_V5_REVOKE_SERVICE_EXIT);
            if (publishSessionLoss)
            {
                evidenceSessionId = session->SessionId;
                evidenceGeneration = session->Generation;
            }
            OacClearLaunchState(session);
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
            OacClearLaunchState(session);
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

    if (publishSessionLoss)
    {
        OacPublishSessionLoss(
            &evidenceSessionId,
            evidenceGeneration,
            OAC_V5_REVOKE_SERVICE_EXIT,
            ProcessId);
    }

    if (targetProcess != NULL) ObDereferenceObject(targetProcess);
    if (releaseControlObjects) OacReleaseControlObjects(session);
    if (releaseDeviceReference) OacSessionReleaseReference(session);
    if (session != NULL) OacSessionReleaseReference(session);
}
