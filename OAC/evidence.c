#include "evidence.h"

#include "compat.h"
#include "scanner.h"
#include "..\shared\protocol\oac_validate.h"

#include <bcrypt.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, OacEvidenceManageSnapshot)
#endif

#define OAC_ALERT_CAPACITY 32UL
#define OAC_EVENT_CAPACITY 256UL
#define OAC_EVIDENCE_POOL_TAG 'eCaO'
#define OAC_SNAPSHOT_LIFETIME_100NS (30ULL * 1000ULL * 1000ULL * 10ULL)

typedef struct OAC_EVIDENCE_QUEUE_TAG
{
    KSPIN_LOCK Lock;
    POAC_V5_EVENT_RECORD Records;
    ULONG Capacity;
    ULONG Head;
    ULONG Count;
    OAC_V5_SESSION_ID SessionId;
    ULONGLONG Generation;
    ULONGLONG PublishedSequence;
    ULONGLONG AcknowledgedSequence;
    ULONGLONG HighestDeliveredSequence;
    ULONGLONG DroppedCount;
    ULONGLONG FirstLostSequence;
    ULONGLONG LostHighCount;
    ULONGLONG LostCriticalCount;
    BOOLEAN Active;
    BOOLEAN LossLatched;
} OAC_EVIDENCE_QUEUE, *POAC_EVIDENCE_QUEUE;

typedef struct OAC_SNAPSHOT_STATE_TAG
{
    EX_PUSH_LOCK Lock;
    OAC_V5_SESSION_ID SessionId;
    ULONGLONG Generation;
    OAC_SNAPSHOT_ID SnapshotId;
    OAC_V5_SCAN_ID ScanId;
    ULONGLONG CreatedTimestamp100ns;
    ULONGLONG ExpirationInterruptTime100ns;
    ULONGLONG CursorGeneration;
    ULONG SnapshotType;
    ULONG State;
    ULONG TotalItems;
    ULONG AvailableItems;
    BOOLEAN Truncated;
    NTSTATUS FailureStatus;
    POAC_SNAPSHOT_RECORD Records;
} OAC_SNAPSHOT_STATE, *POAC_SNAPSHOT_STATE;

typedef struct OAC_EVIDENCE_STATE_TAG
{
    OAC_EVIDENCE_QUEUE Alerts;
    OAC_EVIDENCE_QUEUE Events;
    OAC_SNAPSHOT_STATE Snapshot;
    volatile LONG64 NextScanId;
    volatile LONG64 NextCursorGeneration;
} OAC_EVIDENCE_STATE;

static OAC_EVIDENCE_STATE g_Evidence;

static VOID OacLockSnapshotExclusive(_Inout_ PEX_PUSH_LOCK Lock)
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(Lock);
}

static VOID OacUnlockSnapshotExclusive(_Inout_ PEX_PUSH_LOCK Lock)
{
    ExReleasePushLockExclusive(Lock);
    KeLeaveCriticalRegion();
}

static BOOLEAN OacEvidenceIdentityMatches(
    _In_ const OAC_V5_SESSION_ID* Left,
    _In_ ULONGLONG LeftGeneration,
    _In_ const OAC_V5_SESSION_ID* Right,
    _In_ ULONGLONG RightGeneration)
{
    return OacV5SessionIdEqual(Left, Right) &&
        LeftGeneration == RightGeneration;
}

static VOID OacResetQueueLocked(
    _Inout_ POAC_EVIDENCE_QUEUE Queue,
    _In_ const OAC_V5_SESSION_ID* SessionId,
    _In_ ULONGLONG Generation)
{
    if (Queue->Records != NULL)
    {
        RtlZeroMemory(
            Queue->Records,
            sizeof(*Queue->Records) * Queue->Capacity);
    }
    Queue->Head = 0;
    Queue->Count = 0;
    Queue->SessionId = *SessionId;
    Queue->Generation = Generation;
    Queue->PublishedSequence = 0;
    Queue->AcknowledgedSequence = 0;
    Queue->HighestDeliveredSequence = 0;
    Queue->DroppedCount = 0;
    Queue->FirstLostSequence = 0;
    Queue->LostHighCount = 0;
    Queue->LostCriticalCount = 0;
    Queue->Active = TRUE;
    Queue->LossLatched = FALSE;
}

static VOID OacFreeSnapshotRecordsLocked(_Inout_ POAC_SNAPSHOT_STATE Snapshot)
{
    if (Snapshot->Records != NULL)
    {
        OacReleaseKernelModuleSnapshot(Snapshot->Records);
        Snapshot->Records = NULL;
    }
}

static VOID OacResetSnapshotLocked(
    _Inout_ POAC_SNAPSHOT_STATE Snapshot,
    _In_ const OAC_V5_SESSION_ID* SessionId,
    _In_ ULONGLONG Generation)
{
    OacFreeSnapshotRecordsLocked(Snapshot);
    Snapshot->SessionId = *SessionId;
    Snapshot->Generation = Generation;
    RtlZeroMemory(
        &Snapshot->SnapshotId,
        sizeof(*Snapshot) - FIELD_OFFSET(OAC_SNAPSHOT_STATE, SnapshotId));
}

static NTSTATUS OacGenerateSnapshotId(_Out_ POAC_SNAPSHOT_ID SnapshotId)
{
    NTSTATUS status;
    ULONG attempt;

    for (attempt = 0; attempt < 4; ++attempt)
    {
        status = BCryptGenRandom(
            NULL,
            (PUCHAR)SnapshotId,
            sizeof(*SnapshotId),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!NT_SUCCESS(status)) return status;
        if (!OacSnapshotIdIsZero(SnapshotId)) return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;
}

static ULONGLONG OacNextPositiveCounter(_Inout_ volatile LONG64* Counter)
{
    const LONG64 value = InterlockedIncrement64(Counter);
    return value > 0 ? (ULONGLONG)value : 0;
}

NTSTATUS OacEvidenceInitialize(VOID)
{
    RtlZeroMemory(&g_Evidence, sizeof(g_Evidence));
    KeInitializeSpinLock(&g_Evidence.Alerts.Lock);
    KeInitializeSpinLock(&g_Evidence.Events.Lock);
    ExInitializePushLock(&g_Evidence.Snapshot.Lock);
    g_Evidence.Alerts.Capacity = OAC_ALERT_CAPACITY;
    g_Evidence.Events.Capacity = OAC_EVENT_CAPACITY;
    g_Evidence.Alerts.Records = (POAC_V5_EVENT_RECORD)OacAllocatePool(
        FALSE,
        sizeof(OAC_V5_EVENT_RECORD) * OAC_ALERT_CAPACITY,
        OAC_EVIDENCE_POOL_TAG);
    if (g_Evidence.Alerts.Records == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    g_Evidence.Events.Records = (POAC_V5_EVENT_RECORD)OacAllocatePool(
        FALSE,
        sizeof(OAC_V5_EVENT_RECORD) * OAC_EVENT_CAPACITY,
        OAC_EVIDENCE_POOL_TAG);
    if (g_Evidence.Events.Records == NULL)
    {
        ExFreePoolWithTag(g_Evidence.Alerts.Records, OAC_EVIDENCE_POOL_TAG);
        g_Evidence.Alerts.Records = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(
        g_Evidence.Alerts.Records,
        sizeof(OAC_V5_EVENT_RECORD) * OAC_ALERT_CAPACITY);
    RtlZeroMemory(
        g_Evidence.Events.Records,
        sizeof(OAC_V5_EVENT_RECORD) * OAC_EVENT_CAPACITY);
    return STATUS_SUCCESS;
}

VOID OacEvidenceShutdown(VOID)
{
    POAC_V5_EVENT_RECORD alerts;
    POAC_V5_EVENT_RECORD events;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_Evidence.Alerts.Lock, &oldIrql);
    alerts = g_Evidence.Alerts.Records;
    g_Evidence.Alerts.Records = NULL;
    g_Evidence.Alerts.Active = FALSE;
    KeReleaseSpinLock(&g_Evidence.Alerts.Lock, oldIrql);

    KeAcquireSpinLock(&g_Evidence.Events.Lock, &oldIrql);
    events = g_Evidence.Events.Records;
    g_Evidence.Events.Records = NULL;
    g_Evidence.Events.Active = FALSE;
    KeReleaseSpinLock(&g_Evidence.Events.Lock, oldIrql);

    OacLockSnapshotExclusive(&g_Evidence.Snapshot.Lock);
    OacFreeSnapshotRecordsLocked(&g_Evidence.Snapshot);
    OacUnlockSnapshotExclusive(&g_Evidence.Snapshot.Lock);

    if (alerts != NULL) ExFreePoolWithTag(alerts, OAC_EVIDENCE_POOL_TAG);
    if (events != NULL) ExFreePoolWithTag(events, OAC_EVIDENCE_POOL_TAG);
}

VOID OacEvidenceBeginSession(
    _In_ const OAC_V5_SESSION_ID* SessionId,
    _In_ ULONGLONG Generation,
    _In_ ULONG SessionMode)
{
    KIRQL oldIrql;

    if (SessionId == NULL || OacV5SessionIdIsZero(SessionId) ||
        Generation == 0)
    {
        return;
    }
    KeAcquireSpinLock(&g_Evidence.Alerts.Lock, &oldIrql);
    OacResetQueueLocked(
        &g_Evidence.Alerts,
        SessionId,
        Generation);
    KeReleaseSpinLock(&g_Evidence.Alerts.Lock, oldIrql);

    KeAcquireSpinLock(&g_Evidence.Events.Lock, &oldIrql);
    OacResetQueueLocked(
        &g_Evidence.Events,
        SessionId,
        Generation);
    KeReleaseSpinLock(&g_Evidence.Events.Lock, oldIrql);

    OacLockSnapshotExclusive(&g_Evidence.Snapshot.Lock);
    OacResetSnapshotLocked(&g_Evidence.Snapshot, SessionId, Generation);
    OacUnlockSnapshotExclusive(&g_Evidence.Snapshot.Lock);

    OacEvidencePublish(
        SessionId,
        Generation,
        OAC_V5_RULE_SESSION_CLAIMED,
        OAC_V5_EVENT_SESSION_STATE_CHANGED,
        OAC_V5_OBSERVATION_INFO,
        OAC_V5_POLICY_NOT_EVALUATED,
        OAC_V5_CONFIDENCE_HIGH,
        OAC_V5_CATEGORY_SERVICE,
        PsGetCurrentProcessId(),
        PsGetCurrentThreadId(),
        NULL,
        SessionMode,
        OAC_V5_EVIDENCE_KERNEL_SOURCE);
}

BOOLEAN OacEvidenceHasAlertLoss(
    _In_ const OAC_V5_SESSION_ID* SessionId,
    _In_ ULONGLONG Generation)
{
    BOOLEAN lost = FALSE;
    KIRQL oldIrql;

    if (SessionId == NULL || Generation == 0) return FALSE;
    KeAcquireSpinLock(&g_Evidence.Alerts.Lock, &oldIrql);
    if (g_Evidence.Alerts.Active &&
        OacEvidenceIdentityMatches(
            &g_Evidence.Alerts.SessionId,
            g_Evidence.Alerts.Generation,
            SessionId,
            Generation))
    {
        lost = g_Evidence.Alerts.LossLatched;
    }
    KeReleaseSpinLock(&g_Evidence.Alerts.Lock, oldIrql);
    return lost;
}

VOID OacEvidencePublish(
    _In_ const OAC_V5_SESSION_ID* ExpectedSessionId,
    _In_ ULONGLONG ExpectedGeneration,
    _In_ OAC_V5_RULE_ID RuleId,
    _In_ OAC_V5_EVENT_TYPE EventType,
    _In_ OAC_V5_OBSERVATION_SEVERITY ObservationSeverity,
    _In_ OAC_V5_POLICY_SEVERITY PolicySeverity,
    _In_ OAC_V5_CONFIDENCE Confidence,
    _In_ OAC_V5_CATEGORY Category,
    _In_opt_ HANDLE ProcessId,
    _In_opt_ HANDLE ThreadId,
    _In_opt_ PVOID Address,
    _In_ ULONGLONG Auxiliary,
    _In_ ULONGLONG EvidenceFlags)
{
    OAC_V5_EVENT_RECORD record;
    POAC_EVIDENCE_QUEUE queue;
    LARGE_INTEGER now = { 0 };
    KIRQL oldIrql;
    ULONG index;
    BOOLEAN alert;

    if (ExpectedSessionId == NULL || ExpectedGeneration == 0 ||
        OacV5SessionIdIsZero(ExpectedSessionId) ||
        !OacV5RuleIdValid(RuleId) || !OacV5EventTypeValid(EventType) ||
        !OacV5ObservationSeverityValid(ObservationSeverity) ||
        !OacV5PolicySeverityValid(PolicySeverity) ||
        !OacV5ConfidenceValid(Confidence) || !OacV5CategoryValid(Category) ||
        (EvidenceFlags & ~OAC_V5_EVIDENCE_FLAGS) != 0 ||
        (EventType == OAC_V5_EVENT_POLICY_VIOLATION &&
         PolicySeverity == OAC_V5_POLICY_NOT_EVALUATED))
    {
        return;
    }
    alert = ObservationSeverity >= OAC_V5_OBSERVATION_HIGH ||
        PolicySeverity >= OAC_V5_POLICY_HIGH;
    queue = alert ? &g_Evidence.Alerts : &g_Evidence.Events;

    RtlZeroMemory(&record, sizeof(record));
    KeQuerySystemTime(&now);
    record.Version = OAC_V5_VERSION;
    record.Size = sizeof(record);
    record.RuleId = RuleId;
    record.EventType = EventType;
    record.ObservationSeverity = ObservationSeverity;
    record.PolicySeverity = PolicySeverity;
    record.Confidence = Confidence;
    record.Category = Category;
    record.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
    record.ThreadId = (ULONGLONG)(ULONG_PTR)ThreadId;
    record.Address = (ULONGLONG)(ULONG_PTR)Address;
    record.Auxiliary = Auxiliary;
    record.EvidenceFlags = EvidenceFlags;
    record.Timestamp100ns = (ULONGLONG)now.QuadPart;
    record.OccurrenceCount = 1;
    record.FirstOccurrence100ns = record.Timestamp100ns;
    record.LastOccurrence100ns = record.Timestamp100ns;

    KeAcquireSpinLock(&queue->Lock, &oldIrql);
    if (!queue->Active || queue->Records == NULL ||
        !OacEvidenceIdentityMatches(
            &queue->SessionId,
            queue->Generation,
            ExpectedSessionId,
            ExpectedGeneration))
    {
        KeReleaseSpinLock(&queue->Lock, oldIrql);
        return;
    }
    record.SessionId = queue->SessionId;
    record.Generation = queue->Generation;
    record.Sequence = ++queue->PublishedSequence;
    if (queue->Count == queue->Capacity)
    {
        if (alert)
        {
            ++queue->DroppedCount;
            if (!queue->LossLatched)
            {
                queue->LossLatched = TRUE;
                queue->FirstLostSequence = record.Sequence;
            }
            if (ObservationSeverity == OAC_V5_OBSERVATION_CRITICAL ||
                PolicySeverity == OAC_V5_POLICY_CRITICAL)
            {
                ++queue->LostCriticalCount;
            }
            else
            {
                ++queue->LostHighCount;
            }
        }
        else
        {
            if (!queue->LossLatched)
            {
                queue->LossLatched = TRUE;
                queue->FirstLostSequence =
                    queue->Records[queue->Head].Sequence;
            }
            queue->Head = (queue->Head + 1) % queue->Capacity;
            --queue->Count;
            ++queue->DroppedCount;
        }
    }
    if (!alert || queue->Count != queue->Capacity)
    {
        index = (queue->Head + queue->Count) % queue->Capacity;
        queue->Records[index] = record;
        ++queue->Count;
    }
    KeReleaseSpinLock(&queue->Lock, oldIrql);

}

static NTSTATUS OacAcknowledgeAlertsLocked(
    _Inout_ POAC_EVIDENCE_QUEUE Queue,
    _In_ ULONGLONG AcknowledgeThrough)
{
    if (AcknowledgeThrough == 0) return STATUS_SUCCESS;
    if (AcknowledgeThrough < Queue->AcknowledgedSequence ||
        AcknowledgeThrough > Queue->HighestDeliveredSequence)
    {
        return STATUS_INVALID_PARAMETER;
    }
    while (Queue->Count != 0 &&
        Queue->Records[Queue->Head].Sequence <= AcknowledgeThrough)
    {
        RtlZeroMemory(
            &Queue->Records[Queue->Head],
            sizeof(Queue->Records[Queue->Head]));
        Queue->Head = (Queue->Head + 1) % Queue->Capacity;
        --Queue->Count;
    }
    Queue->AcknowledgedSequence = AcknowledgeThrough;
    return STATUS_SUCCESS;
}

NTSTATUS OacEvidenceRead(
    _In_ const OAC_EVIDENCE_READ_REQUEST* Request,
    _In_ BOOLEAN SessionRevoked,
    _Out_writes_bytes_to_(OutputLength, *BytesWritten)
        POAC_EVIDENCE_READ_RESPONSE Response,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesWritten)
{
    const ULONG prefix = FIELD_OFFSET(OAC_EVIDENCE_READ_RESPONSE, Records);
    POAC_EVIDENCE_QUEUE queue;
    ULONG requiredLength;
    ULONG sourceIndex;
    ULONG copied = 0;
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;
    ULONGLONG lastCopied = 0;

    if (Request == NULL || Response == NULL || BytesWritten == NULL)
        return STATUS_INVALID_PARAMETER;
    *BytesWritten = 0;
    requiredLength = prefix +
        Request->MaximumRecords * sizeof(OAC_V5_EVENT_RECORD);
    if (OutputLength < requiredLength) return STATUS_BUFFER_TOO_SMALL;
    RtlZeroMemory(Response, requiredLength);
    queue = Request->Channel == OAC_EVIDENCE_CHANNEL_ALERT
        ? &g_Evidence.Alerts
        : &g_Evidence.Events;

    KeAcquireSpinLock(&queue->Lock, &oldIrql);
    if (!queue->Active || queue->Records == NULL ||
        !OacEvidenceIdentityMatches(
            &queue->SessionId,
            queue->Generation,
            &Request->Header.SessionId,
            Request->Header.Generation))
    {
        status = STATUS_ACCESS_DENIED;
        goto Exit;
    }
    if (Request->AfterSequence > queue->PublishedSequence)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    if (Request->Channel == OAC_EVIDENCE_CHANNEL_ALERT)
    {
        if (Request->AfterSequence < queue->AcknowledgedSequence ||
            Request->AfterSequence > queue->HighestDeliveredSequence)
        {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }
        status = OacAcknowledgeAlertsLocked(
            queue,
            Request->AcknowledgeThrough);
        if (!NT_SUCCESS(status)) goto Exit;
    }

    Response->Channel = Request->Channel;
    Response->PublishedSequence = queue->PublishedSequence;
    Response->AcknowledgedSequence = queue->AcknowledgedSequence;
    Response->DroppedCount = queue->DroppedCount;
    Response->FirstLostSequence = queue->FirstLostSequence;
    Response->LostHighCount = queue->LostHighCount;
    Response->LostCriticalCount = queue->LostCriticalCount;
    Response->LossLatched = queue->LossLatched ? 1UL : 0UL;
    if (queue->Count != 0)
    {
        Response->FirstAvailableSequence = queue->Records[queue->Head].Sequence;
        Response->LastAvailableSequence = queue->Records[
            (queue->Head + queue->Count - 1) % queue->Capacity].Sequence;
        if (Request->AfterSequence <
            Response->FirstAvailableSequence - 1)
        {
            Response->Header.Flags |= OAC_V5_RESPONSE_PARTIAL;
        }
    }
    for (sourceIndex = 0;
         sourceIndex < queue->Count && copied < Request->MaximumRecords;
         ++sourceIndex)
    {
        const POAC_V5_EVENT_RECORD record = &queue->Records[
            (queue->Head + sourceIndex) % queue->Capacity];
        if (record->Sequence <= Request->AfterSequence) continue;
        Response->Records[copied] = *record;
        lastCopied = record->Sequence;
        ++copied;
    }
    Response->RecordCount = copied;
    if (copied != 0 && lastCopied < Response->LastAvailableSequence)
        Response->Header.Flags |= OAC_V5_RESPONSE_MORE_DATA;
    if (Request->Channel == OAC_EVIDENCE_CHANNEL_ALERT &&
        lastCopied > queue->HighestDeliveredSequence)
    {
        queue->HighestDeliveredSequence = lastCopied;
    }
    if (SessionRevoked) Response->Header.Flags |= OAC_V5_RESPONSE_REVOKED;
    *BytesWritten = prefix + copied * sizeof(OAC_V5_EVENT_RECORD);

Exit:
    KeReleaseSpinLock(&queue->Lock, oldIrql);
    return status;
}

static VOID OacFillSnapshotResponseLocked(
    _In_ const OAC_SNAPSHOT_STATE* Snapshot,
    _In_ const OAC_SNAPSHOT_REQUEST* Request,
    _In_ BOOLEAN SessionRevoked,
    _Out_ POAC_SNAPSHOT_RESPONSE Response,
    _Out_ PULONG BytesWritten)
{
    const ULONG prefix = FIELD_OFFSET(OAC_SNAPSHOT_RESPONSE, Records);
    ULONG count = 0;

    Response->SnapshotId = Snapshot->SnapshotId;
    Response->ScanId = Snapshot->ScanId;
    Response->CreatedTimestamp100ns = Snapshot->CreatedTimestamp100ns;
    Response->ExpirationInterruptTime100ns =
        Snapshot->ExpirationInterruptTime100ns;
    Response->CursorGeneration = Snapshot->CursorGeneration;
    Response->SnapshotType = Snapshot->SnapshotType;
    Response->State = Snapshot->State;
    Response->TotalItems = Snapshot->TotalItems;
    Response->AvailableItems = Snapshot->AvailableItems;
    Response->Truncated = Snapshot->Truncated ? 1UL : 0UL;
    Response->FailureStatus = Snapshot->FailureStatus;
    if (Snapshot->State == OAC_SNAPSHOT_STATE_READY &&
        Request->Operation != OAC_SNAPSHOT_OPERATION_CLOSE)
    {
        Response->Cursor = Request->Cursor;
        count = min(
            Request->MaximumRecords,
            Snapshot->AvailableItems - (ULONG)Request->Cursor);
        if (count != 0)
        {
            RtlCopyMemory(
                Response->Records,
                &Snapshot->Records[(ULONG)Request->Cursor],
                count * sizeof(OAC_SNAPSHOT_RECORD));
        }
        Response->RecordCount = count;
        Response->NextCursor = Request->Cursor + count;
        if (Response->NextCursor < Snapshot->AvailableItems)
            Response->Header.Flags |= OAC_V5_RESPONSE_MORE_DATA;
    }
    if (SessionRevoked) Response->Header.Flags |= OAC_V5_RESPONSE_REVOKED;
    *BytesWritten = prefix + count * sizeof(OAC_SNAPSHOT_RECORD);
}

NTSTATUS OacEvidenceManageSnapshot(
    _In_ const OAC_SNAPSHOT_REQUEST* Request,
    _In_ BOOLEAN SessionRevoked,
    _Out_writes_bytes_to_(OutputLength, *BytesWritten)
        POAC_SNAPSHOT_RESPONSE Response,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesWritten)
{
    const ULONG prefix = FIELD_OFFSET(OAC_SNAPSHOT_RESPONSE, Records);
    POAC_SNAPSHOT_STATE snapshot = &g_Evidence.Snapshot;
    LARGE_INTEGER now = { 0 };
    ULONG requiredLength;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();
    if (Request == NULL || Response == NULL || BytesWritten == NULL)
        return STATUS_INVALID_PARAMETER;
    *BytesWritten = 0;
    requiredLength = prefix +
        Request->MaximumRecords * sizeof(OAC_SNAPSHOT_RECORD);
    if (OutputLength < requiredLength) return STATUS_BUFFER_TOO_SMALL;
    RtlZeroMemory(Response, requiredLength);

    OacLockSnapshotExclusive(&snapshot->Lock);
    if (!OacEvidenceIdentityMatches(
            &snapshot->SessionId,
            snapshot->Generation,
            &Request->Header.SessionId,
            Request->Header.Generation))
    {
        status = STATUS_ACCESS_DENIED;
        goto Exit;
    }
    if (SessionRevoked &&
        Request->Operation == OAC_SNAPSHOT_OPERATION_OPEN)
    {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    if (Request->Operation == OAC_SNAPSHOT_OPERATION_OPEN)
    {
        if (!OacSnapshotIdIsZero(&snapshot->SnapshotId) &&
            KeQueryInterruptTime() <
                snapshot->ExpirationInterruptTime100ns)
        {
            status = STATUS_DEVICE_BUSY;
            goto Exit;
        }
        OacFreeSnapshotRecordsLocked(snapshot);
        RtlZeroMemory(
            &snapshot->SnapshotId,
            sizeof(*snapshot) - FIELD_OFFSET(OAC_SNAPSHOT_STATE, SnapshotId));
        status = OacGenerateSnapshotId(&snapshot->SnapshotId);
        if (!NT_SUCCESS(status)) goto Exit;
        snapshot->ScanId = OacNextPositiveCounter(&g_Evidence.NextScanId);
        snapshot->CursorGeneration = OacNextPositiveCounter(
            &g_Evidence.NextCursorGeneration);
        if (snapshot->ScanId == 0 || snapshot->CursorGeneration == 0)
        {
            status = STATUS_INTEGER_OVERFLOW;
            goto Exit;
        }
        KeQuerySystemTime(&now);
        snapshot->CreatedTimestamp100ns = (ULONGLONG)now.QuadPart;
        snapshot->ExpirationInterruptTime100ns =
            KeQueryInterruptTime() + OAC_SNAPSHOT_LIFETIME_100NS;
        snapshot->SnapshotType = Request->SnapshotType;
        snapshot->FailureStatus = OacCaptureKernelModuleSnapshot(
            &snapshot->Records,
            &snapshot->TotalItems,
            &snapshot->AvailableItems,
            &snapshot->Truncated);
        snapshot->State = NT_SUCCESS(snapshot->FailureStatus)
            ? OAC_SNAPSHOT_STATE_READY
            : OAC_SNAPSHOT_STATE_FAILED;
        /* Snapshot collection is a typed operation result.  Once the
         * request itself has been accepted, return a valid response and
         * carry collection failure in State/FailureStatus. */
        status = STATUS_SUCCESS;
    }
    else
    {
        if (OacSnapshotIdIsZero(&snapshot->SnapshotId) ||
            !OacSnapshotIdEqual(
                &snapshot->SnapshotId,
                &Request->SnapshotId) ||
            snapshot->CursorGeneration != Request->CursorGeneration ||
            snapshot->SnapshotType != Request->SnapshotType)
        {
            status = STATUS_NOT_FOUND;
            goto Exit;
        }
        if (KeQueryInterruptTime() >=
            snapshot->ExpirationInterruptTime100ns)
        {
            OacFreeSnapshotRecordsLocked(snapshot);
            RtlZeroMemory(
                &snapshot->SnapshotId,
                sizeof(*snapshot) -
                    FIELD_OFFSET(OAC_SNAPSHOT_STATE, SnapshotId));
            status = STATUS_TIMEOUT;
            goto Exit;
        }
        if (Request->Operation == OAC_SNAPSHOT_OPERATION_READ &&
            Request->Cursor > snapshot->AvailableItems)
        {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }
    }

    if (Request->Operation == OAC_SNAPSHOT_OPERATION_CLOSE)
    {
        snapshot->State = OAC_SNAPSHOT_STATE_CLOSED;
        snapshot->FailureStatus = STATUS_SUCCESS;
    }
    OacFillSnapshotResponseLocked(
        snapshot,
        Request,
        SessionRevoked,
        Response,
        BytesWritten);
    if (Request->Operation == OAC_SNAPSHOT_OPERATION_CLOSE)
    {
        OacFreeSnapshotRecordsLocked(snapshot);
        RtlZeroMemory(
            &snapshot->SnapshotId,
            sizeof(*snapshot) - FIELD_OFFSET(OAC_SNAPSHOT_STATE, SnapshotId));
    }

Exit:
    OacUnlockSnapshotExclusive(&snapshot->Lock);
    return status;
}

VOID OacEvidenceEventCounters(
    _Out_ PULONGLONG Written,
    _Out_ PULONGLONG Dropped)
{
    KIRQL oldIrql;

    if (Written == NULL || Dropped == NULL) return;
    KeAcquireSpinLock(&g_Evidence.Events.Lock, &oldIrql);
    *Written = g_Evidence.Events.PublishedSequence;
    *Dropped = g_Evidence.Events.DroppedCount;
    KeReleaseSpinLock(&g_Evidence.Events.Lock, oldIrql);
}
