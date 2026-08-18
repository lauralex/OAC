#pragma once

#include <ntifs.h>

#include "..\shared\protocol\oac_v5.h"

NTSTATUS OacEvidenceInitialize(VOID);
VOID OacEvidenceShutdown(VOID);

VOID OacEvidenceBeginSession(
    _In_ const OAC_V5_SESSION_ID* SessionId,
    _In_ ULONGLONG Generation,
    _In_ ULONG SessionMode);

BOOLEAN OacEvidenceHasAlertLoss(
    _In_ const OAC_V5_SESSION_ID* SessionId,
    _In_ ULONGLONG Generation);

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
    _In_ ULONGLONG EvidenceFlags);

NTSTATUS OacEvidenceRead(
    _In_ const OAC_EVIDENCE_READ_REQUEST* Request,
    _In_ BOOLEAN SessionRevoked,
    _Out_writes_bytes_to_(OutputLength, *BytesWritten)
        POAC_EVIDENCE_READ_RESPONSE Response,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesWritten);

NTSTATUS OacEvidenceManageSnapshot(
    _In_ const OAC_SNAPSHOT_REQUEST* Request,
    _In_ BOOLEAN SessionRevoked,
    _Out_writes_bytes_to_(OutputLength, *BytesWritten)
        POAC_SNAPSHOT_RESPONSE Response,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesWritten);

VOID OacEvidenceEventCounters(
    _Out_ PULONGLONG Written,
    _Out_ PULONGLONG Dropped);
