#include "telemetry.h"
#include "compat.h"
#include "scanner.h"

#include <ntstrsafe.h>

#define OAC_FINDING_CAPACITY 512UL
#define OAC_TELEMETRY_TAG 'TcaO'

typedef struct OAC_TELEMETRY_STATE_TAG
{
    KSPIN_LOCK Lock;
    POAC_FINDING Records;
    ULONG Head;
    ULONG Count;
    ULONGLONG Sequence;
    ULONGLONG Dropped;
} OAC_TELEMETRY_STATE;

static OAC_TELEMETRY_STATE g_Telemetry;

NTSTATUS OacTelemetryInitialize(VOID)
{
    RtlZeroMemory(&g_Telemetry, sizeof(g_Telemetry));
    KeInitializeSpinLock(&g_Telemetry.Lock);
    g_Telemetry.Records = (POAC_FINDING)OacAllocatePool(
        FALSE,
        sizeof(OAC_FINDING) * OAC_FINDING_CAPACITY,
        OAC_TELEMETRY_TAG);
    if (g_Telemetry.Records == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(
        g_Telemetry.Records,
        sizeof(OAC_FINDING) * OAC_FINDING_CAPACITY);
    return STATUS_SUCCESS;
}

VOID OacTelemetryShutdown(VOID)
{
    KIRQL oldIrql;
    POAC_FINDING records;

    KeAcquireSpinLock(&g_Telemetry.Lock, &oldIrql);
    records = g_Telemetry.Records;
    g_Telemetry.Records = NULL;
    g_Telemetry.Head = 0;
    g_Telemetry.Count = 0;
    KeReleaseSpinLock(&g_Telemetry.Lock, oldIrql);

    if (records != NULL)
    {
        ExFreePoolWithTag(records, OAC_TELEMETRY_TAG);
    }
}

VOID OacReportFinding(
    _In_ OAC_SEVERITY Severity,
    _In_ OAC_CATEGORY Category,
    _In_opt_ HANDLE ProcessId,
    _In_opt_ HANDLE ThreadId,
    _In_opt_ PVOID Address,
    _In_ ULONGLONG Auxiliary,
    _In_z_ _Printf_format_string_ PCWSTR Format,
    ...)
{
    OAC_FINDING record;
    LARGE_INTEGER now = { 0 };
    va_list args;
    KIRQL oldIrql;
    ULONG index;

    RtlZeroMemory(&record, sizeof(record));
    KeQuerySystemTime(&now);
    record.Timestamp100ns = (ULONGLONG)now.QuadPart;
    record.ProcessId = HandleToULong(ProcessId);
    record.ThreadId = HandleToULong(ThreadId);
    record.Severity = (ULONG)Severity;
    record.Category = (ULONG)Category;
    record.Address = (ULONGLONG)(ULONG_PTR)Address;
    record.Auxiliary = Auxiliary;

    va_start(args, Format);
    (VOID)RtlStringCchVPrintfW(
        record.Text,
        RTL_NUMBER_OF(record.Text),
        Format,
        args);
    va_end(args);

    OacPublishEndpointFinding(&record);

    KeAcquireSpinLock(&g_Telemetry.Lock, &oldIrql);
    if (g_Telemetry.Records == NULL)
    {
        KeReleaseSpinLock(&g_Telemetry.Lock, oldIrql);
        return;
    }

    record.Sequence = ++g_Telemetry.Sequence;
    if (g_Telemetry.Count == OAC_FINDING_CAPACITY)
    {
        g_Telemetry.Head = (g_Telemetry.Head + 1) % OAC_FINDING_CAPACITY;
        --g_Telemetry.Count;
        ++g_Telemetry.Dropped;
    }

    index = (g_Telemetry.Head + g_Telemetry.Count) % OAC_FINDING_CAPACITY;
    g_Telemetry.Records[index] = record;
    ++g_Telemetry.Count;
    KeReleaseSpinLock(&g_Telemetry.Lock, oldIrql);
}

NTSTATUS OacReadFindings(
    _Out_writes_bytes_to_(OutputLength, *BytesWritten) POAC_FINDINGS_RESPONSE Response,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesWritten)
{
    const ULONG headerSize = FIELD_OFFSET(OAC_FINDINGS_RESPONSE, Findings);
    ULONG capacity;
    ULONG count;
    ULONG i;
    ULONG initializedBytes;
    KIRQL oldIrql;

    *BytesWritten = 0;
    if (OutputLength < headerSize)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    capacity = (OutputLength - headerSize) / sizeof(OAC_FINDING);
    if (capacity > OAC_MAX_FINDINGS_PER_READ)
    {
        capacity = OAC_MAX_FINDINGS_PER_READ;
    }

    if (capacity > (MAXULONG - headerSize) / sizeof(OAC_FINDING))
    {
        return STATUS_INTEGER_OVERFLOW;
    }
    initializedBytes = headerSize + capacity * sizeof(OAC_FINDING);
    if (initializedBytes > OutputLength)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(Response, initializedBytes);
    Response->Version = OAC_PROTOCOL_VERSION;
    Response->Size = headerSize;

    KeAcquireSpinLock(&g_Telemetry.Lock, &oldIrql);
    if (g_Telemetry.Records == NULL)
    {
        KeReleaseSpinLock(&g_Telemetry.Lock, oldIrql);
        return STATUS_DEVICE_NOT_READY;
    }
    count = min(capacity, g_Telemetry.Count);
    for (i = 0; i < count; ++i)
    {
        Response->Findings[i] = g_Telemetry.Records[g_Telemetry.Head];
        g_Telemetry.Head = (g_Telemetry.Head + 1) % OAC_FINDING_CAPACITY;
        --g_Telemetry.Count;
    }
    Response->Count = count;
    Response->Remaining = g_Telemetry.Count;
    KeReleaseSpinLock(&g_Telemetry.Lock, oldIrql);

    Response->Size = headerSize + count * sizeof(OAC_FINDING);
    *BytesWritten = Response->Size;
    return STATUS_SUCCESS;
}

ULONGLONG OacTelemetryWritten(VOID)
{
    return InterlockedCompareExchange64(
        (volatile LONG64*)&g_Telemetry.Sequence,
        0,
        0);
}

ULONGLONG OacTelemetryDropped(VOID)
{
    return InterlockedCompareExchange64(
        (volatile LONG64*)&g_Telemetry.Dropped,
        0,
        0);
}
