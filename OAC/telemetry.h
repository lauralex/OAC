#pragma once

#include <ntifs.h>
#include "..\shared\oac_protocol.h"

NTSTATUS OacTelemetryInitialize(VOID);
VOID OacTelemetryShutdown(VOID);

VOID OacReportFinding(
    _In_ OAC_SEVERITY Severity,
    _In_ OAC_CATEGORY Category,
    _In_opt_ HANDLE ProcessId,
    _In_opt_ HANDLE ThreadId,
    _In_opt_ PVOID Address,
    _In_ ULONGLONG Auxiliary,
    _In_z_ _Printf_format_string_ PCWSTR Format,
    ...
);

NTSTATUS OacReadFindings(
    _Out_writes_bytes_to_(OutputLength, *BytesWritten) POAC_FINDINGS_RESPONSE Response,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesWritten
);

ULONGLONG OacTelemetryWritten(VOID);
ULONGLONG OacTelemetryDropped(VOID);
