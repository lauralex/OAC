#pragma once

#include <ntifs.h>
#include "..\shared\oac_protocol.h"

NTSTATUS OacCpuSnapshotInitialize(VOID);
VOID OacCpuSnapshotShutdown(VOID);

NTSTATUS OacCaptureCpuSnapshot(
    _Out_writes_bytes_(OutputLength) POAC_CPU_RESPONSE Response,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesWritten
);
