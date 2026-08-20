#pragma once

#include <ntifs.h>
#include "..\shared\oac_protocol.h"
#include "..\shared\protocol\oac_v5.h"

NTSTATUS OacScannerInitialize(_In_ PDRIVER_OBJECT DriverObject);
VOID OacScannerShutdown(VOID);
ULONG OacScannerCapabilities(VOID);

NTSTATUS OacRunKernelScan(_In_ const OAC_SCAN_REQUEST* Request);

NTSTATUS OacRunEndpointScan(
    _In_ const OAC_ENDPOINT_SCAN_REQUEST* Request,
    _Out_ POAC_ENDPOINT_SCAN_RESPONSE Response);

VOID OacPublishEndpointFinding(_In_ const OAC_FINDING* Finding);

NTSTATUS OacCaptureKernelModuleSnapshot(
    _Outptr_result_buffer_maybenull_(*AvailableItems)
        POAC_SNAPSHOT_RECORD* Records,
    _Out_ PULONG TotalItems,
    _Out_ PULONG AvailableItems,
    _Out_ PBOOLEAN Truncated);

VOID OacReleaseKernelModuleSnapshot(
    _Frees_ptr_opt_ POAC_SNAPSHOT_RECORD Records);
