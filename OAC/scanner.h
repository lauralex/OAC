#pragma once

#include <ntifs.h>
#include "..\shared\oac_protocol.h"

NTSTATUS OacScannerInitialize(_In_ PDRIVER_OBJECT DriverObject);
VOID OacScannerShutdown(VOID);
ULONG OacScannerCapabilities(VOID);

NTSTATUS OacRunKernelScan(_In_ const OAC_SCAN_REQUEST* Request);
