#pragma once

#include <ntifs.h>
#include "..\shared\oac_protocol.h"
#include "session.h"

#define OAC_PROCESS_VM_READ_ACCESS 0x0010UL

#ifndef OAC_OB_ALTITUDE
#define OAC_OB_ALTITUDE L"321000.11001"
#endif

NTSTATUS OacProtectionInitialize(_In_ PDRIVER_OBJECT DriverObject);
VOID OacProtectionShutdown(VOID);

NTSTATUS OacConfigureProtection(
    _In_ const OAC_CONFIG_REQUEST* Request,
    _In_ HANDLE RequestorProcessId,
    _In_ const OAC_SESSION_LEASE* SessionLease
);

VOID OacProtectionRevokeController(_In_ PEPROCESS Controller);

HANDLE OacProtectedProcessId(VOID);
HANDLE OacTrustedClientProcessId(VOID);
BOOLEAN OacIsProtectedProcessObject(_In_opt_ PVOID Object);
BOOLEAN OacIsTrustedClientProcess(_In_ PEPROCESS Process);
ULONG OacConfigurationFlags(VOID);
ULONGLONG OacPostStartLoads(VOID);
ULONGLONG OacDriverGateTrips(VOID);
ACCESS_MASK OacRestrictedProcessRights(VOID);
