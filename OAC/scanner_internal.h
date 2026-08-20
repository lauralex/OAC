#pragma once

#include "scanner.h"

#include <aux_klib.h>

#define OAC_SCAN_TAG 'ScaO'
#define OAC_MAX_SYSTEM_QUERY (64UL * 1024UL * 1024UL)

NTSTATUS OacQuerySystemInformation(
    _In_ ULONG InformationClass,
    _Outptr_result_bytebuffer_(*BufferLength) PVOID* Buffer,
    _Out_ PULONG BufferLength);

NTSTATUS OacQueryKernelModules(
    _Outptr_result_buffer_(*ModuleCount) PAUX_MODULE_EXTENDED_INFO* Modules,
    _Out_ PULONG ModuleCount);

BOOLEAN OacAddressInModules(
    _In_ PVOID Address,
    _In_reads_(ModuleCount) PAUX_MODULE_EXTENDED_INFO Modules,
    _In_ ULONG ModuleCount,
    _Out_opt_ PULONG ModuleIndex);

VOID OacAsciiToWide(
    _In_reads_opt_(SourceLength) const UCHAR* Source,
    _In_ SIZE_T SourceLength,
    _Out_writes_(DestinationCount) PWCHAR Destination,
    _In_ SIZE_T DestinationCount);

VOID OacScanKernelModules(
    _In_reads_(ModuleCount) PAUX_MODULE_EXTENDED_INFO Modules,
    _In_ ULONG ModuleCount);

VOID OacScanProcessesAndHandles(
    _In_reads_(ModuleCount) PAUX_MODULE_EXTENDED_INFO Modules,
    _In_ ULONG ModuleCount,
    _In_ ULONG ScanFlags);
