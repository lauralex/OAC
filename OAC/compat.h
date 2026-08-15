#pragma once

#include <ntifs.h>

VOID OacCompatibilityInitialize(VOID);

_Post_maybenull_
PVOID OacAllocatePool(
    _In_ BOOLEAN Paged,
    _In_ SIZE_T Size,
    _In_ ULONG Tag
);

NTSTATUS OacCopyVirtualMemorySafe(
    _Out_writes_bytes_(Size) PVOID Destination,
    _In_ PVOID Source,
    _In_ SIZE_T Size,
    _Out_ PSIZE_T BytesCopied
);
