#include "compat.h"

typedef PVOID (*OAC_EX_ALLOCATE_POOL2)(
    _In_ POOL_FLAGS Flags,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag);

typedef NTSTATUS (*OAC_MM_COPY_MEMORY)(
    _Out_writes_bytes_(NumberOfBytes) PVOID TargetAddress,
    _In_ MM_COPY_ADDRESS SourceAddress,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Flags,
    _Out_ PSIZE_T NumberOfBytesTransferred);

static OAC_EX_ALLOCATE_POOL2 g_ExAllocatePool2;
static OAC_MM_COPY_MEMORY g_MmCopyMemory;
static BOOLEAN g_NonPagedNxAvailable;

VOID OacCompatibilityInitialize(VOID)
{
    UNICODE_STRING name;
    RTL_OSVERSIONINFOW version;

    RtlZeroMemory(&version, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    if (NT_SUCCESS(RtlGetVersion(&version)))
    {
        g_NonPagedNxAvailable = version.dwMajorVersion > 6 ||
            (version.dwMajorVersion == 6 && version.dwMinorVersion >= 2);
    }

    RtlInitUnicodeString(&name, L"ExAllocatePool2");
    g_ExAllocatePool2 = (OAC_EX_ALLOCATE_POOL2)MmGetSystemRoutineAddress(&name);
    RtlInitUnicodeString(&name, L"MmCopyMemory");
    g_MmCopyMemory = (OAC_MM_COPY_MEMORY)MmGetSystemRoutineAddress(&name);
}

_Post_maybenull_
PVOID OacAllocatePool(
    _In_ BOOLEAN Paged,
    _In_ SIZE_T Size,
    _In_ ULONG Tag)
{
    if (g_ExAllocatePool2 != NULL)
    {
        return g_ExAllocatePool2(
            Paged ? POOL_FLAG_PAGED : POOL_FLAG_NON_PAGED,
            Size,
            Tag);
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(
        Paged ? PagedPool : (g_NonPagedNxAvailable ? NonPagedPoolNx : NonPagedPool),
        Size,
        Tag);
#pragma warning(pop)
}

NTSTATUS OacCopyVirtualMemorySafe(
    _Out_writes_bytes_(Size) PVOID Destination,
    _In_ PVOID Source,
    _In_ SIZE_T Size,
    _Out_ PSIZE_T BytesCopied)
{
    SIZE_T offset;

    *BytesCopied = 0;
    if (Destination == NULL || Source == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (Size == 0) return STATUS_SUCCESS;
    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (g_MmCopyMemory != NULL)
    {
        MM_COPY_ADDRESS sourceAddress;
        sourceAddress.VirtualAddress = Source;
        return g_MmCopyMemory(
            Destination,
            sourceAddress,
            Size,
            MM_COPY_MEMORY_VIRTUAL,
            BytesCopied);
    }

    /* MmCopyMemory is available starting with Windows 8.1.  On older
     * kernels, reject every nonresident page before the guarded copy.  The
     * scanner only uses this fallback for stable system-image addresses; the
     * checks prevent discarded PE sections from becoming fatal kernel page
     * faults on legacy builds. */
    if (Size - 1 > MAXULONG_PTR - (ULONG_PTR)Source)
    {
        return STATUS_INTEGER_OVERFLOW;
    }
    for (offset = 0; offset < Size;)
    {
        ULONG_PTR current = (ULONG_PTR)Source + offset;
        SIZE_T pageRemaining = PAGE_SIZE - BYTE_OFFSET(current);
        SIZE_T chunk = min(Size - offset, pageRemaining);
        if (!MmIsAddressValid((PVOID)current) ||
            !MmIsAddressValid((PVOID)(current + chunk - 1)))
        {
            return STATUS_PARTIAL_COPY;
        }
        offset += chunk;
    }

    __try
    {
        RtlCopyMemory(Destination, Source, Size);
        *BytesCopied = Size;
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }
}
