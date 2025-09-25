#pragma once
#include <ntddk.h>

#pragma warning(push)
#pragma warning(disable : 4201) // nameless struct/union
typedef union _VIRTUAL_ADDRESS
{
    struct
    {
        UINT64 offset : 12;
        UINT64 pt_index : 9;
        UINT64 pd_index : 9;
        UINT64 pdpt_index : 9;
        UINT64 pml4_index : 9;
        UINT64 sign_extend : 16;
    };

    UINT64 vaddr;
} VIRTUAL_ADDRESS, *PVIRTUAL_ADDRESS;
#pragma warning(pop)

//
// Undocumented Windows Definitions
//
#pragma warning(push)
#pragma warning(disable : 4201) // nameless struct/union
typedef struct _KAFFINITY_EX
{
    USHORT Count;
    USHORT Size;
    ULONG  Reserved;

    union
    {
        ULONG_PTR Bitmap[1];
        ULONG_PTR StaticBitmap[32];
    } DUMMYUNIONNAME;
} KAFFINITY_EX, *PKAFFINITY_EX;
#pragma warning(pop)

// We must define IoCreateDriver as it's not in the WDK headers.
// This function creates a DRIVER_OBJECT.
//
NTSTATUS NTAPI IoCreateDriver(
    _In_opt_ PUNICODE_STRING DriverName, // Optional: \Driver\DriverName
    _In_ PDRIVER_INITIALIZE  InitializationFunction
);


VOID NTAPI IoDeleteDriver(
    IN PDRIVER_OBJECT DriverObject
);

//
// Undocumented HAL function to send an NMI to a set of processors.
//
NTSTATUS NTAPI HalSendNMI(
    _In_ PKAFFINITY_EX Affinity
);

PVOID NTAPI KeInitializeAffinityEx(
    _In_ PKAFFINITY_EX Affinity
);

ULONG NTAPI KeAddProcessorAffinityEx(
    _In_ PKAFFINITY_EX Affinity,
    _In_ ULONG         ProcessorIndex
);
