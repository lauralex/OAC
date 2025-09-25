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
// Undocumented Function Definitions
//

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
