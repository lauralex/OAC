#pragma once
#include <ntddk.h>

#pragma warning(push)
#pragma warning(disable : 4201) // nameless struct/union
typedef union _VIRTUAL_ADDRESS
{
    struct
    {
        UINT64 Offset : 12;
        UINT64 PtIndex : 9;
        UINT64 PdIndex : 9;
        UINT64 PdptIndex : 9;
        UINT64 Pml4Index : 9;
        UINT64 SignExtend : 16;
    };

    UINT64 Vaddr;
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

#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2
#define UNW_FLAG_CHAININFO 0x4
#define UNW_FLAG_NO_EPILOGUE  0x80000000UL

typedef struct _RUNTIME_FUNCTION
{
    ULONG BeginAddress;
    ULONG EndAddress;
    ULONG UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

#pragma warning(push)
#pragma warning(disable : 4201) // nameless struct/union
typedef struct _KNONVOLATILE_CONTEXT_POINTERS
{
    union
    {
        PM128A FloatingContext[16];

        struct
        {
            PM128A Xmm0;
            PM128A Xmm1;
            PM128A Xmm2;
            PM128A Xmm3;
            PM128A Xmm4;
            PM128A Xmm5;
            PM128A Xmm6;
            PM128A Xmm7;
            PM128A Xmm8;
            PM128A Xmm9;
            PM128A Xmm10;
            PM128A Xmm11;
            PM128A Xmm12;
            PM128A Xmm13;
            PM128A Xmm14;
            PM128A Xmm15;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    union
    {
        PULONG64 IntegerContext[16];

        struct
        {
            PULONG64 Rax;
            PULONG64 Rcx;
            PULONG64 Rdx;
            PULONG64 Rbx;
            PULONG64 Rsp;
            PULONG64 Rbp;
            PULONG64 Rsi;
            PULONG64 Rdi;
            PULONG64 R8;
            PULONG64 R9;
            PULONG64 R10;
            PULONG64 R11;
            PULONG64 R12;
            PULONG64 R13;
            PULONG64 R14;
            PULONG64 R15;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME2;
} KNONVOLATILE_CONTEXT_POINTERS, *PKNONVOLATILE_CONTEXT_POINTERS;
#pragma warning(pop)

#define UNWIND_HISTORY_TABLE_SIZE 12

typedef struct _UNWIND_HISTORY_TABLE_ENTRY
{
    ULONG64           ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
} UNWIND_HISTORY_TABLE_ENTRY, *PUNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE
{
    ULONG                      Count;
    UCHAR                      LocalHint;
    UCHAR                      GlobalHint;
    UCHAR                      Search;
    UCHAR                      Once;
    ULONG64                    LowAddress;
    ULONG64                    HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[UNWIND_HISTORY_TABLE_SIZE];
} UNWIND_HISTORY_TABLE, *PUNWIND_HISTORY_TABLE;

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


PEXCEPTION_ROUTINE NTAPI RtlVirtualUnwind(_In_ ULONG                                 HandlerType,
                                          _In_ ULONG64                               ImageBase,
                                          _In_ ULONG64                               ControlPc,
                                          _In_ PRUNTIME_FUNCTION                     FunctionEntry,
                                          _Inout_ PCONTEXT                           Context,
                                          _Outptr_ PVOID*                            HandlerData,
                                          _Out_ PULONG64                             EstablisherFrame,
                                          _Inout_opt_ PKNONVOLATILE_CONTEXT_POINTERS ContextPointers
);

PRUNTIME_FUNCTION
NTAPI
RtlLookupFunctionEntry(
    _In_ DWORD64                      ControlPc,
    _Out_ PDWORD64                    ImageBase,
    _Inout_opt_ PUNWIND_HISTORY_TABLE HistoryTable
);
