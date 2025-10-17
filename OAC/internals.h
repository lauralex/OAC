/**
 * @file internals.h
 * @brief Internal structures and function prototypes for the driver.
 *
 * This header file contains definitions of internal structures, unions, and
 * function prototypes that are used within the driver. It includes partial
 * definitions of undocumented Windows structures and functions that are not
 * available in the standard WDK headers.
 *
 * Note: This code is intended for educational purposes and should be used
 * with caution in production environments, as it relies on undocumented
 * features of the Windows operating system.
 */

#pragma once
#include <ntddk.h>

/**
 * @brief Initializes internal structures and pointers used by the driver.
 *
 * This function should be called at driver initialization time, at PASSIVE_LEVEL.
 * It sets up any necessary internal state required for the driver's operation.
 */
VOID InitializeInternals(VOID);

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

// --------------------------------

// Partial _KPROCESS, _EPROCESS, _KTHREAD, _ETHREAD,  _KAPC_STATE and _PEB_LDR_DATA structures for our use.
typedef struct _KPROCESS
{
    DISPATCHER_HEADER Header;
    LIST_ENTRY        ProfileListHead;
    ULONGLONG         DirectoryTableBase;
    UCHAR             Padding[0x408];
} KPROCESS;

//0x58 bytes (sizeof)
typedef struct _PEB_LDR_DATA
{
    ULONG              Length;                          //0x0
    UCHAR              Initialized;                     //0x4
    VOID*              SsHandle;                        //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;           //0x10
    struct _LIST_ENTRY InMemoryOrderModuleList;         //0x20
    struct _LIST_ENTRY InInitializationOrderModuleList; //0x30
    VOID*              EntryInProgress;                 //0x40
    UCHAR              ShutdownInProgress;              //0x48
    VOID*              ShutdownThreadId;                //0x50
} PEB_LDR_DATA, *PPEB_LDR_DATA;


typedef struct _PEB
{
    UCHAR         Padding0[0x18];
    PPEB_LDR_DATA Ldr;
    UCHAR         Padding1[0x7B0];
} PEB;

typedef struct _EPROCESS
{
    KPROCESS     Pcb;
    EX_PUSH_LOCK ProcessLock;
    VOID*        UniqueProcessId;
    LIST_ENTRY   ActiveProcessLinks;
    UCHAR        Padding0[0xF8];
    PPEB         Peb;
    UCHAR        Padding1[0x628];
} EPROCESS;

// 0x480 bytes (sizeof)
typedef struct _KTHREAD
{
    UCHAR        Padding0[0x90];
    PKTRAP_FRAME TrapFrame; //0x90
    UCHAR        Padding1[0x3E8];
} KTHREAD;

// 0x900 bytes (sizeof)
typedef struct _ETHREAD
{
    KTHREAD Tcb;
    UCHAR   Padding0[0x480];
} ETHREAD;

//0x30 bytes (sizeof)
#pragma warning(push)
#pragma warning(disable : 4201) // namesless struct/union
typedef struct _KAPC_STATE
{
    struct _LIST_ENTRY ApcListHead[2]; //0x0
    struct _KPROCESS*  Process;        //0x20
    union
    {
        UCHAR InProgressFlags; //0x28
        struct
        {
            UCHAR KernelApcInProgress : 1;  //0x28
            UCHAR SpecialApcInProgress : 1; //0x28
        };
    };

    UCHAR KernelApcPending; //0x29
    union
    {
        UCHAR UserApcPendingAll; //0x2a
        struct
        {
            UCHAR SpecialUserApcPending : 1; //0x2a
            UCHAR UserApcPending : 1;        //0x2a
        };
    };
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;
#pragma warning(pop)

//--------------------------------

typedef struct _MEMORY_BASIC_INFORMATION
{
    PVOID  BaseAddress;
    PVOID  AllocationBase;
    ULONG  AllocationProtect;
    USHORT PartitionId;
    SIZE_T RegionSize;
    ULONG  State;
    ULONG  Protect;
    ULONG  Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,              // q: MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation,         // q: MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation,     // q: UNICODE_STRING
    MemoryRegionInformation,             // q: MEMORY_REGION_INFORMATION
    MemoryWorkingSetExInformation,       // q: MEMORY_WORKING_SET_EX_INFORMATION // since VISTA
    MemorySharedCommitInformation,       // q: MEMORY_SHARED_COMMIT_INFORMATION // since WIN8
    MemoryImageInformation,              // q: MEMORY_IMAGE_INFORMATION
    MemoryRegionInformationEx,           // q: MEMORY_REGION_INFORMATION
    MemoryPrivilegedBasicInformation,    // q: MEMORY_BASIC_INFORMATION
    MemoryEnclaveImageInformation,       // q: MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
    MemoryBasicInformationCapped,        // q: 10
    MemoryPhysicalContiguityInformation, // q: MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
    MemoryBadInformation,                // q: since WIN11
    MemoryBadInformationAllProcesses,    // qs: not implemented // since 22H1
    MemoryImageExtensionInformation,     // q: MEMORY_IMAGE_EXTENSION_INFORMATION // since 24H2
    MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;

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

typedef struct _FILETIME
{
    UINT32 LowDateTime;
    UINT32 HighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;

// We must define IoCreateDriver as it's not in the WDK headers.
// This function creates a DRIVER_OBJECT.
//
NTKERNELAPI
NTSTATUS
IoCreateDriver(
    _In_opt_ PUNICODE_STRING DriverName, // Optional: \Driver\DriverName
    _In_ PDRIVER_INITIALIZE  InitializationFunction
);

NTKERNELAPI
VOID
IoDeleteDriver(
    IN PDRIVER_OBJECT DriverObject
);

//
// Undocumented HAL function to send an NMI to a set of processors.
//
NTKERNELAPI
NTSTATUS
HalSendNMI(
    _In_ PKAFFINITY_EX Affinity
);

// Undocumented head of the system's active process list.
extern PLIST_ENTRY PsActiveProcessHead;

extern PRUNTIME_FUNCTION
(*RtlLookupFunctionEntryUsermode)(
    _In_ DWORD64                      ControlPc,
    _Out_ PDWORD64                    ImageBase,
    _Inout_opt_ PUNWIND_HISTORY_TABLE HistoryTable
);

extern PRUNTIME_FUNCTION
(*RtlpLookupFunctionEntryForStackWalks)(
    _In_ ULONG64   ControlPc,
    _Out_ PULONG64 ImageBase
);

NTKERNELAPI
PVOID
KeInitializeAffinityEx(
    _In_ PKAFFINITY_EX Affinity
);

NTKERNELAPI
ULONG
KeAddProcessorAffinityEx(
    _In_ PKAFFINITY_EX Affinity,
    _In_ ULONG         ProcessorIndex
);

NTKERNELAPI
PEXCEPTION_ROUTINE
RtlVirtualUnwind(_In_ ULONG                                 HandlerType,
                 _In_ ULONG64                               ImageBase,
                 _In_ ULONG64                               ControlPc,
                 _In_ PRUNTIME_FUNCTION                     FunctionEntry,
                 _Inout_ PCONTEXT                           Context,
                 _Outptr_ PVOID*                            HandlerData,
                 _Out_ PULONG64                             EstablisherFrame,
                 _Inout_opt_ PKNONVOLATILE_CONTEXT_POINTERS ContextPointers
);

NTKERNELAPI
PRUNTIME_FUNCTION
RtlLookupFunctionEntry(
    _In_ DWORD64                      ControlPc,
    _Out_ PDWORD64                    ImageBase,
    _Inout_opt_ PUNWIND_HISTORY_TABLE HistoryTable
);


NTKERNELAPI
PVOID
RtlPcToFileHeader(
    _In_ PVOID   PcValue,
    _Out_ PVOID* BaseOfImage
);

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE      ProcessId,
    _Out_ PEPROCESS* Process
);

NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);

NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PRKPROCESS PROCESS,
    _Out_ PRKAPC_STATE ApcState
);

NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PRKAPC_STATE ApcState
);

NTKERNELAPI
NTSTATUS
PsLookupThreadByThreadId(
    HANDLE    ThreadId,
    PETHREAD* Thread
);

NTKERNELAPI
NTSTATUS
ZwQueryVirtualMemory(
    _In_ HANDLE                   ProcessHandle,
    _In_opt_ PVOID                BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_ PVOID                   MemoryInformation,
    _In_ SIZE_T                   MemoryInformationLength,
    _Out_opt_ PSIZE_T             ReturnLength
);
