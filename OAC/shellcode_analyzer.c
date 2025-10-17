/**
 * @file shellcode_analyzer.c
 * @brief Implementation of user-mode shellcode detection logic.
 */
#include "shellcode_analyzer.h"
#include "internals.h"
#include "serial_logger.h"
#include "stackwalk.h"
#include "zyan_stackwalker.h"

#include <intrin.h>

//
// === Constants and Definitions ===
//
#define MAX_SHELLCODE_STACK_WALK_DEPTH 5

// An example of shellcode pattern. In practice, this would be a more comprehensive set.
const UCHAR G_ReverseShellSignature[] = {0x31, 0xC9, 0xF7, 0xE1, 0x51, 0x54};


//
// === Internal Function Prototypes ===
//

/**
 * @brief Checks if a memory address space is in an RWX region and contains a signature.
 *
 * @param[in] Address The memory address to check.
 * @return TRUE if the region is RWX and contains the signature, FALSE otherwise.
 */
static BOOLEAN IsMemoryRwAndContainsSignature(
    _In_ PVOID Address
);


//
// === Function Implementations ===
//

/**
 * @brief Analyzes a thread's user-mode call stack for evidence of shellcode injection.
 *
 * This function performs a stack walk of the specified user-mode thread. For each
 * return address on the stack, it checks if the code resides in an RWX memory
 * region and if it matches known shellcode signatures.
 *
 * @note This function must be called at PASSIVE_LEVEL. It temporarily attaches to
 *       the target process's address space.
 *
 * @param[in] ProcessId The ID of the process to inspect.
 * @param[in] ThreadId The ID of the thread whose stack will be walked.
 *
 * @return TRUE if shellcode is detected, FALSE otherwise.
 */
BOOLEAN AnalyzeThreadForShellcode(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId
)
{
    NTSTATUS  Status;
    PEPROCESS Process      = NULL;
    PETHREAD  Thread       = NULL;
    BOOLEAN   IsSuspicious = FALSE;

    // Get the EPROCESS and ETHREAD objects.
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[-] PsLookupProcessByProcessId failed: 0x%X\n", Status);
        return FALSE;
    }

    Status = PsLookupThreadByThreadId(ThreadId, &Thread);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[-] PsLookupThreadByThreadId failed: 0x%X\n", Status);
        ObDereferenceObject(Process);
        return FALSE;
    }

    // We need to check if current CR3 matches the target process's DTB.
    UINT64 ProcessDtb  = Process->Pcb.DirectoryTableBase;
    UINT64 OriginalCr3 = __readcr3();

    // We can only analyze TrapFrame if the OriginalCr3 matches the target process's DTB.
    // We skip analysis if they don't match to avoid complex context switching.
    // TODO: Implement thread pinning routine.
    if (OriginalCr3 != ProcessDtb)
    {
        DbgPrint("[-] Current CR3 (0x%llX) does not match target process DTB (0x%llX). Skipping analysis.\n",
                 OriginalCr3, ProcessDtb);
        ObDereferenceObject(Thread);
        ObDereferenceObject(Process);
        return FALSE;
    }

    __try
    {
        // To initialize a user-mode stack walk from the kernel, we need the thread's
        // context. Since the thread is blocked in a syscall, we can find its trap
        // frame, which contains the user-mode register state.
        PKTRAP_FRAME TrapFrame = (PKTRAP_FRAME)Thread->Tcb.TrapFrame;
        if (!TrapFrame)
        {
            DbgPrint("[-] Thread has no trap frame; cannot analyze.\n");
            __leave;
        }

        // Fill a CONTEXT structure from the trap frame.
        CONTEXT ContextRecord      = {0};
        ContextRecord.ContextFlags = CONTEXT_FULL;
        FillContextStructure(&ContextRecord, TrapFrame);

        if (!ContextRecord.Rip)
        {
            // No further caller.
            __leave;
        }

        // First, check the current return address.
        DbgPrint("[*] Scanning address: 0x%llx for PID: %p and TID: %p. DTB: 0x%llX\n",
                 ContextRecord.Rip, ProcessId, ThreadId, ProcessDtb);

        if (IsMemoryRwAndContainsSignature((PVOID)ContextRecord.Rip))
        {
            DbgPrint("[!!!] Shellcode signature found at RIP: 0x%llX\n", ContextRecord.Rip);
            IsSuspicious = TRUE;
            __leave;
        }

        UINT64 StackwalkFrames[MAX_SHELLCODE_STACK_WALK_DEPTH];
        SIZE_T FramesRetrieved = 0;

        BOOLEAN StackWalkValid = StackWalkWithZydis(ContextRecord.Rip, ContextRecord.Rsp, StackwalkFrames,
                                                    MAX_SHELLCODE_STACK_WALK_DEPTH, &FramesRetrieved);

        if (!StackWalkValid)
        {
            DbgPrint("[-] Unwind failed at RIP: 0x%llX, Status: 0x%X\n", ContextRecord.Rip, Status);
            __leave;
        }

        for (SIZE_T i = 0; i < FramesRetrieved; i++)
        {
            DbgPrint("[*] Scanning address: 0x%llx for PID: %p and TID: %p. DTB: 0x%llX\n",
                     StackwalkFrames[i], ProcessId, ThreadId, ProcessDtb);
            if (IsMemoryRwAndContainsSignature((PVOID)StackwalkFrames[i]))
            {
                DbgPrint("[!!!] Shellcode signature found at RIP: 0x%llX\n", StackwalkFrames[i]);
                IsSuspicious = TRUE;
                __leave;
            }
        }
        DbgPrint("[*] No shellcode signatures found in stack walk.\n");
    }
    __finally
    {
        SerialLoggerWrite("Finally block in AnalyzeThreadForShellcode");
        // CRITICAL: Always restore the original CR3 value.
        __writecr3(OriginalCr3);
    }

    // Release the objects.
    ObDereferenceObject(Thread);
    ObDereferenceObject(Process);

    return IsSuspicious;
}


/**
 * @brief Checks if a memory address space is in an RWX region and contains a signature.
 *
 * @param[in] Address The memory address to check.
 * @return TRUE if the region is RWX and contains the signature, FALSE otherwise.
 */
static BOOLEAN IsMemoryRwAndContainsSignature(
    _In_ PVOID Address
)
{
    // Check if the address is in user-mode space.
    if (Address > (PVOID)MM_USER_PROBE_ADDRESS)
    {
        return FALSE;
    }

    NTSTATUS                 Status;
    MEMORY_BASIC_INFORMATION MemoryInfo;
    BOOLEAN                  SignatureFound = FALSE;
    SIZE_T                   BytesReturned  = 0;

    // Query the memory region's protection attributes.
    Status = ZwQueryVirtualMemory(ZwCurrentProcess(), Address, MemoryBasicInformation, &MemoryInfo, sizeof(MemoryInfo),
                                  &BytesReturned);

    if (!NT_SUCCESS(Status) || BytesReturned != sizeof(MemoryInfo))
    {
        DbgPrint("[-] ZwQueryVirtualMemory failed: 0x%X\n", Status);
        return FALSE;
    }

    // The key indicator: Is the page executable, readable, AND writable?
    if (MemoryInfo.Protect == PAGE_EXECUTE_READWRITE)
    {
        DbgPrint("[*] Found RWX memory region at base: 0x%p\n", MemoryInfo.BaseAddress);
        // The region is suspicious. Now scan it for our shellcode signature.
        __try
        {
            // Check if the signature exists at the given address.
            if (RtlCompareMemory(Address, G_ReverseShellSignature, sizeof(G_ReverseShellSignature)) == sizeof(
                G_ReverseShellSignature))
            {
                SignatureFound = TRUE;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // Access violation while scanning.
            SignatureFound = FALSE;
        }
    }

    return SignatureFound;
}
