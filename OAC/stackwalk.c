#include <intrin.h>

#include "stackwalk.h"
#include "arch.h"
#include "ia32.h"
#include "internals.h"
#include "globals.h"
#include "ci.h"

//
// The global instance of our context structure.
//
NMI_CONTEXT G_NmiContext = {0};

//
// Global handle for the NMI callback registration.
//
PVOID G_NmiCallbackHandle = NULL;

//
// === Internal (Static) Function Prototypes ===
//
// By declaring these as static, we ensure they are only visible within this translation unit,
// which is proper encapsulation for internal helper functions.
//
static VOID SignatureCheckDpcRoutine(
    _In_ PKDPC     Dpc, _In_opt_ PVOID             DeferredContext,
    _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2
);

static VOID SignatureCheckWorkerRoutine(
    _In_ PVOID Parameter
);


/**
 * @brief The NMI callback routine that performs a stack walk.
 *
 * @param Context A pointer to our driver-defined NMI_CONTEXT structure.
 * @param Handled A boolean that indicates if a previous NMI handler has already claimed this NMI.
 *
 * @return TRUE if the NMI was handled, otherwise FALSE.
 */
BOOLEAN NmiCallback(
    _In_opt_ PVOID Context,
    _In_ BOOLEAN   Handled
)
{
    //
    // Step 1: Check if another driver has already handled this NMI.
    // If so, we must not interfere. Just pass it on.
    //
    if (Handled)
    {
        return FALSE;
    }

    //
    // Step 2: Validate our context. This is the most critical check.
    // If the context is missing or the signature is invalid, this NMI is not for us,
    // or something is seriously wrong (e.g., memory corruption, tampering).
    //
    PNMI_CONTEXT NmiContext = (PNMI_CONTEXT)Context;
    if (!NmiContext || NmiContext->MagicSignature != NMI_CONTEXT_SIGNATURE)
    {
        // Invalid context, not our NMI.
        return FALSE;
    }

    // Step 3: Check if this NMI was triggered by our driver.
    // If the pending count is 0, it's an unexpected NMI (e.g., hardware error).
    //
    if (InterlockedDecrement(&NmiContext->PendingCount) < 0)
    {
        InterlockedIncrement(&NmiContext->PendingCount);
        return FALSE; // Not our NMI, let others handle it.
    }

    // --- Acquire Spinlock for Transactional Logging ---
    // Since we are at HIGH_LEVEL IRQL, we use the "AtDpcLevel" variant.
    KeAcquireSpinLockAtDpcLevel(&NmiContext->Lock);

    PROCESSOR_NUMBER CurrentProcNum = {0};
    KeGetCurrentProcessorNumberEx(&CurrentProcNum);

    DbgPrint("===============================================================================\n");
    DbgPrint(" NMI STACK TRACE FOR CPU %u (Group: %u)\n", CurrentProcNum.Number, CurrentProcNum.Group);
    DbgPrint("===============================================================================\n");

    //
    // --- Unwind-Data-Based Stack Walk Logic ---
    //
    PKTRAP_FRAME TrapFrame = FindNmiTrapFrame();
    if (!TrapFrame)
    {
        DbgPrint("[-] Failed to locate KTRAP_FRAME on NMI stack.\n");
        // Release the lock before returning.
        KeReleaseSpinLockFromDpcLevel(&NmiContext->Lock);
        return TRUE; // We handled our NMI, but failed the walk.
    }

    DbgPrint("[+] Found KTRAP_FRAME at 0x%p\n", TrapFrame);
    DbgPrint("    RIP: 0x%llX\n", TrapFrame->Rip);
    DbgPrint("    RSP: 0x%llX\n", TrapFrame->Rsp);
    DbgPrint("    RBP: 0x%llX\n", TrapFrame->Rbp);

    // Step 1. Initialize a CONTEXT record from the KTRAP_FRAME.
    // This CONTEXT record is the starting point for our unwind operation.
    CONTEXT ContextRecord      = {0};
    ContextRecord.ContextFlags = CONTEXT_FULL;

    // Copy all general-purpose and control registers.
    ContextRecord.Rax    = TrapFrame->Rax;
    ContextRecord.Rcx    = TrapFrame->Rcx;
    ContextRecord.Rdx    = TrapFrame->Rdx;
    ContextRecord.Rbx    = TrapFrame->Rbx;
    ContextRecord.Rsp    = TrapFrame->Rsp;
    ContextRecord.Rbp    = TrapFrame->Rbp;
    ContextRecord.Rsi    = TrapFrame->Rsi;
    ContextRecord.Rdi    = TrapFrame->Rdi;
    ContextRecord.R8     = TrapFrame->R8;
    ContextRecord.R9     = TrapFrame->R9;
    ContextRecord.R10    = TrapFrame->R10;
    ContextRecord.R11    = TrapFrame->R11;
    ContextRecord.Rip    = TrapFrame->Rip;
    ContextRecord.EFlags = TrapFrame->EFlags;
    ContextRecord.SegCs  = TrapFrame->SegCs;
    ContextRecord.SegDs  = TrapFrame->SegDs;
    ContextRecord.SegEs  = TrapFrame->SegEs;
    ContextRecord.SegFs  = TrapFrame->SegFs;
    ContextRecord.SegGs  = TrapFrame->SegGs;
    ContextRecord.SegSs  = TrapFrame->SegSs;

    // Print the initial frame (the interrupted context).
    DbgPrint("[+] --- Trap Frame Info:\n");
    DbgPrint("  RAX -> 0x%llX\n", ContextRecord.Rax);
    DbgPrint("  RCX -> 0x%llX\n", ContextRecord.Rcx);
    DbgPrint("  RDX -> 0x%llX\n", ContextRecord.Rdx);
    DbgPrint("  RBX -> 0x%llX\n", ContextRecord.Rbx);
    DbgPrint("  RSP -> 0x%llX\n", ContextRecord.Rsp);
    DbgPrint("  RBP -> 0x%llX\n", ContextRecord.Rbp);
    DbgPrint("  RSI -> 0x%llX\n", ContextRecord.Rsi);
    DbgPrint("  RDI -> 0x%llX\n", ContextRecord.Rdi);
    DbgPrint("  R8  -> 0x%llX\n", ContextRecord.R8);
    DbgPrint("  R9  -> 0x%llX\n", ContextRecord.R9);
    DbgPrint("  R10 -> 0x%llX\n", ContextRecord.R10);
    DbgPrint("  R11 -> 0x%llX\n", ContextRecord.R11);
    DbgPrint("  RIP -> 0x%llX\n", ContextRecord.Rip);
    DbgPrint("  EFL -> 0x%lX\n", ContextRecord.EFlags);
    DbgPrint("  CS  -> 0x%X\n", ContextRecord.SegCs);
    DbgPrint("  DS  -> 0x%X\n", ContextRecord.SegDs);
    DbgPrint("  ES  -> 0x%X\n", ContextRecord.SegEs);
    DbgPrint("  FS  -> 0x%X\n", ContextRecord.SegFs);
    DbgPrint("  GS  -> 0x%X\n", ContextRecord.SegGs);
    DbgPrint("  SS  -> 0x%X\n", ContextRecord.SegSs);

    DbgPrint("[+] --- Begin Unwind-Data Stack Walk ---\n");
    DbgPrint("  [00] 0x%p (Interrupted RIP)\n", (PVOID)ContextRecord.Rip);

    ULONG64 RetrievedRipArray[MAX_STACK_FRAMES] = {0};
    RetrievedRipArray[0]                        = ContextRecord.Rip;

    for (int i = 1; i < MAX_STACK_FRAMES; i++)
    {
        ULONG64 ImageBase   = 0;
        PVOID   HandlerData = NULL;


        // Step 2: Find the runtime function entry for the current instruction pointer.
        // This reads the .pdata section of the PE file in memory.
        PRUNTIME_FUNCTION RuntimeFunction = RtlLookupFunctionEntry(ContextRecord.Rip, &ImageBase, NULL);

        if (!RuntimeFunction)
        {
            // We've likely reached the end of the call stack for which we have unwind data.
            break;
        }

        // Step 3: Call RtlVirtualUnwind to "go back in time" to the caller's context.
        // This function will read the current context, and using the unwind data,
        // it will modify the context record to reflect the state of the calling function.

        // We must pass a valid pointer, but we don't use it, otherwise a page-fault may occur (and a BSOD :().
        ULONG64 EstablisherFrame = {0};

        RtlVirtualUnwind(
            UNW_FLAG_NHANDLER,
            ImageBase,
            ContextRecord.Rip,
            RuntimeFunction,
            &ContextRecord,
            &HandlerData,
            &EstablisherFrame,
            NULL);

        // The Rip in the now-modified context record is our return address.
        if (!ContextRecord.Rip)
        {
            break;
        }

        DbgPrint("  [%02d] 0x%p\n", i, (PVOID)ContextRecord.Rip);
        RetrievedRipArray[i] = ContextRecord.Rip;
    }

    DbgPrint("[+] --- End Unwind-Data Stack Walk ---\n");

    // Add a newline for clarity.
    DbgPrint("\n");

    // Release the spinlock.
    KeReleaseSpinLockFromDpcLevel(&NmiContext->Lock);

    //
    // Here we check if all the retrieved RIPs are from signed modules.
    //
    for (int RipIndex = 0; RipIndex < MAX_STACK_FRAMES && RetrievedRipArray[RipIndex] != 0; RipIndex++)
    {
        // Use a pre-allocated item from our pool. This is safe at HIGH_LEVEL IRQL.
        LONG ItemIndex = InterlockedIncrement(&NmiContext->PoolIndex) - 1;
        if (ItemIndex < MAX_PENDING_CHECKS)
        {
            PSIGNATURE_CHECK_ITEM CheckItem = &NmiContext->CheckItemPool[ItemIndex];
            CheckItem->Rip = (PVOID)RetrievedRipArray[RipIndex]; // Use the last retrieved RIP for checking.

            ExInterlockedInsertTailList(&NmiContext->PendingCheckList, &CheckItem->ListEntry,
                                        &NmiContext->CheckListLock);
        }
        else
        {
            DbgPrint("[-] Signature check pool exhausted, dropping signature verification for this NMI.\n");
            break;
        }
    }

    // Schedule the DPC to queue the worker thread.
    KeInsertQueueDpc(&NmiContext->SignatureDpc, NULL, NULL);

    return TRUE;
}

// =================================================================================================
// == Deferred Checking Routines
// =================================================================================================

/**
 * @brief DPC routine that queues the worker thread.
 * @note Runs at DISPATCH_LEVEL.
 */
static VOID SignatureCheckDpcRoutine(
    _In_ PKDPC     Dpc, _In_opt_ PVOID             DeferredContext,
    _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2
)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    // Attempt to transition the worker state from inactive (0) to active (1).
    if (InterlockedCompareExchange(&G_NmiContext.IsWorkerActive, 1, 0) == 0)
    {
        // We successfully claimed the worker. Queue it.
        ExQueueWorkItem(&G_NmiContext.SignatureWorkItem, DelayedWorkQueue);
    }
    // If the state was already 1, another DPC has already queued the worker,
    // or the worker is currently running. We do nothing and let the active
    // worker handle the item we just added to the list.
}

/**
 * @brief Worker thread routine that performs the robust signature check.
 * @note Runs at PASSIVE_LEVEL.
 */
static VOID SignatureCheckWorkerRoutine(
    _In_ PVOID Parameter
)
{
    UNREFERENCED_PARAMETER(Parameter);

    PLIST_ENTRY ListEntry;
    while ((ListEntry = ExInterlockedRemoveHeadList(&G_NmiContext.PendingCheckList, &G_NmiContext.CheckListLock)) !=
        NULL)
    {
        PSIGNATURE_CHECK_ITEM CheckItem = CONTAINING_RECORD(ListEntry, SIGNATURE_CHECK_ITEM, ListEntry);
        if (CheckItem)
        {
            // This function call does all the heavy lifting at PASSIVE_LEVEL.
            VerifyModuleSignatureByRip(CheckItem->Rip);
        }
    }

    // Reset the pool index so the pre-allocated items can be reused.
    InterlockedExchange(&G_NmiContext.PoolIndex, 0);
}

/**
 * @brief Initializes the NMI callback for stack walking.
 *
 * @return STATUS_SUCCESS on success, otherwise an error code.
 */
NTSTATUS InitializeNmiHandler(void)
{
    // Check if already initialized.
    if (G_NmiCallbackHandle)
    {
        return STATUS_SUCCESS;
    }

    // Resolve CI functions before setting up the NMI handler.
    NTSTATUS Status = ResolveCiFunctions();
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[-] Failed to resolve CI functions: 0x%X\n", Status);
        return Status;
    }

    // Initialize our context structure.
    RtlZeroMemory(&G_NmiContext, sizeof(NMI_CONTEXT));
    G_NmiContext.MagicSignature = NMI_CONTEXT_SIGNATURE;
    G_NmiContext.PoolIndex      = 0;
    KeInitializeSpinLock(&G_NmiContext.Lock);

    // Initialize deferred checking resources.
    InitializeListHead(&G_NmiContext.PendingCheckList);
    KeInitializeSpinLock(&G_NmiContext.CheckListLock);
    KeInitializeDpc(&G_NmiContext.SignatureDpc, SignatureCheckDpcRoutine, NULL);
    ExInitializeWorkItem(&G_NmiContext.SignatureWorkItem, SignatureCheckWorkerRoutine, NULL);

    // Ensure the pending count starts at 0.
    G_NmiContext.PendingCount = 0;

    //
    // Register the NMI callback.
    //
    G_NmiCallbackHandle = KeRegisterNmiCallback(NmiCallback, &G_NmiContext);
    if (!G_NmiCallbackHandle)
    {
        DbgPrint("[-] Failed to register NMI callback.\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DbgPrint("[+] NMI callback and deferred checker registered successfully.\n");
    return STATUS_SUCCESS;
}

/**
 * @brief Deinitializes the NMI callback.
 */
VOID DeinitializeNmiHandler(void)
{
    if (G_NmiCallbackHandle)
    {
        KeDeregisterNmiCallback(G_NmiCallbackHandle);
        G_NmiCallbackHandle = NULL;
        DbgPrint("[+] NMI callback deregistered.\n");
    }
}

/**
 * @brief Locates the KTRAP_FRAME saved on the NMI stack.
 * This is an advanced technique that inspects core system structures.
 *
 * @return A pointer to the KTRAP_FRAME, or NULL on failure.
 */
PKTRAP_FRAME FindNmiTrapFrame(void)
{
    // Step 1: Get the IDT to find the NMI descriptor.
    SEGMENT_DESCRIPTOR_REGISTER_64 Idtr = {0};
    __sidt(&Idtr);
    if (Idtr.Limit == 0 || Idtr.BaseAddress == 0)
    {
        DbgPrint("[-] Invalid IDT.\n");
        return NULL;
    }

    // NMI is always vector 2.
    SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64* NmiDescriptor = (SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64*)(Idtr.BaseAddress + 2 *
        sizeof(SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64));

    // Step 2: Get the IST index from the NMI descriptor.
    UINT32 IstIndex = NmiDescriptor->InterruptStackTable;
    if (IstIndex == 0 || IstIndex > 7)
    {
        DbgPrint("[-] Invalid IST index in NMI descriptor: %u\n", IstIndex);
        return NULL;
    }

    // Step 3: Get the GDT and TSS to find the IST stack pointer.
    SEGMENT_DESCRIPTOR_REGISTER_64 Gdtr        = {0};
    SEGMENT_SELECTOR               TssSelector = {0};
    _sgdt(&Gdtr);
    _str(&TssSelector);

    if (Gdtr.Limit == 0 || Gdtr.BaseAddress == 0 || TssSelector.Index == 0)
    {
        DbgPrint("[-] Invalid GDT or TSS selector.\n");
        return NULL;
    }

    SEGMENT_DESCRIPTOR_64* TssDescriptor = (SEGMENT_DESCRIPTOR_64*)(Gdtr.BaseAddress + TssSelector.Index * sizeof(
        UINT64));

    // The TSS base address is split across multiple fields in its descriptor.
    UINT64 TssBase = ((UINT64)(TssDescriptor->BaseAddressLow)) |
        ((UINT64)(TssDescriptor->BaseAddressMiddle) << 16) |
        ((UINT64)(TssDescriptor->BaseAddressHigh) << 24) |
        ((UINT64)(TssDescriptor->BaseAddressUpper) << 32);

    TASK_STATE_SEGMENT_64* Tss = (TASK_STATE_SEGMENT_64*)TssBase;

    // Step 4: Get the top of the NMI stack from the TSS.
    // The TSS struct has Ist1..7, which corresponds to indices 1..7.
    // The IST index in the descriptor is 1-based.
    UINT64 IstStackTop = *(&Tss->Ist1 + (IstIndex - 1));
    if (!IstStackTop)
    {
        DbgPrint("[-] Failed to find a valid IST stack top for NMI.\n");
        return NULL;
    }

    // Step 5: The KTRAP_FRAME is placed at the top of the stack by the kernel.
    // The stack grows downwards, so the frame is located at the top address minus its size.
    PKTRAP_FRAME TrapFrame = (PKTRAP_FRAME)(IstStackTop - sizeof(KTRAP_FRAME));

    return TrapFrame;
}

/**
 * @brief Triggers an NMI on the current processor to perform a stack walk.
 */
VOID TriggerNmiStackwalk(void)
{
    // Assert that the IRQL is at PASSIVE_LEVEL using a macro (just to be sure that affinity changes are immediate).
    PAGED_CODE()

    // Pin execution to one CPU to avoid complications with thread migration.
    KAFFINITY OldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1ULL << KeGetCurrentProcessorNumberEx(NULL)));

    // Step 1: Initialize NMI handler if it not already initialized.
    NTSTATUS InitializationStatus = InitializeNmiHandler();
    if (!NT_SUCCESS(InitializationStatus))
    {
        DbgPrint("[-] Failed to initialize NMI handler: 0x%X\n", InitializationStatus);
        return;
    }

    // Step 2: Get the processor number of the core executing this request.
    // We will skip sending an NMI to ourselves.
    PROCESSOR_NUMBER CurrentProcNum = {0};
    KeGetCurrentProcessorNumberEx(&CurrentProcNum);

    // Step 3: Get the total number of active processors across all processor groups.
    ULONG TotalProcs = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    DbgPrint("[+] Request received on CPU %d (Group %d). Broadcasting NMIs to %d other processors...\n",
             CurrentProcNum.Number, CurrentProcNum.Group, TotalProcs - 1);

    if (TotalProcs <= 1)
    {
        DbgPrint("[-] Only one processor detected. Cannot broadcast NMI.\n");
        return;
    }

    // Initialize an empty affinity mask.
    KAFFINITY_EX Affinity = {0};
    KeInitializeAffinityEx(&Affinity);

    // Step 4: Iterate through all active processors by their system-wide index.
    for (ULONG ProcessorIndex = 0; ProcessorIndex < TotalProcs; ProcessorIndex++)
    {
        PROCESSOR_NUMBER TargetProcNum = {0};
        NTSTATUS         Status        = KeGetProcessorNumberFromIndex(ProcessorIndex, &TargetProcNum);

        if (!NT_SUCCESS(Status))
        {
            DbgPrint("[-] Failed to get processor number for index %d: 0x%X\n", ProcessorIndex, Status);
            continue;
        }

        // Step 5: Check if the target processor is the same as the current one.
        if (TargetProcNum.Group == CurrentProcNum.Group && TargetProcNum.Number == CurrentProcNum.Number)
        {
            // Skip sending NMI to ourselves.
            continue;
        }

        // Add the target processor to the affinity mask.
        KeAddProcessorAffinityEx(&Affinity, ProcessorIndex);

        //
        // Increment our pending counter BEFORE sending the NMI.
        // This creates the "pending" state that the NMI callback will check for.
        //
        InterlockedIncrement(&G_NmiContext.PendingCount);
    }

    // Multiply the G_NmiContext.PendingCount by the number of broadcasts we will do.
    InterlockedMultiply(&G_NmiContext.PendingCount, NMI_MAX_BROADCAST_COUNT);

    for (int NmiBroadcastCount = 0; NmiBroadcastCount < NMI_MAX_BROADCAST_COUNT; NmiBroadcastCount++)
    {
        DbgPrint("[*] Broadcasting NMI attempt %d...\n", NmiBroadcastCount + 1);
        // Step 6: Send the NMI to the target processors.
        HalSendNMI(&Affinity);

        // Wait a short moment to allow NMIs to be processed.
        LARGE_INTEGER WaitInterval = {0};
        WaitInterval.QuadPart      = -10ll * 1000 * 50; // 50 milliseconds in 100-nanosecond intervals
        KeDelayExecutionThread(KernelMode, FALSE, &WaitInterval);
    }

    DbgPrint("[+] NMIs sent.\n");

    // Step 7: Wait for all NMIs to be handled. Wait up to 5 seconds.
    LARGE_INTEGER Timeout      = {0};
    Timeout.QuadPart           = -10ll * 1000 * 5000; // 5 seconds in 100-nanosecond intervals
    LARGE_INTEGER WaitInterval = {0};
    WaitInterval.QuadPart      = -10ll * 1000 * 100; // 100 milliseconds in 100-nanosecond intervals
    while (G_NmiContext.PendingCount > 0 && Timeout.QuadPart < 0)
    {
        KeDelayExecutionThread(KernelMode, FALSE, &WaitInterval);
        Timeout.QuadPart -= WaitInterval.QuadPart;
    }

    // Step 8: Check if there was an NMI blocking issue.
    if (G_NmiContext.PendingCount != 0)
    {
        DbgPrint("[-] Warning: Some NMIs were not handled within the timeout period. Pending count: %ld\n",
                 G_NmiContext.PendingCount);
        // Reset the pending count to avoid stale state.
        G_NmiContext.PendingCount = 0;
    }
    else
    {
        DbgPrint("[+] All NMIs handled successfully.\n");
    }


    // Restore the original thread affinity.
    KeRevertToUserAffinityThreadEx(OldAffinity);
}
