/**
 * @file cr3_thrasher.c
 * @brief Implements a CR3 thrashing routine to test for hypervisor presence.
 *
 * This code sets up a minimal page table hierarchy in a contiguous memory pool,
 * modifies the IDT to point to a custom page fault handler, and then thrashes
 * the CR3 register to trigger page faults. The custom handler restores the original
 * CR3 and IDT, ensuring system stability.
 *
 * Note: This code is intended for educational purposes only. Running it on a
 * production system may cause instability or crashes.
 */

#include "cr3_thrasher.h"
#include "globals.h"
#include "mm.h"
#include "isr.h"
#include "arch.h"
#include "ia32.h"
#include "serial_logger.h"

#include <ntddk.h>
#include <intrin.h>

/**
 * @brief Global variable to share the original CR3 with our assembly ISR, defined in cr3_thrasher.c.
 */
UINT64 G_OriginalCr3 = 0;

// Global array to hold a copy of the IDT for our ISR to use.
SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64 Cr3ThrashIdtArray[256] = {0};

// =================================================================================================
// == CR3 Thrashing / Anti-Hypervisor Test Routine
// =================================================================================================

VOID TriggerCr3Thrash(VOID)
{
    // Initialize the serial logger
    LoggerInit();

    PHYSICAL_ADDRESS NewPml4Pa     = {0};
    PVOID            PageTablePool = NULL;

    // Allocate our pool of pages for the new page table hierarchy.
    PageTablePool = MmAllocateContiguousMemory(PAGE_SIZE * PAGE_TABLE_POOL_PAGES, (PHYSICAL_ADDRESS){.QuadPart = -1});
    if (!PageTablePool)
    {
        DbgPrint("[-] MmAllocateContiguousMemory failed\n");
        return;
    }

    // Print page table pool address
    DbgPrint("[*] Page table pool VA: 0x%p\n", PageTablePool);

    RtlZeroMemory(PageTablePool, PAGE_SIZE * PAGE_TABLE_POOL_PAGES);
    NewPml4Pa = MmGetPhysicalAddress(PageTablePool);

    // Print physical address of the pool
    DbgPrint("[*] Page table pool PA: 0x%llX\n", NewPml4Pa.QuadPart);

    // The first page of the pool is the PML4. Subsequent pages are allocated as needed.
    ULONG NextFreePageIdx = 1;

    // Pin execution to the current processor.
    KAFFINITY OldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1ULL << KeGetCurrentProcessorNumberEx(NULL)));

    DbgPrint("[+] Pinning thread to current processor.\n");

    // Get the IDT
    SEGMENT_DESCRIPTOR_REGISTER_64 Idtr = {0};
    __sidt(&Idtr);

    // Step 1: Set up our minimal page tables
    DbgPrint("[+] Dynamically mapping all the required pages...\n");

    // Map all the required VAs. Our dynamic mapper will handle any index collisions.
#pragma warning(suppress: 4152) // Suppress "function/data pointer conversion" warning
    MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx, &PageFaultIsr);
    MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx, &G_OriginalCr3);
    MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx, (PVOID)Idtr.BaseAddress);
    MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx, Cr3ThrashIdtArray);

    // Map the current RIP region
    PVOID CurrentRip = GetRip();
    DbgPrint("[*] Current RIP: 0x%p\n", CurrentRip);
    MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx, CurrentRip);

    // Map also one page ahead (just in case)
    MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx, (PUCHAR)CurrentRip + 0x1000);

    // Handle IDT spanning a page boundary
    if (((ULONG_PTR)Idtr.BaseAddress & ~0xFFF) != (((ULONG_PTR)Idtr.BaseAddress + Idtr.Limit) & ~0xFFF))
    {
        MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx,
                                     (PVOID)((PUCHAR)Idtr.BaseAddress + Idtr.Limit));
    }

    // Save the original CR3
    G_OriginalCr3 = __readcr3();
    DbgPrint("[*] Original CR3: 0x%llX\n", G_OriginalCr3);

    // Copy the original IDT to our global array for the ISR to use.
    RtlCopyMemory(Cr3ThrashIdtArray, (PVOID)Idtr.BaseAddress, sizeof(Cr3ThrashIdtArray));

    // Modify the IDT entry for the Page Fault (vector 14) to point to our custom handler.
    SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64* NewPfDescriptor = &Cr3ThrashIdtArray[14];

    NewPfDescriptor->OffsetLow    = (UINT16)((UINT64)PageFaultIsr & 0xFFFF);
    NewPfDescriptor->OffsetMiddle = (UINT16)(((UINT64)PageFaultIsr >> 16) & 0xFFFF);
    NewPfDescriptor->OffsetHigh   = (UINT32)(((UINT64)PageFaultIsr >> 32) & 0xFFFFFFFF);

    // Discover the existing IST stack used by the default PF handler
    UINT32 IstIndex = NewPfDescriptor->InterruptStackTable;

    // We must locate the TSS (Task State Segment) to find the interrupt stack pointers.
    SEGMENT_DESCRIPTOR_REGISTER_64 Gdtr        = {0};
    SEGMENT_SELECTOR               TssSelector = {0};
    _sgdt(&Gdtr);
    _str(&TssSelector);
    SEGMENT_DESCRIPTOR_64* TssDescriptor = (SEGMENT_DESCRIPTOR_64*)(Gdtr.BaseAddress + TssSelector.Index * sizeof(
        UINT64));

    UINT64 TssBase = ((UINT64)(TssDescriptor->BaseAddressLow)) |
        ((UINT64)(TssDescriptor->BaseAddressMiddle) << 16) |
        ((UINT64)(TssDescriptor->BaseAddressHigh) << 24) |
        ((UINT64)(TssDescriptor->BaseAddressUpper) << 32);

    TASK_STATE_SEGMENT_64* Tss = (TASK_STATE_SEGMENT_64*)TssBase;

    UINT64 StackTop  = 0;
    UINT64 StackBase = 0;

    if (IstIndex == 0)
    {
        // IST index is 0, which means we use the legacy mechanism. For a ring-0 interrupt,
        // the CPU will use the RSP0 field from the TSS.
        DbgPrint("[*] Original Page Fault handler does not use IST. Using legacy RSP0 stack.\n");
        StackTop  = Tss->Rsp0;
        StackBase = StackTop - 0x10000; // Assume 64KB maximum stack size
    }
    else
    {
        // An IST index is specified. Get the stack top from the correct IST entry.
        // The TSS struct has Ist1..7, which corresponds to indices 1..7.
        DbgPrint("[*] Original Page Fault handler IST index: %u\n", IstIndex);
        StackTop  = *(&Tss->Ist1 + (IstIndex - 1));
        StackBase = StackTop - 0x10000; // Assume 64KB maximum stack size
    }

    // Map all pages of the discovered IST stack
    for (UINT64 Addr = StackBase; Addr < StackTop; Addr += PAGE_SIZE)
    {
        MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx, (PVOID)Addr);
    }

    DbgPrint("[!!} Entering CRITICAL section. Disabling interrupts.\n");
    DbgPrint("[!!] Swapping IDT entry and thrashing CR3...\n");

    // --- CRITICAL SECTION START ---
    _disable(); // Disable Interrupts

    // Swap the IDTR to point to our modified IDT with the custom PF handler.
    SEGMENT_DESCRIPTOR_REGISTER_64 Cr3ThrashIdtr = Idtr;
    Cr3ThrashIdtr.BaseAddress                    = (UINT64)Cr3ThrashIdtArray;
    __lidt(&Cr3ThrashIdtr);

    // Thrash CR3 to trigger page faults
    CR3 Cr3                    = {.AsUInt = G_OriginalCr3};
    Cr3.AddressOfPageDirectory = (NewPml4Pa.QuadPart >> 12);

    __writecr3(Cr3.AsUInt);

    // Cause an unconditional VM-exit.
    int DummyCpuId[4] = {0};
    __cpuid(DummyCpuId, 0);

    // Deliberately cause a page fault. This MUST fail.
    // The write is volatile to prevent compiler optimization.
    *(volatile char*)0x0 = 1;

    // --- EXECUTION RESUMES HERE AFTER ISR RESTORES ORIGINAL CR3 ---
    // The CPU state is now back to normal, but interrupts are still off.

    // Restore the original IDTR
    __lidt(&Idtr);

    // Restore original CR3 (should already be restored by the ISR, but just in case)
    __writecr3(G_OriginalCr3);

    _enable(); // Re-enable Interrupts
    // --- CRITICAL SECTION END ---

    DbgPrint("[!!] CRITICAL section finished. System stable.\n");

    // Restore the original thread affinity.
    KeRevertToUserAffinityThreadEx(OldAffinity);

    DbgPrint("[+] Thread affinity restored. Test complete.\n");

    // Step 2: Clean up the memory we allocated
    if (PageTablePool)
    {
        MmFreeContiguousMemory(PageTablePool);
        DbgPrint("[+] Freed page table memory.\n");
    }

    DbgPrint("[+] Test complete.\n");
}
