#include <ntddk.h>
#include <intrin.h>

#include "mm.h"
#include "isr.h"
#include "arch.h"
#include "cr3_thrasher.h"
#include "ia32.h"

// Global variable to share the original CR3 with our assembly ISR.
// This MUST be global.
UINT64 G_OriginalCr3 = 0;

// =================================================================================================
// == CR3 Thrashing / Anti-Hypervisor Test Routine
// =================================================================================================

VOID TriggerCr3Thrash(void)
{
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

    // Get the IDT
    SEGMENT_DESCRIPTOR_REGISTER_64 Idtr;
    __sidt(&Idtr);

    // Step 1: Set up our minimal page tables
    DbgPrint("[+] Dynamically mapping all the required pages...\n");

    // Map all the required VAs. Our dynamic mapper will handle any index collisions.
#pragma warning(suppress: 4152) // Suppress "function/data pointer conversion" warning
    MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx, &PageFaultIsr);
    MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx, &G_OriginalCr3);
    MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx, (PVOID)Idtr.BaseAddress);

    PVOID CurrentRip = GetRip();
    DbgPrint("[*] Current RIP: 0x%p\n", CurrentRip);
    MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx, CurrentRip);

    // Handle IDT spanning a page boundary
    if (((ULONG_PTR)Idtr.BaseAddress & ~0xFFF) != (((ULONG_PTR)Idtr.BaseAddress + Idtr.Limit) & ~0xFFF))
    {
        MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx,
                                     (PVOID)((PUCHAR)Idtr.BaseAddress + Idtr.Limit));
    }

    DbgPrint("[+] Pinning thread to current processor.\n");

    // Pin execution to the current processor.
    KAFFINITY OldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1ULL << KeGetCurrentProcessorNumberEx(NULL)));

    SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64* PageFaultDescriptor = (SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64*)(Idtr.BaseAddress
        + (14 * sizeof(SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64)));


    // Print the address of the IDT entry
    DbgPrint("[*] IDT pageFaultDescriptor: 0x%p\n", PageFaultDescriptor);

    // Save the original CR3
    G_OriginalCr3 = __readcr3();
    DbgPrint("[*] Original CR3: 0x%llX\n", G_OriginalCr3);

    // Create a new IDT entry for our custom ISR
    SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64 NewPfDescriptor = {0};

    NewPfDescriptor.OffsetLow                = (UINT16)((UINT64)PageFaultIsr & 0xFFFF);
    NewPfDescriptor.SegmentSelector          = PageFaultDescriptor->SegmentSelector;          // Kernel code segment
    NewPfDescriptor.Type                     = PageFaultDescriptor->Type;                     // 64-bit interrupt gate
    NewPfDescriptor.DescriptorPrivilegeLevel = PageFaultDescriptor->DescriptorPrivilegeLevel; // Kernel level
    NewPfDescriptor.Present                  = PageFaultDescriptor->Present;
    NewPfDescriptor.OffsetMiddle             = (UINT16)(((UINT64)PageFaultIsr >> 16) & 0xFFFF);
    NewPfDescriptor.OffsetHigh               = (UINT32)(((UINT64)PageFaultIsr >> 32) & 0xFFFFFFFF);
    NewPfDescriptor.InterruptStackTable      = PageFaultDescriptor->InterruptStackTable; // Use same IST as original
    NewPfDescriptor.Reserved                 = PageFaultDescriptor->Reserved;


    // Discover the existing IST stack used by the default PF handler
    UINT32 IstIndex = PageFaultDescriptor->InterruptStackTable;
    if (IstIndex == 0)
    {
        DbgPrint("[-] Original Page Fault handler does not use IST. Aborting.\n");
        KeRevertToUserAffinityThreadEx(OldAffinity);
        MmFreeContiguousMemory(PageTablePool);
        return;
    }

    DbgPrint("[*] Original Page Fault handler IST index: %u\n", IstIndex);

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

    // Get the stack top from the correct IST entry.
    // The TSS struct has Ist1..7, which corresponds to indices 1..7.
    UINT64 IstStackTop  = *(&Tss->Ist1 + (IstIndex - 1));
    UINT64 IstStackBase = IstStackTop - 0x6000; // Assume 24KB stack size
    DbgPrint("[*] IST stack for PF handler: 0x%llX - 0x%llX\n", IstStackBase, IstStackTop);

    // Map all pages of the discovered IST stack
    for (UINT64 Addr = IstStackBase; Addr < IstStackTop; Addr += PAGE_SIZE)
    {
        MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx, (PVOID)Addr);
    }

    DbgPrint("[!!} Entering CRITICAL section. Disabling interrupts.\n");
    DbgPrint("[!!] Swapping IDT entry and thrashing CR3...\n");

    // --- CRITICAL SECTION START ---
    _disable(); // Disable Interrupts

    // == BYPASS WRITE PROTECTION TO MODIFY IDT ==
    UINT64 OriginalCr0 = __readcr0();
    UINT64 NewCr0      = OriginalCr0 & (~0x10000); // Clear WP bit (bit 16)
    __writecr0(NewCr0);
    // ===========================================

    // Save the original Page Fault handler entry struct
    SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64 OriginalPfDescriptor = {0};
    RtlCopyMemory(&OriginalPfDescriptor, PageFaultDescriptor, sizeof(SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64));

    // Overwrite the IDT entry for the Page Fault handler
    RtlCopyMemory(PageFaultDescriptor, &NewPfDescriptor, sizeof(SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64));

    // == RE-ENABLE WRITE PROTECTION IMMEDIATELY ==
    __writecr0(OriginalCr0);
    // ============================================

    // Thrash CR3 to trigger page faults
    CR3 Cr3                    = {.AsUInt = G_OriginalCr3};
    Cr3.AddressOfPageDirectory = (NewPml4Pa.QuadPart >> 12);

    __writecr3(Cr3.AsUInt);

    // Cause an unconditional VM-exit on some hypervisors.
    _invd();

    // Deliberately cause a page fault. This MUST fail.
    // The write is volatile to prevent compiler optimization.
    *(volatile char*)0xDEADBEEF = 1;

    // --- EXECUTION RESUMES HERE AFTER ISR RESTORES ORIGINAL CR3 ---
    // The CPU state is now back to normal, but interrupts are still off.

    // == BYPASS WRITE PROTECTION TO MODIFY IDT ==
    OriginalCr0 = __readcr0();
    NewCr0      = OriginalCr0 & (~0x10000); // Clear WP bit (bit 16)
    __writecr0(NewCr0);
    // ===========================================

    // Restore the original IDT entry
    RtlCopyMemory(PageFaultDescriptor, &OriginalPfDescriptor, sizeof(SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64));

    // == RE-ENABLE WRITE PROTECTION IMMEDIATELY ==
    __writecr0(OriginalCr0);
    // ============================================

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
