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
    PHYSICAL_ADDRESS new_pml4_pa     = {0};
    PVOID            page_table_pool = NULL;

    // Allocate our pool of pages for the new page table hierarchy.
    page_table_pool = MmAllocateContiguousMemory(PAGE_SIZE * PAGE_TABLE_POOL_PAGES, (PHYSICAL_ADDRESS){.QuadPart = -1});
    if (!page_table_pool)
    {
        DbgPrint("[-] MmAllocateContiguousMemory failed\n");
        return;
    }

    // Print page table pool address
    DbgPrint("[*] Page table pool VA: 0x%p\n", page_table_pool);

    RtlZeroMemory(page_table_pool, PAGE_SIZE * PAGE_TABLE_POOL_PAGES);
    new_pml4_pa = MmGetPhysicalAddress(page_table_pool);

    // Print physical address of the pool
    DbgPrint("[*] Page table pool PA: 0x%llX\n", new_pml4_pa.QuadPart);

    // The first page of the pool is the PML4. Subsequent pages are allocated as needed.
    ULONG next_free_page_idx = 1;

    // Get the IDT
    SEGMENT_DESCRIPTOR_REGISTER_64 idtr;
    __sidt(&idtr);

    // Step 1: Set up our minimal page tables
    DbgPrint("[+] Dynamically mapping all the required pages...\n");

    // Map all the required VAs. Our dynamic mapper will handle any index collisions.
#pragma warning(suppress: 4152) // Suppress "function/data pointer conversion" warning
    MapVirtualAddressDynamically(page_table_pool, &next_free_page_idx, &PageFaultIsr);
    MapVirtualAddressDynamically(page_table_pool, &next_free_page_idx, &G_OriginalCr3);
    MapVirtualAddressDynamically(page_table_pool, &next_free_page_idx, (PVOID)idtr.BaseAddress);

    PVOID currentRip = GetRIP();
    DbgPrint("[*] Current RIP: 0x%p\n", currentRip);
    MapVirtualAddressDynamically(page_table_pool, &next_free_page_idx, currentRip);

    // Handle IDT spanning a page boundary
    if (((ULONG_PTR)idtr.BaseAddress & ~0xFFF) != (((ULONG_PTR)idtr.BaseAddress + idtr.Limit) & ~0xFFF))
    {
        MapVirtualAddressDynamically(page_table_pool, &next_free_page_idx,
                                     (PVOID)((PUCHAR)idtr.BaseAddress + idtr.Limit));
    }

    DbgPrint("[+] Pinning thread to current processor.\n");

    // Pin execution to the current processor.
    KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1ULL << KeGetCurrentProcessorNumberEx(NULL)));

    SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64* pageFaultDescriptor = (SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64*)(idtr.BaseAddress
        + (14 * sizeof(SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64)));


    // Print the address of the IDT entry
    DbgPrint("[*] IDT pageFaultDescriptor: 0x%p\n", pageFaultDescriptor);

    // Save the original CR3
    G_OriginalCr3 = __readcr3();
    DbgPrint("[*] Original CR3: 0x%llX\n", G_OriginalCr3);

    // Create a new IDT entry for our custom ISR
    SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64 newPfDescriptor = {0};

    newPfDescriptor.OffsetLow                = (UINT16)((UINT64)PageFaultIsr & 0xFFFF);
    newPfDescriptor.SegmentSelector          = pageFaultDescriptor->SegmentSelector;          // Kernel code segment
    newPfDescriptor.Type                     = pageFaultDescriptor->Type;                     // 64-bit interrupt gate
    newPfDescriptor.DescriptorPrivilegeLevel = pageFaultDescriptor->DescriptorPrivilegeLevel; // Kernel level
    newPfDescriptor.Present                  = pageFaultDescriptor->Present;
    newPfDescriptor.OffsetMiddle             = (UINT16)(((UINT64)PageFaultIsr >> 16) & 0xFFFF);
    newPfDescriptor.OffsetHigh               = (UINT32)(((UINT64)PageFaultIsr >> 32) & 0xFFFFFFFF);
    newPfDescriptor.InterruptStackTable      = pageFaultDescriptor->InterruptStackTable; // Use same IST as original
    newPfDescriptor.Reserved                 = pageFaultDescriptor->Reserved;


    // Discover the existing IST stack used by the default PF handler
    UINT32 ist_index = pageFaultDescriptor->InterruptStackTable;
    if (ist_index == 0)
    {
        DbgPrint("[-] Original Page Fault handler does not use IST. Aborting.\n");
        KeRevertToUserAffinityThreadEx(oldAffinity);
        MmFreeContiguousMemory(page_table_pool);
        return;
    }

    DbgPrint("[*] Original Page Fault handler IST index: %u\n", ist_index);

    SEGMENT_DESCRIPTOR_REGISTER_64 gdtr         = {0};
    SEGMENT_SELECTOR               tss_selector = {0};
    _sgdt(&gdtr);
    _str(&tss_selector);
    SEGMENT_DESCRIPTOR_64* tss_descriptor = (SEGMENT_DESCRIPTOR_64*)(gdtr.BaseAddress + tss_selector.Index * sizeof(
        UINT64));

    UINT64 tss_base = ((UINT64)(tss_descriptor->BaseAddressLow)) |
        ((UINT64)(tss_descriptor->BaseAddressMiddle) << 16) |
        ((UINT64)(tss_descriptor->BaseAddressHigh) << 24) |
        ((UINT64)(tss_descriptor->BaseAddressUpper) << 32);

    TASK_STATE_SEGMENT_64* tss = (TASK_STATE_SEGMENT_64*)tss_base;

    // Get the stack top from the correct IST entry.
    // The TSS struct has Ist1..7, which corresponds to indices 1..7.
    UINT64 ist_stack_top  = *(&tss->Ist1 + (ist_index - 1));
    UINT64 ist_stack_base = ist_stack_top - 0x6000; // Assume 24KB stack size
    DbgPrint("[*] IST stack for PF handler: 0x%llX - 0x%llX\n", ist_stack_base, ist_stack_top);

    // Map all pages of the discovered IST stack
    for (UINT64 addr = ist_stack_base; addr < ist_stack_top; addr += PAGE_SIZE)
    {
        MapVirtualAddressDynamically(page_table_pool, &next_free_page_idx, (PVOID)addr);
    }

    DbgPrint("[!!} Entering CRITICAL section. Disabling interrupts.\n");
    DbgPrint("[!!] Swapping IDT entry and thrashing CR3...\n");

    // --- CRITICAL SECTION START ---
    _disable(); // Disable Interrupts

    // == BYPASS WRITE PROTECTION TO MODIFY IDT ==
    UINT64 originalCr0 = __readcr0();
    UINT64 newCr0      = originalCr0 & (~0x10000); // Clear WP bit (bit 16)
    __writecr0(newCr0);
    // ===========================================

    // Save the original Page Fault handler entry struct
    SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64 originalPfDescriptor = {0};
    RtlCopyMemory(&originalPfDescriptor, pageFaultDescriptor, sizeof(SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64));

    // Overwrite the IDT entry for the Page Fault handler
    RtlCopyMemory(pageFaultDescriptor, &newPfDescriptor, sizeof(SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64));

    // == RE-ENABLE WRITE PROTECTION IMMEDIATELY ==
    __writecr0(originalCr0);
    // ============================================

    // Thrash CR3 to trigger page faults
    CR3 cr3                    = {.AsUInt = G_OriginalCr3};
    cr3.AddressOfPageDirectory = (new_pml4_pa.QuadPart >> 12);

    __writecr3(cr3.AsUInt);

    // Cause an unconditional VM-exit on some hypervisors.
    _invd();

    // Deliberately cause a page fault. This MUST fail.
    // The write is volatile to prevent compiler optimization.
    *(volatile char*)0xDEADBEEF = 1;

    // --- EXECUTION RESUMES HERE AFTER ISR RESTORES ORIGINAL CR3 ---
    // The CPU state is now back to normal, but interrupts are still off.

    // == BYPASS WRITE PROTECTION TO MODIFY IDT ==
    originalCr0 = __readcr0();
    newCr0      = originalCr0 & (~0x10000); // Clear WP bit (bit 16)
    __writecr0(newCr0);
    // ===========================================

    // Restore the original IDT entry
    RtlCopyMemory(pageFaultDescriptor, &originalPfDescriptor, sizeof(SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64));

    // == RE-ENABLE WRITE PROTECTION IMMEDIATELY ==
    __writecr0(originalCr0);
    // ============================================

    // Restore original CR3 (should already be restored by the ISR, but just in case)
    __writecr3(G_OriginalCr3);

    _enable(); // Re-enable Interrupts
    // --- CRITICAL SECTION END ---

    DbgPrint("[!!] CRITICAL section finished. System stable.\n");

    // Restore the original thread affinity.
    KeRevertToUserAffinityThreadEx(oldAffinity);

    DbgPrint("[+] Thread affinity restored. Test complete.\n");

    // Step 2: Clean up the memory we allocated
    if (page_table_pool)
    {
        MmFreeContiguousMemory(page_table_pool);
        DbgPrint("[+] Freed page table memory.\n");
    }

    DbgPrint("[+] Test complete.\n");
}
