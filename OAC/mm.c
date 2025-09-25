#include "mm.h"
#include "ia32.h"
#include "internals.h"

NTSTATUS MapVirtualAddressDynamically(PVOID pool_base, ULONG* next_free_page_index, PVOID target_va)
{
    PHYSICAL_ADDRESS pool_pa   = MmGetPhysicalAddress(pool_base);
    PHYSICAL_ADDRESS target_pa = MmGetPhysicalAddress(target_va);
    if (target_pa.QuadPart == 0)
    {
        DbgPrint("[-] Target VA 0x%p is not mapped in current page tables.\n", target_va);
        return STATUS_NOT_FOUND;
    }

    // The PML4 is always the first page in our pool.
    PML4E_64* pml4 = (PML4E_64*)pool_base;

    VIRTUAL_ADDRESS va = {.vaddr = (UINT64)target_va};

    // --- Level 1: PML4 -> PDPT ---
    PDPTE_64* pdpt;
    if (pml4[va.pml4_index].Present)
    {
        // Entry exists, follow it. Convert the PFN back to a VA within our pool.
        pdpt = (PDPTE_64*)((PUCHAR)pool_base + ((pml4[va.pml4_index].PageFrameNumber - (pool_pa.QuadPart >> 12)) <<
            12));
    }
    else
    {
        // No entry, allocate a new PDPT from our pool.
        if (*next_free_page_index >= PAGE_TABLE_POOL_PAGES)
        {
            DbgPrint("[-] Out of page table memory in pool.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        pdpt = (PDPTE_64*)((PUCHAR)pool_base + (*next_free_page_index) * PAGE_SIZE);
        RtlZeroMemory(pdpt, PAGE_SIZE);

        PHYSICAL_ADDRESS pdpt_pa            = {.QuadPart = pool_pa.QuadPart + (*next_free_page_index) * PAGE_SIZE};
        pml4[va.pml4_index].Present         = 1;
        pml4[va.pml4_index].Write           = 1;
        pml4[va.pml4_index].PageFrameNumber = pdpt_pa.QuadPart >> 12;
        (*next_free_page_index)++;
    }

    // --- Level 2: PDPT -> PD ---
    PDE_64* pd;
    if (pdpt[va.pdpt_index].Present)
    {
        pd = (PDE_64*)((PUCHAR)pool_base + ((pdpt[va.pdpt_index].PageFrameNumber - (pool_pa.QuadPart >> 12)) << 12));
    }
    else
    {
        if (*next_free_page_index >= PAGE_TABLE_POOL_PAGES)
        {
            DbgPrint("[-] Out of page table memory in pool.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        pd = (PDE_64*)((PUCHAR)pool_base + (*next_free_page_index) * PAGE_SIZE);
        RtlZeroMemory(pd, PAGE_SIZE);

        PHYSICAL_ADDRESS pd_pa              = {.QuadPart = pool_pa.QuadPart + (*next_free_page_index) * PAGE_SIZE};
        pdpt[va.pdpt_index].Present         = 1;
        pdpt[va.pdpt_index].Write           = 1;
        pdpt[va.pdpt_index].PageFrameNumber = pd_pa.QuadPart >> 12;
        (*next_free_page_index)++;
    }

    // --- Level 3: PD -> PT ---
    PTE_64* pt;
    if (pd[va.pd_index].Present)
    {
        pt = (PTE_64*)((PUCHAR)pool_base + ((pd[va.pd_index].PageFrameNumber - (pool_pa.QuadPart >> 12)) << 12));
    }
    else
    {
        if (*next_free_page_index >= PAGE_TABLE_POOL_PAGES)
        {
            DbgPrint("[-] Out of page table memory in pool.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        pt = (PTE_64*)((PUCHAR)pool_base + (*next_free_page_index) * PAGE_SIZE);
        RtlZeroMemory(pt, PAGE_SIZE);
        PHYSICAL_ADDRESS pt_pa          = {.QuadPart = pool_pa.QuadPart + (*next_free_page_index) * PAGE_SIZE};
        pd[va.pd_index].Present         = 1;
        pd[va.pd_index].Write           = 1;
        pd[va.pd_index].PageFrameNumber = pt_pa.QuadPart >> 12;
        (*next_free_page_index)++;
    }

    // --- Level 4: PT -> Page ---
    pt[va.pt_index].Present         = 1;
    pt[va.pt_index].Write           = 1;
    pt[va.pt_index].PageFrameNumber = target_pa.QuadPart >> 12;

    return STATUS_SUCCESS;
}
