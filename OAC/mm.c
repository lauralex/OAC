#include "mm.h"
#include "ia32.h"
#include "internals.h"

NTSTATUS MapVirtualAddressDynamically(PVOID PoolBase, ULONG* NextFreePageIndex, PVOID TargetVa)
{
    PHYSICAL_ADDRESS PoolPa   = MmGetPhysicalAddress(PoolBase);
    PHYSICAL_ADDRESS TargetPa = MmGetPhysicalAddress(TargetVa);
    if (TargetPa.QuadPart == 0)
    {
        DbgPrint("[-] Target VA 0x%p is not mapped in current page tables.\n", TargetVa);
        return STATUS_NOT_FOUND;
    }

    // The PML4 is always the first page in our pool.
    PML4E_64* Pml4 = (PML4E_64*)PoolBase;

    VIRTUAL_ADDRESS Va = {.Vaddr = (UINT64)TargetVa};

    // --- Level 1: PML4 -> PDPT ---
    PDPTE_64* Pdpt;
    if (Pml4[Va.Pml4Index].Present)
    {
        // Entry exists, follow it. Convert the PFN back to a VA within our pool.
        Pdpt = (PDPTE_64*)((PUCHAR)PoolBase + ((Pml4[Va.Pml4Index].PageFrameNumber - (PoolPa.QuadPart >> 12)) <<
            12));
    }
    else
    {
        // No entry, allocate a new PDPT from our pool.
        if (*NextFreePageIndex >= PAGE_TABLE_POOL_PAGES)
        {
            DbgPrint("[-] Out of page table memory in pool.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Pdpt = (PDPTE_64*)((PUCHAR)PoolBase + (*NextFreePageIndex) * PAGE_SIZE);
        RtlZeroMemory(Pdpt, PAGE_SIZE);

        PHYSICAL_ADDRESS PdptPa            = {.QuadPart = PoolPa.QuadPart + (*NextFreePageIndex) * PAGE_SIZE};
        Pml4[Va.Pml4Index].Present         = 1;
        Pml4[Va.Pml4Index].Write           = 1;
        Pml4[Va.Pml4Index].PageFrameNumber = PdptPa.QuadPart >> 12;
        (*NextFreePageIndex)++;
    }

    // --- Level 2: PDPT -> PD ---
    PDE_64* Pd;
    if (Pdpt[Va.PdptIndex].Present)
    {
        Pd = (PDE_64*)((PUCHAR)PoolBase + ((Pdpt[Va.PdptIndex].PageFrameNumber - (PoolPa.QuadPart >> 12)) << 12));
    }
    else
    {
        if (*NextFreePageIndex >= PAGE_TABLE_POOL_PAGES)
        {
            DbgPrint("[-] Out of page table memory in pool.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Pd = (PDE_64*)((PUCHAR)PoolBase + (*NextFreePageIndex) * PAGE_SIZE);
        RtlZeroMemory(Pd, PAGE_SIZE);

        PHYSICAL_ADDRESS PdPa              = {.QuadPart = PoolPa.QuadPart + (*NextFreePageIndex) * PAGE_SIZE};
        Pdpt[Va.PdptIndex].Present         = 1;
        Pdpt[Va.PdptIndex].Write           = 1;
        Pdpt[Va.PdptIndex].PageFrameNumber = PdPa.QuadPart >> 12;
        (*NextFreePageIndex)++;
    }

    // --- Level 3: PD -> PT ---
    PTE_64* Pt;
    if (Pd[Va.PdIndex].Present)
    {
        Pt = (PTE_64*)((PUCHAR)PoolBase + ((Pd[Va.PdIndex].PageFrameNumber - (PoolPa.QuadPart >> 12)) << 12));
    }
    else
    {
        if (*NextFreePageIndex >= PAGE_TABLE_POOL_PAGES)
        {
            DbgPrint("[-] Out of page table memory in pool.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Pt = (PTE_64*)((PUCHAR)PoolBase + (*NextFreePageIndex) * PAGE_SIZE);
        RtlZeroMemory(Pt, PAGE_SIZE);
        PHYSICAL_ADDRESS PtPa          = {.QuadPart = PoolPa.QuadPart + (*NextFreePageIndex) * PAGE_SIZE};
        Pd[Va.PdIndex].Present         = 1;
        Pd[Va.PdIndex].Write           = 1;
        Pd[Va.PdIndex].PageFrameNumber = PtPa.QuadPart >> 12;
        (*NextFreePageIndex)++;
    }

    // --- Level 4: PT -> Page ---
    Pt[Va.PtIndex].Present         = 1;
    Pt[Va.PtIndex].Write           = 1;
    Pt[Va.PtIndex].PageFrameNumber = TargetPa.QuadPart >> 12;

    return STATUS_SUCCESS;
}
