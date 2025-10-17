/**
 * @file mm.c
 * @brief Memory management helper functions.
 *
 * This file contains helper functions for managing memory, particularly for
 * setting up and manipulating page tables in a custom manner.
 */

#include "mm.h"
#include "ia32.h"
#include "internals.h"

/**
 * @brief Dynamically maps a virtual address into our custom page table hierarchy,
 *        allocating new tables from a pool as needed to resolve index collisions.
 *
 * @param[in]    PoolBase The virtual address of our pre-allocated page pool.
 * @param[inout] NextFreePageIndex A pointer to an index tracking the next free page in the pool.
 * @param[in]    TargetVa The virtual address of the page we want to map.
 * @return STATUS_SUCCESS on success, or an error code.
 */
NTSTATUS MapVirtualAddressDynamically(
    _In_ PVOID     PoolBase,
    _Inout_ ULONG* NextFreePageIndex,
    _In_ PVOID     TargetVa
)
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

/**
 * @brief Retrieves the PTE for a given virtual address from a specified DTB.
 *
 * @param[in] Dtb The Directory Table Base (CR3) of the target process.
 * @param[in] Va The virtual address to translate.
 * @return The PTE_64 structure corresponding to the virtual address, or an empty PTE_64 if not found.
 */
PTE_64 GetPteForVa(
    _In_ PVOID Dtb,
    _In_ PVOID Va
)
{
    VIRTUAL_ADDRESS  VirtAddr = {.Vaddr = (UINT64)Va};
    PHYSICAL_ADDRESS DtbPa    = {.QuadPart = (LONGLONG)((UINT64)Dtb & ~0xFFFull)};
    PML4E_64*        Pml4     = (PML4E_64*)MmMapIoSpace(DtbPa, PAGE_SIZE, MmNonCached);
    if (!Pml4)
    {
        DbgPrint("[-] Failed to map PML4 at PA 0x%llx\n", DtbPa.QuadPart);
        PTE_64 FoundPte = {0};
        return FoundPte;
    }
    if (!Pml4[VirtAddr.Pml4Index].Present)
    {
        DbgPrint("[-] PML4E not present for VA 0x%p\n", Va);
        MmUnmapIoSpace(Pml4, PAGE_SIZE);
        PTE_64 FoundPte = {0};
        return FoundPte;
    }
    PHYSICAL_ADDRESS PdptPa = {.QuadPart = (UINT64)(Pml4[VirtAddr.Pml4Index].PageFrameNumber << 12)};
    PDPTE_64*        Pdpt   = (PDPTE_64*)MmMapIoSpace(PdptPa, PAGE_SIZE, MmNonCached);
    if (!Pdpt)
    {
        DbgPrint("[-] Failed to map PDPT at PA 0x%llx\n", PdptPa.QuadPart);
        MmUnmapIoSpace(Pml4, PAGE_SIZE);
        PTE_64 FoundPte = {0};
        return FoundPte;
    }
    if (!Pdpt[VirtAddr.PdptIndex].Present)
    {
        DbgPrint("[-] PDPTE not present for VA 0x%p\n", Va);
        MmUnmapIoSpace(Pdpt, PAGE_SIZE);
        MmUnmapIoSpace(Pml4, PAGE_SIZE);
        PTE_64 FoundPte = {0};
        return FoundPte;
    }
    if (Pdpt[VirtAddr.PdptIndex].LargePage)
    {
        MmUnmapIoSpace(Pml4, PAGE_SIZE);

        PTE_64 FoundPte = {0};
        RtlCopyMemory(&FoundPte, &Pdpt[VirtAddr.PdptIndex], sizeof(FoundPte));

        MmUnmapIoSpace(Pdpt, PAGE_SIZE);

        return FoundPte;
    }

    PHYSICAL_ADDRESS PdPa = {.QuadPart = (UINT64)(Pdpt[VirtAddr.PdptIndex].PageFrameNumber << 12)};
    PDE_64*          Pd   = (PDE_64*)MmMapIoSpace(PdPa, PAGE_SIZE, MmNonCached);
    if (!Pd)
    {
        DbgPrint("[-] Failed to map PD at PA 0x%llx\n", PdPa.QuadPart);
        MmUnmapIoSpace(Pdpt, PAGE_SIZE);
        MmUnmapIoSpace(Pml4, PAGE_SIZE);
        PTE_64 FoundPte = {0};
        return FoundPte;
    }

    if (!Pd[VirtAddr.PdIndex].Present)
    {
        DbgPrint("[-] PDE not present for VA 0x%p\n", Va);
        MmUnmapIoSpace(Pd, PAGE_SIZE);
        MmUnmapIoSpace(Pdpt, PAGE_SIZE);
        MmUnmapIoSpace(Pml4, PAGE_SIZE);
        PTE_64 FoundPte = {0};
        return FoundPte;
    }

    if (Pd[VirtAddr.PdIndex].LargePage)
    {
        MmUnmapIoSpace(Pdpt, PAGE_SIZE);
        MmUnmapIoSpace(Pml4, PAGE_SIZE);

        PTE_64 FoundPte = {0};
        RtlCopyMemory(&FoundPte, &Pd[VirtAddr.PdIndex], sizeof(FoundPte));

        MmUnmapIoSpace(Pd, PAGE_SIZE);

        return FoundPte;
    }

    PHYSICAL_ADDRESS PtPa = {.QuadPart = (UINT64)(Pd[VirtAddr.PdIndex].PageFrameNumber << 12)};
    PTE_64*          Pt   = (PTE_64*)MmMapIoSpace(PtPa, PAGE_SIZE, MmNonCached);
    if (!Pt)
    {
        DbgPrint("[-] Failed to map PT at PA 0x%llx\n", PtPa.QuadPart);
        MmUnmapIoSpace(Pd, PAGE_SIZE);
        MmUnmapIoSpace(Pdpt, PAGE_SIZE);
        MmUnmapIoSpace(Pml4, PAGE_SIZE);
        PTE_64 FoundPte = {0};
        return FoundPte;
    }
    if (!Pt[VirtAddr.PtIndex].Present)
    {
        DbgPrint("[-] PTE not present for VA 0x%p\n", Va);
        MmUnmapIoSpace(Pt, PAGE_SIZE);
        MmUnmapIoSpace(Pd, PAGE_SIZE);
        MmUnmapIoSpace(Pdpt, PAGE_SIZE);
        MmUnmapIoSpace(Pml4, PAGE_SIZE);
        PTE_64 FoundPte = {0};
        return FoundPte;
    }
    MmUnmapIoSpace(Pd, PAGE_SIZE);
    MmUnmapIoSpace(Pdpt, PAGE_SIZE);
    MmUnmapIoSpace(Pml4, PAGE_SIZE);

    PTE_64 FoundPte = {0};
    RtlCopyMemory(&FoundPte, &Pt[VirtAddr.PtIndex], sizeof(FoundPte));

    MmUnmapIoSpace(Pt, PAGE_SIZE);

    return FoundPte;
}
