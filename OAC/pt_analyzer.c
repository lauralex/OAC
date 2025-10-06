#include "pt_analyzer.h"
#include "internals.h"
#include "stackwalk.h"
#include "globals.h"

#define PT_ENTRY_COUNT 512
#define KERNEL_MODE_BOUNDARY 0xFFFF800000000000ULL

// === Internal Function Prototypes ===

static VOID WalkPageTableHierarchy(
    _In_ PEPROCESS Process,
    _In_ UINT64    DirectoryTableBase
);

static VOID WalkPdpt(
    _In_ PEPROCESS Process,
    _In_ PDPTE_64* Pdpt,
    _In_ UINT64    Pml4eVa,
    _In_ BOOLEAN   IsUserChain

);


static VOID WalkPd(
    _In_ PEPROCESS Process,
    _In_ PDE_64*   Pd,
    _In_ UINT64    PdpteVa,
    _In_ BOOLEAN   IsUserChain
);

static VOID WalkPt(
    _In_ PEPROCESS Process,
    _In_ PTE_64*   Pt,
    _In_ UINT64    PdeVa,
    _In_ BOOLEAN   IsUserChain
);

// === Public Function Implementation ===

VOID AnalyzeProcessPageTables(
    _In_ PEPROCESS TargetProcess
)
{
    PAGED_CODE()

    if (!TargetProcess) return;

    // Get the process's DTB (DirectoryTableBase).
    UINT64 ProcessDtb = TargetProcess->Pcb.DirectoryTableBase;
    CR3    ProcessCr3 = {.AsUInt = ProcessDtb};
    CR3    SystemCr3  = {.AsUInt = G_NmiContext.SystemCr3};

    // Skip the system process and idle as they have legitimate kernel mappings.
    if (ProcessCr3.AddressOfPageDirectory == SystemCr3.AddressOfPageDirectory || (UINT64)PsGetProcessId(TargetProcess)
        <= 4)
    {
        return;
    }

    DbgPrint("[+] Analyzing page tables for process PID: %llu\n", (UINT64)PsGetProcessId(TargetProcess));
    WalkPageTableHierarchy(TargetProcess, ProcessDtb);
}

// === Internal Walker Implementation ===

/**
 * @brief Begins the recursive walk of a process's page tables starting from the PML4.
 */
static VOID WalkPageTableHierarchy(
    _In_ PEPROCESS Process,
    _In_ UINT64    DirectoryTableBase
)
{
    CR3              CurrentProcessCr3 = {.AsUInt = DirectoryTableBase};
    PHYSICAL_ADDRESS Pml4Pa            = {.QuadPart = (LONGLONG)(CurrentProcessCr3.AddressOfPageDirectory << 12)};
    PML4E_64*        Pml4              = MmMapIoSpace(Pml4Pa, PAGE_SIZE, MmNonCached);

    if (!Pml4) return;

    for (int Pml4Index = 256; Pml4Index < PT_ENTRY_COUNT; Pml4Index++)
    {
        if (Pml4[Pml4Index].Present)
        {
            PHYSICAL_ADDRESS PdptPa = {.QuadPart = (LONGLONG)(Pml4[Pml4Index].PageFrameNumber << 12)};
            PDPTE_64*        Pdpt   = MmMapIoSpace(PdptPa, PAGE_SIZE, MmNonCached);

            if (Pdpt)
            {
                // Construct the base virtual address this PML4 entry covers
                UINT64 Pml4eVa = (UINT64)Pml4Index << 39;
                // Sign extend if it's a kernel address
                if (Pml4Index >= 256) Pml4eVa |= 0xFFFF000000000000;

                // Start the permission chain check.
                BOOLEAN IsUserChain = (Pml4[Pml4Index].Supervisor == 1);
                WalkPdpt(Process, Pdpt, Pml4eVa, IsUserChain);

                // Unmap the PDPT after processing
                MmUnmapIoSpace(Pdpt, PAGE_SIZE);
            }
        }
    }

    // Unmap the PML4 after processing
    MmUnmapIoSpace(Pml4, PAGE_SIZE);
}

/**
 * @brief Walks a Page Directory Pointer Table (PDPT), continuing the permission chain check.
 */
static VOID WalkPdpt(
    _In_ PEPROCESS Process,
    _In_ PDPTE_64* Pdpt,
    _In_ UINT64    Pml4eVa,
    _In_ BOOLEAN   IsUserChain
)
{
    for (int PdptIndex = 0; PdptIndex < PT_ENTRY_COUNT; PdptIndex++)
    {
        if (Pdpt[PdptIndex].Present)
        {
            PHYSICAL_ADDRESS PdPa = {.QuadPart = (LONGLONG)(Pdpt[PdptIndex].PageFrameNumber << 12)};
            PDE_64*          Pd   = MmMapIoSpace(PdPa, PAGE_SIZE, MmNonCached);

            if (Pd)
            {
                UINT64 PdpteVa = Pml4eVa | ((UINT64)PdptIndex << 30);

                // The chain is only considered user-accessible if BOTH the parent
                // and the current entry allow user access.
                BOOLEAN IsCurrentUserChain = IsUserChain && (Pdpt[PdptIndex].Supervisor == 1);
                WalkPd(Process, Pd, PdpteVa, IsCurrentUserChain);

                // Unmap the PD after processing
                MmUnmapIoSpace(Pd, PAGE_SIZE);
            }
        }
    }
}

/**
 * @brief Walks a Page Directory (PD), continuing the permission chain check.
 */
static VOID WalkPd(
    _In_ PEPROCESS Process,
    _In_ PDE_64*   Pd,
    _In_ UINT64    PdpteVa,
    _In_ BOOLEAN   IsUserChain
)
{
    for (int PdIndex = 0; PdIndex < PT_ENTRY_COUNT; PdIndex++)
    {
        if (Pd[PdIndex].Present)
        {
            if (Pd[PdIndex].LargePage)
            {
                UINT64  CurrentVa        = PdpteVa | ((UINT64)PdIndex << 21);
                BOOLEAN IsUserAccessible = IsUserChain && (Pd[PdIndex].Supervisor == 1);

                if (IsUserAccessible && CurrentVa >= KERNEL_MODE_BOUNDARY)
                {
                    DbgPrint("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                    DbgPrint("!!! KERNEL-MAPPING VIOLATION DETECTED in PID: %llu\n", (UINT64)PsGetProcessId(Process));
                    DbgPrint("!!! User-mode is granted access to kernel address: 0x%llX\n", CurrentVa);
                    DbgPrint("!!! PDE Content: 0x%llX\n", Pd[PdIndex].AsUInt);
                    DbgPrint("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                }
                continue; // Skip large pages as they don't have a PT to walk.
            }

            PHYSICAL_ADDRESS PtPa = {.QuadPart = (LONGLONG)(Pd[PdIndex].PageFrameNumber << 12)};
            PTE_64*          Pt   = MmMapIoSpace(PtPa, PAGE_SIZE, MmNonCached);

            if (Pt)
            {
                UINT64  PdeVa              = PdpteVa | ((UINT64)PdIndex << 21);
                BOOLEAN IsCurrentUserChain = IsUserChain && (Pd[PdIndex].Supervisor == 1);
                WalkPt(Process, Pt, PdeVa, IsCurrentUserChain);

                // Unmap the PT after processing
                MmUnmapIoSpace(Pt, PAGE_SIZE);
            }
        }
    }
}

/**
 * @brief Walks a Page Table (PT) and performs the final, robust analysis on its PTEs.
 */
static VOID WalkPt(
    _In_ PEPROCESS Process,
    _In_ PTE_64*   Pt,
    _In_ UINT64    PdeVa,
    _In_ BOOLEAN   IsUserChain
)
{
    for (int PtIndex = 0; PtIndex < PT_ENTRY_COUNT; PtIndex++)
    {
        if (Pt[PtIndex].Present)
        {
            UINT64  CurrentVa        = PdeVa | ((UINT64)PtIndex << 12);
            BOOLEAN IsUserAccessible = IsUserChain && (Pt[PtIndex].Supervisor == 1);

            //
            // [ROBUST DETECTION LOGIC]
            //
            // A violation occurs IF AND ONLY IF:
            // 1. The virtual address is in the canonical kernel-mode space.
            // 2. The *entire chain* of page table entries (PML4E, PDPTE, PDE, PTE)
            //    has the User/Supervisor bit set to "User".
            //
            if (IsUserAccessible && CurrentVa >= KERNEL_MODE_BOUNDARY)
            {
                DbgPrint("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                DbgPrint("!!! KERNEL-MAPPING VIOLATION DETECTED in PID: %llu\n", (UINT64)PsGetProcessId(Process));
                DbgPrint("!!! User-mode is granted access to kernel address: 0x%llX\n", CurrentVa);
                DbgPrint("!!! PTE Content: 0x%llX\n", Pt[PtIndex].AsUInt);
                DbgPrint("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
            }
        }
    }
}
