#pragma once
#include <ntddk.h>

// =================================================================================================
// == Page Table Pool Definitions
// =================================================================================================

// We'll allocate a pool of pages. 1 for PML4, and worst-case many others for each subsequent level
// for our distinct VAs. We'll allocate 60 pages for now, which is overkill but simple.
#define PAGE_TABLE_POOL_PAGES 60ull

/**
 * @brief Dynamically maps a virtual address into our custom page table hierarchy,
 *        allocating new tables from a pool as needed to resolve index collisions.
 *
 * @param[in] PoolBase The virtual address of our pre-allocated page pool.
 * @param[inout] NextFreePageIndex A pointer to an index tracking the next free page in the pool.
 * @param[in] TargetVa The virtual address of the page we want to map.
 * @return STATUS_SUCCESS on success, or an error code.
 */
NTSTATUS MapVirtualAddressDynamically(
    _In_ PVOID     PoolBase,
    _Inout_ ULONG* NextFreePageIndex,
    _In_ PVOID     TargetVa
);
