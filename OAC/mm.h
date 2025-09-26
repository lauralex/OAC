#pragma once
#include <ntddk.h>

// =================================================================================================
// == Page Table Pool Definitions
// =================================================================================================

// We'll allocate a pool of pages. 1 for PML4, and worst-case many others for each subsequent level
// for our distinct VAs. We'll allocate 50 pages for now, which is overkill but simple.
#define PAGE_TABLE_POOL_PAGES 50ull

/**
 * @brief Dynamically maps a virtual address into our custom page table hierarchy,
 *        allocating new tables from a pool as needed to resolve index collisions.
 *
 * @param PoolBase The virtual address of our pre-allocated page pool.
 * @param NextFreePageIndex A pointer to an index tracking the next free page in the pool.
 * @param TargetVa The virtual address of the page we want to map.
 * @return STATUS_SUCCESS on success, or an error code.
 */
NTSTATUS MapVirtualAddressDynamically(PVOID PoolBase, ULONG* NextFreePageIndex, PVOID TargetVa);
