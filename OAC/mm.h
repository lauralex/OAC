/**
 * @file mm.h
 * @brief Header for memory management functions and definitions.
 *
 * This header defines structures and functions related to dynamic page table
 * management, including a function to map virtual addresses using a custom
 * page table hierarchy.
 */

#pragma once
#include <ntddk.h>

#include "ia32.h"

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
);
