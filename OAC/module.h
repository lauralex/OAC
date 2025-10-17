/**
 * @file module.h
 * @brief Provides an interface for kernel module enumeration and PE header parsing.
 *
 * This module contains reusable helper functions to find kernel modules by name
 * and to resolve exported functions from their PE headers.
 */
#pragma once
#include <ntddk.h>

/**
 * @struct _LDR_DATA_TABLE_ENTRY
 * @brief An undocumented structure representing a loaded kernel module.
 *
 * This structure is a node in the PsLoadedModuleList linked list.
 */
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // ... other fields exist but are not needed for this project
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

/**
 * @brief An undocumented kernel variable that points to the head of a list
 *        of loaded kernel modules.
 */
extern PLIST_ENTRY PsLoadedModuleList;


//
// === Function Prototypes ===
//

/**
 * @brief Finds the base address of a loaded kernel module by its name.
 *
 * @param[in] ModuleName The case-insensitive name of the module (e.g., L"ci.dll").
 * @param[in_opt] ModuleSize If non-NULL, receives the size of the module in bytes.
 * @return The base address of the module if found; otherwise, NULL.
 * @note This function must be called at IRQL = PASSIVE_LEVEL.
 */
PVOID FindModuleByName2(
    _In_ PCWSTR      ModuleName,
    _In_opt_ PSIZE_T ModuleSize
);

/**
 * @brief Finds the base address of a loaded kernel module by its name.
 *
 * @param[in] ModuleName The case-insensitive name of the module (e.g., L"ci.dll").
 * @return The base address of the module if found; otherwise, NULL.
 * @note This function must be called at IRQL = PASSIVE_LEVEL.
 */
PVOID FindModuleByName(
    _In_ PCWSTR ModuleName
);

/**
 * @brief Finds the base address of a user-mode module by its name.
 *
 * @param[in] Process The EPROCESS pointer of the target process.
 * @param[in] ModuleName The case-insensitive name of the module (e.g., L"kernel32.dll").
 * @return The base address of the module if found; otherwise, NULL.
 */
PVOID FindUserModuleByName(
    _In_ PEPROCESS Process,
    _In_ PCWSTR    ModuleName
);

/**
 * @brief Finds the address of an exported function from a module's export table.
 *
 * @param[in] ModuleBase The base address of the kernel module to search.
 * @param[in] FunctionName The ASCII name of the function to find.
 * @return The address of the function if found; otherwise, NULL.
 * @note This function must be called at IRQL = PASSIVE_LEVEL.
 */
PVOID FindExportedFunction(
    _In_ PVOID ModuleBase,
    _In_ PCSTR FunctionName
);
