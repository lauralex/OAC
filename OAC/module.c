/**
 * @file module.c
 * @brief Implementation of kernel module enumeration and PE header parsing functions.
 */
#include "module.h"
#include "internals.h"

#include <ntddk.h>
#include <ntimage.h> // For PE header structures


/**
 * @brief Finds the base address of a loaded kernel module by its name.
 *
 * @param[in] ModuleName The case-insensitive name of the module (e.g., L"ci.dll").
 * @return The base address of the module if found; otherwise, NULL.
 * @note This function must be called at IRQL = PASSIVE_LEVEL.
 */
PVOID FindModuleByName(
    _In_ PCWSTR ModuleName
)
{
    return FindModuleByName2(ModuleName, NULL);
}

/**
 * @brief Finds the base address of a loaded kernel module by its name.
 *
 * @param[in]     ModuleName The case-insensitive name of the module (e.g., L"ci.dll").
 * @param[in_opt] ModuleSize If non-NULL, receives the size of the module in bytes.
 * @return The base address of the module if found; otherwise, NULL.
 * @note This function must be called at IRQL = PASSIVE_LEVEL.
 */
PVOID FindModuleByName2(
    _In_ PCWSTR      ModuleName,
    _In_opt_ PSIZE_T ModuleSize
)
{
    UNICODE_STRING ModuleNameUnicode;
    RtlInitUnicodeString(&ModuleNameUnicode, ModuleName);
    PVOID ModuleBase = NULL;

    // PsLoadedModuleList is an undocumented global. Accessing it should be
    // wrapped in a try/except block for production-level robustness.
    __try
    {
        if (!PsLoadedModuleList)
        {
            return NULL;
        }

        PLIST_ENTRY ListEntry = PsLoadedModuleList;
        do
        {
            PLDR_DATA_TABLE_ENTRY ModuleEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (RtlEqualUnicodeString(&ModuleEntry->BaseDllName, &ModuleNameUnicode, TRUE))
            {
                ModuleBase = ModuleEntry->DllBase;
                if (ModuleSize)
                {
                    *ModuleSize = ModuleEntry->SizeOfImage;
                }
                break;
            }
            ListEntry = ListEntry->Flink;
        }
        while (ListEntry != PsLoadedModuleList);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[-] Exception while accessing PsLoadedModuleList.\n");
        return NULL;
    }

    return ModuleBase;
}

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
)
{
    UNICODE_STRING ModuleNameUnicode;
    RtlInitUnicodeString(&ModuleNameUnicode, ModuleName);
    PVOID ModuleBase = NULL;
    __try
    {
        // The PEB is located at offset 0x60 in the EPROCESS structure on x64 Windows.
        // This offset may vary between Windows versions; this code assumes a common layout.
        PPEB Peb = Process->Peb;
        if (!Peb || !Peb->Ldr)
        {
            return NULL;
        }
        PLIST_ENTRY ListEntry = Peb->Ldr->InLoadOrderModuleList.Flink;
        PLIST_ENTRY ListHead  = &Peb->Ldr->InLoadOrderModuleList;
        while (ListEntry != ListHead)
        {
            PLDR_DATA_TABLE_ENTRY ModuleEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (RtlEqualUnicodeString(&ModuleEntry->BaseDllName, &ModuleNameUnicode, TRUE))
            {
                ModuleBase = ModuleEntry->DllBase;
                break;
            }
            ListEntry = ListEntry->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[-] Exception while accessing user-mode module list.\n");
        return NULL;
    }
    return ModuleBase;
}

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
)
{
    __try
    {
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
        if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

        PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + DosHeader->e_lfanew);
        if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

        IMAGE_DATA_DIRECTORY ExportDirData = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (ExportDirData.VirtualAddress == 0 || ExportDirData.Size == 0) return NULL;

        PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + ExportDirData.
            VirtualAddress);

        PULONG  Functions = (PULONG)((PUCHAR)ModuleBase + ExportDir->AddressOfFunctions);
        PULONG  Names     = (PULONG)((PUCHAR)ModuleBase + ExportDir->AddressOfNames);
        PUSHORT Ordinals  = (PUSHORT)((PUCHAR)ModuleBase + ExportDir->AddressOfNameOrdinals);

        for (UINT32 i = 0; i < ExportDir->NumberOfNames; ++i)
        {
            PCSTR CurrentName = (PCSTR)((PUCHAR)ModuleBase + Names[i]);
            if (strcmp(CurrentName, FunctionName) == 0)
            {
                USHORT Ordinal     = Ordinals[i];
                ULONG  FunctionRva = Functions[Ordinal];
                return (PVOID)((PUCHAR)ModuleBase + FunctionRva);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[-] Exception while parsing PE export table for module at 0x%p.\n", ModuleBase);
        return NULL;
    }

    return NULL;
}
