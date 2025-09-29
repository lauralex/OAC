/**
 * @file module.c
 * @brief Implementation of kernel module enumeration and PE header parsing functions.
 */
#include <ntddk.h>
#include <ntimage.h> // For PE header structures
#include "module.h"

/**
  * @brief Finds the base address of a loaded kernel module by its name.
  */
PVOID FindModuleByName(
    _In_ PCWSTR ModuleName
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
 * @brief Finds the address of an exported function from a module's export table.
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
