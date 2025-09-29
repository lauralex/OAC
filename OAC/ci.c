/**
 * @file ci.c
 * @brief Implementation of Code Integrity (CI) functions.
 */
#include "ci.h"
#include "module.h"
#include "globals.h"
#include "internals.h"

//
// Define Global Function Pointers
//
CI_VALIDATE_FILE_OBJECT G_CiValidateFileObject = NULL;
CI_FREE_POLICY_INFO     G_CiFreePolicyInfo     = NULL;

/**
 * @brief Dynamically resolves the addresses of necessary functions from ci.dll.
 */
NTSTATUS ResolveCiFunctions(
    VOID)
{
    PVOID ciBase = FindModuleByName(L"ci.dll");
    if (!ciBase)
    {
        DbgPrint("[-] Could not find ci.dll module base.\n");
        return STATUS_NOT_FOUND;
    }

    G_CiValidateFileObject = (CI_VALIDATE_FILE_OBJECT)FindExportedFunction(ciBase, "CiValidateFileObject");
    G_CiFreePolicyInfo     = (CI_FREE_POLICY_INFO)FindExportedFunction(ciBase, "CiFreePolicyInfo");

    if (G_CiValidateFileObject && G_CiFreePolicyInfo)
    {
        DbgPrint("[+] Resolved CiValidateFileObject at 0x%p\n", G_CiValidateFileObject);
        DbgPrint("[+] Resolved CiFreePolicyInfo at 0x%p\n", G_CiFreePolicyInfo);
        return STATUS_SUCCESS;
    }

    DbgPrint("[-] Could not resolve required CI functions from ci.dll.\n");
    return STATUS_NOT_FOUND;
}

/**
 * @brief Verifies the digital signature of the module containing a given RIP.
 */
NTSTATUS VerifyModuleSignatureByRip(
    _In_ PVOID Rip
)
{
    if (!G_CiValidateFileObject || !G_CiFreePolicyInfo)
    {
        DbgPrint("[-] Code Integrity functions are not resolved. Cannot perform signature check.\n");
        return STATUS_NOT_FOUND;
    }

    PVOID ModuleBase = NULL;
    ModuleBase       = RtlPcToFileHeader(Rip, &ModuleBase);
    if (!ModuleBase)
    {
        DbgPrint("[-] RIP 0x%p is not inside any known module.\n", Rip);
        return STATUS_NOT_FOUND;
    }

    // Find the full path of the module from PsLoadedModuleList
    PLDR_DATA_TABLE_ENTRY ModuleEntry  = NULL;
    PLIST_ENTRY           CurrentEntry = PsLoadedModuleList;
    BOOLEAN               FoundModule  = FALSE;
    do
    {
        ModuleEntry = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (ModuleEntry->DllBase == ModuleBase)
        {
            FoundModule = TRUE;
            break;
        }
        CurrentEntry = CurrentEntry->Flink;
    }
    while (CurrentEntry != PsLoadedModuleList);

    if (!FoundModule)
    {
        DbgPrint("[-] Could not find module LDR entry for base 0x%p.\n", ModuleBase);
        return STATUS_NOT_FOUND;
    }

    DbgPrint("[*] Checking signature for module: %wZ\n", &ModuleEntry->FullDllName);

    NTSTATUS          Status;
    HANDLE            FileHandle    = NULL;
    PFILE_OBJECT      FileObject    = NULL;
    IO_STATUS_BLOCK   IoStatusBlock = {0};
    OBJECT_ATTRIBUTES ObjAttr       = {0};

    // Initialize policy structures on the stack
    POLICY_INFO SignerPolicy    = {0};
    POLICY_INFO TimestampPolicy = {0};
    SignerPolicy.StructSize    = sizeof(POLICY_INFO);
    TimestampPolicy.StructSize = sizeof(POLICY_INFO);

    InitializeObjectAttributes(&ObjAttr, &ModuleEntry->FullDllName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL,
                               NULL)

    __try
    {
        Status = ZwCreateFile(&FileHandle, FILE_READ_DATA | SYNCHRONIZE, &ObjAttr, &IoStatusBlock, NULL,
                              FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(Status))
        {
            DbgPrint("[-] ZwCreateFile failed with status 0x%X for %wZ\n", Status, &ModuleEntry->FullDllName);
            __leave;
        }

        Status = ObReferenceObjectByHandle(FileHandle, FILE_READ_DATA, *IoFileObjectType, KernelMode,
                                           (PVOID*)&FileObject, NULL);
        if (!NT_SUCCESS(Status))
        {
            DbgPrint("[-] ObReferenceObjectByHandle failed with status 0x%X\n", Status);
            __leave;
        }
        LARGE_INTEGER SigningTime = {0};
        Status = G_CiValidateFileObject(FileObject, 0, 0, &SignerPolicy, &TimestampPolicy, &SigningTime, NULL, NULL,
                                        NULL);
        if (NT_SUCCESS(Status))
        {
            DbgPrint("[+] Module %wZ is digitally signed and trusted.\n", &ModuleEntry->BaseDllName);
        }
        else
        {
            DbgPrint("[-] Module %wZ is NOT signed or trusted. Status: 0x%X\n", &ModuleEntry->BaseDllName, Status);
        }
    }
    __finally
    {
        DbgPrint("[*] Cleaning up resources after signature check.\n");
        // This cleanup block is critical for stability.
        if (SignerPolicy.CertChainInfo) G_CiFreePolicyInfo(&SignerPolicy);
        if (TimestampPolicy.CertChainInfo) G_CiFreePolicyInfo(&TimestampPolicy);
        if (FileObject)
            ObDereferenceObject(FileObject);
        if (FileHandle) ZwClose(FileHandle);
    }

    return Status;
}
