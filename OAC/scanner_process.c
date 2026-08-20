#include "scanner_internal.h"
#include "compat.h"
#include "protection.h"
#include "telemetry.h"

#define OAC_SYSTEM_PROCESS_INFORMATION_CLASS 5UL
#define OAC_SYS_EXT_HANDLE_INFO 64UL
#define OAC_PID_BITMAP_BITS (8UL * 1024UL * 1024UL)

typedef struct OAC_SYSTEM_THREAD_INFORMATION_TAG
{
    LARGE_INTEGER Reserved1[3];
    ULONG Reserved2;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG Reserved3;
    ULONG ThreadState;
    ULONG WaitReason;
} OAC_SYSTEM_THREAD_INFORMATION, *POAC_SYSTEM_THREAD_INFORMATION;

typedef struct OAC_SYSTEM_PROCESS_INFORMATION_TAG
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    UCHAR Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} OAC_SYSTEM_PROCESS_INFORMATION, *POAC_SYSTEM_PROCESS_INFORMATION;

typedef struct OAC_SYSTEM_HANDLE_ENTRY_TAG
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} OAC_SYSTEM_HANDLE_ENTRY, *POAC_SYSTEM_HANDLE_ENTRY;

typedef struct OAC_SYSTEM_HANDLE_INFORMATION_TAG
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    OAC_SYSTEM_HANDLE_ENTRY Handles[ANYSIZE_ARRAY];
} OAC_SYSTEM_HANDLE_INFORMATION, *POAC_SYSTEM_HANDLE_INFORMATION;

static BOOLEAN OacScanProcessesAndSystemThreads(
    _In_reads_(ModuleCount) PAUX_MODULE_EXTENDED_INFO Modules,
    _In_ ULONG ModuleCount,
    _In_opt_ POAC_SYSTEM_HANDLE_INFORMATION Handles,
    _In_ ULONG HandleBufferLength)
{
    PVOID processBuffer = NULL;
    ULONG processLength = 0;
    PULONG bitmapBuffer = NULL;
    RTL_BITMAP bitmap;
    PUCHAR cursor;
    PUCHAR end;
    NTSTATUS status;
    ULONG processCount = 0;
    ULONG threadCount = 0;
    BOOLEAN terminalRecord = FALSE;

    status = OacQuerySystemInformation(
        OAC_SYSTEM_PROCESS_INFORMATION_CLASS,
        &processBuffer,
        &processLength);
    if (!NT_SUCCESS(status))
    {
        OacReportFinding(OacSeverityMedium, OacCategoryProcess, NULL, NULL,
            NULL, status, L"Process cross-view query failed: 0x%08X", status);
        return FALSE;
    }

    bitmapBuffer = (PULONG)OacAllocatePool(
        TRUE,
        OAC_PID_BITMAP_BITS / 8,
        OAC_SCAN_TAG);
    if (bitmapBuffer == NULL)
    {
        OacReportFinding(
            OacSeverityHigh,
            OacCategoryIntegrity,
            NULL,
            NULL,
            NULL,
            OAC_PID_BITMAP_BITS / 8,
            L"Process cross-view bitmap allocation failed");
        ExFreePoolWithTag(processBuffer, OAC_SCAN_TAG);
        return FALSE;
    }
    RtlZeroMemory(bitmapBuffer, OAC_PID_BITMAP_BITS / 8);
    RtlInitializeBitMap(&bitmap, bitmapBuffer, OAC_PID_BITMAP_BITS);

    if (processLength < sizeof(OAC_SYSTEM_PROCESS_INFORMATION))
    {
        OacReportFinding(
            OacSeverityHigh,
            OacCategoryIntegrity,
            NULL,
            NULL,
            NULL,
            processLength,
            L"Process snapshot was shorter than its fixed header");
        ExFreePoolWithTag(processBuffer, OAC_SCAN_TAG);
        ExFreePoolWithTag(bitmapBuffer, OAC_SCAN_TAG);
        return FALSE;
    }

    cursor = (PUCHAR)processBuffer;
    end = cursor + processLength;
    while (cursor + sizeof(OAC_SYSTEM_PROCESS_INFORMATION) <= end)
    {
        POAC_SYSTEM_PROCESS_INFORMATION process =
            (POAC_SYSTEM_PROCESS_INFORMATION)cursor;
        ULONG entryLength = process->NextEntryOffset != 0
            ? process->NextEntryOffset
            : (ULONG)(end - cursor);
        ULONG pid = HandleToULong(process->UniqueProcessId);
        ULONG availableThreads;
        ULONG i;
        POAC_SYSTEM_THREAD_INFORMATION threads;

        if (entryLength < sizeof(*process) || cursor + entryLength > end)
        {
            OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
                cursor, entryLength, L"Malformed SystemProcessInformation record");
            ExFreePoolWithTag(processBuffer, OAC_SCAN_TAG);
            ExFreePoolWithTag(bitmapBuffer, OAC_SCAN_TAG);
            return FALSE;
        }

        ++processCount;
        if (pid >= OAC_PID_BITMAP_BITS)
        {
            OacReportFinding(
                OacSeverityHigh,
                OacCategoryIntegrity,
                process->UniqueProcessId,
                NULL,
                NULL,
                OAC_PID_BITMAP_BITS,
                L"Process identifier exceeds the bounded cross-view range");
            ExFreePoolWithTag(processBuffer, OAC_SCAN_TAG);
            ExFreePoolWithTag(bitmapBuffer, OAC_SCAN_TAG);
            return FALSE;
        }
        RtlSetBit(&bitmap, pid);

        threads = (POAC_SYSTEM_THREAD_INFORMATION)(process + 1);
        availableThreads = (entryLength - sizeof(*process)) /
                           sizeof(OAC_SYSTEM_THREAD_INFORMATION);
        if (process->NumberOfThreads > availableThreads)
        {
            OacReportFinding(
                OacSeverityHigh,
                OacCategoryIntegrity,
                process->UniqueProcessId,
                NULL,
                NULL,
                process->NumberOfThreads,
                L"Process snapshot thread array was truncated; available=%lu reported=%lu",
                availableThreads,
                process->NumberOfThreads);
            ExFreePoolWithTag(processBuffer, OAC_SCAN_TAG);
            ExFreePoolWithTag(bitmapBuffer, OAC_SCAN_TAG);
            return FALSE;
        }
        threadCount += availableThreads;

        if (pid == 4)
        {
            for (i = 0; i < availableThreads; ++i)
            {
                if (threads[i].StartAddress != NULL &&
                    !OacAddressInModules(
                        threads[i].StartAddress,
                        Modules,
                        ModuleCount,
                        NULL))
                {
                    OacReportFinding(
                        OacSeverityCritical,
                        OacCategoryThread,
                        process->UniqueProcessId,
                        threads[i].ClientId.UniqueThread,
                        threads[i].StartAddress,
                        threads[i].ThreadState,
                        L"Probable manually mapped kernel code: System-thread start address is outside every loaded module");
                }
            }
        }

        if (process->NextEntryOffset == 0)
        {
            terminalRecord = TRUE;
            break;
        }
        cursor += process->NextEntryOffset;
    }

    if (!terminalRecord)
    {
        OacReportFinding(
            OacSeverityHigh,
            OacCategoryIntegrity,
            NULL,
            NULL,
            NULL,
            processLength,
            L"Process snapshot ended without a terminal record");
        ExFreePoolWithTag(processBuffer, OAC_SCAN_TAG);
        ExFreePoolWithTag(bitmapBuffer, OAC_SCAN_TAG);
        return FALSE;
    }

    OacReportFinding(OacSeverityInfo, OacCategoryProcess, NULL, NULL,
        NULL, threadCount, L"Process snapshot: %lu processes, %lu threads",
        processCount, threadCount);

    if (Handles != NULL &&
        HandleBufferLength >=
            (ULONG)FIELD_OFFSET(OAC_SYSTEM_HANDLE_INFORMATION, Handles))
    {
        ULONG_PTR maxHandles =
            (HandleBufferLength -
                FIELD_OFFSET(OAC_SYSTEM_HANDLE_INFORMATION, Handles)) /
            sizeof(OAC_SYSTEM_HANDLE_ENTRY);
        ULONG_PTR count = min(Handles->NumberOfHandles, maxHandles);
        ULONG_PTR i;
        ULONG discrepancies = 0;
        for (i = 0; i < count && discrepancies < 128; ++i)
        {
            ULONG pid = (ULONG)Handles->Handles[i].UniqueProcessId;
            if (pid != 0 && pid < OAC_PID_BITMAP_BITS &&
                !RtlCheckBit(&bitmap, pid))
            {
                PEPROCESS process;
                status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);
                if (NT_SUCCESS(status))
                {
                    ObDereferenceObject(process);
                    RtlSetBit(&bitmap, pid);
                    ++discrepancies;
                    OacReportFinding(
                        OacSeverityHigh,
                        OacCategoryProcess,
                        ULongToHandle(pid),
                        NULL,
                        Handles->Handles[i].Object,
                        Handles->Handles[i].HandleValue,
                        L"Process exists in handle/object cross-view but not process snapshot");
                }
            }
        }
    }

    ExFreePoolWithTag(bitmapBuffer, OAC_SCAN_TAG);
    ExFreePoolWithTag(processBuffer, OAC_SCAN_TAG);
    return TRUE;
}

static NTSTATUS OacReferencePhysicalMemoryObject(
    _Outptr_ PVOID* PhysicalMemoryObject,
    _Out_ PHANDLE OpenedHandle)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    NTSTATUS status;

    *PhysicalMemoryObject = NULL;
    *OpenedHandle = NULL;
    RtlInitUnicodeString(&name, L"\\Device\\PhysicalMemory");
    InitializeObjectAttributes(
        &attributes,
        &name,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwOpenSection(OpenedHandle, SECTION_QUERY, &attributes);
    if (!NT_SUCCESS(status)) return status;

    status = ObReferenceObjectByHandle(
        *OpenedHandle,
        0,
        NULL,
        KernelMode,
        PhysicalMemoryObject,
        NULL);
    if (!NT_SUCCESS(status))
    {
        ZwClose(*OpenedHandle);
        *OpenedHandle = NULL;
    }
    return status;
}

static BOOLEAN OacScanHandles(
    _In_ POAC_SYSTEM_HANDLE_INFORMATION Handles,
    _In_ ULONG BufferLength,
    _In_ ULONG ScanFlags)
{
    ULONG_PTR maximum;
    ULONG_PTR count;
    ULONG_PTR i;
    PVOID physicalMemoryObject = NULL;
    HANDLE physicalMemoryHandle = NULL;
    HANDLE protectedPid = OacProtectedProcessId();
    HANDLE trustedPid = OacTrustedClientProcessId();
    ULONG protectedHandleCount = 0;
    ULONG physicalHandleCount = 0;

    if (Handles == NULL ||
        BufferLength < (ULONG)FIELD_OFFSET(OAC_SYSTEM_HANDLE_INFORMATION, Handles))
    {
        OacReportFinding(
            OacSeverityMedium,
            OacCategoryHandle,
            NULL,
            NULL,
            NULL,
            BufferLength,
            L"Extended handle snapshot was shorter than its fixed header");
        return FALSE;
    }

    maximum = (BufferLength - FIELD_OFFSET(OAC_SYSTEM_HANDLE_INFORMATION, Handles)) /
              sizeof(OAC_SYSTEM_HANDLE_ENTRY);
    if (Handles->NumberOfHandles > maximum)
    {
        OacReportFinding(
            OacSeverityHigh,
            OacCategoryIntegrity,
            NULL,
            NULL,
            NULL,
            Handles->NumberOfHandles,
            L"Extended handle snapshot was truncated; available=%llu reported=%llu",
            (ULONGLONG)maximum,
            (ULONGLONG)Handles->NumberOfHandles);
        return FALSE;
    }
    count = min(Handles->NumberOfHandles, maximum);

    (VOID)OacReferencePhysicalMemoryObject(
        &physicalMemoryObject,
        &physicalMemoryHandle);

    for (i = 0; i < count; ++i)
    {
        POAC_SYSTEM_HANDLE_ENTRY entry = &Handles->Handles[i];
        HANDLE ownerPid = ULongToHandle((ULONG)entry->UniqueProcessId);

        if (OacIsProtectedProcessObject(entry->Object))
        {
            ++protectedHandleCount;
            if (ownerPid != protectedPid && ownerPid != trustedPid)
            {
                ACCESS_MASK risky = entry->GrantedAccess &
                    OacRestrictedProcessRights();
                ACCESS_MASK mutation = risky & ~OAC_PROCESS_VM_READ_ACCESS;
                if (risky != 0)
                {
                    OacReportFinding(
                        OacSeverityInfo,
                        OacCategoryHandle,
                        ownerPid,
                        NULL,
                        entry->Object,
                        entry->GrantedAccess,
                        mutation != 0
                            ? L"Existing target mutation handle pending signed-owner classification: handle=0x%llX access=0x%08X"
                            : L"Existing target read handle pending signed-owner classification: handle=0x%llX access=0x%08X",
                        (ULONGLONG)entry->HandleValue,
                        entry->GrantedAccess);
                }
            }
        }

        if (physicalMemoryObject != NULL && entry->Object == physicalMemoryObject)
        {
            ++physicalHandleCount;
            OacReportFinding(
                OacSeverityHigh,
                OacCategoryHandle,
                ownerPid,
                NULL,
                entry->Object,
                entry->GrantedAccess,
                L"Handle to \\Device\\PhysicalMemory: handle=0x%llX access=0x%08X",
                (ULONGLONG)entry->HandleValue,
                entry->GrantedAccess);
        }

        if ((ScanFlags & OAC_SCAN_VERBOSE_HANDLES) != 0 && i < 4096)
        {
            OacReportFinding(
                OacSeverityInfo,
                OacCategoryHandle,
                ownerPid,
                NULL,
                entry->Object,
                entry->GrantedAccess,
                L"Open handle 0x%llX type-index=%hu",
                (ULONGLONG)entry->HandleValue,
                entry->ObjectTypeIndex);
        }
    }

    OacReportFinding(OacSeverityInfo, OacCategoryHandle, NULL, NULL,
        NULL, count,
        L"System handle snapshot: %llu handles; %lu target; %lu physical-memory",
        (ULONGLONG)count, protectedHandleCount, physicalHandleCount);

    if (physicalMemoryObject != NULL) ObDereferenceObject(physicalMemoryObject);
    if (physicalMemoryHandle != NULL) ZwClose(physicalMemoryHandle);
    return TRUE;
}

ULONG OacScanProcessesAndHandles(
    _In_reads_(ModuleCount) PAUX_MODULE_EXTENDED_INFO Modules,
    _In_ ULONG ModuleCount,
    _In_ ULONG ScanFlags,
    _In_ ULONG RequestedEndpointFlags)
{
    PVOID handleBuffer = NULL;
    ULONG handleLength = 0;
    NTSTATUS status;
    ULONG completedFlags = 0;
    BOOLEAN processComplete;

    status = OacQuerySystemInformation(
        OAC_SYS_EXT_HANDLE_INFO,
        &handleBuffer,
        &handleLength);
    if (!NT_SUCCESS(status))
    {
        OacReportFinding(OacSeverityMedium, OacCategoryHandle, NULL, NULL,
            NULL, status, L"System handle query failed: 0x%08X", status);
        handleBuffer = NULL;
        handleLength = 0;
    }

    processComplete = OacScanProcessesAndSystemThreads(
        Modules,
        ModuleCount,
        (POAC_SYSTEM_HANDLE_INFORMATION)handleBuffer,
        handleLength);
    if (processComplete &&
        (RequestedEndpointFlags & OAC_ENDPOINT_SCAN_PROCESS_STATE) != 0)
    {
        completedFlags |= OAC_ENDPOINT_SCAN_PROCESS_STATE;
    }
    if (handleBuffer != NULL)
    {
        if (OacScanHandles(
            (POAC_SYSTEM_HANDLE_INFORMATION)handleBuffer,
            handleLength,
            ScanFlags) &&
            (RequestedEndpointFlags &
                OAC_ENDPOINT_SCAN_DANGEROUS_HANDLES) != 0)
        {
            completedFlags |= OAC_ENDPOINT_SCAN_DANGEROUS_HANDLES;
        }
        ExFreePoolWithTag(handleBuffer, OAC_SCAN_TAG);
    }
    return completedFlags;
}
