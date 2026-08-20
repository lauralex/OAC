#include "scanner_internal.h"
#include "compat.h"
#include "telemetry.h"
#include "..\shared\oac_driver_policy.h"

#define OAC_SYSTEM_MODULE_INFORMATION_CLASS 11UL
#define OAC_MAX_SNAPSHOT_MODULES 1024UL

typedef struct OAC_SYSTEM_MODULE_ENTRY_TAG
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} OAC_SYSTEM_MODULE_ENTRY, *POAC_SYSTEM_MODULE_ENTRY;

typedef struct OAC_SYSTEM_MODULE_INFORMATION_TAG
{
    ULONG NumberOfModules;
    OAC_SYSTEM_MODULE_ENTRY Modules[ANYSIZE_ARRAY];
} OAC_SYSTEM_MODULE_INFORMATION, *POAC_SYSTEM_MODULE_INFORMATION;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, OacCaptureKernelModuleSnapshot)
#pragma alloc_text(PAGE, OacReleaseKernelModuleSnapshot)
#endif

NTSTATUS OacQueryKernelModules(
    _Outptr_result_buffer_(*ModuleCount) PAUX_MODULE_EXTENDED_INFO* Modules,
    _Out_ PULONG ModuleCount)
{
    NTSTATUS status;
    ULONG bytes = 0;
    ULONG allocatedBytes;
    PAUX_MODULE_EXTENDED_INFO modules = NULL;
    ULONG attempt;

    *Modules = NULL;
    *ModuleCount = 0;
    status = AuxKlibQueryModuleInformation(
        &bytes,
        sizeof(AUX_MODULE_EXTENDED_INFO),
        NULL);
    if (!NT_SUCCESS(status) || bytes == 0 || bytes > OAC_MAX_SYSTEM_QUERY)
    {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    for (attempt = 0; attempt < 4; ++attempt)
    {
        allocatedBytes = bytes;
        modules = (PAUX_MODULE_EXTENDED_INFO)OacAllocatePool(
            TRUE,
            allocatedBytes,
            OAC_SCAN_TAG);
        if (modules == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = AuxKlibQueryModuleInformation(
            &bytes,
            sizeof(AUX_MODULE_EXTENDED_INFO),
            modules);
        if (NT_SUCCESS(status))
        {
            if (bytes == 0 || bytes > allocatedBytes)
            {
                ExFreePoolWithTag(modules, OAC_SCAN_TAG);
                return STATUS_DATA_ERROR;
            }
            break;
        }
        ExFreePoolWithTag(modules, OAC_SCAN_TAG);
        modules = NULL;
        if ((status != STATUS_BUFFER_TOO_SMALL &&
             status != STATUS_INFO_LENGTH_MISMATCH &&
             status != STATUS_BUFFER_OVERFLOW) ||
            bytes == 0 || bytes > OAC_MAX_SYSTEM_QUERY)
        {
            return status;
        }
    }

    if (!NT_SUCCESS(status) || modules == NULL)
    {
        return NT_SUCCESS(status) ? STATUS_INFO_LENGTH_MISMATCH : status;
    }
    if ((bytes % sizeof(AUX_MODULE_EXTENDED_INFO)) != 0)
    {
        ExFreePoolWithTag(modules, OAC_SCAN_TAG);
        return STATUS_DATA_ERROR;
    }

    *Modules = modules;
    *ModuleCount = bytes / sizeof(AUX_MODULE_EXTENDED_INFO);
    return STATUS_SUCCESS;
}

static BOOLEAN OacDriverBaseNameEquals(
    _In_reads_bytes_(Length) const UCHAR* Path,
    _In_ SIZE_T Length,
    _In_z_ PCSTR Expected)
{
    SIZE_T end = 0;
    SIZE_T start;
    SIZE_T expectedLength = strlen(Expected);
    SIZE_T i;

    while (end < Length && Path[end] != 0) ++end;
    start = end;
    while (start != 0 && Path[start - 1] != '\\' && Path[start - 1] != '/')
        --start;
    if (end - start != expectedLength) return FALSE;
    for (i = 0; i < expectedLength; ++i)
    {
        CHAR left = (CHAR)Path[start + i];
        CHAR right = Expected[i];
        if (left >= 'A' && left <= 'Z') left = (CHAR)(left + ('a' - 'A'));
        if (right >= 'A' && right <= 'Z') right = (CHAR)(right + ('a' - 'A'));
        if (left != right) return FALSE;
    }
    return TRUE;
}

static OAC_SEVERITY OacDriverIocSeverity(
    _In_reads_bytes_(Length) const UCHAR* Path,
    _In_ SIZE_T Length)
{
    static const PCSTR highConfidence[] =
    {
        OAC_DRIVER_DENY_BASENAMES_A
    };
    static const PCSTR review[] =
    {
        OAC_DRIVER_REVIEW_BASENAMES_A
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(highConfidence); ++i)
    {
        if (OacDriverBaseNameEquals(Path, Length, highConfidence[i]))
            return OacSeverityHigh;
    }
    for (i = 0; i < RTL_NUMBER_OF(review); ++i)
    {
        if (OacDriverBaseNameEquals(Path, Length, review[i]))
            return OacSeverityLow;
    }
    return OacSeverityInfo;
}

static ULONG OacCopySnapshotModuleName(
    _In_reads_bytes_(SourceLength) const UCHAR* Source,
    _In_ SIZE_T SourceLength,
    _Out_writes_(OAC_SNAPSHOT_MAX_NAME_CHARS) PWCHAR Destination)
{
    ULONG count = 0;

    while (count + 1 < OAC_SNAPSHOT_MAX_NAME_CHARS &&
        count < SourceLength && Source[count] != 0)
    {
        const UCHAR value = Source[count];
        Destination[count] = value >= 0x20 && value <= 0x7e
            ? (WCHAR)value
            : L'?';
        ++count;
    }
    if (count == 0)
    {
        static const WCHAR unnamed[] = L"<unnamed>";
        RtlCopyMemory(Destination, unnamed, sizeof(unnamed));
        return RTL_NUMBER_OF(unnamed) - 1;
    }
    Destination[count] = L'\0';
    return count;
}

static BOOLEAN OacSystemModuleContainsBase(
    _In_ POAC_SYSTEM_MODULE_INFORMATION Modules,
    _In_ ULONG BufferLength,
    _In_ PVOID Base)
{
    ULONG maxEntries;
    ULONG count;
    ULONG i;

    if (BufferLength < (ULONG)FIELD_OFFSET(OAC_SYSTEM_MODULE_INFORMATION, Modules))
        return FALSE;

    maxEntries = (BufferLength - FIELD_OFFSET(OAC_SYSTEM_MODULE_INFORMATION, Modules)) /
                 sizeof(OAC_SYSTEM_MODULE_ENTRY);
    count = min(Modules->NumberOfModules, maxEntries);
    for (i = 0; i < count; ++i)
    {
        if (Modules->Modules[i].ImageBase == Base) return TRUE;
    }
    return FALSE;
}

BOOLEAN OacScanKernelModules(
    _In_reads_(ModuleCount) PAUX_MODULE_EXTENDED_INFO Modules,
    _In_ ULONG ModuleCount)
{
    PVOID systemBuffer = NULL;
    ULONG systemLength = 0;
    NTSTATUS status;
    BOOLEAN complete;
    ULONG i;

    status = OacQuerySystemInformation(
        OAC_SYSTEM_MODULE_INFORMATION_CLASS,
        &systemBuffer,
        &systemLength);
    complete = NT_SUCCESS(status);

    for (i = 0; i < ModuleCount; ++i)
    {
        WCHAR path[OAC_MAX_FINDING_TEXT];
        OAC_SEVERITY severity = OacDriverIocSeverity(
            Modules[i].FullPathName,
            sizeof(Modules[i].FullPathName));
        OacAsciiToWide(
            Modules[i].FullPathName,
            sizeof(Modules[i].FullPathName),
            path,
            RTL_NUMBER_OF(path));

        OacReportFinding(
            severity,
            OacCategoryDriver,
            NULL,
            NULL,
            Modules[i].BasicInfo.ImageBase,
            Modules[i].ImageSize,
            severity >= OacSeverityHigh
                ? L"OAC deny-policy driver family is already loaded: %ls"
                : (severity == OacSeverityLow
                    ? L"Driver requires version/signature policy review: %ls"
                    : L"Loaded driver: %ls"),
            path);

        if (NT_SUCCESS(status) && !OacSystemModuleContainsBase(
                (POAC_SYSTEM_MODULE_INFORMATION)systemBuffer,
                systemLength,
                Modules[i].BasicInfo.ImageBase))
        {
            OacReportFinding(
                OacSeverityHigh,
                OacCategoryDriver,
                NULL,
                NULL,
                Modules[i].BasicInfo.ImageBase,
                Modules[i].ImageSize,
                L"Kernel-module cross-view mismatch: %ls",
                path);
        }
    }

    if (!NT_SUCCESS(status))
    {
        OacReportFinding(
            OacSeverityMedium,
            OacCategoryDriver,
            NULL,
            NULL,
            NULL,
            status,
            L"Secondary kernel-module view failed: 0x%08X",
            status);
    }
    else if (systemLength <
        (ULONG)FIELD_OFFSET(OAC_SYSTEM_MODULE_INFORMATION, Modules))
    {
        complete = FALSE;
        OacReportFinding(
            OacSeverityHigh,
            OacCategoryIntegrity,
            NULL,
            NULL,
            NULL,
            systemLength,
            L"Secondary kernel-module view was shorter than its fixed header");
    }
    else
    {
        POAC_SYSTEM_MODULE_INFORMATION systemModules =
            (POAC_SYSTEM_MODULE_INFORMATION)systemBuffer;
        ULONG maximum =
            (systemLength - FIELD_OFFSET(OAC_SYSTEM_MODULE_INFORMATION, Modules)) /
            sizeof(OAC_SYSTEM_MODULE_ENTRY);
        ULONG count = min(systemModules->NumberOfModules, maximum);
        if (systemModules->NumberOfModules > maximum)
        {
            complete = FALSE;
            OacReportFinding(
                OacSeverityHigh,
                OacCategoryIntegrity,
                NULL,
                NULL,
                NULL,
                systemModules->NumberOfModules,
                L"Secondary kernel-module view was truncated; available=%lu reported=%lu",
                maximum,
                systemModules->NumberOfModules);
        }
        for (i = 0; i < count; ++i)
        {
            POAC_SYSTEM_MODULE_ENTRY entry = &systemModules->Modules[i];
            if (!OacAddressInModules(entry->ImageBase, Modules, ModuleCount, NULL))
            {
                WCHAR path[OAC_MAX_FINDING_TEXT];
                OacAsciiToWide(
                    entry->FullPathName,
                    sizeof(entry->FullPathName),
                    path,
                    RTL_NUMBER_OF(path));
                OacReportFinding(
                    OacSeverityHigh,
                    OacCategoryDriver,
                    NULL,
                    NULL,
                    entry->ImageBase,
                    entry->ImageSize,
                    L"Reverse kernel-module cross-view mismatch: %ls",
                    path);
            }
        }
    }

    if (systemBuffer != NULL)
        ExFreePoolWithTag(systemBuffer, OAC_SCAN_TAG);
    return complete;
}

NTSTATUS OacCaptureKernelModuleSnapshot(
    _Outptr_result_buffer_maybenull_(*AvailableItems)
        POAC_SNAPSHOT_RECORD* Records,
    _Out_ PULONG TotalItems,
    _Out_ PULONG AvailableItems,
    _Out_ PBOOLEAN Truncated)
{
    PAUX_MODULE_EXTENDED_INFO modules = NULL;
    POAC_SNAPSHOT_RECORD records = NULL;
    ULONG moduleCount = 0;
    ULONG available;
    ULONG index;
    NTSTATUS status;

    PAGED_CODE();
    if (Records == NULL || TotalItems == NULL || AvailableItems == NULL ||
        Truncated == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *Records = NULL;
    *TotalItems = 0;
    *AvailableItems = 0;
    *Truncated = FALSE;

    status = OacQueryKernelModules(&modules, &moduleCount);
    if (!NT_SUCCESS(status)) return status;
    available = min(moduleCount, OAC_MAX_SNAPSHOT_MODULES);
    if (available != 0)
    {
        records = (POAC_SNAPSHOT_RECORD)OacAllocatePool(
            TRUE,
            sizeof(*records) * available,
            OAC_SCAN_TAG);
        if (records == NULL)
        {
            ExFreePoolWithTag(modules, OAC_SCAN_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(records, sizeof(*records) * available);
        for (index = 0; index < available; ++index)
        {
            POAC_SNAPSHOT_RECORD record = &records[index];

            if (modules[index].BasicInfo.ImageBase == NULL ||
                modules[index].ImageSize == 0)
            {
                ExFreePoolWithTag(records, OAC_SCAN_TAG);
                ExFreePoolWithTag(modules, OAC_SCAN_TAG);
                return STATUS_DATA_ERROR;
            }
            record->Version = OAC_V5_VERSION;
            record->Size = sizeof(*record);
            record->RecordType = OAC_SNAPSHOT_RECORD_KERNEL_MODULE;
            record->Index = index;
            record->Address =
                (ULONGLONG)(ULONG_PTR)modules[index].BasicInfo.ImageBase;
            record->Length = modules[index].ImageSize;
            record->NameLength = OacCopySnapshotModuleName(
                modules[index].FullPathName,
                sizeof(modules[index].FullPathName),
                record->Name);
        }
    }

    ExFreePoolWithTag(modules, OAC_SCAN_TAG);
    *Records = records;
    *TotalItems = moduleCount;
    *AvailableItems = available;
    *Truncated = available < moduleCount;
    return STATUS_SUCCESS;
}

VOID OacReleaseKernelModuleSnapshot(
    _Frees_ptr_opt_ POAC_SNAPSHOT_RECORD Records)
{
    PAGED_CODE();
    if (Records != NULL) ExFreePoolWithTag(Records, OAC_SCAN_TAG);
}
