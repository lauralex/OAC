#include "scanner.h"
#include "compat.h"
#include "descriptor.h"
#include "protection.h"
#include "telemetry.h"
#include "..\shared\oac_driver_policy.h"

#include <aux_klib.h>
#include <intrin.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, OacRunKernelScan)
#endif

#define OAC_SCAN_TAG 'ScaO'
#define OAC_MAX_SYSTEM_QUERY (64UL * 1024UL * 1024UL)
#define OAC_PID_BITMAP_BITS (8UL * 1024UL * 1024UL)
#define OAC_EXPORT_BASELINE_BYTES 24UL
#define OAC_MAX_EXPORT_NAME 128UL
#define OAC_MAX_IMPORT_THUNKS 65536UL
#define OAC_MSR_SYSENTER_ESP 0x00000175UL
#define OAC_MSR_SYSENTER_EIP 0x00000176UL
#define OAC_MSR_EFER 0xC0000080UL
#define OAC_MSR_STAR 0xC0000081UL
#define OAC_MSR_LSTAR 0xC0000082UL
#define OAC_MSR_CSTAR 0xC0000083UL
#define OAC_MSR_FMASK 0xC0000084UL

#define OAC_CR0_PE (1ULL << 0)
#define OAC_CR0_WP (1ULL << 16)
#define OAC_CR0_PG (1ULL << 31)
#define OAC_CR4_PAE (1ULL << 5)
#define OAC_CR4_SMEP (1ULL << 20)
#define OAC_CR4_SMAP (1ULL << 21)
#define OAC_EFER_SCE (1ULL << 0)
#define OAC_EFER_LME (1ULL << 8)
#define OAC_EFER_LMA (1ULL << 10)
#define OAC_EFER_NXE (1ULL << 11)

#define OAC_SYSTEM_PROCESS_INFORMATION_CLASS 5UL
#define OAC_SYSTEM_MODULE_INFORMATION_CLASS 11UL
#define OAC_SYS_EXT_HANDLE_INFO 64UL

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

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

typedef struct OAC_UNLOADED_DRIVER_TAG
{
    UNICODE_STRING Name;
    PVOID StartAddress;
    PVOID EndAddress;
    LARGE_INTEGER CurrentTime;
} OAC_UNLOADED_DRIVER, *POAC_UNLOADED_DRIVER;

typedef struct OAC_PIDDB_CACHE_ENTRY_TAG
{
    LIST_ENTRY List;
    UNICODE_STRING DriverName;
    ULONG TimeDateStamp;
    NTSTATUS LoadStatus;
    UCHAR DriverData[16];
} OAC_PIDDB_CACHE_ENTRY, *POAC_PIDDB_CACHE_ENTRY;

#pragma pack(push, 1)
typedef struct OAC_IDTR_TAG
{
    USHORT Limit;
    ULONGLONG Base;
} OAC_IDTR;

typedef struct OAC_IDT_GATE_TAG
{
    USHORT OffsetLow;
    USHORT Selector;
    UCHAR Ist;
    UCHAR TypeAttributes;
    USHORT OffsetMiddle;
    ULONG OffsetHigh;
    ULONG Reserved;
} OAC_IDT_GATE;
#pragma pack(pop)

typedef struct OAC_CPU_INTEGRITY_CONTEXT_TAG
{
    POAC_CPU_RECORD Samples;
    ULONG Capacity;
    volatile LONG Count;
} OAC_CPU_INTEGRITY_CONTEXT, *POAC_CPU_INTEGRITY_CONTEXT;

typedef struct OAC_EXPORT_BASELINE_TAG
{
    PCSTR Name;
    PVOID Address;
    UCHAR Bytes[OAC_EXPORT_BASELINE_BYTES];
    BOOLEAN Available;
} OAC_EXPORT_BASELINE, *POAC_EXPORT_BASELINE;

static const PCSTR g_IntegrityExportNames[] =
{
    "NtOpenProcess", "NtReadVirtualMemory", "NtWriteVirtualMemory",
    "NtProtectVirtualMemory", "NtCreateThreadEx", "PsLookupProcessByProcessId",
    "MmCopyVirtualMemory", "ObOpenObjectByPointer", "ObRegisterCallbacks",
    "PsSetCreateProcessNotifyRoutineEx", "PsSetLoadImageNotifyRoutine",
    "ZwQuerySystemInformation"
};

static PVOID g_NtoskrnlBase;
static ULONG g_NtoskrnlSize;
static BOOLEAN g_PrivateProfileAvailable;
static PDRIVER_OBJECT g_DriverObject;
static PVOID g_DriverBase;
static ULONG g_DriverSize;
static PVOID g_DriverSectionBaseline;
static PFAST_IO_DISPATCH g_FastIoBaseline;
static PDRIVER_UNLOAD g_DriverUnloadBaseline;
static PDRIVER_DISPATCH g_MajorFunctionBaseline[IRP_MJ_MAXIMUM_FUNCTION + 1];
static OAC_EXPORT_BASELINE g_ExportBaselines[RTL_NUMBER_OF(g_IntegrityExportNames)];
typedef PVOID (*OAC_PS_GET_PROCESS_DEBUG_PORT)(_In_ PEPROCESS Process);
static OAC_PS_GET_PROCESS_DEBUG_PORT g_PsGetProcessDebugPort;

static PVOID OacFindImageExport(_In_ PVOID ImageBase, _In_z_ PCSTR Name);
static BOOLEAN OacReadVirtual(
    _Out_writes_bytes_(Size) PVOID Destination,
    _In_ PVOID Source,
    _In_ SIZE_T Size);
static BOOLEAN OacAddressInImage(
    _In_opt_ PVOID Address,
    _In_opt_ PVOID ImageBase,
    _In_ ULONG ImageSize);

static NTSTATUS OacQuerySystemInformation(
    _In_ ULONG InformationClass,
    _Outptr_result_bytebuffer_(*BufferLength) PVOID* Buffer,
    _Out_ PULONG BufferLength)
{
    NTSTATUS status;
    ULONG length = 0;
    ULONG allocationLength;
    ULONG returnedLength;
    ULONG attempt;
    PVOID allocation;

    *Buffer = NULL;
    *BufferLength = 0;
    status = ZwQuerySystemInformation(InformationClass, NULL, 0, &length);
    if (status != STATUS_INFO_LENGTH_MISMATCH &&
        status != STATUS_BUFFER_TOO_SMALL &&
        status != STATUS_BUFFER_OVERFLOW &&
        !NT_SUCCESS(status))
    {
        return status;
    }

    for (attempt = 0; attempt < 4; ++attempt)
    {
        if (length == 0 || length > OAC_MAX_SYSTEM_QUERY - (64UL * 1024UL))
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        allocationLength = length + 64UL * 1024UL;
        allocation = OacAllocatePool(TRUE, allocationLength, OAC_SCAN_TAG);
        if (allocation == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        returnedLength = 0;
        status = ZwQuerySystemInformation(
            InformationClass,
            allocation,
            allocationLength,
            &returnedLength);
        if (NT_SUCCESS(status))
        {
            if (returnedLength == 0 || returnedLength > allocationLength)
            {
                ExFreePoolWithTag(allocation, OAC_SCAN_TAG);
                return STATUS_DATA_ERROR;
            }
            *Buffer = allocation;
            *BufferLength = returnedLength;
            return STATUS_SUCCESS;
        }

        ExFreePoolWithTag(allocation, OAC_SCAN_TAG);
        if (status != STATUS_INFO_LENGTH_MISMATCH &&
            status != STATUS_BUFFER_TOO_SMALL &&
            status != STATUS_BUFFER_OVERFLOW)
        {
            return status;
        }
        length = returnedLength;
    }

    return STATUS_INFO_LENGTH_MISMATCH;
}

static NTSTATUS OacQueryAuxModules(
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

static BOOLEAN OacAsciiContainsInsensitive(
    _In_reads_(Length) const UCHAR* Text,
    _In_ SIZE_T Length,
    _In_z_ PCSTR Needle)
{
    SIZE_T needleLength = strlen(Needle);
    SIZE_T i;
    SIZE_T j;

    if (needleLength == 0 || needleLength > Length)
    {
        return FALSE;
    }

    for (i = 0; i <= Length - needleLength; ++i)
    {
        for (j = 0; j < needleLength; ++j)
        {
            __analysis_assume(i + j < Length);
            CHAR a = (CHAR)Text[i + j];
            CHAR b = Needle[j];
            if (a >= 'A' && a <= 'Z') a = (CHAR)(a + ('a' - 'A'));
            if (b >= 'A' && b <= 'Z') b = (CHAR)(b + ('a' - 'A'));
            if (a != b) break;
        }
        if (j == needleLength) return TRUE;
    }
    return FALSE;
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
        {
            return OacSeverityHigh;
        }
    }
    for (i = 0; i < RTL_NUMBER_OF(review); ++i)
    {
        if (OacDriverBaseNameEquals(Path, Length, review[i]))
        {
            return OacSeverityLow;
        }
    }
    return OacSeverityInfo;
}

static VOID OacAsciiToWide(
    _In_reads_opt_(SourceLength) const UCHAR* Source,
    _In_ SIZE_T SourceLength,
    _Out_writes_(DestinationCount) PWCHAR Destination,
    _In_ SIZE_T DestinationCount)
{
    SIZE_T i;
    SIZE_T count;
    if (Destination == NULL || DestinationCount == 0)
    {
        return;
    }
    if (Source == NULL)
    {
        Destination[0] = L'\0';
        return;
    }
    count = SourceLength;
    if (count >= DestinationCount)
    {
        count = DestinationCount - 1;
    }
    for (i = 0; i < count; ++i)
    {
        __analysis_assume(i < SourceLength);
        if (Source[i] == '\0') break;
        Destination[i] = (WCHAR)Source[i];
    }
    __analysis_assume(i < DestinationCount);
    Destination[i] = L'\0';
}

static BOOLEAN OacAddressInModules(
    _In_ PVOID Address,
    _In_reads_(ModuleCount) PAUX_MODULE_EXTENDED_INFO Modules,
    _In_ ULONG ModuleCount,
    _Out_opt_ PULONG ModuleIndex)
{
    ULONG_PTR value = (ULONG_PTR)Address;
    ULONG i;
    if (ModuleIndex != NULL) *ModuleIndex = MAXULONG;
    for (i = 0; i < ModuleCount; ++i)
    {
        ULONG_PTR start = (ULONG_PTR)Modules[i].BasicInfo.ImageBase;
        ULONG_PTR end = start + Modules[i].ImageSize;
        if (value >= start && value < end && end >= start)
        {
            if (ModuleIndex != NULL) *ModuleIndex = i;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN OacAddressInImage(
    _In_opt_ PVOID Address,
    _In_opt_ PVOID ImageBase,
    _In_ ULONG ImageSize)
{
    ULONG_PTR value = (ULONG_PTR)Address;
    ULONG_PTR start = (ULONG_PTR)ImageBase;
    ULONG_PTR end;

    if (Address == NULL || ImageBase == NULL || ImageSize == 0)
    {
        return FALSE;
    }
    end = start + ImageSize;
    return end >= start && value >= start && value < end;
}

static PVOID OacDispatchAddress(_In_opt_ PDRIVER_DISPATCH Function)
{
    PVOID address = NULL;
    C_ASSERT(sizeof(address) == sizeof(Function));
    RtlCopyMemory(&address, &Function, sizeof(PVOID));
    return address;
}

static PVOID OacUnloadAddress(_In_opt_ PDRIVER_UNLOAD Function)
{
    PVOID address = NULL;
    C_ASSERT(sizeof(address) == sizeof(Function));
    RtlCopyMemory(&address, &Function, sizeof(PVOID));
    return address;
}

static BOOLEAN OacPrintableAscii(
    _In_reads_bytes_(Length) const UCHAR* Text,
    _In_ SIZE_T Length)
{
    SIZE_T i;
    BOOLEAN any = FALSE;
    for (i = 0; i < Length; ++i)
    {
        if (Text[i] == 0) continue;
        if (Text[i] < 0x20 || Text[i] > 0x7e) return FALSE;
        any = TRUE;
    }
    return any;
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
    {
        return FALSE;
    }
    maxEntries = (BufferLength - FIELD_OFFSET(OAC_SYSTEM_MODULE_INFORMATION, Modules)) /
                 sizeof(OAC_SYSTEM_MODULE_ENTRY);
    count = min(Modules->NumberOfModules, maxEntries);
    for (i = 0; i < count; ++i)
    {
        if (Modules->Modules[i].ImageBase == Base) return TRUE;
    }
    return FALSE;
}

static VOID OacScanModules(
    _In_reads_(ModuleCount) PAUX_MODULE_EXTENDED_INFO Modules,
    _In_ ULONG ModuleCount)
{
    PVOID systemBuffer = NULL;
    ULONG systemLength = 0;
    NTSTATUS status;
    ULONG i;

    status = OacQuerySystemInformation(
        OAC_SYSTEM_MODULE_INFORMATION_CLASS,
        &systemBuffer,
        &systemLength);

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
    else if (systemLength >=
        (ULONG)FIELD_OFFSET(OAC_SYSTEM_MODULE_INFORMATION, Modules))
    {
        POAC_SYSTEM_MODULE_INFORMATION systemModules =
            (POAC_SYSTEM_MODULE_INFORMATION)systemBuffer;
        ULONG maximum =
            (systemLength - FIELD_OFFSET(OAC_SYSTEM_MODULE_INFORMATION, Modules)) /
            sizeof(OAC_SYSTEM_MODULE_ENTRY);
        ULONG count = min(systemModules->NumberOfModules, maximum);
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
    {
        ExFreePoolWithTag(systemBuffer, OAC_SCAN_TAG);
    }
}

static VOID OacScanProcessesAndSystemThreads(
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

    status = OacQuerySystemInformation(
        OAC_SYSTEM_PROCESS_INFORMATION_CLASS,
        &processBuffer,
        &processLength);
    if (!NT_SUCCESS(status))
    {
        OacReportFinding(OacSeverityMedium, OacCategoryProcess, NULL, NULL,
            NULL, status, L"Process cross-view query failed: 0x%08X", status);
        return;
    }

    bitmapBuffer = (PULONG)OacAllocatePool(
        TRUE,
        OAC_PID_BITMAP_BITS / 8,
        OAC_SCAN_TAG);
    if (bitmapBuffer != NULL)
    {
        RtlZeroMemory(bitmapBuffer, OAC_PID_BITMAP_BITS / 8);
        RtlInitializeBitMap(&bitmap, bitmapBuffer, OAC_PID_BITMAP_BITS);
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
            break;
        }

        ++processCount;
        if (bitmapBuffer != NULL && pid < OAC_PID_BITMAP_BITS)
        {
            RtlSetBit(&bitmap, pid);
        }

        threads = (POAC_SYSTEM_THREAD_INFORMATION)(process + 1);
        availableThreads = (entryLength - sizeof(*process)) /
                           sizeof(OAC_SYSTEM_THREAD_INFORMATION);
        availableThreads = min(availableThreads, process->NumberOfThreads);
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

        if (process->NextEntryOffset == 0) break;
        cursor += process->NextEntryOffset;
    }

    OacReportFinding(OacSeverityInfo, OacCategoryProcess, NULL, NULL,
        NULL, threadCount, L"Process snapshot: %lu processes, %lu threads",
        processCount, threadCount);

    if (bitmapBuffer != NULL && Handles != NULL &&
        HandleBufferLength >= (ULONG)FIELD_OFFSET(OAC_SYSTEM_HANDLE_INFORMATION, Handles))
    {
        ULONG_PTR maxHandles =
            (HandleBufferLength - FIELD_OFFSET(OAC_SYSTEM_HANDLE_INFORMATION, Handles)) /
            sizeof(OAC_SYSTEM_HANDLE_ENTRY);
        ULONG_PTR count = min(Handles->NumberOfHandles, maxHandles);
        ULONG_PTR i;
        ULONG discrepancies = 0;
        for (i = 0; i < count && discrepancies < 128; ++i)
        {
            ULONG pid = (ULONG)Handles->Handles[i].UniqueProcessId;
            if (pid != 0 && pid < OAC_PID_BITMAP_BITS && !RtlCheckBit(&bitmap, pid))
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

    if (bitmapBuffer != NULL) ExFreePoolWithTag(bitmapBuffer, OAC_SCAN_TAG);
    ExFreePoolWithTag(processBuffer, OAC_SCAN_TAG);
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

static VOID OacScanHandles(
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
        return;
    }

    maximum = (BufferLength - FIELD_OFFSET(OAC_SYSTEM_HANDLE_INFORMATION, Handles)) /
              sizeof(OAC_SYSTEM_HANDLE_ENTRY);
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
}

static BOOLEAN OacImageRvaRangeValid(_In_ ULONG Rva, _In_ SIZE_T Size)
{
    return Rva <= g_NtoskrnlSize &&
        Size <= (SIZE_T)(g_NtoskrnlSize - Rva);
}

static BOOLEAN OacExportNameMatches(
    _In_ PVOID ImageBase,
    _In_ ULONG NameRva,
    _In_z_ PCSTR Expected)
{
    CHAR actual[OAC_MAX_EXPORT_NAME];
    SIZE_T expectedLength = strlen(Expected);
    if (expectedLength == 0 || expectedLength >= sizeof(actual) ||
        !OacImageRvaRangeValid(NameRva, expectedLength + 1) ||
        !OacReadVirtual(
            actual,
            (PUCHAR)ImageBase + NameRva,
            expectedLength + 1))
    {
        return FALSE;
    }
    return RtlCompareMemory(actual, Expected, expectedLength + 1) ==
        expectedLength + 1;
}

static PVOID OacFindImageExport(_In_ PVOID ImageBase, _In_z_ PCSTR Name)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_EXPORT_DIRECTORY exports;
    ULONG exportRva;
    ULONG exportSize;
    ULONG i;

    if (ImageBase == NULL || Name == NULL ||
        g_NtoskrnlSize < sizeof(dos) ||
        !OacReadVirtual(&dos, ImageBase, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
        !OacImageRvaRangeValid(
            (ULONG)dos.e_lfanew,
            sizeof(nt)) ||
        !OacReadVirtual(
            &nt,
            (PUCHAR)ImageBase + (ULONG)dos.e_lfanew,
            sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        return NULL;
    }

    exportRva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    exportSize = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (exportRva == 0 || exportSize < sizeof(exports) ||
        !OacImageRvaRangeValid(exportRva, exportSize) ||
        !OacReadVirtual(
            &exports,
            (PUCHAR)ImageBase + exportRva,
            sizeof(exports)) ||
        exports.NumberOfNames > g_NtoskrnlSize / sizeof(ULONG) ||
        exports.NumberOfFunctions > g_NtoskrnlSize / sizeof(ULONG) ||
        !OacImageRvaRangeValid(
            exports.AddressOfNames,
            (SIZE_T)exports.NumberOfNames * sizeof(ULONG)) ||
        !OacImageRvaRangeValid(
            exports.AddressOfNameOrdinals,
            (SIZE_T)exports.NumberOfNames * sizeof(USHORT)) ||
        !OacImageRvaRangeValid(
            exports.AddressOfFunctions,
            (SIZE_T)exports.NumberOfFunctions * sizeof(ULONG)))
    {
        return NULL;
    }

    for (i = 0; i < exports.NumberOfNames; ++i)
    {
        ULONG nameRva;
        USHORT ordinal;
        ULONG functionRva;
        if (!OacReadVirtual(
                &nameRva,
                (PUCHAR)ImageBase + exports.AddressOfNames +
                    i * sizeof(ULONG),
                sizeof(nameRva)) ||
            !OacReadVirtual(
                &ordinal,
                (PUCHAR)ImageBase + exports.AddressOfNameOrdinals +
                    i * sizeof(USHORT),
                sizeof(ordinal)))
        {
            return NULL;
        }
        if (!OacExportNameMatches(ImageBase, nameRva, Name)) continue;
        if (ordinal >= exports.NumberOfFunctions ||
            !OacReadVirtual(
                &functionRva,
                (PUCHAR)ImageBase + exports.AddressOfFunctions +
                    ordinal * sizeof(ULONG),
                sizeof(functionRva)))
        {
            return NULL;
        }
        if (functionRva >= exportRva &&
            functionRva - exportRva < exportSize) return NULL;
        if (functionRva >= g_NtoskrnlSize) return NULL;
        return (PUCHAR)ImageBase + functionRva;
    }
    return NULL;
}

static PVOID OacDecodeHookTarget(
    _In_reads_bytes_(16) const UCHAR* Code,
    _In_ PVOID CodeAddress)
{
    LONG displacement;
    PVOID target;
    if (Code == NULL || CodeAddress == NULL) return NULL;

    if (Code[0] == 0xEB)
    {
        CHAR shortDisplacement = (CHAR)Code[1];
        return (PUCHAR)CodeAddress + 2 + shortDisplacement;
    }
    if (Code[0] == 0xE9)
    {
        RtlCopyMemory(&displacement, Code + 1, sizeof(displacement));
        return (PUCHAR)CodeAddress + 5 + displacement;
    }
    if (Code[0] == 0xFF && Code[1] == 0x25)
    {
        RtlCopyMemory(&displacement, Code + 2, sizeof(displacement));
        if (OacReadVirtual(
                &target,
                (PUCHAR)CodeAddress + 6 + displacement,
                sizeof(PVOID))) return target;
        return NULL;
    }
    if (Code[0] == 0x48 && Code[1] == 0xB8 &&
        Code[10] == 0xFF && Code[11] == 0xE0)
    {
        RtlCopyMemory(&target, Code + 2, sizeof(PVOID));
        return target;
    }
    if (Code[0] == 0x49 &&
        (Code[1] & 0xF8) == 0xB8 &&
        Code[10] == 0x41 && Code[11] == 0xFF &&
        (Code[12] & 0xF8) == 0xE0 &&
        (Code[1] & 7) == (Code[12] & 7))
    {
        RtlCopyMemory(&target, Code + 2, sizeof(PVOID));
        return target;
    }
    if (Code[0] == 0x48 && Code[1] == 0xB8 &&
        Code[10] == 0x50 && Code[11] == 0xC3)
    {
        RtlCopyMemory(&target, Code + 2, sizeof(PVOID));
        return target;
    }
    if (Code[0] == 0x68 && Code[5] == 0xC3)
    {
        RtlCopyMemory(&displacement, Code + 1, sizeof(displacement));
        return (PVOID)(LONG_PTR)displacement;
    }
    if (Code[0] == 0x48 && Code[1] == 0x8B && Code[2] == 0x05 &&
        Code[7] == 0xFF && Code[8] == 0xE0)
    {
        RtlCopyMemory(&displacement, Code + 3, sizeof(displacement));
        if (OacReadVirtual(
                &target,
                (PUCHAR)CodeAddress + 7 + displacement,
                sizeof(PVOID))) return target;
    }
    return NULL;
}

static ULONG_PTR OacCaptureCpuIntegrity(_In_ ULONG_PTR RawContext)
{
    POAC_CPU_INTEGRITY_CONTEXT context =
        (POAC_CPU_INTEGRITY_CONTEXT)RawContext;
    ULONG slot = (ULONG)(InterlockedIncrement(&context->Count) - 1);
    PROCESSOR_NUMBER processorNumber;
    OAC_IDTR idtr;
    OAC_IDTR gdtr;
    POAC_CPU_RECORD sample;
    int registers[4];
    unsigned int tscAux = 0;

    if (slot >= context->Capacity) return 0;
    KeGetCurrentProcessorNumberEx(&processorNumber);
    __sidt(&idtr);
    OacStoreGdtr(&gdtr);
    sample = &context->Samples[slot];
    sample->ProcessorIndex = KeGetProcessorIndexFromNumber(&processorNumber);
    sample->Group = processorNumber.Group;
    sample->Number = processorNumber.Number;
    sample->CallbackAddress = (ULONGLONG)(ULONG_PTR)_ReturnAddress();
    sample->Cr0 = __readcr0();
    sample->Cr3 = __readcr3();
    sample->Cr4 = __readcr4();
    sample->Dr0 = __readdr(0);
    sample->Dr1 = __readdr(1);
    sample->Dr2 = __readdr(2);
    sample->Dr3 = __readdr(3);
    sample->Dr6 = __readdr(6);
    sample->Dr7 = __readdr(7);
    sample->Efer = __readmsr(OAC_MSR_EFER);
    sample->Lstar = __readmsr(OAC_MSR_LSTAR);
    sample->Cstar = __readmsr(OAC_MSR_CSTAR);
    sample->Star = __readmsr(OAC_MSR_STAR);
    sample->Fmask = __readmsr(OAC_MSR_FMASK);
    sample->SysenterEip = __readmsr(OAC_MSR_SYSENTER_EIP);
    sample->SysenterEsp = __readmsr(OAC_MSR_SYSENTER_ESP);
    sample->IdtLimit = idtr.Limit;
    sample->IdtBase = idtr.Base;
    sample->GdtLimit = gdtr.Limit;
    sample->GdtBase = gdtr.Base;

    __cpuid(registers, 0);
    sample->CpuidBasicMaximum = (ULONG)registers[0];
    __cpuid(registers, 0x80000000);
    sample->CpuidExtendedMaximum = (ULONG)registers[0];
    __cpuid(registers, 1);
    sample->Cpuid1Ecx = (ULONG)registers[2];
    sample->Cpuid1Edx = (ULONG)registers[3];
    if (sample->CpuidBasicMaximum >= 7)
    {
        __cpuidex(registers, 7, 0);
        sample->Cpuid7Ebx = (ULONG)registers[1];
        sample->Cpuid7Ecx = (ULONG)registers[2];
    }
    if (sample->CpuidExtendedMaximum >= 0x80000001UL)
    {
        __cpuid(registers, 0x80000001);
        sample->CpuidExtended1Ecx = (ULONG)registers[2];
        sample->CpuidExtended1Edx = (ULONG)registers[3];
    }
    if ((sample->Cpuid1Ecx & (1UL << 31)) != 0)
    {
        sample->Flags |= OAC_CPU_FLAG_HYPERVISOR_PRESENT;
        __cpuid(registers, 0x40000000);
        sample->HypervisorMaximumLeaf = (ULONG)registers[0];
        RtlCopyMemory(sample->HypervisorVendor + 0, &registers[1], 4);
        RtlCopyMemory(sample->HypervisorVendor + 4, &registers[2], 4);
        RtlCopyMemory(sample->HypervisorVendor + 8, &registers[3], 4);
    }
    if ((sample->CpuidExtended1Edx & (1UL << 27)) != 0)
    {
        (VOID)__rdtscp(&tscAux);
        sample->TscAux = tscAux;
    }
    else
    {
        sample->TscAux = MAXULONG;
    }
    return 0;
}

static BOOLEAN OacImageRangeValid(
    _In_ ULONG ImageSize,
    _In_ ULONG Rva,
    _In_ SIZE_T Size)
{
    return Rva <= ImageSize && Size <= (SIZE_T)(ImageSize - Rva);
}

static BOOLEAN OacReadImageRange(
    _In_ PVOID ImageBase,
    _In_ ULONG ImageSize,
    _In_ ULONG Rva,
    _Out_writes_bytes_(Size) PVOID Destination,
    _In_ SIZE_T Size)
{
    if (ImageBase == NULL || Destination == NULL ||
        !OacImageRangeValid(ImageSize, Rva, Size))
    {
        return FALSE;
    }
    return OacReadVirtual(Destination, (PUCHAR)ImageBase + Rva, Size);
}

static VOID OacScanImageIatTargets(
    _In_ PVOID ImageBase,
    _In_ ULONG ImageSize,
    _In_z_ PCWSTR Label,
    _In_reads_(ModuleCount) PAUX_MODULE_EXTENDED_INFO Modules,
    _In_ ULONG ModuleCount)
{
    ULONG checked = 0;
    ULONG unbacked = 0;
    BOOLEAN incomplete = FALSE;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_DATA_DIRECTORY imports;
    ULONG descriptorCount;
    ULONG i;

    if (ImageBase == NULL || ImageSize < sizeof(dos) ||
        !OacReadImageRange(ImageBase, ImageSize, 0, &dos, sizeof(dos)))
    {
        OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
            ImageBase, 0, L"%ls image headers are not safely readable", Label);
        return;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
        !OacReadImageRange(
            ImageBase,
            ImageSize,
            (ULONG)dos.e_lfanew,
            &nt,
            sizeof(nt)))
    {
        OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
            ImageBase, 0, L"%ls image headers failed bounded validation", Label);
        return;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
    {
        OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
            ImageBase, 0, L"%ls PE metadata is invalid or incomplete", Label);
        return;
    }

    imports = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imports.VirtualAddress == 0 || imports.Size == 0)
    {
        OacReportFinding(OacSeverityInfo, OacCategoryIntegrity, NULL, NULL,
            ImageBase, 0, L"%ls has no import directory", Label);
        return;
    }
    if (imports.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
        !OacImageRangeValid(ImageSize, imports.VirtualAddress, imports.Size))
    {
        OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
            ImageBase, imports.VirtualAddress,
            L"%ls import directory failed bounded validation", Label);
        return;
    }

    descriptorCount = imports.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    for (i = 0; i < descriptorCount; ++i)
    {
        IMAGE_IMPORT_DESCRIPTOR descriptor;
        ULONG descriptorRva = imports.VirtualAddress +
            i * (ULONG)sizeof(IMAGE_IMPORT_DESCRIPTOR);
        ULONG thunkCount;
        ULONG j;

        if (!OacReadImageRange(
                ImageBase,
                ImageSize,
                descriptorRva,
                &descriptor,
                sizeof(descriptor)))
        {
            incomplete = TRUE;
            break;
        }
        if (descriptor.Name == 0 && descriptor.FirstThunk == 0) break;
        if (descriptor.FirstThunk == 0 ||
            !OacImageRangeValid(
                ImageSize,
                descriptor.FirstThunk,
                sizeof(IMAGE_THUNK_DATA64)))
        {
            OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
                ImageBase, descriptor.FirstThunk,
                L"%ls import descriptor %lu has an invalid IAT", Label, i);
            continue;
        }

        thunkCount = min(
            (ImageSize - descriptor.FirstThunk) /
                (ULONG)sizeof(IMAGE_THUNK_DATA64),
            OAC_MAX_IMPORT_THUNKS);
        for (j = 0; j < thunkCount; ++j)
        {
            IMAGE_THUNK_DATA64 thunk;
            ULONG thunkRva = descriptor.FirstThunk +
                j * (ULONG)sizeof(IMAGE_THUNK_DATA64);
            PVOID target;
            if (!OacReadImageRange(
                    ImageBase,
                    ImageSize,
                    thunkRva,
                    &thunk,
                    sizeof(thunk)))
            {
                incomplete = TRUE;
                break;
            }
            target = (PVOID)(ULONG_PTR)thunk.u1.Function;
            if (target == NULL) break;
            ++checked;
            if (!OacAddressInModules(target, Modules, ModuleCount, NULL))
            {
                ++unbacked;
                if (unbacked <= 16)
                {
                    OacReportFinding(
                        OacSeverityCritical,
                        OacCategoryIntegrity,
                        NULL,
                        NULL,
                        target,
                        i,
                        L"%ls IAT entry %lu:%lu targets memory outside every loaded module",
                        Label,
                        i,
                        j);
                }
            }
        }
        if (incomplete) break;
    }

    if (incomplete)
    {
        OacReportFinding(OacSeverityLow, OacCategoryIntegrity, NULL, NULL,
            ImageBase, checked,
            L"%ls import metadata or IAT became unavailable/nonresident; scan stopped safely",
            Label);
        return;
    }
    OacReportFinding(
        unbacked == 0 ? OacSeverityInfo : OacSeverityCritical,
        OacCategoryIntegrity,
        NULL,
        NULL,
        ImageBase,
        unbacked,
        L"%ls IAT ownership: %lu resolved entries, %lu unbacked targets",
        Label,
        checked,
        unbacked);
}

/* These WDK-defined DRIVER_OBJECT fields are intentionally sampled only from
 * referenced objects to detect dispatch-table tampering. PREfast otherwise
 * warns because ordinary drivers should generally treat the object as opaque. */
#pragma warning(push)
#pragma warning(disable: 28175)
static VOID OacScanDriverSelfIntegrity(
    _In_reads_(ModuleCount) PAUX_MODULE_EXTENDED_INFO Modules,
    _In_ ULONG ModuleCount)
{
    ULONG i;
    ULONG changes = 0;
    if (g_DriverObject == NULL) return;

    if (g_DriverObject->DriverStart != g_DriverBase ||
        g_DriverObject->DriverSize != g_DriverSize)
    {
        ++changes;
        OacReportFinding(OacSeverityCritical, OacCategoryIntegrity, NULL, NULL,
            g_DriverObject->DriverStart, g_DriverObject->DriverSize,
            L"OAC DriverObject image identity was modified");
    }
    if (g_DriverObject->DriverSection != g_DriverSectionBaseline)
    {
        ++changes;
        OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
            g_DriverObject->DriverSection,
            (ULONGLONG)(ULONG_PTR)g_DriverSectionBaseline,
            L"OAC DriverSection pointer changed after initialization");
    }
    if (g_DriverObject->FastIoDispatch != g_FastIoBaseline)
    {
        ++changes;
        OacReportFinding(OacSeverityCritical, OacCategoryIntegrity, NULL, NULL,
            g_DriverObject->FastIoDispatch,
            (ULONGLONG)(ULONG_PTR)g_FastIoBaseline,
            L"OAC FastIoDispatch pointer changed after initialization");
    }
    if (g_DriverObject->DriverUnload != g_DriverUnloadBaseline)
    {
        PVOID currentAddress = OacUnloadAddress(g_DriverObject->DriverUnload);
        PVOID baselineAddress = OacUnloadAddress(g_DriverUnloadBaseline);
        ++changes;
        OacReportFinding(OacSeverityCritical, OacCategoryIntegrity, NULL, NULL,
            currentAddress,
            (ULONGLONG)(ULONG_PTR)baselineAddress,
            L"OAC DriverUnload pointer changed after initialization");
    }

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
    {
        PDRIVER_DISPATCH current = g_DriverObject->MajorFunction[i];
        PVOID currentAddress = OacDispatchAddress(current);
        if (current != g_MajorFunctionBaseline[i])
        {
            ++changes;
            OacReportFinding(OacSeverityCritical, OacCategoryIntegrity, NULL, NULL,
                currentAddress, i,
                L"OAC MajorFunction[%lu] changed after initialization", i);
        }
        if (!OacAddressInImage(currentAddress, g_DriverBase, g_DriverSize) ||
            !OacAddressInModules(currentAddress, Modules, ModuleCount, NULL))
        {
            ++changes;
            OacReportFinding(OacSeverityCritical, OacCategoryIntegrity, NULL, NULL,
                currentAddress, i,
                L"OAC MajorFunction[%lu] points outside the loaded OAC image", i);
        }
    }

    OacReportFinding(
        changes == 0 ? OacSeverityInfo : OacSeverityCritical,
        OacCategoryIntegrity,
        NULL,
        NULL,
        g_DriverObject,
        changes,
        L"OAC driver dispatch self-integrity: %lu changes",
        changes);
}
#pragma warning(pop)

static VOID OacScanExportIntegrity(
    _In_reads_(ModuleCount) PAUX_MODULE_EXTENDED_INFO Modules,
    _In_ ULONG ModuleCount)
{
    ULONG i;
    ULONG available = 0;
    ULONG changes = 0;
    for (i = 0; i < RTL_NUMBER_OF(g_ExportBaselines); ++i)
    {
        POAC_EXPORT_BASELINE baseline = &g_ExportBaselines[i];
        UCHAR current[OAC_EXPORT_BASELINE_BYTES];
        PVOID currentAddress;
        PVOID target;
        WCHAR name[64];
        ULONG targetModule;

        if (!baseline->Available) continue;
        ++available;
        currentAddress = OacFindImageExport(g_NtoskrnlBase, baseline->Name);
        OacAsciiToWide((const UCHAR*)baseline->Name, strlen(baseline->Name),
            name, RTL_NUMBER_OF(name));
        if (currentAddress != baseline->Address)
        {
            ++changes;
            OacReportFinding(OacSeverityCritical, OacCategoryIntegrity, NULL, NULL,
                currentAddress, (ULONGLONG)(ULONG_PTR)baseline->Address,
                L"Kernel export directory target for %ls changed after initialization", name);
            continue;
        }
        if (!OacReadVirtual(current, currentAddress, sizeof(current)))
        {
            ++changes;
            OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
                currentAddress, 0, L"Unable to read kernel export %ls", name);
            continue;
        }
        if (RtlCompareMemory(current, baseline->Bytes, sizeof(current)) != sizeof(current))
        {
            ++changes;
            OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
                currentAddress, 0,
                L"Kernel export %ls prologue changed after OAC initialization", name);
        }

        target = OacDecodeHookTarget(current, currentAddress);
        if (target == NULL) continue;
        if (!OacAddressInModules(target, Modules, ModuleCount, &targetModule))
        {
            OacReportFinding(OacSeverityCritical, OacCategoryIntegrity, NULL, NULL,
                currentAddress, (ULONGLONG)(ULONG_PTR)target,
                L"Inline detour from %ls targets unbacked kernel memory", name);
        }
        else if (!OacAddressInImage(target, g_NtoskrnlBase, g_NtoskrnlSize))
        {
            OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
                currentAddress, (ULONGLONG)(ULONG_PTR)target,
                L"Inline detour from %ls crosses into kernel module %lu", name, targetModule);
        }
    }

    OacReportFinding(
        changes == 0 ? OacSeverityInfo : OacSeverityHigh,
        OacCategoryIntegrity,
        NULL,
        NULL,
        g_NtoskrnlBase,
        changes,
        L"Kernel export baseline: %lu monitored exports, %lu changes",
        available,
        changes);
}

static VOID OacValidateKernelControlTarget(
    _In_z_ PCWSTR Name,
    _In_ ULONGLONG Target,
    _In_ ULONG ProcessorIndex,
    _In_ BOOLEAN ZeroAllowed,
    _In_reads_(ModuleCount) PAUX_MODULE_EXTENDED_INFO Modules,
    _In_ ULONG ModuleCount)
{
    PVOID address = (PVOID)(ULONG_PTR)Target;
    ULONG moduleIndex;
    if (Target == 0 && ZeroAllowed) return;
    if (OacAddressInImage(address, g_NtoskrnlBase, g_NtoskrnlSize)) return;
    if (OacAddressInModules(address, Modules, ModuleCount, &moduleIndex))
    {
        OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
            address, ProcessorIndex,
            L"CPU %lu %ls points into non-kernel module %lu",
            ProcessorIndex, Name, moduleIndex);
    }
    else
    {
        OacReportFinding(OacSeverityCritical, OacCategoryIntegrity, NULL, NULL,
            address, ProcessorIndex,
            L"CPU %lu %ls points outside every loaded kernel module",
            ProcessorIndex, Name);
    }
}

static VOID OacScanKernelIntegrity(
    _In_reads_(ModuleCount) PAUX_MODULE_EXTENDED_INFO Modules,
    _In_ ULONG ModuleCount)
{
    OAC_CPU_INTEGRITY_CONTEXT cpuContext;
    POAC_CPU_RECORD samples = NULL;
    OAC_CPU_RECORD fallbackSample;
    ULONGLONG referenceIdt[256];
    UCHAR referenceIdtValid[256];
    BOOLEAN referenceIdtSet = FALSE;
    ULONG processorCapacity;
    ULONG capturedProcessors;
    ULONG idtDivergences = 0;
    ULONG malformedGates = 0;
    ULONG i;

    RtlZeroMemory(&cpuContext, sizeof(cpuContext));
    RtlZeroMemory(&fallbackSample, sizeof(fallbackSample));
    RtlZeroMemory(referenceIdt, sizeof(referenceIdt));
    RtlZeroMemory(referenceIdtValid, sizeof(referenceIdtValid));
    processorCapacity = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (processorCapacity != 0 &&
        processorCapacity <= MAXULONG / (ULONG)sizeof(OAC_CPU_RECORD))
    {
        samples = (POAC_CPU_RECORD)OacAllocatePool(
            FALSE,
            (SIZE_T)processorCapacity * sizeof(OAC_CPU_RECORD),
            OAC_SCAN_TAG);
    }
    if (samples != NULL)
    {
        RtlZeroMemory(
            samples,
            (SIZE_T)processorCapacity * sizeof(OAC_CPU_RECORD));
        cpuContext.Samples = samples;
        cpuContext.Capacity = processorCapacity;
        (VOID)KeIpiGenericCall(
            OacCaptureCpuIntegrity,
            (ULONG_PTR)&cpuContext);
        capturedProcessors = min(
            (ULONG)InterlockedCompareExchange(&cpuContext.Count, 0, 0),
            processorCapacity);
    }
    else
    {
        cpuContext.Samples = &fallbackSample;
        cpuContext.Capacity = 1;
        (VOID)OacCaptureCpuIntegrity((ULONG_PTR)&cpuContext);
        samples = &fallbackSample;
        capturedProcessors = 1;
        OacReportFinding(
            OacSeverityMedium,
            OacCategoryIntegrity,
            NULL,
            NULL,
            NULL,
            processorCapacity,
            L"All-processor integrity snapshot allocation failed; sampled current CPU only");
    }

    for (i = 0; i < capturedProcessors; ++i)
    {
        const ULONGLONG requiredCr0 = OAC_CR0_PE | OAC_CR0_WP | OAC_CR0_PG;
        const ULONGLONG requiredEfer = OAC_EFER_SCE | OAC_EFER_LME | OAC_EFER_LMA;
        if ((samples[i].Cr0 & requiredCr0) != requiredCr0)
        {
            OacReportFinding(OacSeverityCritical, OacCategoryIntegrity, NULL, NULL,
                NULL, samples[i].Cr0,
                L"CPU %lu CR0 is missing PE/WP/PG integrity bits",
                samples[i].ProcessorIndex);
        }
        if ((samples[i].Cr4 & OAC_CR4_PAE) == 0)
        {
            OacReportFinding(OacSeverityCritical, OacCategoryIntegrity, NULL, NULL,
                NULL, samples[i].Cr4, L"CPU %lu CR4.PAE is clear",
                samples[i].ProcessorIndex);
        }
        if ((samples[i].Efer & requiredEfer) != requiredEfer)
        {
            OacReportFinding(OacSeverityCritical, OacCategoryIntegrity, NULL, NULL,
                NULL, samples[i].Efer,
                L"CPU %lu EFER is missing SCE/LME/LMA integrity bits",
                samples[i].ProcessorIndex);
        }
        if ((samples[i].CpuidExtended1Edx & (1UL << 20)) != 0 &&
            (samples[i].Efer & OAC_EFER_NXE) == 0)
        {
            OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
                NULL, samples[i].Efer,
                L"CPU %lu advertises NX but EFER.NXE is clear",
                samples[i].ProcessorIndex);
        }
        if ((samples[i].Cpuid7Ebx & (1UL << 7)) != 0 &&
            (samples[i].Cr4 & OAC_CR4_SMEP) == 0)
        {
            OacReportFinding(OacSeverityMedium, OacCategoryIntegrity, NULL, NULL,
                NULL, samples[i].Cr4,
                L"CPU %lu advertises SMEP but CR4.SMEP is clear",
                samples[i].ProcessorIndex);
        }
        if ((samples[i].Cpuid7Ebx & (1UL << 20)) != 0 &&
            (samples[i].Cr4 & OAC_CR4_SMAP) == 0)
        {
            OacReportFinding(OacSeverityLow, OacCategoryIntegrity, NULL, NULL,
                NULL, samples[i].Cr4,
                L"CPU %lu advertises SMAP but CR4.SMAP is clear",
                samples[i].ProcessorIndex);
        }
        if ((samples[i].Dr7 & 0xFFULL) != 0 ||
            (samples[i].Dr7 & (1ULL << 13)) != 0)
        {
            OacReportFinding(OacSeverityHigh, OacCategoryDebugger, NULL, NULL,
                (PVOID)(ULONG_PTR)samples[i].Dr0, samples[i].Dr7,
                L"CPU %lu has enabled hardware breakpoints or DR7.GD",
                samples[i].ProcessorIndex);
        }

        OacValidateKernelControlTarget(L"IPI callback return", samples[i].CallbackAddress,
            samples[i].ProcessorIndex, FALSE, Modules, ModuleCount);
        OacValidateKernelControlTarget(L"IA32_LSTAR", samples[i].Lstar,
            samples[i].ProcessorIndex, FALSE, Modules, ModuleCount);
        OacValidateKernelControlTarget(L"IA32_CSTAR", samples[i].Cstar,
            samples[i].ProcessorIndex, TRUE, Modules, ModuleCount);
        OacValidateKernelControlTarget(L"IA32_SYSENTER_EIP", samples[i].SysenterEip,
            samples[i].ProcessorIndex, TRUE, Modules, ModuleCount);

        if (samples[i].IdtLimit < (256UL * sizeof(OAC_IDT_GATE) - 1) ||
            samples[i].GdtLimit < 0x3FUL)
        {
            OacReportFinding(OacSeverityMedium, OacCategoryIntegrity, NULL, NULL,
                (PVOID)(ULONG_PTR)samples[i].IdtBase,
                ((ULONGLONG)samples[i].IdtLimit << 32) | samples[i].GdtLimit,
                L"CPU %lu has unexpectedly short descriptor tables",
                samples[i].ProcessorIndex);
        }
        {
            ULONGLONG descriptor = 0;
            if (!OacReadVirtual(&descriptor,
                    (PVOID)(ULONG_PTR)samples[i].GdtBase,
                    sizeof(descriptor)))
            {
                OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
                    (PVOID)(ULONG_PTR)samples[i].GdtBase,
                    samples[i].ProcessorIndex,
                    L"Unable to safely read CPU %lu GDT", samples[i].ProcessorIndex);
            }
        }

        if ((samples[i].Flags & OAC_CPU_FLAG_HYPERVISOR_PRESENT) != 0)
        {
            if (samples[i].HypervisorMaximumLeaf < 0x40000000UL ||
                samples[i].HypervisorMaximumLeaf > 0x4000FFFFUL ||
                !OacPrintableAscii(samples[i].HypervisorVendor, 12))
            {
                OacReportFinding(OacSeverityHigh, OacCategoryVirtualization, NULL, NULL,
                    NULL, samples[i].HypervisorMaximumLeaf,
                    L"CPU %lu exposes an inconsistent hypervisor CPUID namespace",
                    samples[i].ProcessorIndex);
            }
        }

        if (i != 0)
        {
            if (samples[i].Lstar != samples[0].Lstar ||
                samples[i].Cstar != samples[0].Cstar ||
                samples[i].Star != samples[0].Star ||
                samples[i].Fmask != samples[0].Fmask)
            {
                OacReportFinding(OacSeverityCritical, OacCategoryIntegrity, NULL, NULL,
                    (PVOID)(ULONG_PTR)samples[i].Lstar, samples[i].ProcessorIndex,
                    L"CPU %lu syscall MSRs disagree with CPU %lu",
                    samples[i].ProcessorIndex, samples[0].ProcessorIndex);
            }
            if (samples[i].Cr0 != samples[0].Cr0 ||
                samples[i].Cr4 != samples[0].Cr4 ||
                samples[i].Efer != samples[0].Efer)
            {
                OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
                    NULL, samples[i].ProcessorIndex,
                    L"CPU %lu control-register state disagrees with CPU %lu",
                    samples[i].ProcessorIndex, samples[0].ProcessorIndex);
            }
            if ((samples[i].Flags & OAC_CPU_FLAG_HYPERVISOR_PRESENT) !=
                    (samples[0].Flags & OAC_CPU_FLAG_HYPERVISOR_PRESENT) ||
                samples[i].HypervisorMaximumLeaf != samples[0].HypervisorMaximumLeaf ||
                RtlCompareMemory(samples[i].HypervisorVendor,
                    samples[0].HypervisorVendor, 12) != 12)
            {
                OacReportFinding(OacSeverityHigh, OacCategoryVirtualization, NULL, NULL,
                    NULL, samples[i].ProcessorIndex,
                    L"CPU %lu hypervisor CPUID state disagrees with CPU %lu",
                    samples[i].ProcessorIndex, samples[0].ProcessorIndex);
            }
        }
    }

    for (i = 0; i < capturedProcessors; ++i)
    {
        ULONG j;
        ULONG idtCount;
        BOOLEAN duplicate = FALSE;
        for (j = 0; j < i; ++j)
        {
            if (samples[j].IdtBase == samples[i].IdtBase &&
                samples[j].IdtLimit == samples[i].IdtLimit)
            {
                duplicate = TRUE;
                break;
            }
        }
        if (duplicate) continue;
        idtCount = min(
            (ULONG)((samples[i].IdtLimit + 1) / sizeof(OAC_IDT_GATE)),
            256UL);
        for (j = 0; j < idtCount; ++j)
        {
            OAC_IDT_GATE gate;
            ULONGLONG handler;
            if (!OacReadVirtual(
                    &gate,
                    (PVOID)(ULONG_PTR)(samples[i].IdtBase + j * sizeof(gate)),
                    sizeof(gate)))
            {
                OacReportFinding(
                    OacSeverityCritical,
                    OacCategoryIntegrity,
                    NULL,
                    NULL,
                    (PVOID)(ULONG_PTR)samples[i].IdtBase,
                    samples[i].ProcessorIndex,
                    L"Unable to safely read CPU %lu IDT vector %lu",
                    samples[i].ProcessorIndex,
                    j);
                break;
            }
            handler = gate.OffsetLow |
                ((ULONGLONG)gate.OffsetMiddle << 16) |
                ((ULONGLONG)gate.OffsetHigh << 32);
            if (handler != 0 &&
                (((gate.TypeAttributes & 0x80) == 0) ||
                 ((gate.TypeAttributes & 0x0F) != 0x0E &&
                  (gate.TypeAttributes & 0x0F) != 0x0F) ||
                 gate.Selector == 0 || gate.Reserved != 0 || (gate.Ist & 0xF8) != 0))
            {
                ++malformedGates;
                if (malformedGates <= 16)
                {
                    OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
                        (PVOID)(ULONG_PTR)handler, samples[i].ProcessorIndex,
                        L"CPU %lu IDT vector %lu has malformed gate metadata",
                        samples[i].ProcessorIndex, j);
                }
            }
            if (handler != 0 &&
                !OacAddressInImage(
                    (PVOID)(ULONG_PTR)handler,
                    g_NtoskrnlBase,
                    g_NtoskrnlSize))
            {
                ULONG moduleIndex;
                if (!OacAddressInModules(
                        (PVOID)(ULONG_PTR)handler,
                        Modules,
                        ModuleCount,
                        &moduleIndex))
                {
                    OacReportFinding(OacSeverityCritical, OacCategoryIntegrity,
                        NULL, NULL, (PVOID)(ULONG_PTR)handler,
                        samples[i].ProcessorIndex,
                        L"CPU %lu IDT vector %lu points outside every loaded module",
                        samples[i].ProcessorIndex, j);
                }
                else
                {
                    OacReportFinding(OacSeverityHigh, OacCategoryIntegrity,
                        NULL, NULL, (PVOID)(ULONG_PTR)handler, moduleIndex,
                        L"CPU %lu IDT vector %lu points into non-kernel module %lu",
                        samples[i].ProcessorIndex, j, moduleIndex);
                }
            }
            if (!referenceIdtSet)
            {
                referenceIdt[j] = handler;
                referenceIdtValid[j] = 1;
            }
            else if (referenceIdtValid[j] != 0 && referenceIdt[j] != handler)
            {
                ++idtDivergences;
                if (idtDivergences <= 16)
                {
                    OacReportFinding(OacSeverityMedium, OacCategoryIntegrity,
                        NULL, NULL, (PVOID)(ULONG_PTR)handler,
                        samples[i].ProcessorIndex,
                        L"CPU %lu IDT vector %lu differs across processor tables",
                        samples[i].ProcessorIndex, j);
                }
            }
        }
        if (!referenceIdtSet) referenceIdtSet = TRUE;
    }

    OacReportFinding(
        OacSeverityInfo,
        OacCategoryIntegrity,
        NULL,
        NULL,
        NULL,
        ((ULONGLONG)idtDivergences << 32) | malformedGates,
        L"Validated control registers, syscall MSRs, IDT/GDT state, debug registers, and CPUID across %lu logical processors; IDT divergences=%lu malformed-gates=%lu",
        capturedProcessors,
        idtDivergences,
        malformedGates);
    if (samples != &fallbackSample)
        ExFreePoolWithTag(samples, OAC_SCAN_TAG);

    OacScanExportIntegrity(Modules, ModuleCount);
    OacScanImageIatTargets(g_NtoskrnlBase, g_NtoskrnlSize,
        L"ntoskrnl", Modules, ModuleCount);
    OacScanImageIatTargets(g_DriverBase, g_DriverSize,
        L"OAC", Modules, ModuleCount);
    OacScanDriverSelfIntegrity(Modules, ModuleCount);

    {
        PBOOLEAN debuggerEnabled = (PBOOLEAN)OacFindImageExport(g_NtoskrnlBase, "KdDebuggerEnabled");
        PBOOLEAN debuggerNotPresent = (PBOOLEAN)OacFindImageExport(g_NtoskrnlBase, "KdDebuggerNotPresent");
        BOOLEAN enabled;
        BOOLEAN notPresent;
        if (debuggerEnabled != NULL && debuggerNotPresent != NULL &&
            OacReadVirtual(&enabled, debuggerEnabled, sizeof(enabled)) &&
            OacReadVirtual(&notPresent, debuggerNotPresent, sizeof(notPresent)))
        {
            if (enabled && !notPresent)
            {
                OacReportFinding(OacSeverityHigh, OacCategoryDebugger, NULL, NULL,
                    NULL, 0, L"Kernel debugger is enabled and attached");
            }
        }
        else
        {
            OacReportFinding(OacSeverityMedium, OacCategoryIntegrity, NULL, NULL,
                NULL, (ULONGLONG)(ULONG)STATUS_PARTIAL_COPY,
                L"Kernel-debugger state read failed");
        }
    }
}

static VOID OacScanProtectedDebugPort(VOID)
{
    HANDLE pid = OacProtectedProcessId();
    PEPROCESS process;
    NTSTATUS status;
    PVOID debugPort;

    if (pid == NULL || g_PsGetProcessDebugPort == NULL) return;
    status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status)) return;
    debugPort = g_PsGetProcessDebugPort(process);
    if (debugPort != NULL)
    {
        OacReportFinding(OacSeverityHigh, OacCategoryDebugger, pid, NULL,
            debugPort, 0, L"PsGetProcessDebugPort reports an attached debugger");
    }
    ObDereferenceObject(process);
}

static VOID OacScanHypervisor(VOID)
{
    int registers[4];
    CHAR vendor[13] = { 0 };

    __cpuid(registers, 1);
    if (((ULONG)registers[2] & (1UL << 31)) == 0)
    {
        OacReportFinding(OacSeverityInfo, OacCategoryVirtualization, NULL, NULL,
            NULL, 0, L"CPUID hypervisor-present bit is clear");
        return;
    }

    __cpuid(registers, 0x40000000);
    RtlCopyMemory(vendor + 0, &registers[1], 4);
    RtlCopyMemory(vendor + 4, &registers[2], 4);
    RtlCopyMemory(vendor + 8, &registers[3], 4);
    vendor[12] = '\0';
    {
        WCHAR wideVendor[16];
        OacAsciiToWide((const UCHAR*)vendor, 12, wideVendor, RTL_NUMBER_OF(wideVendor));
        OacReportFinding(OacSeverityLow, OacCategoryVirtualization, NULL, NULL,
            NULL, (ULONG)registers[0],
            L"Hypervisor present (may be VBS/Hyper-V): %ls", wideVendor);
    }
}

static VOID OacScanTdlArtifacts(VOID)
{
    UNICODE_STRING name;
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;

    RtlInitUnicodeString(&name, L"\\Device\\VBoxDrv");
    status = IoGetDeviceObjectPointer(
        &name,
        FILE_READ_ATTRIBUTES,
        &fileObject,
        &deviceObject);
    if (NT_SUCCESS(status))
    {
        OacReportFinding(OacSeverityLow, OacCategoryDevice, NULL, NULL,
            deviceObject, 0,
            L"VBoxDrv device is present; verify version/signature for deprecated TDL artifacts");
        ObDereferenceObject(fileObject);
    }
}

static BOOLEAN OacReadVirtual(
    _Out_writes_bytes_(Size) PVOID Destination,
    _In_ PVOID Source,
    _In_ SIZE_T Size)
{
    SIZE_T copied = 0;
    return NT_SUCCESS(OacCopyVirtualMemorySafe(
        Destination,
        Source,
        Size,
        &copied)) && copied == Size;
}

static BOOLEAN OacReadUnicodeString(
    _In_ const UNICODE_STRING* Source,
    _Out_writes_(DestinationCount) PWCHAR Destination,
    _In_ SIZE_T DestinationCount)
{
    SIZE_T bytes;
    if (Source->Buffer == NULL || Source->Length == 0 ||
        Source->Length > Source->MaximumLength ||
        (Source->Length & (sizeof(WCHAR) - 1)) != 0 ||
        DestinationCount < 2)
    {
        return FALSE;
    }
    bytes = min((SIZE_T)Source->Length, (DestinationCount - 1) * sizeof(WCHAR));
    if (!OacReadVirtual(Destination, Source->Buffer, bytes)) return FALSE;
    Destination[bytes / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

static BOOLEAN OacPrivateProfileMatches(VOID)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    if (g_NtoskrnlBase == NULL ||
        !OacReadVirtual(&dos, g_NtoskrnlBase, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
        !OacImageRvaRangeValid(
            (ULONG)dos.e_lfanew,
            sizeof(nt)) ||
        !OacReadVirtual(
            &nt,
            (PUCHAR)g_NtoskrnlBase + (ULONG)dos.e_lfanew,
            sizeof(nt)))
    {
        return FALSE;
    }
    return nt.Signature == IMAGE_NT_SIGNATURE &&
        nt.FileHeader.TimeDateStamp == 0x087FAA22UL &&
        nt.OptionalHeader.SizeOfImage == 0x01047000UL &&
        nt.OptionalHeader.CheckSum == 0x00B888DBUL;
}

static VOID OacScanPrivateKernelTraces(VOID)
{
    PVOID unloadedGlobal;
    PVOID lastGlobal;
    PRTL_AVL_TABLE table;
    PERESOURCE lock;
    PVOID unloadedArray = NULL;
    ULONG lastIndex = 0;
    ULONG i;

    if (!g_PrivateProfileAvailable)
    {
        OacReportFinding(OacSeverityInfo, OacCategoryIntegrity, NULL, NULL,
            NULL, 0,
            L"Private kernel-trace scan skipped: no exact IDALib build profile");
        return;
    }

    /* Exact-build RVAs recovered with IDALib and public PDB symbols. */
    unloadedGlobal = (PUCHAR)g_NtoskrnlBase + 0x00C13610UL;
    lastGlobal = (PUCHAR)g_NtoskrnlBase + 0x00C13618UL;
    table = (PRTL_AVL_TABLE)((PUCHAR)g_NtoskrnlBase + 0x00D55320UL);
    lock = (PERESOURCE)((PUCHAR)g_NtoskrnlBase + 0x00C5C980UL);
    if (!OacImageRvaRangeValid(0x00C13610UL, sizeof(PVOID)) ||
        !OacImageRvaRangeValid(0x00C13618UL, sizeof(ULONG)) ||
        !OacImageRvaRangeValid(0x00D55320UL, sizeof(RTL_AVL_TABLE)) ||
        !OacImageRvaRangeValid(0x00C5C980UL, sizeof(ERESOURCE)))
    {
        OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
            NULL, 0, L"IDALib trace signature decoded outside ntoskrnl image");
        return;
    }

    if (OacReadVirtual((PVOID)&unloadedArray, unloadedGlobal, sizeof(PVOID)) &&
        OacReadVirtual(&lastIndex, lastGlobal, sizeof(lastIndex)) &&
        unloadedArray != NULL && lastIndex <= 50)
    {
        for (i = 0; i < 50; ++i)
        {
            OAC_UNLOADED_DRIVER entry;
            WCHAR name[128];
            if (!OacReadVirtual(&entry,
                    (PUCHAR)unloadedArray + i * sizeof(entry),
                    sizeof(entry))) continue;
            if (OacReadUnicodeString(&entry.Name, name, RTL_NUMBER_OF(name)))
            {
                OacReportFinding(OacSeverityLow, OacCategoryDriver, NULL, NULL,
                    entry.StartAddress,
                    (ULONGLONG)(ULONG_PTR)entry.EndAddress,
                    L"MmUnloadedDrivers trace: %ls", name);
            }
        }
    }

    {
        BOOLEAN acquired = FALSE;
        NTSTATUS exceptionStatus = STATUS_SUCCESS;
        __try
        {
            ULONG number = 0;
            acquired = ExAcquireResourceSharedLite(lock, FALSE);
            if (acquired)
            {
                number = RtlNumberGenericTableElementsAvl(table);
                PVOID restartKey = NULL;
                PVOID element;
                ULONG enumerated = 0;
                if (number > 65536)
                {
                    exceptionStatus = STATUS_DATA_ERROR;
                }
                while (NT_SUCCESS(exceptionStatus) &&
                       enumerated < min(number, 4096UL) &&
                       (element = RtlEnumerateGenericTableWithoutSplayingAvl(
                           table,
                           &restartKey)) != NULL)
                {
                    POAC_PIDDB_CACHE_ENTRY entry = (POAC_PIDDB_CACHE_ENTRY)element;
                    WCHAR name[128];
                    if (OacReadUnicodeString(&entry->DriverName, name, RTL_NUMBER_OF(name)))
                    {
                        OacReportFinding(
                            OacSeverityLow,
                            OacCategoryDriver,
                            NULL,
                            NULL,
                            element,
                            entry->TimeDateStamp,
                            L"PiDDB cache trace: %ls (load status 0x%08X)",
                            name,
                            entry->LoadStatus);
                    }
                    ++enumerated;
                }
            }
            else
            {
                OacReportFinding(
                    OacSeverityInfo,
                    OacCategoryIntegrity,
                    NULL,
                    NULL,
                    lock,
                    0,
                    L"Private PiDDB trace scan skipped because its lock was busy");
            }
        }
        __except (exceptionStatus = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
        {
        }
        if (acquired)
        {
            ExReleaseResourceLite(lock);
        }
        if (!NT_SUCCESS(exceptionStatus))
        {
            OacReportFinding(OacSeverityHigh, OacCategoryIntegrity, NULL, NULL,
                table, exceptionStatus, L"Private PiDDB trace scan raised an exception");
        }
    }
}

#pragma warning(push)
#pragma warning(disable: 28175)
NTSTATUS OacScannerInitialize(_In_ PDRIVER_OBJECT DriverObject)
{
    PAUX_MODULE_EXTENDED_INFO modules = NULL;
    ULONG moduleCount = 0;
    ULONG i;
    NTSTATUS status;
    if (DriverObject == NULL || DriverObject->DriverStart == NULL ||
        DriverObject->DriverSize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status)) return status;

    status = OacQueryAuxModules(&modules, &moduleCount);
    if (!NT_SUCCESS(status)) return status;
    for (i = 0; i < moduleCount; ++i)
    {
        USHORT offset = modules[i].FileNameOffset;
        if (offset < sizeof(modules[i].FullPathName) &&
            (OacAsciiContainsInsensitive(
                modules[i].FullPathName + offset,
                sizeof(modules[i].FullPathName) - offset,
                "ntoskrnl.exe") ||
             OacAsciiContainsInsensitive(
                modules[i].FullPathName + offset,
                sizeof(modules[i].FullPathName) - offset,
                "ntkrnlmp.exe")))
        {
            g_NtoskrnlBase = modules[i].BasicInfo.ImageBase;
            g_NtoskrnlSize = modules[i].ImageSize;
            break;
        }
    }
    ExFreePoolWithTag(modules, OAC_SCAN_TAG);
    if (g_NtoskrnlBase == NULL) return STATUS_NOT_FOUND;
    g_PsGetProcessDebugPort = (OAC_PS_GET_PROCESS_DEBUG_PORT)
        OacFindImageExport(g_NtoskrnlBase, "PsGetProcessDebugPort");

    g_DriverObject = DriverObject;
    g_DriverBase = DriverObject->DriverStart;
    g_DriverSize = DriverObject->DriverSize;
    g_DriverSectionBaseline = DriverObject->DriverSection;
    g_FastIoBaseline = DriverObject->FastIoDispatch;
    g_DriverUnloadBaseline = DriverObject->DriverUnload;
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
    {
        g_MajorFunctionBaseline[i] = DriverObject->MajorFunction[i];
    }
    for (i = 0; i < RTL_NUMBER_OF(g_ExportBaselines); ++i)
    {
        POAC_EXPORT_BASELINE baseline = &g_ExportBaselines[i];
        baseline->Name = g_IntegrityExportNames[i];
        baseline->Address = OacFindImageExport(g_NtoskrnlBase, baseline->Name);
        if (baseline->Address != NULL &&
            OacReadVirtual(
                baseline->Bytes,
                baseline->Address,
                sizeof(baseline->Bytes)))
        {
            baseline->Available = TRUE;
        }
    }
    g_PrivateProfileAvailable = OacPrivateProfileMatches();
    return STATUS_SUCCESS;
}
#pragma warning(pop)

VOID OacScannerShutdown(VOID)
{
    g_PrivateProfileAvailable = FALSE;
    g_NtoskrnlBase = NULL;
    g_NtoskrnlSize = 0;
    g_PsGetProcessDebugPort = NULL;
    g_DriverObject = NULL;
    g_DriverBase = NULL;
    g_DriverSize = 0;
    g_DriverSectionBaseline = NULL;
    g_FastIoBaseline = NULL;
    g_DriverUnloadBaseline = NULL;
    RtlZeroMemory(g_MajorFunctionBaseline, sizeof(g_MajorFunctionBaseline));
    RtlZeroMemory(g_ExportBaselines, sizeof(g_ExportBaselines));
}

ULONG OacScannerCapabilities(VOID)
{
    ULONG capabilities = OAC_CAP_PROCESS_CROSS_VIEW |
        OAC_CAP_MODULE_CROSS_VIEW |
        OAC_CAP_HANDLE_SCAN |
        OAC_CAP_KERNEL_INTEGRITY |
        OAC_CAP_SYSTEM_THREAD_SCAN |
        OAC_CAP_CPU_PLATFORM_STATE |
        OAC_CAP_DRIVER_SELF_INTEGRITY |
        OAC_CAP_IMPORT_INTEGRITY |
        OAC_CAP_VIRTUALIZATION_STATE;
    if (g_PrivateProfileAvailable)
    {
        capabilities |= OAC_CAP_PRIVATE_TRACE_PROFILE;
    }
    return capabilities;
}

NTSTATUS OacRunKernelScan(_In_ const OAC_SCAN_REQUEST* Request)
{
    PAUX_MODULE_EXTENDED_INFO modules = NULL;
    ULONG moduleCount = 0;
    PVOID handleBuffer = NULL;
    ULONG handleLength = 0;
    NTSTATUS status;

    PAGED_CODE();
    if (Request == NULL || Request->Version != OAC_PROTOCOL_VERSION ||
        Request->Size != sizeof(*Request) || Request->Reserved != 0 ||
        (Request->Flags & ~(OAC_SCAN_VERBOSE_HANDLES |
                            OAC_SCAN_PRIVATE_KERNEL_TRACES)) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = OacQueryAuxModules(&modules, &moduleCount);
    if (!NT_SUCCESS(status)) return status;

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

    OacScanModules(modules, moduleCount);
    OacScanProcessesAndSystemThreads(
        modules,
        moduleCount,
        (POAC_SYSTEM_HANDLE_INFORMATION)handleBuffer,
        handleLength);
    if (handleBuffer != NULL)
    {
        OacScanHandles(
            (POAC_SYSTEM_HANDLE_INFORMATION)handleBuffer,
            handleLength,
            Request->Flags);
    }
    OacScanKernelIntegrity(modules, moduleCount);
    OacScanProtectedDebugPort();
    OacScanHypervisor();
    OacScanTdlArtifacts();
    if ((Request->Flags & OAC_SCAN_PRIVATE_KERNEL_TRACES) != 0)
    {
        OacScanPrivateKernelTraces();
    }

    if (handleBuffer != NULL) ExFreePoolWithTag(handleBuffer, OAC_SCAN_TAG);
    ExFreePoolWithTag(modules, OAC_SCAN_TAG);
    return STATUS_SUCCESS;
}
