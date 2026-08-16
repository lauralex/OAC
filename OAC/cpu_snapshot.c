#include "cpu_snapshot.h"
#include "descriptor.h"

#include <intrin.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, OacCaptureCpuSnapshot)
#endif

#define OAC_MSR_SYSENTER_ESP 0x00000175UL
#define OAC_MSR_SYSENTER_EIP 0x00000176UL
#define OAC_MSR_EFER         0xC0000080UL
#define OAC_MSR_STAR         0xC0000081UL
#define OAC_MSR_LSTAR        0xC0000082UL
#define OAC_MSR_CSTAR        0xC0000083UL
#define OAC_MSR_FMASK        0xC0000084UL

#pragma pack(push, 1)
typedef struct OAC_DESCRIPTOR_REGISTER_TAG
{
    USHORT Limit;
    ULONGLONG Base;
} OAC_DESCRIPTOR_REGISTER;
#pragma pack(pop)

typedef struct OAC_CPU_RESPONSE_HEADER_TAG
{
    ULONG Version;
    ULONG Size;
    ULONG Count;
    ULONG Capacity;
} OAC_CPU_RESPONSE_HEADER, *POAC_CPU_RESPONSE_HEADER;

C_ASSERT(sizeof(OAC_CPU_RESPONSE_HEADER) ==
    FIELD_OFFSET(OAC_CPU_RESPONSE, Records));

static FAST_MUTEX g_CpuSnapshotMutex;
static PUCHAR g_ActiveResponse;
static ULONG g_ActiveCapacity;
static volatile LONG g_ActiveCaptured;

static ULONG_PTR OacCpuSnapshotCallback(_In_ ULONG_PTR Context)
{
    PROCESSOR_NUMBER processorNumber;
    ULONG processorIndex;
    ULONG slot;
    PUCHAR response;
    POAC_CPU_RECORD record;
    OAC_DESCRIPTOR_REGISTER idtr;
    OAC_DESCRIPTOR_REGISTER gdtr;
    int registers[4];
    unsigned int tscAux = 0;

    UNREFERENCED_PARAMETER(Context);
    response = g_ActiveResponse;
    if (response == NULL)
    {
        return 0;
    }

    KeGetCurrentProcessorNumberEx(&processorNumber);
    processorIndex = KeGetProcessorIndexFromNumber(&processorNumber);
    slot = (ULONG)(InterlockedIncrement(&g_ActiveCaptured) - 1);
    if (slot >= g_ActiveCapacity)
    {
        return 0;
    }

    record = (POAC_CPU_RECORD)(response +
        FIELD_OFFSET(OAC_CPU_RESPONSE, Records) +
        slot * sizeof(OAC_CPU_RECORD));
    record->ProcessorIndex = processorIndex;
    record->Group = processorNumber.Group;
    record->Number = processorNumber.Number;
    record->CallbackAddress = (ULONGLONG)(ULONG_PTR)_ReturnAddress();
    record->Cr0 = __readcr0();
    record->Cr3 = __readcr3();
    record->Cr4 = __readcr4();
    record->Dr0 = __readdr(0);
    record->Dr1 = __readdr(1);
    record->Dr2 = __readdr(2);
    record->Dr3 = __readdr(3);
    record->Dr6 = __readdr(6);
    record->Dr7 = __readdr(7);
    record->Efer = __readmsr(OAC_MSR_EFER);
    record->Lstar = __readmsr(OAC_MSR_LSTAR);
    record->Cstar = __readmsr(OAC_MSR_CSTAR);
    record->Star = __readmsr(OAC_MSR_STAR);
    record->Fmask = __readmsr(OAC_MSR_FMASK);
    record->SysenterEip = __readmsr(OAC_MSR_SYSENTER_EIP);
    record->SysenterEsp = __readmsr(OAC_MSR_SYSENTER_ESP);
    __sidt(&idtr);
    OacStoreGdtr(&gdtr);
    record->IdtBase = idtr.Base;
    record->GdtBase = gdtr.Base;
    record->IdtLimit = idtr.Limit;
    record->GdtLimit = gdtr.Limit;

    __cpuid(registers, 0);
    record->CpuidBasicMaximum = (ULONG)registers[0];
    __cpuid(registers, 0x80000000);
    record->CpuidExtendedMaximum = (ULONG)registers[0];
    __cpuid(registers, 1);
    record->Cpuid1Ecx = (ULONG)registers[2];
    record->Cpuid1Edx = (ULONG)registers[3];
    if (record->CpuidBasicMaximum >= 7)
    {
        __cpuidex(registers, 7, 0);
        record->Cpuid7Ebx = (ULONG)registers[1];
        record->Cpuid7Ecx = (ULONG)registers[2];
    }
    if (record->CpuidExtendedMaximum >= 0x80000001UL)
    {
        __cpuid(registers, 0x80000001);
        record->CpuidExtended1Ecx = (ULONG)registers[2];
        record->CpuidExtended1Edx = (ULONG)registers[3];
    }
    if ((record->Cpuid1Ecx & (1UL << 31)) != 0)
    {
        record->Flags |= OAC_CPU_FLAG_HYPERVISOR_PRESENT;
        __cpuid(registers, 0x40000000);
        record->HypervisorMaximumLeaf = (ULONG)registers[0];
        RtlCopyMemory(record->HypervisorVendor + 0, &registers[1], 4);
        RtlCopyMemory(record->HypervisorVendor + 4, &registers[2], 4);
        RtlCopyMemory(record->HypervisorVendor + 8, &registers[3], 4);
    }
    if ((record->CpuidExtended1Edx & (1UL << 27)) != 0)
    {
        (VOID)__rdtscp(&tscAux);
        record->TscAux = tscAux;
    }
    else
    {
        record->TscAux = MAXULONG;
    }
    return 0;
}

NTSTATUS OacCpuSnapshotInitialize(VOID)
{
    ExInitializeFastMutex(&g_CpuSnapshotMutex);
    return STATUS_SUCCESS;
}

VOID OacCpuSnapshotShutdown(VOID)
{
    g_ActiveResponse = NULL;
    g_ActiveCapacity = 0;
    g_ActiveCaptured = 0;
}

NTSTATUS OacCaptureCpuSnapshot(
    _Out_writes_bytes_(OutputLength) PVOID OutputBuffer,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesWritten)
{
    const ULONG headerSize = FIELD_OFFSET(OAC_CPU_RESPONSE, Records);
    POAC_CPU_RESPONSE_HEADER responseHeader =
        (POAC_CPU_RESPONSE_HEADER)OutputBuffer;
    ULONG activeProcessors;
    ULONG capacity;
    ULONG maximumProcessors;
    ULONG required;
    ULONG zeroBytes;
    ULONG captured;

    PAGED_CODE();
    *BytesWritten = 0;
    if (OutputBuffer == NULL || OutputLength < headerSize)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    capacity = (OutputLength - headerSize) / sizeof(OAC_CPU_RECORD);
    maximumProcessors = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (maximumProcessors == 0 ||
        maximumProcessors > (MAXULONG - headerSize) / sizeof(OAC_CPU_RECORD))
    {
        return STATUS_INTEGER_OVERFLOW;
    }
    capacity = min(capacity, maximumProcessors);
    activeProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (capacity < activeProcessors)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (activeProcessors > (MAXULONG - headerSize) / sizeof(OAC_CPU_RECORD))
    {
        return STATUS_INTEGER_OVERFLOW;
    }
    required = headerSize + activeProcessors * sizeof(OAC_CPU_RECORD);
    zeroBytes = headerSize + capacity * sizeof(OAC_CPU_RECORD);
    if (zeroBytes > OutputLength)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    /* zeroBytes is derived from the caller's capacity and checked above. */
#pragma warning(suppress: 6386)
    RtlZeroMemory(OutputBuffer, zeroBytes);
    responseHeader->Version = OAC_PROTOCOL_VERSION;
    responseHeader->Size = required;
    responseHeader->Count = 0;
    responseHeader->Capacity = capacity;

    ExAcquireFastMutex(&g_CpuSnapshotMutex);
    g_ActiveCapacity = capacity;
    InterlockedExchange(&g_ActiveCaptured, 0);
    g_ActiveResponse = (PUCHAR)OutputBuffer;
    KeMemoryBarrier();
    (VOID)KeIpiGenericCall(OacCpuSnapshotCallback, 0);
    KeMemoryBarrier();
    g_ActiveResponse = NULL;
    g_ActiveCapacity = 0;
    captured = (ULONG)InterlockedExchange(&g_ActiveCaptured, 0);
    ExReleaseFastMutex(&g_CpuSnapshotMutex);

    if (captured > capacity)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    responseHeader->Count = captured;
    responseHeader->Size = headerSize + captured * sizeof(OAC_CPU_RECORD);
    required = responseHeader->Size;
    *BytesWritten = required;
    return STATUS_SUCCESS;
}
