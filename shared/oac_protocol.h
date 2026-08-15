#pragma once

/*
 * Shared, versioned protocol between the OAC kernel driver and administrator
 * client.  Keep this header C-compatible: the driver is compiled as C and the
 * client as C++.
 */

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <Windows.h>
#include <winioctl.h>
#endif

#define OAC_PROTOCOL_VERSION 0x00040000UL
#define OAC_MAX_FINDING_TEXT 192
#define OAC_MAX_FINDINGS_PER_READ 64

#define OAC_IOCTL_ACCESS (FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_OAC_PING \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, OAC_IOCTL_ACCESS)
#define IOCTL_OAC_CONFIGURE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, OAC_IOCTL_ACCESS)
#define IOCTL_OAC_RUN_KERNEL_SCAN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, OAC_IOCTL_ACCESS)
#define IOCTL_OAC_GET_FINDINGS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, OAC_IOCTL_ACCESS)
#define IOCTL_OAC_CPU_SNAPSHOT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, OAC_IOCTL_ACCESS)
#define IOCTL_OAC_GET_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, OAC_IOCTL_ACCESS)

#ifdef __cplusplus
typedef enum OAC_SEVERITY_TAG : unsigned char
#else
typedef enum OAC_SEVERITY_TAG
#endif
{
    OacSeverityInfo = 0,
    OacSeverityLow,
    OacSeverityMedium,
    OacSeverityHigh,
    OacSeverityCritical
} OAC_SEVERITY;

#ifdef __cplusplus
typedef enum OAC_CATEGORY_TAG : unsigned char
#else
typedef enum OAC_CATEGORY_TAG
#endif
{
    OacCategoryGeneral = 0,
    OacCategoryProcess,
    OacCategoryHandle,
    OacCategoryModule,
    OacCategoryDriver,
    OacCategoryMemory,
    OacCategoryThread,
    OacCategoryDebugger,
    OacCategoryIntegrity,
    OacCategoryVirtualization,
    OacCategoryService,
    OacCategoryDevice,
    OacCategoryWindow,
    OacCategoryHwid
} OAC_CATEGORY;

#define OAC_CAP_HANDLE_PROTECTION       0x00000001UL
#define OAC_CAP_IMAGE_TELEMETRY         0x00000002UL
#define OAC_CAP_PROCESS_CROSS_VIEW      0x00000004UL
#define OAC_CAP_MODULE_CROSS_VIEW       0x00000008UL
#define OAC_CAP_HANDLE_SCAN             0x00000010UL
#define OAC_CAP_KERNEL_INTEGRITY        0x00000020UL
#define OAC_CAP_SYSTEM_THREAD_SCAN      0x00000040UL
#define OAC_CAP_CPU_SNAPSHOT            0x00000080UL
#define OAC_CAP_PRIVATE_TRACE_PROFILE   0x00000100UL
#define OAC_CAP_CPU_PLATFORM_STATE      0x00000200UL
#define OAC_CAP_DRIVER_SELF_INTEGRITY   0x00000400UL
#define OAC_CAP_IMPORT_INTEGRITY        0x00000800UL
#define OAC_CAP_VIRTUALIZATION_STATE    0x00001000UL
#define OAC_CAP_DRIVER_GATE             0x00002000UL

#define OAC_CPU_FLAG_HYPERVISOR_PRESENT 0x00000001UL

#define OAC_CONFIG_PROTECT_PROCESS      0x00000001UL
#define OAC_CONFIG_ENABLE_IMAGE_LOG     0x00000002UL
#define OAC_CONFIG_DRIVER_GATE          0x00000004UL

#define OAC_SCAN_VERBOSE_HANDLES        0x00000001UL
#define OAC_SCAN_PRIVATE_KERNEL_TRACES  0x00000002UL

typedef struct OAC_CONFIG_REQUEST_TAG
{
    ULONG Version;
    ULONG Size;
    ULONGLONG ProtectedProcessId;
    ULONGLONG ClientProcessId;
    ULONG Flags;
    ULONG Reserved;
} OAC_CONFIG_REQUEST, *POAC_CONFIG_REQUEST;

typedef struct OAC_STATUS_RESPONSE_TAG
{
    ULONG Version;
    ULONG Size;
    ULONG Capabilities;
    ULONG ConfigurationFlags;
    ULONGLONG ProtectedProcessId;
    ULONGLONG ClientProcessId;
    ULONGLONG FindingsWritten;
    ULONGLONG FindingsDropped;
    ULONGLONG PostStartLoads;
    ULONGLONG DriverGateTrips;
} OAC_STATUS_RESPONSE, *POAC_STATUS_RESPONSE;

typedef struct OAC_SCAN_REQUEST_TAG
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Reserved;
} OAC_SCAN_REQUEST, *POAC_SCAN_REQUEST;

typedef struct OAC_FINDING_TAG
{
    ULONGLONG Sequence;
    ULONGLONG Timestamp100ns;
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG Severity;
    ULONG Category;
    ULONGLONG Address;
    ULONGLONG Auxiliary;
    WCHAR Text[OAC_MAX_FINDING_TEXT];
} OAC_FINDING, *POAC_FINDING;

typedef struct OAC_FINDINGS_RESPONSE_TAG
{
    ULONG Version;
    ULONG Size;
    ULONG Count;
    ULONG Remaining;
    OAC_FINDING Findings[OAC_MAX_FINDINGS_PER_READ];
} OAC_FINDINGS_RESPONSE, *POAC_FINDINGS_RESPONSE;

typedef struct OAC_CPU_RECORD_TAG
{
    ULONG ProcessorIndex;
    ULONG Group;
    ULONG Number;
    ULONG Flags;
    ULONGLONG CallbackAddress;
    ULONGLONG Cr0;
    ULONGLONG Cr3;
    ULONGLONG Cr4;
    ULONGLONG Dr0;
    ULONGLONG Dr1;
    ULONGLONG Dr2;
    ULONGLONG Dr3;
    ULONGLONG Dr6;
    ULONGLONG Dr7;
    ULONGLONG Efer;
    ULONGLONG Lstar;
    ULONGLONG Cstar;
    ULONGLONG Star;
    ULONGLONG Fmask;
    ULONGLONG SysenterEip;
    ULONGLONG SysenterEsp;
    ULONGLONG IdtBase;
    ULONGLONG GdtBase;
    ULONG IdtLimit;
    ULONG GdtLimit;
    ULONG CpuidBasicMaximum;
    ULONG CpuidExtendedMaximum;
    ULONG Cpuid1Ecx;
    ULONG Cpuid1Edx;
    ULONG Cpuid7Ebx;
    ULONG Cpuid7Ecx;
    ULONG CpuidExtended1Ecx;
    ULONG CpuidExtended1Edx;
    ULONG HypervisorMaximumLeaf;
    ULONG TscAux;
    UCHAR HypervisorVendor[16];
} OAC_CPU_RECORD, *POAC_CPU_RECORD;

typedef struct OAC_CPU_RESPONSE_TAG
{
    ULONG Version;
    ULONG Size;
    ULONG Count;
    ULONG Capacity;
    OAC_CPU_RECORD Records[ANYSIZE_ARRAY];
} OAC_CPU_RESPONSE, *POAC_CPU_RESPONSE;

#ifdef __cplusplus
#define OAC_STATIC_ASSERT(Expression, Message) static_assert((Expression), Message)
#else
#define OAC_STATIC_ASSERT(Expression, Message) C_ASSERT(Expression)
#endif

OAC_STATIC_ASSERT(sizeof(WCHAR) == 2, "OAC protocol requires 16-bit WCHAR");
OAC_STATIC_ASSERT(sizeof(OAC_CONFIG_REQUEST) == 32, "OAC_CONFIG_REQUEST layout changed");
OAC_STATIC_ASSERT(sizeof(OAC_STATUS_RESPONSE) == 64, "OAC_STATUS_RESPONSE layout changed");
OAC_STATIC_ASSERT(sizeof(OAC_SCAN_REQUEST) == 16, "OAC_SCAN_REQUEST layout changed");
OAC_STATIC_ASSERT(sizeof(OAC_FINDING) == 432, "OAC_FINDING layout changed");
OAC_STATIC_ASSERT(sizeof(OAC_FINDINGS_RESPONSE) == 27664,
    "OAC_FINDINGS_RESPONSE layout changed");
OAC_STATIC_ASSERT(sizeof(OAC_CPU_RECORD) == 232, "OAC_CPU_RECORD layout changed");
OAC_STATIC_ASSERT(sizeof(OAC_CPU_RESPONSE) == 248, "OAC_CPU_RESPONSE layout changed");

#undef OAC_STATIC_ASSERT
