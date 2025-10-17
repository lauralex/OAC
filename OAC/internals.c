/**
 * @file internals.c
 * @brief Implementation of internal structures and initialization functions.
 *
 * This file contains the implementation of various internal structures and
 * initialization functions used by the driver. It includes functions to
 * initialize global pointers, function pointers, and other necessary components.
 */

#include "internals.h"
#include "globals.h"
#include "isr.h"
#include "pattern_scanner.h"
#include "module.h"
#include "serial_logger.h"

#include <intrin.h>

PLIST_ENTRY PsActiveProcessHead = NULL;

PRUNTIME_FUNCTION
(*RtlLookupFunctionEntryUsermode)(
    _In_ DWORD64                      ControlPc,
    _Out_ PDWORD64                    ImageBase,
    _Inout_opt_ PUNWIND_HISTORY_TABLE HistoryTable
) = NULL;

PRUNTIME_FUNCTION
(*RtlpLookupFunctionEntryForStackWalks)(
    _In_ ULONG64   ControlPc,
    _Out_ PULONG64 ImageBase
) = NULL;

/**
 * @brief Initializes the PsActiveProcessHead pointer by locating it in memory.
 *
 * This function should be called at driver initialization time, at PASSIVE_LEVEL.
 * It attempts to locate the PsActiveProcessHead symbol in the kernel and assigns
 * its address to the global variable. If it cannot be found, the variable remains NULL.
 */
static VOID InitializePsActiveProcessHead(VOID)
{
    PsActiveProcessHead = *(PLIST_ENTRY*)(PsSiloContextPagedType + 1);
}

/**
 * @brief Fill RtlLookupFunctionEntryUsermode function pointer.
 *
 * This function initializes the RtlLookupFunctionEntryUsermode function pointer by
 * locating the RtlLookupFunctionEntry symbol in the user-mode ntdll.dll and assigning
 * its address to the global variable. If it cannot be found, the variable remains NULL.
 *
 * @note This function should be called at driver initialization time, at PASSIVE_LEVEL.
 */
static VOID InitializeRtlLookupFunctionEntryUsermode(VOID)
{
    // Lookup the function entry for the current RIP.
    if (!RtlLookupFunctionEntryUsermode)
    {
        PVOID NtdllBaseAddress = FindUserModuleByName(PsGetCurrentProcess(), L"ntdll.dll");
        if (!NtdllBaseAddress)
        {
            DbgPrint("[-] Failed to locate ntdll.dll in target process.\n");
            return;
        }

        DbgPrint("[*] ntdll.dll base address in target process: 0x%p\n", NtdllBaseAddress);

#pragma warning(suppress : 4152) // Suppress warning about function pointer cast.
        RtlLookupFunctionEntryUsermode = FindExportedFunction(NtdllBaseAddress, "RtlLookupFunctionEntry");
        DbgPrint("[*] RtlLookupFunctionEntryUsermode address: 0x%p\n", RtlLookupFunctionEntryUsermode);
    }
}

/**
 * @brief Fill RtlpLookupFunctionEntryForStackWalks function pointer.
 *
 * This function initializes the RtlpLookupFunctionEntryForStackWalks function pointer by
 * locating the RtlpLookupFunctionEntryForStackWalks symbol in the user-mode ntdll.dll and assigning
 * its address to the global variable. If it cannot be found, the variable remains NULL.
 *
 * @note This function should be called at driver initialization time, at PASSIVE_LEVEL.
 */
static VOID InitializeRtlpLookupFunctionEntryForStackWalks(VOID)
{
    if (!RtlpLookupFunctionEntryForStackWalks)
    {
        SIZE_T NtosKrnlSize        = 0;
        PVOID  NtosKrnlBaseAddress = FindModuleByName2(L"ntoskrnl.exe", &NtosKrnlSize);

        DbgPrint("[*] ntoskrnl.exe base address: 0x%p, size: 0x%Ix\n", NtosKrnlBaseAddress, NtosKrnlSize);

#pragma warning(suppress : 4152) // Suppress warning about function pointer cast.
        RtlpLookupFunctionEntryForStackWalks = (PVOID)PatternScan((UINT64)NtosKrnlBaseAddress, NtosKrnlSize,
                                                                  "48 89 5C 24 ? 48 89 74 24 ? 48 89 54 24 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? 0F 82");

        DbgPrint("[*] RtlpLookupFunctionEntryForStackWalks address: 0x%p\n", RtlpLookupFunctionEntryForStackWalks);
    }
}

/**
 * @brief Initializes the unwinding IDT by copying the current IDT.
 *
 * This function should be called at driver initialization time, at PASSIVE_LEVEL.
 * It copies the current IDT into the G_NmiContext.UnwindingIdt array for safe unwinding
 * during NMI handling.
 */
static VOID InitializeUnwindingIdt(VOID)
{
    // Copy the original IDT for safety.
    SEGMENT_DESCRIPTOR_REGISTER_64 Idtr = {0};
    __sidt(&Idtr);

    // Copy to the unwinding IDT backup.
    RtlCopyMemory(G_NmiContext.UnwindingIdt, (PVOID)Idtr.BaseAddress, sizeof(G_NmiContext.UnwindingIdt));

    // Modify the PF handler in the unwinding IDT to point to our recovery ISR.
    SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64* PfDescriptor = &G_NmiContext.UnwindingIdt[14];
    PfDescriptor->OffsetLow                            = (USHORT)((ULONG64)PageFaultRecoveryIsr & 0xFFFF);
    PfDescriptor->OffsetMiddle                         = (USHORT)(((ULONG64)PageFaultRecoveryIsr >> 16) & 0xFFFF);
    PfDescriptor->OffsetHigh                           = (ULONG)(((ULONG64)PageFaultRecoveryIsr >> 32) & 0xFFFFFFFF);
}

/**
 * @brief Initializes internal structures and pointers used by the driver.
 *
 * This function should be called at driver initialization time, at PASSIVE_LEVEL.
 * It sets up any necessary internal state required for the driver's operation.
 */
VOID InitializeInternals(VOID)
{
    LoggerInit();
    InitializeRtlLookupFunctionEntryUsermode();
    InitializeRtlpLookupFunctionEntryForStackWalks();
    InitializeUnwindingIdt();
    InitializePsActiveProcessHead();
}
