/**
 * @file cr3_validation.c
 * @brief Validates a captured CR3 value against the system's active process list.
 *
 * This module provides functionality to verify if a given CR3 value corresponds to any
 * active process in the system. This is crucial for detecting potential anomalies or
 * malicious activities that may involve unauthorized context switches.
 *
 * The primary function, `IsCr3InProcessList`, iterates through the active process list
 * and compares the captured CR3 value against each process's Directory Table Base (DTB).
 * If a match is found, it indicates that the CR3 is valid; otherwise, it is considered suspicious.
 *
 * Note: This code assumes a Windows kernel environment and relies on certain internal
 * structures and globals that may vary between Windows versions. Proper offsets and
 * structures should be verified for compatibility with the target OS version.
 */

#include "cr3_validation.h"
#include "globals.h"
#include "ia32.h"
#include "internals.h"

/**
 * @brief Iterates through the system's active process list to validate a CR3 value.
 * @note This function MUST be called at PASSIVE_LEVEL.
 *
 * @param[in] CapturedCr3Value The CR3 value captured during the NMI.
 * @return TRUE if the CR3 is found in the list of active processes, FALSE otherwise.
 */
BOOLEAN IsCr3InProcessList(
    _In_ UINT64 CapturedCr3Value
)
{
    PAGED_CODE() // Ensures we are at PASSIVE_LEVEL

    if (!PsActiveProcessHead)
    {
        return FALSE; // Should not happen
    }

    // The CR3 value contains the physical address of the PML4 table, but also other bits like PCID.
    // We must compare only the address portion.
    CR3 CapturedCr3 = {.AsUInt = CapturedCr3Value};

    // Check against the system process first.
    if (G_NmiContext.SystemCr3 != 0)
    {
        CR3 System = {.AsUInt = G_NmiContext.SystemCr3};
        if (CapturedCr3.AddressOfPageDirectory == System.AddressOfPageDirectory)
        {
            return TRUE;
        }
    }

    // Walk the list of all active processes.
    // Note: Walking this list without the proper lock (PsActiveProcessLock, which is unexported)
    // carries a small risk of race conditions on a highly active system. For this project's
    // purpose, it is generally safe.
    PLIST_ENTRY CurrentEntry = PsActiveProcessHead->Flink;
    while (CurrentEntry != PsActiveProcessHead)
    {
        // Get the EPROCESS structure from the list entry.
        // The offset of ActiveProcessLinks is 0x448 in our partial struct.
        PEPROCESS CurrentProcess = (PEPROCESS)CONTAINING_RECORD(CurrentEntry, EPROCESS, ActiveProcessLinks);

        // The KPROCESS.DirectoryTableBase is at offset 0x28 of the EPROCESS's KPROCESS member.
        // The KPROCESS (Pcb) is at a known offset within the EPROCESS. For simplicity and broad
        // compatibility, we'll assume a common offset for DirectoryTableBase relative to EPROCESS start.
        // A more robust solution would use version-specific offsets.
        // EPROCESS->Pcb (KPROCESS) is at 0x0. DirectoryTableBase is at 0x28 in KPROCESS.
        UINT64 ProcessDtb = CurrentProcess->Pcb.DirectoryTableBase;

        CR3 CurrentProcessCr3 = {.AsUInt = ProcessDtb};

        if (CapturedCr3.AddressOfPageDirectory == CurrentProcessCr3.AddressOfPageDirectory)
        {
            return TRUE; // Found a match. The CR3 is valid.
        }

        CurrentEntry = CurrentEntry->Flink;
    }

    return FALSE; // No match found. The CR3 is suspicious.
}
