#include "cr3_validation.h"
#include "globals.h"
#include "ia32.h"
#include "internals.h"

/**
 * @brief Iterates through the system's active process list to validate a CR3 value.
 * @note This function MUST be called at PASSIVE_LEVEL.
 *
 * @param[in] CapturedCr3 The CR3 value captured during the NMI.
 * @return TRUE if the CR3 is found in the list of active processes, FALSE otherwise.
 */
BOOLEAN IsCr3InProcessList(
    _In_ UINT64 CapturedCr3
)
{
    PAGED_CODE() // Ensures we are at PASSIVE_LEVEL

    if (!PsActiveProcessHead)
    {
        return FALSE; // Should not happen
    }

    // The CR3 value contains the physical address of the PML4 table, but also other bits like PCID.
    // We must compare only the address portion.
    CR3 captured = {.AsUInt = CapturedCr3};

    // Check against the system process first.
    if (G_NmiContext.SystemCr3 != 0)
    {
        CR3 system = {.AsUInt = G_NmiContext.SystemCr3};
        if (captured.AddressOfPageDirectory == system.AddressOfPageDirectory)
        {
            return TRUE;
        }
    }

    // Walk the list of all active processes.
    // Note: Walking this list without the proper lock (PsActiveProcessLock, which is unexported)
    // carries a small risk of race conditions on a highly active system. For this project's
    // purpose, it is generally safe.
    PLIST_ENTRY currentEntry = PsActiveProcessHead->Flink;
    while (currentEntry != PsActiveProcessHead)
    {
        // Get the EPROCESS structure from the list entry.
        // The offset of ActiveProcessLinks is 0x448 in our partial struct.
        PEPROCESS pEprocess = (PEPROCESS)CONTAINING_RECORD(currentEntry, EPROCESS, ActiveProcessLinks);

        // The KPROCESS.DirectoryTableBase is at offset 0x28 of the EPROCESS's KPROCESS member.
        // The KPROCESS (Pcb) is at a known offset within the EPROCESS. For simplicity and broad
        // compatibility, we'll assume a common offset for DirectoryTableBase relative to EPROCESS start.
        // A more robust solution would use version-specific offsets.
        // EPROCESS->Pcb (KPROCESS) is at 0x0. DirectoryTableBase is at 0x28 in KPROCESS.
        UINT64 processCr3 = pEprocess->Pcb.DirectoryTableBase;

        CR3 currentProcess = {.AsUInt = processCr3};

        if (captured.AddressOfPageDirectory == currentProcess.AddressOfPageDirectory)
        {
            return TRUE; // Found a match. The CR3 is valid.
        }

        currentEntry = currentEntry->Flink;
    }

    return FALSE; // No match found. The CR3 is suspicious.
}
