#pragma once
#include <ntdef.h>

// Global variable to share the original CR3 with our assembly ISR.
// This MUST be global.
extern UINT64 G_OriginalCr3;

/**
 * @brief Triggers the CR3 thrashing routine. This function sets up a custom page table hierarchy,
 *        modifies the IDT to point to a custom Page Fault handler, and thrashes CR3 to induce
 *        page faults. The original CR3 is restored by the ISR.
 */
VOID TriggerCr3Thrash(void);
