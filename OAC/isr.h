#pragma once
#include <ntddk.h>
#include "internals.h" // For RUNTIME_FUNCTION, CONTEXT, etc.

// Our assembly ISR. Tells the C compiler it exists elsewhere.
extern VOID PageFaultIsr(VOID); // Defined in isr.asm


// Implemented in stackwalk_saferecovery.asm
extern VOID PageFaultRecoveryIsr(VOID);
