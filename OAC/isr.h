/**
 * @file isr.h
 * @brief Header file for the custom Page Fault ISR used in CR3 thrashing and safe unwinding.
 *
 * This header declares the external assembly ISR function and the recovery ISR used
 * for safe unwinding during stack walking. The actual implementations are in assembly
 * files (isr.asm and stackwalk_saferecovery.asm).
 */

#pragma once
#include "internals.h" // For RUNTIME_FUNCTION, CONTEXT, etc.

#include <ntddk.h>

// Our assembly ISR. Tells the C compiler it exists elsewhere.
extern VOID PageFaultIsr(VOID); // Defined in isr.asm


// Implemented in stackwalk_saferecovery.asm
extern VOID PageFaultRecoveryIsr(VOID);
