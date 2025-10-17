/**
 * @file cr3_thrasher.h
 * @brief Header file for CR3 thrashing functionality.
 *
 * This header defines the interface for triggering CR3 thrashing, which involves setting up
 * a custom page table hierarchy and modifying the IDT to point to a custom Page Fault handler.
 * The original CR3 is restored by the ISR.
 */

#pragma once
#include "ia32.h"

#include <ntddk.h>

// Global array to hold a copy of the IDT for our ISR to use.
extern SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64 Cr3ThrashIdtArray[256];

/**
 * @brief Triggers the CR3 thrashing routine. This function sets up a custom page table hierarchy,
 *        modifies the IDT to point to a custom Page Fault handler, and thrashes CR3 to induce
 *        page faults. The original CR3 is restored by the ISR.
 */
VOID TriggerCr3Thrash(VOID);
