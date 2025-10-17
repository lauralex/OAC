/**
 * @file globals.h
 * @brief Centralized declarations for global variables used across the project.
 *
 * This header prevents re-definition errors and provides a single source of truth
 * for all global variables.
 */

#pragma once
#include "stackwalk.h" // For NMI_CONTEXT definition
#include "ci.h"       // For CI function pointer definitions
#include "stackwalk_saferecovery.h"

//
// === Global Variables ===
//

/**
 * @brief Global variable to share the original CR3 with our assembly ISR, defined in cr3_thrasher.c.
 */
extern UINT64 G_OriginalCr3;

/**
 * @brief The global context for NMI handling, defined in stackwalk.c.
 */
extern NMI_CONTEXT G_NmiContext;

/**
 * @brief The global handle for the NMI callback registration, defined in stackwalk.c.
 */
extern PVOID G_NmiCallbackHandle;

/**
 * @brief Global pointer to the undocumented CiValidateFileObject function, defined in ci.c.
 */
extern CI_VALIDATE_FILE_OBJECT G_CiValidateFileObject;

/**
 * @brief Global pointer to the undocumented CiFreePolicyInfo function, defined in ci.c.
 */
extern CI_FREE_POLICY_INFO G_CiFreePolicyInfo;

/**
 * @brief Global context for page fault recovery, defined in stackwalk.c
 */
extern SAFE_UNWIND_CONTEXT G_SafeUnwindContext[50];
