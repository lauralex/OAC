#pragma once
#include <ntddk.h>

// =================================================================================================
// == NMI Context and Globals
// =================================================================================================

/**
 * @brief A context structure to be passed to the NMI callback.
 * This provides a verifiable link between our registration and the callback invocation.
 */
typedef struct _NMI_CONTEXT
{
    volatile LONG PendingCount;
    UINT64        MagicSignature; // A unique value to verify the context integrity.
} NMI_CONTEXT, *PNMI_CONTEXT;

// The global instance of our context structure.
extern NMI_CONTEXT G_NmiContext;

// The unique signature we will use to identify our NMI context.
#define NMI_CONTEXT_SIGNATURE 0x494D4E43414F // "OACNMI" in ASCII

// Global handle for the NMI callback registration.
extern PVOID G_NmiCallbackHandle;


// =================================================================================================
// == NMI Callback and Helper Functions
// =================================================================================================

/**
 * @brief Initializes the NMI callback for stack walking.
 *
 * @return STATUS_SUCCESS on success, or an error code.
 */
NTSTATUS InitializeNmiHandler(void);

/**
 * @brief Deinitializes the NMI callback.
 */
VOID DeinitializeNmiHandler(void);

/**
 * @brief Triggers an NMI on the current processor to perform a stack walk.
 */
VOID TriggerNmiStackwalk(void);
