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
    KSPIN_LOCK    Lock;           // A spin lock for synchronizing access to the context.
} NMI_CONTEXT, *PNMI_CONTEXT;

// The global instance of our context structure.
extern NMI_CONTEXT G_NmiContext;

// The unique signature we will use to identify our NMI context.
#define NMI_CONTEXT_SIGNATURE 0x494D4E43414F // "OACNMI" in ASCII

// The number of times to broadcast NMIs to ensure delivery.
#define NMI_MAX_BROADCAST_COUNT 30

// The maximum number of stack frames to unwind during the stack walk.
#define MAX_STACK_FRAMES 8

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

/**
 * @brief Locates the KTRAP_FRAME saved on the NMI stack.
 * This is an advanced technique that inspects core system structures.
 *
 * @return A pointer to the KTRAP_FRAME, or NULL on failure.
 */
PKTRAP_FRAME FindNmiTrapFrame(void);
