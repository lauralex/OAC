#include <ntifs.h>
#include "stackwalk.h"
#include "internals.h"

//
// The global instance of our context structure.
//
NMI_CONTEXT G_NmiContext = {0};

//
// Global handle for the NMI callback registration.
//
PVOID G_NmiCallbackHandle = NULL;


/**
 * @brief The NMI callback routine that performs a stack walk.
 *
 * @param Context A pointer to our driver-defined NMI_CONTEXT structure.
 * @param Handled A boolean that indicates if a previous NMI handler has already claimed this NMI.
 *
 * @return TRUE if the NMI was handled, otherwise FALSE.
 */
BOOLEAN NmiCallback(
    _In_opt_ PVOID Context,
    _In_ BOOLEAN   Handled
)
{
    //
    // Step 1: Check if another driver has already handled this NMI.
    // If so, we must not interfere. Just pass it on.
    //
    if (Handled)
    {
        return FALSE;
    }

    //
    // Step 2: Validate our context. This is the most critical check.
    // If the context is missing or the signature is invalid, this NMI is not for us,
    // or something is seriously wrong (e.g., memory corruption, tampering).
    //
    PNMI_CONTEXT nmiContext = (PNMI_CONTEXT)Context;
    if (!nmiContext || nmiContext->MagicSignature != NMI_CONTEXT_SIGNATURE)
    {
        // Invalid context, not our NMI.
        return FALSE;
    }

    // Step 3: Check if this NMI was triggered by our driver.
    // If the pending count is 0, it's an unexpected NMI (e.g., hardware error).
    //
    if (nmiContext->PendingCount == 0)
    {
        return FALSE;
    }

    //
    // This NMI is confirmed to be for us. Atomically decrement the pending count.
    //
    InterlockedDecrement(&nmiContext->PendingCount);

    DbgPrint("[+] NMI callback triggered on CPU %d\n", KeGetCurrentProcessorNumberEx(NULL));

    //
    // Perform the stack walk.
    //
#define MAX_STACK_FRAMES 32
    PVOID stackFrames[MAX_STACK_FRAMES] = {0};
    ULONG framesCaptured                = RtlCaptureStackBackTrace(0, MAX_STACK_FRAMES, stackFrames, NULL);

    if (framesCaptured > 0)
    {
        DbgPrint("[+] Stack trace:\n");
        for (ULONG i = 0; i < framesCaptured; i++)
        {
            DbgPrint("  [%lu] 0x%p\n", i, stackFrames[i]);
        }
    }
    else
    {
        DbgPrint("[-] Failed to capture stack trace in NMI callback.\n");
    }


    //
    // Step 4: We have successfully handled our self-initiated NMI.
    // Return TRUE to inform the system and other drivers.
    //
    return TRUE;
}

/**
 * @brief Initializes the NMI callback for stack walking.
 *
 * @return STATUS_SUCCESS on success, otherwise an error code.
 */
NTSTATUS InitializeNmiHandler(void)
{
    // Initialize our context structure.
    RtlZeroMemory(&G_NmiContext, sizeof(NMI_CONTEXT));
    G_NmiContext.MagicSignature = NMI_CONTEXT_SIGNATURE;
    G_NmiContext.PendingCount   = 0;

    //
    // Register the NMI callback.
    //
    G_NmiCallbackHandle = KeRegisterNmiCallback(NmiCallback, &G_NmiContext);
    if (!G_NmiCallbackHandle)
    {
        DbgPrint("[-] Failed to register NMI callback.\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DbgPrint("[+] NMI callback registered successfully with context validation.\n");
    return STATUS_SUCCESS;
}

/**
 * @brief Deinitializes the NMI callback.
 */
VOID DeinitializeNmiHandler(void)
{
    if (G_NmiCallbackHandle)
    {
        KeDeregisterNmiCallback(G_NmiCallbackHandle);
        G_NmiCallbackHandle = NULL;
        DbgPrint("[+] NMI callback deregistered.\n");
    }
}

/**
 * @brief Triggers an NMI on the current processor to perform a stack walk.
 */
VOID TriggerNmiStackwalk(void)
{
    // Initialize NMI handler if it not already initialized.
    if (!G_NmiCallbackHandle)
    {
        NTSTATUS status = InitializeNmiHandler();
        if (!NT_SUCCESS(status))
        {
            DbgPrint("[-] Failed to initialize NMI handler: 0x%X\n", status);
            return;
        }
    }

    DbgPrint("[+] Triggering NMI on the current processor.\n");

    KAFFINITY_EX affinity = {0};

    KeInitializeAffinityEx(&affinity);
    KeAddProcessorAffinityEx(&affinity, KeGetCurrentProcessorNumberEx(NULL));

    // Print target affinity
    DbgPrint("[+] Target CPU Affinity Bitmap: 0x%p\n", (PVOID)affinity.Bitmap);

    //
    // Increment our pending counter BEFORE sending the NMI.
    // This creates the "pending" state that the NMI callback will check for.
    //
    InterlockedIncrement(&G_NmiContext.PendingCount);

    //
    // This is an undocumented function, but it is the standard way to
    // programmatically trigger an NMI on a specific processor.
    //
    HalSendNMI(&affinity);

    DbgPrint("[+] NMI sent.\n");
}
