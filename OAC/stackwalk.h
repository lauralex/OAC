/**
 * @file stackwalk.h
 * @brief Defines structures and interfaces for NMI-based stack walking and deferred analysis.
 */
#pragma once
#include "ia32.h"

#include <ntddk.h>

// =================================================================================================
// == Constants and Definitions
// =================================================================================================

// Unique signature to validate our NMI context structure.
#define NMI_CONTEXT_SIGNATURE   0x494D4E43414F // "OACNMI" in ASCII

// Maximum number of times to broadcast NMIs to other processors.
#define NMI_MAX_BROADCAST_COUNT 10

// Maximum stack frames to capture during a stack walk.
#define MAX_STACK_FRAMES        5

/**
 * @def MAX_PENDING_CHECKS
 * @brief The maximum number of RIPs we can queue from NMIs before they are processed.
 *
 * This avoids dynamic allocation in the NMI handler by using a pre-allocated pool.
 * If more NMIs arrive than this limit before the worker thread can process them,
 * subsequent RIPs will be dropped until the pool is cleared.
 */
#define MAX_PENDING_CHECKS      512


// =================================================================================================
// == Structures
// =================================================================================================

/**
 * @struct _SIGNATURE_CHECK_ITEM
 * @brief Represents a single piece of work to be processed by the deferred worker thread.
 */
typedef struct _SIGNATURE_CHECK_ITEM
{
    LIST_ENTRY ListEntry;   //!< Linked list entry for the queue.
    PVOID      Rip;         //!< The instruction pointer captured during the NMI.
    UINT64     CapturedCr3; //!< The CR3 value at the time of capture.
} SIGNATURE_CHECK_ITEM, *PSIGNATURE_CHECK_ITEM;

/**
 * @struct _NMI_CONTEXT
 * @brief A context structure passed to the NMI callback and used for deferred work.
 */
typedef struct _NMI_CONTEXT
{
    volatile LONG                        PendingCount;      //!< Tracks pending NMIs to be handled.
    SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64 UnwindingIdt[256]; //!< Modified Unwinding IDT.
    UINT64                               MagicSignature;    //!< A unique value to verify context integrity.
    UINT64                               SystemCr3;         //!< The CR3 value of the System process (for comparison).
    KSPIN_LOCK                           Lock;              //!< General spinlock for context data (not for the list).

    // --- Deferred Checking Resources ---
    LIST_ENTRY      PendingCheckList;  //!< Lock-free list of RIPs to check.
    KSPIN_LOCK      CheckListLock;     //!< Spinlock for the pending check list.
    KDPC            SignatureDpc;      //!< DPC to schedule the worker thread.
    WORK_QUEUE_ITEM SignatureWorkItem; //!< The work item for the deferred check.
    volatile LONG   IsWorkerActive;    //!< A flag to prevent re-queuing an already active worker thread.

    // --- NMI-Safe Pre-allocated Pool ---
    SIGNATURE_CHECK_ITEM CheckItemPool[MAX_PENDING_CHECKS]; //!< Pool of items to avoid allocation at HIGH_LEVEL IRQL.
    volatile LONG        PoolIndex;                         //!< Atomic index for the next free item in the pool.
} NMI_CONTEXT, *PNMI_CONTEXT;

// =================================================================================================
// == Public Helper Functions
// =================================================================================================

/**
 * @brief Fills a CONTEXT structure from a given KTRAP_FRAME.
 * @param[inout] ContextRecord Pointer to the CONTEXT structure to fill.
 * @param[in]    TrapFrame Pointer to the KTRAP_FRAME containing the saved state.
 */
inline VOID FillContextStructure(
    _Inout_ CONTEXT*  ContextRecord,
    _In_ PKTRAP_FRAME TrapFrame
)
{
    // Copy all general-purpose and control registers.
    ContextRecord->Rax    = TrapFrame->Rax;
    ContextRecord->Rcx    = TrapFrame->Rcx;
    ContextRecord->Rdx    = TrapFrame->Rdx;
    ContextRecord->Rbx    = TrapFrame->Rbx;
    ContextRecord->Rsp    = TrapFrame->Rsp;
    ContextRecord->Rbp    = TrapFrame->Rbp;
    ContextRecord->Rsi    = TrapFrame->Rsi;
    ContextRecord->Rdi    = TrapFrame->Rdi;
    ContextRecord->R8     = TrapFrame->R8;
    ContextRecord->R9     = TrapFrame->R9;
    ContextRecord->R10    = TrapFrame->R10;
    ContextRecord->R11    = TrapFrame->R11;
    ContextRecord->Rip    = TrapFrame->Rip;
    ContextRecord->EFlags = TrapFrame->EFlags;
    ContextRecord->SegCs  = TrapFrame->SegCs;
    ContextRecord->SegDs  = TrapFrame->SegDs;
    ContextRecord->SegEs  = TrapFrame->SegEs;
    ContextRecord->SegFs  = TrapFrame->SegFs;
    ContextRecord->SegGs  = TrapFrame->SegGs;
    ContextRecord->SegSs  = TrapFrame->SegSs;
}


// =================================================================================================
// == Public Function Prototypes
// =================================================================================================

/**
 * @brief Initializes the NMI callback and deferred checking mechanism.
 * @return STATUS_SUCCESS on success, otherwise an error code.
 */
NTSTATUS InitializeNmiHandler(VOID);

/**
 * @brief Deinitializes the NMI callback and cleans up all associated resources.
 */
VOID DeinitializeNmiHandler(VOID);

/**
 * @brief Triggers NMIs on other processors to perform a stack walk and signature check.
 */
VOID TriggerNmiStackwalk(VOID);

/**
 * @brief Locates the KTRAP_FRAME saved on the NMI stack.
 * @return A pointer to the KTRAP_FRAME, or NULL on failure.
 */
PKTRAP_FRAME FindNmiTrapFrame(VOID);
