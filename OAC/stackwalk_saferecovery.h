/**
 * @file stackwalk_saferecovery.h
 * @brief Provides the interface for the safe unwinding mechanism.
 */
#pragma once
#include <ntddk.h>

/**
 * @struct _SAFE_UNWIND_CONTEXT
 * @brief A global structure to facilitate recovery from a page fault during unwinding.
 *
 * This structure holds the machine state before a potentially faulting operation.
 * If a page fault occurs, our custom ISR uses this context to restore the state
 * and redirect execution to a safe recovery point.
 */
typedef struct _SAFE_UNWIND_CONTEXT
{
    volatile LONG FaultOccurred; //!< A flag set by the ISR to indicate a fault happened.
    CONTEXT       RegisterState; //!< A complete snapshot of GPRs, RIP, and RSP for recovery.
} SAFE_UNWIND_CONTEXT, *PSAFE_UNWIND_CONTEXT;

/**
 * @brief An ASM wrapper around RtlVirtualUnwind that provides page fault protection.
 *
 * This function sets up a temporary page fault handler to catch and recover from
 * any page faults that might occur within RtlVirtualUnwind, making it safe to call
 * from an NMI handler.
 *
 * @param[in]       HandlerType         See documentation for RtlVirtualUnwind.
 * @param[in]       ImageBase           See documentation for RtlVirtualUnwind.
 * @param[in]       ControlPc           See documentation for RtlVirtualUnwind.
 * @param[in]       FunctionEntry       See documentation for RtlVirtualUnwind.
 * @param[in,out]   ContextRecord       See documentation for RtlVirtualUnwind.
 * @param[out]      HandlerData         See documentation for RtlVirtualUnwind.
 * @param[out]      EstablisherFrame    See documentation for RtlVirtualUnwind.
 * @param[in,out]   ContextPointers     See documentation for RtlVirtualUnwind.
 *
 * @return STATUS_SUCCESS on success, or STATUS_PAGE_FAULT_IN_NONPAGED_AREA if a fault occurred.
 * @note This function should be called by `PerformUnwindInSafeRegion` after setting up the safe environment.
 */
extern NTSTATUS NTAPI SafeRtlVirtualUnwind(
    _In_ ULONG                                 HandlerType,
    _In_ ULONG64                               ImageBase,
    _In_ ULONG64                               ControlPc,
    _In_ PRUNTIME_FUNCTION                     FunctionEntry,
    _Inout_ PCONTEXT                           ContextRecord,
    _Out_ PVOID*                               HandlerData,
    _Out_ PULONG64                             EstablisherFrame,
    _Inout_opt_ PKNONVOLATILE_CONTEXT_POINTERS ContextPointers
);

/**
 * @brief The C-level function that executes the `SafeRtlVirtualUnwind` ASM wrapper.
 *
 * This function is responsible for swapping the IDT entry for the page fault handler,
 * calling the `SafeRtlVirtualUnwind`, and then restoring the original IDT entry.
 *
 * @param[in]       HandlerType             See documentation for RtlVirtualUnwind.
 * @param[in]       ImageBase               See documentation for RtlVirtualUnwind.
 * @param[in]       ControlPc               See documentation for RtlVirtualUnwind.
 * @param[in]       FunctionEntry           See documentation for RtlVirtualUnwind.
 * @param[in,out]   ContextRecord           See documentation for RtlVirtualUnwind.
 * @param[out]      HandlerData             See documentation for RtlVirtualUnwind.
 * @param[out]      EstablisherFrame        See documentation for RtlVirtualUnwind.
 * @param[in,out]   ContextPointers         See documentation for RtlVirtualUnwind.
 *
 * @return The NTSTATUS result from the underlying RtlVirtualUnwind call.
 */
NTSTATUS NTAPI PerformUnwindInSafeRegion(
    _In_ ULONG                                 HandlerType,
    _In_ ULONG64                               ImageBase,
    _In_ ULONG64                               ControlPc,
    _In_ PRUNTIME_FUNCTION                     FunctionEntry,
    _Inout_ PCONTEXT                           ContextRecord,
    _Out_ PVOID*                               HandlerData,
    _Out_ PULONG64                             EstablisherFrame,
    _Inout_opt_ PKNONVOLATILE_CONTEXT_POINTERS ContextPointers
);
