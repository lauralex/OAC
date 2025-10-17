/**
 * @file arch.h
 * @brief Architecture-specific definitions and utilities for x86_64.
 *
 * This header file contains architecture-specific structures, inline functions,
 * and external function declarations tailored for x86_64 architecture. It includes
 * utilities for retrieving the instruction pointer (RIP), stack pointer (RSP),
 * and performing atomic operations.
 *
 * @note This code is intended for use in kernel-mode drivers and should be compiled
 *       with appropriate settings for the target architecture.
 */

#pragma once
#include <ntddk.h>
#include <intrin.h>

typedef struct _MACHINE_FRAME
{
    UINT64 ErrorCode;
    UINT64 Rip;
    UINT64 Cs;
    UINT64 Rflags;
    UINT64 Rsp;
    UINT64 Ss;
} MACHINE_FRAME, *PMACHINE_FRAME;

/**
 * @brief Retrieves the return address (RIP) of the caller function.
 *
 * This function uses the MSVC intrinsic `_ReturnAddress` to obtain the
 * instruction pointer of the calling function. It is marked as `noinline`
 * to prevent the compiler from optimizing it away, ensuring accurate retrieval.
 *
 * @return A pointer to the return address (RIP) of the caller.
 */
inline __declspec(noinline) PVOID GetRip(VOID)
{
    return _ReturnAddress();
}

/**
 * @brief Retrieves the current stack pointer (RSP).
 *
 * This function is defined in assembly (arch.asm) and returns the value of
 * the RSP register, which points to the top of the current stack frame.
 *
 * @return A pointer to the current stack pointer (RSP).
 */
extern PVOID GetRsp(VOID);

/**
 * @brief Sets the Trap Flag (TF) in the RFLAGS register.
 *
 * This function is defined in assembly (arch.asm) and sets the Trap Flag
 * in the RFLAGS register. Setting this flag enables single-step mode,
 * causing a debug exception after each instruction is executed.
 */
extern VOID SetTrapFlag(VOID);

/**
 * @brief Clears the Trap Flag (TF) in the RFLAGS register.
 *
 * This function is defined in assembly (arch.asm) and clears the Trap Flag
 * in the RFLAGS register, disabling single-step mode.
 */
extern VOID ClearTrapFlag(VOID);

/**
 * @brief Sets a write data breakpoint at the specified address.
 *
 * This function is defined in assembly (arch.asm) and configures a
 * hardware data breakpoint to monitor write accesses to the specified
 * memory address. This is useful for debugging purposes.
 *
 * @param[in] Address The memory address to set the write data breakpoint on.
 */
extern VOID SetWriteDataBreakpoint(PVOID Address);

/**
 * @brief Clears all data breakpoints.
 *
 * This function is defined in assembly (arch.asm) and clears any
 * hardware data breakpoints that have been set. This is useful for
 * cleaning up after debugging sessions.
 */
extern VOID ClearDataBreakpoints(VOID);

/**
 * @brief Atomically multiplies a LONG value by a given factor.
 *
 * This function performs an atomic multiplication operation on a LONG integer
 * pointed to by `Target`, multiplying it by `Factor`. It uses a compare-and-swap
 * loop to ensure that the operation is thread-safe.
 *
 * @param[inout] Target A pointer to the LONG value to be multiplied.
 * @param[in] Factor The factor by which to multiply the target value.
 * @return The new value after multiplication.
 */
inline LONG InterlockedMultiply(
    _Inout_ volatile LONG* Target,
    _In_ LONG              Factor
)
{
    LONG OldVal, NewVal;
    do
    {
        OldVal = *Target;         // read current value
        NewVal = OldVal * Factor; // compute new value
        // try to swap in newVal if *Target is still oldVal
    }
    while (InterlockedCompareExchange(Target, NewVal, OldVal) != OldVal);

    return NewVal; // returns the updated value
}

/**
 * @brief Atomically increments a LONG value if it is less than or equal to a threshold.
 *
 * This function atomically increments the LONG integer pointed to by `Target`
 * only if its current value is less than or equal to the specified `Threshold`.
 * It uses a compare-and-swap loop to ensure thread safety.
 *
 * @param[inout] Target A pointer to the LONG value to be conditionally incremented.
 * @param[in]    Threshold The threshold value for the increment condition.
 * @return The new value after incrementing, or the old value if the condition was not met.
 */
inline LONG InterlockedIncrementIfLessOrEqual(
    volatile LONG* Target,
    LONG           Threshold
)
{
    LONG OldValue, NewValue;
    do
    {
        OldValue = *Target;
        if (OldValue > Threshold)
        {
            return OldValue; // Do not increment
        }
        NewValue = OldValue + 1;
    }
    while (InterlockedCompareExchange(Target, NewValue, OldValue) != OldValue);
    return NewValue;
}

extern void _sgdt(void*); // MSVC-provided intrinsic
extern void _str(void*);  // Defined in arch.asm
extern void _invd(void);  // Defined in arch.asm
