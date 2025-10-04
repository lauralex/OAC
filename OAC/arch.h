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

extern void _sgdt(void*); // MSVC-provided intrinsic
extern void _str(void*);  // Defined in arch.asm
extern void _invd(void);  // Defined in arch.asm
