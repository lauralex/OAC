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

inline __declspec(noinline) PVOID GetRip(void)
{
    return _ReturnAddress();
}

inline LONG InterlockedMultiply(volatile LONG* Target, LONG Factor)
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
