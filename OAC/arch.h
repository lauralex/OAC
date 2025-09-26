#pragma once
#include <ntddk.h>

struct _MACHINE_FRAME
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

extern void _sgdt(void*); // MSVC-provided intrinsic
extern void _str(void*);  // Defined in arch.asm
extern void _invd(void);  // Defined in arch.asm
