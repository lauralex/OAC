#pragma once
#include <ntdef.h>

inline __declspec(noinline) PVOID GetRIP(void)
{
    return _ReturnAddress();
}

extern void _sgdt(void*); // MSVC-provided intrinsic
extern void _str(void*);  // Defined in arch.asm
extern void _invd(void);  // Defined in arch.asm
