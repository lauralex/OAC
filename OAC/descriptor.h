#pragma once

#include <ntifs.h>

/* MSVC x64 exposes SIDT but not SGDT as a C intrinsic. */
VOID OacStoreGdtr(_Out_writes_bytes_(10) PVOID DescriptorRegister);
