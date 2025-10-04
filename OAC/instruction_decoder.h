// --- START OF FILE decoder.h ---

#pragma once
#include "Zydis.h"

/**
 * @brief Dynamically calculates the length of an x86-64 instruction.
 *
 * @param[in] InstructionPtr A pointer to the beginning of the instruction.
 * @return The length of the instruction in bytes.
 */
ZyanU8 GetInstructionLength(
    _In_ PUCHAR InstructionPtr
);
