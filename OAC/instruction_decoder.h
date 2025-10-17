/**
 * @file instruction_decoder.h
 * @brief Header file for instruction length calculation using Zydis.
 *
 * This file declares the function to calculate the length of an x86-64 instruction
 * using the Zydis disassembly library.
 */

#pragma once
#pragma warning(push)
#pragma warning(disable : 4201) // nameless struct/union
#include "Zydis.h"
#pragma warning(pop)

typedef struct _INSTRUCTION_INFO
{
    ZydisDecodedInstruction Instruction;
    ZydisDecodedOperand     Operands[ZYDIS_MAX_OPERAND_COUNT];
} INSTRUCTION_INFO, *PINSTRUCTION_INFO;

/**
 * @brief Dynamically calculates the length of an x86-64 instruction.
 *
 * @param[in] InstructionPtr A pointer to the beginning of the instruction.
 * @return The length of the instruction in bytes.
 */
ZyanU8 GetInstructionLength(
    _In_ PUCHAR InstructionPtr
);
