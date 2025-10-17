/**
 * @file instruction_decoder.c
 * @brief Implements dynamic x86-64 instruction length decoding using the Zydis library.
 *
 * This module provides a function to determine the length of an x86-64 instruction
 * at runtime, which is essential for accurate stack walking and unwinding.
 * It leverages the Zydis library, a fast and lightweight x86/x86-64 instruction decoder.
 */

#include "instruction_decoder.h"
#include "Zydis.h"

#include <ntddk.h>

/**
 * @brief Dynamically calculates the length of an x86-64 instruction.
 *
 * @param[in] InstructionPtr A pointer to the beginning of the instruction.
 * @return The length of the instruction in bytes.
 */
ZyanU8 GetInstructionLength(
    _In_ PUCHAR InstructionPtr
)
{
    // Check for a null pointer, just in case.
    if (!InstructionPtr)
    {
        return 1;
    }

    ZydisDecoder Decoder;
    ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisDecodedInstruction Instruction;

    // The maximum length of an x86 instruction is 15 bytes.
    // We pass the instruction pointer and a max length to decode.
    if (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&Decoder, ZYAN_NULL, InstructionPtr, 15, &Instruction)))
    {
        // If decoding was successful, the length is in the struct.
        return Instruction.length;
    }

    // If Zydis fails for some reason (e.g., invalid instruction),
    // return 1 as a safe fallback to prevent getting stuck.
    return 1;
}
