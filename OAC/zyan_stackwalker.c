/**
 * @file zyan_stackwalker.c
 *
 * @brief Implementation of a stack walker using Zydis for instruction decoding.
 */
#include <ntddk.h>
#include "zyan_stackwalker.h"
#include "internals.h"

/**
* @brief Safely reads memory from a potentially non-resident address.
*
* This function checks if the memory pages in the specified range are resident
* before performing the read. It avoids page faults by verifying each page
* with MmIsAddressValid.
*
* @param[in]  Source      The source address to read from.
* @param[out] Destination The destination buffer to copy data into.
* @param[in]  Size        The number of bytes to read.
* @return TRUE if the memory was successfully read, FALSE if any page is non-resident.
*/
static BOOLEAN SafeReadMemory(
    _In_ PVOID  Source,
    _Out_ PVOID Destination,
    _In_ SIZE_T Size
)
{
    DbgPrint("[*] SafeReadMemory: Source=%p, Destination=%p, Size=%llu\n", Source, Destination, Size);
    if (Size == 0) return TRUE;

    // Align to page boundaries and check every page in the range
    PVOID StartPage   = (PVOID)((UINT64)Source & ~(PAGE_SIZE - 1));
    PVOID EndPage     = (PVOID)(((UINT64)Source + Size - 1) & ~(PAGE_SIZE - 1));
    PVOID CurrentPage = StartPage;

    while (CurrentPage <= EndPage)
    {
        if (!MmIsAddressValid(CurrentPage))
        {
            return FALSE;
        }
        CurrentPage = (PVOID)((UINT64)CurrentPage + PAGE_SIZE);
    }

    // All pages are resident; perform the copy (non-paged operation)
    RtlCopyMemory(Destination, Source, Size);
    return TRUE;
}

/**
 * @brief Checks if a virtual address is within user-mode address space (x64).
 *
 * @param[in]  VirtualAddress The virtual address to check.
 * @return TRUE if the address is in user-mode space, FALSE otherwise.
 */
static BOOLEAN IsUserModeAddress(
    _In_ UINT64 VirtualAddress
)
{
    return (VirtualAddress > 0x10000 && VirtualAddress <= 0x00007FFFFFFFFFFFULL);
}

/**
 * @brief Checks if a virtual address is executable.
 *
 * This function queries the memory protection of the page containing the
 * specified virtual address to determine if it has execute permissions.
 *
 * @param[in]  VirtualAddress The virtual address to check.
 * @return TRUE if the address is executable, FALSE otherwise.
 */
static BOOLEAN IsAddressExecutable(
    _In_ UINT64 VirtualAddress
)
{
    MEMORY_BASIC_INFORMATION MemoryInfo;
    SIZE_T                   ReturnLength;
    NTSTATUS                 Status = ZwQueryVirtualMemory(
        ZwCurrentProcess(),
        (PVOID)VirtualAddress,
        MemoryBasicInformation,
        &MemoryInfo,
        sizeof(MemoryInfo),
        &ReturnLength
    );
    if (!NT_SUCCESS(Status) || ReturnLength != sizeof(MemoryInfo))
    {
        return FALSE;
    }
    // Check if page is present and has execute permissions
    return (MemoryInfo.State == MEM_COMMIT &&
        (MemoryInfo.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)));
}

/**
 * @brief Checks if the instruction at Address is preceded by a CALL instruction.
 *
 * This function disassembles backwards from the given address to find a CALL
 * instruction that targets the address. It uses Zydis for decoding and checks
 * execute permissions for the memory range being analyzed.
 *
 * @param[in]  Address      The address to check.
 * @param[in]  Decoder      A pointer to an initialized ZydisDecoder.
 * @param[in]  SearchBytes  The number of bytes to search backwards from Address.
 * @return TRUE if a preceding CALL instruction is found, FALSE otherwise.
 */
static BOOLEAN IsPrecededByCall(
    _In_ UINT64        Address,
    _In_ ZydisDecoder* Decoder,
    _In_ SIZE_T        SearchBytes
)
{
    if (SearchBytes < ZYDIS_MAX_INSTRUCTION_LENGTH * 2)
    {
        SearchBytes = ZYDIS_MAX_INSTRUCTION_LENGTH * 3; // ~45 bytes for more context
    }

    if (Address < (UINT64)SearchBytes) return FALSE; // Invalid address

    // Check execute permission for the range (addr - search_bytes) to addr
    UINT64 StartAddress = Address - SearchBytes;
    UINT64 Current      = StartAddress & ~(PAGE_SIZE - 1);
    while (Current < Address)
    {
        if (!IsAddressExecutable(Current))
        {
            return FALSE;
        }
        Current += PAGE_SIZE;
    }

    UINT8 Buffer[128]; // Buffer for up to 128 bytes
    if (SearchBytes > sizeof(Buffer)) SearchBytes = sizeof(Buffer);

    // Safely read the preceding bytes
    if (!SafeReadMemory((PVOID)StartAddress, Buffer, SearchBytes))
    {
        return FALSE;
    }

    // Limit decode failures to avoid infinite loops
    const SIZE_T MaxDecodeFailures = 3; // Stop if too many decode failures (non-code region)


    ZydisDecodedInstruction Instruction;
    ZydisDecodedOperand     Operands[ZYDIS_MAX_OPERAND_COUNT];
    ZyanUSize               Offset         = 0;
    SIZE_T                  DecodeFailures = 0;


    while (Offset < SearchBytes)
    {
        ZyanStatus Status = ZydisDecoderDecodeFull(Decoder, Buffer + Offset, SearchBytes - Offset,
                                                   &Instruction, Operands);
        if (!ZYAN_SUCCESS(Status))
        {
            DecodeFailures++;
            if (DecodeFailures >= MaxDecodeFailures)
            {
                return FALSE; // Likely not code
            }
            Offset++; // Skip byte (heuristic for misalignment)
            continue;
        }

        UINT64 InstructionStart = Address - SearchBytes + Offset;
        UINT64 InstructionEnd   = InstructionStart + Instruction.length;

        if (InstructionEnd == Address)
        {
            if (Instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
                Instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
            {
                // Relative near calls
                if (Instruction.operand_count_visible > 0 &&
                    (Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER ||
                        Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY))
                {
                    // For relative calls, validate target address
                    if (Operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                        Operands[0].imm.is_relative)
                    {
                        UINT64 call_target = InstructionEnd + (INT64)Operands[0].imm.value.s;
                        if (!IsUserModeAddress(call_target))
                        {
                            return FALSE;
                        }
                    }
                    return TRUE;
                }
            }
        }

        Offset += Instruction.length;
        DecodeFailures = 0; // Reset on successful decode
    }

    return FALSE;
}

/**
 * @brief Performs a stack walk using Zydis for instruction decoding and heuristics.
 *
 * This function attempts to reconstruct the call stack by scanning the stack memory
 * for potential return addresses. It uses several heuristics to validate candidates:
 * 1. Address space check (user-mode only).
 * 2. Execute permission check.
 * 3. Preceded by a CALL instruction.
 * If a candidate passes all checks, it is accepted as a valid frame.
 *
 * @param[in]  InitialRip     The initial instruction pointer (RIP) to start the stack walk from.
 * @param[in]  InitialRsp     The initial stack pointer (RSP) to start scanning the stack.
 * @param[out] OutFrames      An array to store the captured stack frames (RIP values).
 * @param[in]  MaxFrames      The maximum number of stack frames to capture.
 * @param[out] OutFramesCount The actual number of frames captured.
 *
 * @return TRUE if at least one frame was captured, FALSE otherwise.
 */
BOOLEAN StackWalkWithZydis(
    _In_ UINT64   InitialRip,
    _In_ UINT64   InitialRsp,
    _Out_ PUINT64 OutFrames,
    _In_ SIZE_T   MaxFrames,
    _Out_ PSIZE_T OutFramesCount
)
{
    if (MaxFrames == 0 || OutFrames == NULL)
    {
        return FALSE;
    }
    // Initialize OutFrames to zero
    RtlZeroMemory(OutFrames, MaxFrames * sizeof(UINT64));

    // Initialize Zydis decoder for x64
    ZydisDecoder Decoder;
    ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    DbgPrint("Stack trace (heuristic):\n");

    // Validate initial RIP
    if (IsUserModeAddress(InitialRip) &&
        IsAddressExecutable(InitialRip))
    {
        // Add to OutFrames
        OutFrames[0] = InitialRip;
    }
    else
    {
        DbgPrint("Invalid initial RIP: %p\n", (PVOID)InitialRip);
        return FALSE;
    }

    // Heuristic scanning parameters
    const SIZE_T MaxStackSearch         = 65536;          // 64KB max stack scan
    const SIZE_T Step                   = sizeof(UINT64); // 8-byte alignment
    const SIZE_T MaxConsecutiveFailures = 5;              // Stop after too many invalid candidates


    SIZE_T FrameCount          = 1; // Already have initial frame
    SIZE_T Offset              = 0; // Offset from InitialRsp
    SIZE_T ConsecutiveFailures = 0; // Count of consecutive invalid candidates


    while (Offset < MaxStackSearch && FrameCount < MaxFrames)
    {
        UINT64 Candidate;
        PVOID  StackAddress = (PVOID)(InitialRsp + Offset);

        // Safely read candidate
        if (!SafeReadMemory(StackAddress, &Candidate, sizeof(Candidate)))
        {
            ConsecutiveFailures++;
            if (ConsecutiveFailures >= MaxConsecutiveFailures)
            {
                break; // Likely end of valid stack
            }
            Offset += Step;
            continue;
        }

        // Heuristics chain:
        // 1. Address space check
        if (!IsUserModeAddress(Candidate))
        {
            Offset += Step;
            continue;
        }

        // 2. Execute permission check
        if (!IsAddressExecutable(Candidate))
        {
            Offset += Step;
            continue;
        }

        // 3. Preceded by CALL
        if (!IsPrecededByCall(Candidate, &Decoder, 64))
        {
            Offset += Step;
            continue;
        }

        // All heuristics passed; accept as frame
        DbgPrint("Frame %llu: %p\n", FrameCount, (PVOID)Candidate);
        OutFrames[FrameCount] = Candidate;
        FrameCount++;
        ConsecutiveFailures = 0;

        // Heuristic: Jump to estimated next frame (skip shadow space + locals)
        Offset += 32;                               // Assume 32-128 bytes per frame
        Offset = (Offset + Step - 1) & ~(Step - 1); // Re-align
    }

    if (FrameCount < 2)
    {
        return FALSE;
    }

    *OutFramesCount = FrameCount;

    return TRUE;
}
