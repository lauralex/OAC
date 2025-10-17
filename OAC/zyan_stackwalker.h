/**
 * @file zyan_stackwalker.h
 *
 * @brief Header file for a stack walker using Zydis for instruction decoding.
 */
#pragma once
#pragma warning(push)
#pragma warning(disable : 4201) // nameless struct/union
#include "Zydis.h"
#pragma warning(pop)

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
);
