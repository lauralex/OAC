/**
 * @file shellcode_analyzer.h
 * @brief Provides an interface for analyzing user-mode threads for shellcode.
 */
#pragma once
#include <ntddk.h>

/**
 * @brief Analyzes a thread's user-mode call stack for evidence of shellcode injection.
 *
 * This function performs a stack walk of the specified user-mode thread. For each
 * return address on the stack, it checks if the code resides in an RWX memory
 * region and if it matches known shellcode signatures.
 *
 * @note This function must be called at PASSIVE_LEVEL. It temporarily attaches to
 *       the target process's address space.
 *
 * @param[in] ProcessId The ID of the process to inspect.
 * @param[in] ThreadId The ID of the thread whose stack will be walked.
 *
 * @return TRUE if shellcode is detected, FALSE otherwise.
 */
BOOLEAN AnalyzeThreadForShellcode(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId
);
