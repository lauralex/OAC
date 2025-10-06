#pragma once
#include <ntddk.h>

/**
 * @file pt_analyzer.h
 * @brief Provides the interface for analyzing process page tables for suspicious mappings.
 */

/**
 * @brief Analyzes the page tables of a given process for security violations.
 *
 * This function initiates a recursive walk of the process's page table hierarchy
 * to detect anomalies, such as user-mode mappings of kernel-mode virtual addresses.
 *
 * @note This function must be called at PASSIVE_LEVEL.
 * @param[in] TargetProcess A pointer to the EPROCESS object of the process to analyze.
 */
VOID AnalyzeProcessPageTables(
    _In_ PEPROCESS TargetProcess
);
