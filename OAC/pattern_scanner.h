/**
 * @file pattern_scanner.h
 * @brief Header file for pattern scanning functionality.
 *
 * This header defines the interface for scanning memory regions for specific byte patterns,
 * which can include wildcards. It provides a function to perform the scan and a helper
 * function to parse pattern strings into a structured format.
 * This functionality is useful for locating functions or data structures in memory
 * when their addresses are not known at compile time.
 * The pattern format supports hexadecimal byte values and '?' as a wildcard.
 * Example pattern: "48 8B ?? ?? ?? 48 85 C0 74 0E"
 *
 * @note This code is intended for use in a Windows kernel-mode driver.
 */

#pragma once
#include <ntddk.h>

#define MAX_PATTERN_LEN 256

typedef struct _SIGNATURE
{
    UCHAR   Bytes[MAX_PATTERN_LEN];
    BOOLEAN Mask[MAX_PATTERN_LEN]; // TRUE = concrete byte, FALSE = wildcard
    SIZE_T  Length;
} SIGNATURE;

/**
 * @brief Parses a pattern string into a SIGNATURE structure.
 *
 * This function takes a pattern string, which may include hexadecimal byte values
 * and '?' characters as wildcards, and converts it into a SIGNATURE structure.
 * The resulting SIGNATURE contains the byte values, a mask indicating which bytes
 * are concrete and which are wildcards, and the total length of the pattern.
 * The pattern string can include spaces and is case-insensitive.
 * Example input: "48 8B ?? ?? ?? 48 85 C0 74 0E"
 *
 * @param Sig The pattern string to parse.
 * @return A SIGNATURE structure representing the parsed pattern.
 */
inline SIGNATURE ParseSignature(
    PCSTR Sig
)
{
    SIGNATURE Result = {0};

    const char* SigCursor = Sig;

    while (*SigCursor && Result.Length < MAX_PATTERN_LEN)
    {
        // Skip whitespace
        while (*SigCursor == ' ' || *SigCursor == '\t' || *SigCursor == '\r' || *SigCursor == '\n') SigCursor++;
        if (!*SigCursor) break;

        // Wildcards
        if (*SigCursor == '?')
        {
            Result.Bytes[Result.Length] = 0x00;
            Result.Mask[Result.Length]  = FALSE;
            Result.Length++;

            // Skip one or two '?'
            SigCursor++;
            if (*SigCursor == '?') SigCursor++;
            continue;
        }

        // Expect hex token (1–2 chars)
        CHAR Buf[3] = {0};
        Buf[0]      = *SigCursor++;
        if (*SigCursor && *SigCursor != ' ' && *SigCursor != '\t' && *SigCursor != '\r' && *SigCursor != '\n')
        {
            Buf[1] = *SigCursor++;
        }

        ULONG    Value  = 0;
        NTSTATUS Status = RtlCharToInteger(Buf, 16, &Value);
        if (NT_SUCCESS(Status))
        {
            Result.Bytes[Result.Length] = (UCHAR)Value;
            Result.Mask[Result.Length]  = TRUE;
            Result.Length++;
        }
    }

    return Result;
}

/**
 * @brief Scans a memory region for a specific byte pattern with wildcards.
 *
 * This function implements a pattern scanning algorithm that searches through a specified.
 * memory region for a byte pattern defined by the `Sign` parameter. The pattern can include
 * wildcards represented by '?' characters, which can match any byte value.
 * The algorithm (modified version of Horspool's) uses a skip table to optimize the search process,
 * allowing it to skip ahead in the memory region when a mismatch is found.
 *
 * @param[in] StartAddress The starting address of the memory region to scan.
 * @param[in] SearchSize The size of the memory region to scan, in bytes.
 * @param[in] Sign The pattern string to search for, using hexadecimal byte values and '?' as wildcards.
 * @return The address where the pattern is found, or 0 if not found.
 */
inline UINT64 PatternScan(
    _In_ UINT64 StartAddress,
    _In_ SIZE_T SearchSize,
    _In_ PCSTR  Sign
)
{
    if (StartAddress == 0 || SearchSize == 0)
    {
        return 0;
    }

    SIGNATURE Sig         = ParseSignature(Sign);
    SIZE_T    PatternSize = Sig.Length;

    if (PatternSize == 0 || SearchSize < PatternSize)
    {
        return 0;
    }

    // Default shift
    SIZE_T DefaultShift = PatternSize;
    for (SSIZE_T MaskIndex = (SSIZE_T)PatternSize - 2; MaskIndex >= 0; --MaskIndex)
    {
        if (!Sig.Mask[MaskIndex])
        {
            DefaultShift = PatternSize - 1 - (SIZE_T)MaskIndex;
            break;
        }
    }

    SIZE_T SkipTable[256];
    for (int SkipTableIndex = 0; SkipTableIndex < 256; SkipTableIndex++)
    {
        SkipTable[SkipTableIndex] = DefaultShift;
    }
    for (SIZE_T PatternIndex = 0; PatternIndex < PatternSize - 1; PatternIndex++)
    {
        if (Sig.Mask[PatternIndex])
        {
            SkipTable[Sig.Bytes[PatternIndex]] = min(PatternSize - 1 - PatternIndex, DefaultShift);
        }
    }

    uintptr_t CurrentAddress = StartAddress;
    uintptr_t EndAddress     = StartAddress + SearchSize - PatternSize;

    while (CurrentAddress <= EndAddress)
    {
        SSIZE_T ReverseIndex = (SSIZE_T)PatternSize - 1;

        while (ReverseIndex >= 0)
        {
            UCHAR MemByte = *(UCHAR*)(CurrentAddress + (uintptr_t)ReverseIndex);
            if (!Sig.Mask[ReverseIndex] || MemByte == Sig.Bytes[ReverseIndex])
            {
                ReverseIndex--;
            }
            else
            {
                break;
            }
        }

        if (ReverseIndex < 0)
        {
            return CurrentAddress; // match
        }

        UCHAR  LastByte = *(UCHAR*)(CurrentAddress + PatternSize - 1);
        SIZE_T Jump     = SkipTable[LastByte];
        CurrentAddress += Jump;
    }

    return 0;
}
