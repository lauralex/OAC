#pragma once
#include <ntdef.h>


/**
 * @brief Iterates through the system's active process list to validate a CR3 value.
 * @note This function MUST be called at PASSIVE_LEVEL.
 *
 * @param[in] CapturedCr3Value The CR3 value captured during the NMI.
 * @return TRUE if the CR3 is found in the list of active processes, FALSE otherwise.
 */
BOOLEAN IsCr3InProcessList(
    _In_ UINT64 CapturedCr3Value
);
