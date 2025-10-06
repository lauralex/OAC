#include "internals.h"

PLIST_ENTRY PsActiveProcessHead = NULL;

/**
 * @brief Initializes the PsActiveProcessHead pointer by locating it in memory.
 *
 * This function should be called at driver initialization time, at PASSIVE_LEVEL.
 * It attempts to locate the PsActiveProcessHead symbol in the kernel and assigns
 * its address to the global variable. If it cannot be found, the variable remains NULL.
 */
static VOID InitializePsActiveProcessHead(VOID)
{
    PsActiveProcessHead = *(PLIST_ENTRY*)(PsSiloContextPagedType + 1);
}

/**
 * @brief Initializes internal structures and pointers used by the driver.
 *
 * This function should be called at driver initialization time, at PASSIVE_LEVEL.
 * It sets up any necessary internal state required for the driver's operation.
 */
VOID InitializeInternals(VOID)
{
    InitializePsActiveProcessHead();
}
