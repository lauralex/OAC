/**
 * @file wfp_monitor.h
 * @brief Provides an interface for the WFP-based network monitor.
 *
 * This module detects and blocks suspicious outbound socket connections.
 */
#pragma once
#include <ntddk.h>

/**
 * @brief Initializes the Windows Filtering Platform (WFP) components.
 *
 * Sets up the necessary filters and callouts to monitor outbound network connections.
 * This function must be called at PASSIVE_LEVEL, typically in DriverEntry.
 *
 * @param[in] DeviceObject Pointer to the device object (not used in this implementation).
 * @return STATUS_SUCCESS on success, otherwise an NTSTATUS error code.
 */
NTSTATUS InitializeWfpMonitor(
    _In_ PDEVICE_OBJECT DeviceObject
);


/**
 * @brief De-initializes the Windows Filtering Platform (WFP) components.
 *
 * Removes all filters and callouts, cleaning up any allocated resources.
 * This function must be called at PASSIVE_LEVEL, typically in the driver's
 * Unload routine.
 */
VOID DeinitializeWfpMonitor(VOID);
