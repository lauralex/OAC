/**
 * @file wfp_monitor.c
 * @brief Implementation of a WFP-based network connection monitor.
 */
#include "wfp_monitor.h"
#include "arch.h"
#include "serial_logger.h"
#include "shellcode_analyzer.h"

#include <initguid.h>
#include <ndis/nbl.h>
#pragma warning(push)
#pragma warning(disable : 4201) // nameless struct/union
#include <fwpsk.h> // WFP Classify/Callout APIs
#include <fwpmk.h> // WFP Management APIs
#pragma warning(pop)
#include <intrin.h>

// Undocumented function to get a process object from its PID.
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE      ProcessId,
    _Out_ PEPROCESS* Process
);

// Undocumented function to get the image file name of a process.
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);

//
// === Global WFP Variables ===
//
HANDLE G_WfpEngineHandle = NULL;
UINT32 G_WfpV4CalloutId  = 0;
UINT32 G_WfpV6CalloutId  = 0;
UINT64 G_WfpV4FilterId   = 0;
UINT64 G_WfpV6FilterId   = 0;

//
// === GUIDs for our WFP objects ===
// These unique identifiers are used to register our driver's components with WFP.
//
// {0BECACC2-5FF9-405E-BB0F-C725A36BDB96}
DEFINE_GUID(WFP_CONNECT_CALLOUT_V4_GUID, 0xbecacc2, 0x5ff9, 0x405e, 0xbb, 0xf, 0xc7, 0x25, 0xa3, 0x6b, 0xdb, 0x96);

// {5AB6A196-7F28-4388-8CCC-1B31B48F8E36}
DEFINE_GUID(WFP_CONNECT_CALLOUT_V6_GUID, 0x5ab6a196, 0x7f28, 0x4388, 0x8c, 0xcc, 0x1b, 0x31, 0xb4, 0x8f, 0x8e, 0x36);

// {B3E288B1-1FDA-4107-B841-DCA732579515}
DEFINE_GUID(WFP_SUBLAYER_GUID, 0xb3e288b1, 0x1fda, 0x4107, 0xb8, 0x41, 0xdc, 0xa7, 0x32, 0x57, 0x95, 0x15);


//
// == Forward Declarations ==
//
VOID NTAPI WfpConnectCallout(
    _In_ const FWPS_INCOMING_VALUES0*          InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID*                          LayerData,
    _In_ const FWPS_FILTER0*                   Filter,
    _In_ UINT64                                FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0*                ClassifyOut
);

NTSTATUS NTAPI WfpNotifyCallback(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID*              FilterKey,
    _Inout_ FWPS_FILTER0*         Filter
);


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
)
{
    NTSTATUS          Status         = STATUS_SUCCESS;
    FWPM_SUBLAYER0    SubLayer       = {0};
    FWPS_CALLOUT0     Callout        = {0};
    FWPM_CALLOUT0     MCallout       = {0};
    FWPM_FILTER0      Filter         = {0};
    FWPM_DISPLAY_DATA DisplayData    = {0};
    BOOLEAN           InTransaction  = FALSE;
    BOOLEAN           EngineOpened   = FALSE;
    BOOLEAN           CalloutV4Added = FALSE;
    BOOLEAN           CalloutV6Added = FALSE;


    // Open a session to the WFP Base Filtering Engine (BFE)
    Status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &G_WfpEngineHandle);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[-] Failed to open WFP engine handle: 0x%X\n", Status);
        goto Exit;
    }
    EngineOpened = TRUE;

    // Begin a transaction. All WFP object additions should be atomic.
    Status = FwpmTransactionBegin0(G_WfpEngineHandle, 0);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[-] Failed to begin WFP transaction: 0x%X\n", Status);
        goto Exit;
    }
    InTransaction = TRUE;

    // --- Register a custom sublayer for our filters ---
    SubLayer.subLayerKey             = WFP_SUBLAYER_GUID;
    SubLayer.displayData.name        = L"OAC Driver Sub-Layer";
    SubLayer.displayData.description = L"Sub-Layer for OAC Driver Network Filters";
    SubLayer.flags                   = 0;
    SubLayer.weight                  = FWP_EMPTY; // Use default weight.
    Status                           = FwpmSubLayerAdd0(G_WfpEngineHandle, &SubLayer, NULL);
    if (!NT_SUCCESS(Status) && Status != STATUS_FWP_ALREADY_EXISTS)
    {
        DbgPrint("[-] Failed to add WFP sublayer: 0x%X\n", Status);
        goto Exit;
    }

    // --- Register our callout functions with WFP ---
    DisplayData.name        = L"OAC Driver Connect Callout";
    DisplayData.description = L"Monitors and blocks suspicious outbound connections";

    // IPv4 Callout Registration
    Callout.calloutKey = WFP_CONNECT_CALLOUT_V4_GUID;
    //Callout.flags      = FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW;
    Callout.classifyFn = WfpConnectCallout;
    Callout.notifyFn   = WfpNotifyCallback;

    Status = FwpsCalloutRegister0(DeviceObject, &Callout, &G_WfpV4CalloutId);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[-] Failed to register WFP IPv4 callout: 0x%X\n", Status);
        goto Exit;
    }
    CalloutV4Added = TRUE;

    MCallout.calloutKey      = WFP_CONNECT_CALLOUT_V4_GUID;
    MCallout.displayData     = DisplayData;
    MCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    Status                   = FwpmCalloutAdd0(G_WfpEngineHandle, &MCallout, NULL, NULL);
    if (!NT_SUCCESS(Status) && Status != STATUS_FWP_ALREADY_EXISTS)
    {
        DbgPrint("[-] Failed to add WFP IPv4 callout metadata: 0x%X\n", Status);
        goto Exit;
    }

    // IPv6 Callout Registration
    Callout.calloutKey = WFP_CONNECT_CALLOUT_V6_GUID;
    Status             = FwpsCalloutRegister0(DeviceObject, &Callout, &G_WfpV6CalloutId);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[-] Failed to register WFP IPv6 callout: 0x%X\n", Status);
        goto Exit;
    }
    CalloutV6Added = TRUE;

    MCallout.calloutKey      = WFP_CONNECT_CALLOUT_V6_GUID;
    MCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    Status                   = FwpmCalloutAdd0(G_WfpEngineHandle, &MCallout, NULL, NULL);
    if (!NT_SUCCESS(Status) && Status != STATUS_FWP_ALREADY_EXISTS)
    {
        DbgPrint("[-] Failed to add WFP IPv6 callout metadata: 0x%X\n", Status);
        goto Exit;
    }

    // --- Create filters to direct traffic to our callouts ---
    Filter.displayData.name        = L"OAC Driver Connect Filter";
    Filter.displayData.description = L"Intercepts all outbound TCP connection attempts";
    Filter.subLayerKey             = WFP_SUBLAYER_GUID;
    Filter.weight.type             = FWP_UINT8;
    Filter.weight.uint8            = 0xF;                            // High weight to ensure it's evaluated
    Filter.action.type             = FWP_ACTION_CALLOUT_TERMINATING; // Pass traffic to our callout

    // IPv4 Filter
    Filter.layerKey          = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    Filter.action.calloutKey = WFP_CONNECT_CALLOUT_V4_GUID;
    Status                   = FwpmFilterAdd0(G_WfpEngineHandle, &Filter, NULL, &G_WfpV4FilterId);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[-] Failed to add WFP IPv4 filter: 0x%X\n", Status);
        goto Exit;
    }

    // IPv6 Filter
    Filter.layerKey          = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    Filter.action.calloutKey = WFP_CONNECT_CALLOUT_V6_GUID;
    Status                   = FwpmFilterAdd0(G_WfpEngineHandle, &Filter, NULL, &G_WfpV6FilterId);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[-] Failed to add WFP IPv6 filter: 0x%X\n", Status);
        goto Exit;
    }


    // Commit the transaction to apply all our changes.
    Status = FwpmTransactionCommit0(G_WfpEngineHandle);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[-] Failed to commit WFP transaction: 0x%X\n", Status);
        goto Exit;
    }
    InTransaction = FALSE; // Transaction is committed.

    DbgPrint("[+] WFP monitor initialized successfully.\n");

Exit:
    if (!NT_SUCCESS(Status))
    {
        if (InTransaction)
        {
            NTSTATUS CleanStatus = FwpmTransactionAbort0(G_WfpEngineHandle);
            if (!NT_SUCCESS(CleanStatus))
            {
                DbgPrint("[-] Failed to abort WFP transaction: 0x%X\n", CleanStatus);
            }
            else
            {
                DbgPrint("[*] WFP transaction aborted due to error.\n");
            }
        }
        if (CalloutV4Added)
        {
            NTSTATUS CleanStatus = FwpsCalloutUnregisterById0(G_WfpV4CalloutId);
            if (!NT_SUCCESS(CleanStatus))
            {
                DbgPrint("[-] Failed to unregister WFP IPv4 callout: 0x%X\n", CleanStatus);
            }
            else
            {
                DbgPrint("[*] WFP IPv4 callout unregistered due to error.\n");
            }
        }
        if (CalloutV6Added)
        {
            NTSTATUS CleanStatus = FwpsCalloutUnregisterById0(G_WfpV6CalloutId);
            if (!NT_SUCCESS(CleanStatus))
            {
                DbgPrint("[-] Failed to unregister WFP IPv6 callout: 0x%X\n", CleanStatus);
            }
            else
            {
                DbgPrint("[*] WFP IPv6 callout unregistered due to error.\n");
            }
        }
        if (EngineOpened)
        {
            // --- TRANSACTION BEGIN ---
            if (!NT_SUCCESS(FwpmTransactionBegin0(G_WfpEngineHandle, 0)))
                DbgPrint("[-] Failed to begin WFP cleanup transaction.\n");

            if (!NT_SUCCESS(FwpmFilterDeleteById0(G_WfpEngineHandle, G_WfpV4FilterId)))
                DbgPrint("[-] Failed to delete WFP IPv4 filter during cleanup.\n");
            if (!NT_SUCCESS(FwpmFilterDeleteById0(G_WfpEngineHandle, G_WfpV6FilterId)))
                DbgPrint("[-] Failed to delete WFP IPv6 filter during cleanup.\n");
            if (!NT_SUCCESS(FwpmCalloutDeleteById0(G_WfpEngineHandle, G_WfpV4CalloutId)))
                DbgPrint("[-] Failed to delete WFP IPv4 callout during cleanup.\n");
            if (!NT_SUCCESS(FwpmCalloutDeleteById0(G_WfpEngineHandle, G_WfpV6CalloutId)))
                DbgPrint("[-] Failed to delete WFP IPv6 callout during cleanup.\n");
            if (!NT_SUCCESS(FwpmSubLayerDeleteByKey0(G_WfpEngineHandle, &WFP_SUBLAYER_GUID)))
                DbgPrint("[-] Failed to delete WFP sublayer during cleanup.\n");

            if (!NT_SUCCESS(FwpmTransactionCommit0(G_WfpEngineHandle)))
                DbgPrint("[-] Failed to commit WFP cleanup transaction.\n");
            // --- TRANSACTION END ---

            FwpmEngineClose0(G_WfpEngineHandle);
            G_WfpV4CalloutId  = 0;
            G_WfpV6CalloutId  = 0;
            G_WfpEngineHandle = NULL;
            DbgPrint("[*] WFP engine handle closed due to error.\n");
        }
    }
    return Status;
}


/**
 * @brief De-initializes the Windows Filtering Platform (WFP) components.
 *
 * Removes all filters and callouts, cleaning up any allocated resources.
 * This function must be called at PASSIVE_LEVEL, typically in the driver's
 * Unload routine.
 */
VOID DeinitializeWfpMonitor(VOID)
{
    if (G_WfpV4CalloutId)
    {
        NTSTATUS ClearStatus = FwpsCalloutUnregisterById0(G_WfpV4CalloutId);
        if (!NT_SUCCESS(ClearStatus))
        {
            DbgPrint("[-] Failed to unregister WFP IPv4 callout: 0x%X\n", ClearStatus);
        }
        else
        {
            DbgPrint("[*] WFP IPv4 callout unregistered.\n");
        }
    }
    if (G_WfpV6CalloutId)
    {
        NTSTATUS ClearStatus = FwpsCalloutUnregisterById0(G_WfpV6CalloutId);
        if (!NT_SUCCESS(ClearStatus))
        {
            DbgPrint("[-] Failed to unregister WFP IPv6 callout: 0x%X\n", ClearStatus);
        }
        else
        {
            DbgPrint("[+] WFP IPv6 callout unregistered.\n");
        }
    }

    if (G_WfpEngineHandle)
    {
        // --- TRANSACTION BEGIN ---
        if (!NT_SUCCESS(FwpmTransactionBegin0(G_WfpEngineHandle, 0)))
            DbgPrint("[-] Failed to begin WFP cleanup transaction.\n");

        if (!NT_SUCCESS(FwpmFilterDeleteById0(G_WfpEngineHandle, G_WfpV4FilterId)))
            DbgPrint("[-] Failed to delete WFP IPv4 filter during cleanup.\n");
        if (!NT_SUCCESS(FwpmFilterDeleteById0(G_WfpEngineHandle, G_WfpV6FilterId)))
            DbgPrint("[-] Failed to delete WFP IPv6 filter during cleanup.\n");
        if (!NT_SUCCESS(FwpmCalloutDeleteById0(G_WfpEngineHandle, G_WfpV4CalloutId)))
            DbgPrint("[-] Failed to delete WFP IPv4 callout during cleanup.\n");
        if (!NT_SUCCESS(FwpmCalloutDeleteById0(G_WfpEngineHandle, G_WfpV6CalloutId)))
            DbgPrint("[-] Failed to delete WFP IPv6 callout during cleanup.\n");
        if (!NT_SUCCESS(FwpmSubLayerDeleteByKey0(G_WfpEngineHandle, &WFP_SUBLAYER_GUID)))
            DbgPrint("[-] Failed to delete WFP sublayer during cleanup.\n");

        if (!NT_SUCCESS(FwpmTransactionCommit0(G_WfpEngineHandle)))
            DbgPrint("[-] Failed to commit WFP cleanup transaction.\n");
        // --- TRANSACTION END ---

        FwpmEngineClose0(G_WfpEngineHandle);
        G_WfpV4CalloutId  = 0;
        G_WfpV6CalloutId  = 0;
        G_WfpEngineHandle = NULL;
        DbgPrint("[+] WFP engine handle closed.\n");
    }
}


/**
 * @brief The callout function that inspects each outbound connection.
 *
 * This function is invoked by WFP for each outbound connection attempt.
 * 
 * @note This function runs at IRQL = DISPATCH_LEVEL.
 */
VOID NTAPI WfpConnectCallout(
    _In_ const FWPS_INCOMING_VALUES0*          InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID*                          LayerData,
    _In_ const FWPS_FILTER0*                   Filter,
    _In_ UINT64                                FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0*                ClassifyOut
)
{
    UNREFERENCED_PARAMETER(InFixedValues);
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    DbgPrint("[+] WfpConnectCallout invoked.\n");

    // By default, we permit the connection unless we find a reason to block it.
    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    // We need the process and thread ID to perform our analysis.
    HANDLE ProcessId = (HANDLE)InMetaValues->processId;

    HANDLE ThreadId = PsGetCurrentThreadId();

    if (ProcessId == 0 || ThreadId == 0)
    {
        DbgPrint("[-] Unable to retrieve ProcessId or ThreadId. Permitting connection.\n");
        return; // Not enough info, permit.
    }

    // --- PAYLOAD DETECTION HEURISTIC: Analyze the user-mode call stack ---
    if (AnalyzeThreadForShellcode(ProcessId, ThreadId))
    {
        SerialLoggerWrite("Shellcode detected in process %p, thread %p. Blocking connection.", ProcessId, ThreadId);
        // The analyzer found evidence of shellcode. Block the connection.
        DbgPrint("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        DbgPrint("!!! REVERSE SHELL SHELLCODE DETECTED! BLOCKING OUTBOUND CONNECTION.\n");
        DbgPrint("!!! Process ID: %p\n", ProcessId);
        DbgPrint("!!! Thread ID:  %p\n", ThreadId);
        DbgPrint("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE; // Prevent further modification.
    }
}


/**
 * @brief A callback for handling notifications related to our client.
 */
NTSTATUS NTAPI WfpNotifyCallback(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID*              FilterKey,
    _Inout_ FWPS_FILTER0*         Filter
)
{
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);

    // This function is required for callout registration, but we don't need
    // to handle any notifications for this simple filter.
    if (NotifyType == FWPS_CALLOUT_NOTIFY_DELETE_FILTER)
    {
        DbgPrint("[+] WFP filter deleted.\n");
    }

    return STATUS_SUCCESS;
}
