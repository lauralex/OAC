#pragma once

#include <Windows.h>

#include <cstddef>
#include <string_view>

#include "..\shared\oac_ipc.h"
#include "..\shared\oac_policy.h"
#include "..\shared\protocol\oac_v5.h"
#include "backend.hpp"
#include "endpoint_preflight.hpp"
#include "manifest.hpp"
#include "policy.hpp"
#include "runtime_module.hpp"
#include "target_scanner.hpp"

class ServiceHost final
{
public:
    explicit ServiceHost(HANDLE stopEvent) noexcept;
    ~ServiceHost();

    ServiceHost(const ServiceHost&) = delete;
    ServiceHost& operator=(const ServiceHost&) = delete;

    DWORD Start(OAC_SERVICE_FAILURE_STAGE& failureStage) noexcept;
    DWORD Wait() noexcept;
    DWORD Stop() noexcept;

private:
    static DWORD WINAPI PipeThreadEntry(void* context) noexcept;
    DWORD PipeLoop() noexcept;
    DWORD PollEvidence() noexcept;
    DWORD PollEvidenceChannel(ULONG channel) noexcept;
    DWORD EvaluateAndQueueEvidence(
        OAC_V5_EVENT_RECORD& record,
        ULONG source) noexcept;
    DWORD AuthorizeRuntimeModule(OAC_V5_EVENT_RECORD& record) noexcept;
    DWORD QueueEndpointObservation(
        const oac::EndpointObservation& observation) noexcept;
    DWORD QueueObservation(
        OAC_V5_RULE_ID ruleId,
        OAC_V5_EVENT_TYPE eventType,
        OAC_V5_OBSERVATION_SEVERITY severity,
        OAC_V5_CATEGORY category,
        OAC_V5_SCAN_ID scanId,
        ULONGLONG processId,
        ULONGLONG threadId,
        ULONGLONG address,
        ULONGLONG auxiliary,
        ULONGLONG evidenceFlags,
        std::wstring_view text) noexcept;
    DWORD PollTargetObservations() noexcept;
    DWORD WaitForBackendAcknowledgement(
        ULONGLONG expectedSequence) noexcept;
    DWORD RunEndpointPreflight() noexcept;
    void SetFatalError(DWORD error) noexcept;

    HANDLE stopEvent_ = nullptr;
    HANDLE fatalEvent_ = nullptr;
    HANDLE targetReadyEvent_ = nullptr;
    HANDLE pipeThread_ = nullptr;
    HANDLE firstPipe_ = INVALID_HANDLE_VALUE;
    HANDLE driver_ = INVALID_HANDLE_VALUE;
    HANDLE targetJob_ = nullptr;
    HANDLE targetProcess_ = nullptr;
    HANDLE targetUserToken_ = nullptr;
    oac::BackendSession backend_;
    oac::TargetScanWorker targetScanner_;
    volatile LONG stopped_ = FALSE;
    volatile LONG stopError_ = ERROR_SUCCESS;
    volatile LONG fatalError_ = ERROR_SUCCESS;
    volatile LONG launchDenied_ = FALSE;
    volatile LONG launchInProgress_ = FALSE;
    volatile LONG activeManifestValid_ = FALSE;
    ULONG driverVersion_ = 0;
    ULONGLONG driverCapabilities_ = 0;
    OAC_V5_SESSION_ID driverSessionId_{};
    ULONGLONG driverSessionGeneration_ = 0;
    oac::VerifiedPolicy policy_{};
    oac::VerifiedGameManifest activeManifest_{};
    ULONGLONG alertCursor_ = 0;
    ULONGLONG eventCursor_ = 0;
    ULONGLONG serviceEvidenceSequence_ = 0;
    ULONGLONG serviceObservationSequence_ = 0;
};
