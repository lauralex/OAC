#pragma once

#include <Windows.h>

#include <cstddef>

#include "..\shared\oac_ipc.h"
#include "..\shared\oac_policy.h"
#include "..\shared\protocol\oac_v5.h"
#include "backend.hpp"
#include "policy.hpp"
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
    ULONG driverVersion_ = 0;
    ULONGLONG driverCapabilities_ = 0;
    OAC_V5_SESSION_ID driverSessionId_{};
    ULONGLONG driverSessionGeneration_ = 0;
    oac::VerifiedPolicy policy_{};
    ULONGLONG alertCursor_ = 0;
    ULONGLONG eventCursor_ = 0;
    ULONGLONG serviceEvidenceSequence_ = 0;
};
