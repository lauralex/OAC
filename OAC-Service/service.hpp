#pragma once

#include <Windows.h>

#include "..\shared\oac_ipc.h"
#include "..\shared\protocol\oac_v5.h"

class ServiceHost final
{
public:
    explicit ServiceHost(HANDLE stopEvent) noexcept;
    ~ServiceHost();

    ServiceHost(const ServiceHost&) = delete;
    ServiceHost& operator=(const ServiceHost&) = delete;

    DWORD Start(OAC_SERVICE_FAILURE_STAGE& failureStage) noexcept;
    DWORD Wait() const noexcept;
    void Stop() noexcept;

private:
    static DWORD WINAPI PipeThreadEntry(void* context) noexcept;
    DWORD PipeLoop() noexcept;
    void SetFatalError(DWORD error) noexcept;

    HANDLE stopEvent_ = nullptr;
    HANDLE fatalEvent_ = nullptr;
    HANDLE targetReadyEvent_ = nullptr;
    HANDLE pipeThread_ = nullptr;
    HANDLE firstPipe_ = INVALID_HANDLE_VALUE;
    HANDLE driver_ = INVALID_HANDLE_VALUE;
    HANDLE targetJob_ = nullptr;
    HANDLE targetProcess_ = nullptr;
    volatile LONG stopped_ = FALSE;
    volatile LONG fatalError_ = ERROR_SUCCESS;
    ULONG driverVersion_ = 0;
    ULONGLONG driverCapabilities_ = 0;
    OAC_V5_SESSION_ID driverSessionId_{};
    ULONGLONG driverSessionGeneration_ = 0;
};
