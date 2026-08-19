#include <Windows.h>

#include <memory>

#include "service.hpp"
#include "..\shared\oac_ipc.h"

namespace
{
SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
SERVICE_STATUS g_Status{};
SRWLOCK g_StatusLock = SRWLOCK_INIT;
HANDLE g_StopEvent = nullptr;
volatile LONG g_StopRequested = FALSE;

void ReportStatus(
    DWORD state,
    DWORD win32Error,
    DWORD serviceError,
    DWORD waitHint) noexcept
{
    AcquireSRWLockExclusive(&g_StatusLock);
    g_Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_Status.dwCurrentState = state;
    g_Status.dwWin32ExitCode = win32Error;
    g_Status.dwServiceSpecificExitCode = serviceError;
    g_Status.dwWaitHint = waitHint;
    g_Status.dwControlsAccepted = state == SERVICE_RUNNING
        ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        : 0;
    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
        ++g_Status.dwCheckPoint;
    else
        g_Status.dwCheckPoint = 0;
    if (g_StatusHandle != nullptr)
        (void)SetServiceStatus(g_StatusHandle, &g_Status);
    ReleaseSRWLockExclusive(&g_StatusLock);
}

DWORD WINAPI ControlHandler(
    DWORD control,
    DWORD eventType,
    void* eventData,
    void* context) noexcept
{
    UNREFERENCED_PARAMETER(eventType);
    UNREFERENCED_PARAMETER(eventData);
    UNREFERENCED_PARAMETER(context);

    switch (control)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        if (InterlockedCompareExchange(&g_StopRequested, TRUE, FALSE) == FALSE)
        {
            ReportStatus(SERVICE_STOP_PENDING, ERROR_SUCCESS, 0, 10000);
            if (g_StopEvent != nullptr) SetEvent(g_StopEvent);
        }
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        AcquireSRWLockShared(&g_StatusLock);
        if (g_StatusHandle != nullptr)
            (void)SetServiceStatus(g_StatusHandle, &g_Status);
        ReleaseSRWLockShared(&g_StatusLock);
        return NO_ERROR;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI ServiceMain(DWORD argumentCount, wchar_t** arguments) noexcept
{
    g_StatusHandle = RegisterServiceCtrlHandlerExW(
        OAC_SERVICE_NAME,
        ControlHandler,
        nullptr);
    if (g_StatusHandle == nullptr) return;

    g_Status = {};
    g_Status.dwCheckPoint = 0;
    InterlockedExchange(&g_StopRequested, FALSE);
    ReportStatus(SERVICE_START_PENDING, ERROR_SUCCESS, 0, 10000);

    DWORD result = ERROR_SUCCESS;
    OAC_SERVICE_FAILURE_STAGE failureStage = OAC_SERVICE_STAGE_BOOTSTRAP;
    if (argumentCount == 0 || arguments == nullptr || arguments[0] == nullptr ||
        _wcsicmp(arguments[0], OAC_SERVICE_NAME) != 0)
    {
        result = ERROR_INVALID_NAME;
    }
    else
    {
        g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (g_StopEvent == nullptr)
            result = GetLastError();
        else if (InterlockedCompareExchange(
                     &g_StopRequested, FALSE, FALSE) != FALSE)
            SetEvent(g_StopEvent);
    }

    if (result == ERROR_SUCCESS)
    {
        try
        {
            auto host = std::make_unique<ServiceHost>(g_StopEvent);
            result = host->Start(failureStage);
            if (result == ERROR_SUCCESS)
            {
                ReportStatus(SERVICE_RUNNING, ERROR_SUCCESS, 0, 0);
                result = host->Wait();
                if (result != ERROR_SUCCESS && result != ERROR_OPERATION_ABORTED)
                    failureStage = OAC_SERVICE_STAGE_RUNTIME;
                if (InterlockedCompareExchange(&g_StopRequested, TRUE, FALSE) == FALSE)
                    ReportStatus(SERVICE_STOP_PENDING, ERROR_SUCCESS, 0, 10000);
            }
            const DWORD stopResult = host->Stop();
            if ((result == ERROR_SUCCESS || result == ERROR_OPERATION_ABORTED) &&
                stopResult != ERROR_SUCCESS)
            {
                result = stopResult;
                failureStage = OAC_SERVICE_STAGE_RUNTIME;
            }
        }
        catch (const std::bad_alloc&)
        {
            result = ERROR_NOT_ENOUGH_MEMORY;
        }
        catch (...)
        {
            result = ERROR_UNHANDLED_EXCEPTION;
        }
    }

    if (g_StopEvent != nullptr)
    {
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
    }
    if (result == ERROR_OPERATION_ABORTED &&
        InterlockedCompareExchange(&g_StopRequested, FALSE, FALSE) != FALSE)
        result = ERROR_SUCCESS;
    const DWORD serviceError = OacEncodeServiceFailure(failureStage, result);
    const DWORD win32Error = serviceError != 0
        ? ERROR_SERVICE_SPECIFIC_ERROR
        : result;
    ReportStatus(SERVICE_STOPPED, win32Error, serviceError, 0);
}
} // namespace

int wmain()
{
    SERVICE_TABLE_ENTRYW table[] =
    {
        {const_cast<wchar_t*>(OAC_SERVICE_NAME), ServiceMain},
        {nullptr, nullptr}
    };
    if (!StartServiceCtrlDispatcherW(table))
        return static_cast<int>(GetLastError());
    return 0;
}
