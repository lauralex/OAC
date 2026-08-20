#include <Windows.h>
#include <bcrypt.h>

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "..\shared\oac_ipc.h"
#include "..\shared\oac_windows.hpp"
#include "..\shared\protocol\oac_v5.h"

namespace
{
using oac::UniqueHandle;
using oac::UniqueServiceHandle;

constexpr DWORD kRequestTimeoutMs = 5000;

std::wstring ErrorText(DWORD error)
{
    wchar_t* raw = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<wchar_t*>(&raw),
        0,
        nullptr);
    std::wstring text = length != 0 && raw != nullptr
        ? std::wstring(raw, length)
        : L"Win32 error " + std::to_wstring(error);
    if (raw != nullptr) LocalFree(raw);
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n'))
        text.pop_back();
    return text;
}

bool MakeRequestId(ULONGLONG& requestId)
{
    requestId = 0;
    const NTSTATUS status = BCryptGenRandom(
        nullptr,
        reinterpret_cast<PUCHAR>(&requestId),
        static_cast<ULONG>(sizeof(requestId)),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(status) && requestId != 0;
}

bool EnsureServiceRunning(
    DWORD& error,
    OAC_SERVICE_FAILURE_STAGE& failureStage)
{
    failureStage = OAC_SERVICE_STAGE_NONE;
    UniqueServiceHandle manager(OpenSCManagerW(
        nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager)
    {
        error = GetLastError();
        return false;
    }
    UniqueServiceHandle service(OpenServiceW(
        manager.get(),
        OAC_SERVICE_NAME,
        SERVICE_QUERY_STATUS | SERVICE_START));
    if (!service)
    {
        error = GetLastError();
        return false;
    }

    constexpr ULONGLONG timeoutMs = 10000;
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    bool startAttempted = false;
    for (;;)
    {
        SERVICE_STATUS_PROCESS status{};
        DWORD returned = 0;
        if (!QueryServiceStatusEx(
                service.get(),
                SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE*>(&status),
                static_cast<DWORD>(sizeof(status)),
                &returned) || returned != sizeof(status))
        {
            error = GetLastError();
            if (error == ERROR_SUCCESS) error = ERROR_INVALID_DATA;
            return false;
        }
        if (status.dwServiceType != SERVICE_WIN32_OWN_PROCESS)
        {
            error = ERROR_SERVICE_NOT_FOUND;
            return false;
        }
        if (status.dwCurrentState == SERVICE_RUNNING) return true;
        if (status.dwCurrentState == SERVICE_STOPPED && !startAttempted)
        {
            startAttempted = true;
            if (!StartServiceW(service.get(), 0, nullptr))
            {
                error = GetLastError();
                if (error != ERROR_SERVICE_ALREADY_RUNNING) return false;
            }
        }
        else if (status.dwCurrentState != SERVICE_START_PENDING)
        {
            if (status.dwWin32ExitCode == ERROR_SERVICE_SPECIFIC_ERROR)
            {
                uint32_t stage = 0;
                uint32_t decodedError = 0;
                if (!OacDecodeServiceFailure(
                        status.dwServiceSpecificExitCode,
                        &stage,
                        &decodedError))
                {
                    error = ERROR_INVALID_DATA;
                    return false;
                }
                failureStage =
                    static_cast<OAC_SERVICE_FAILURE_STAGE>(stage);
                error = decodedError;
            }
            else
            {
                error = status.dwWin32ExitCode != ERROR_SUCCESS
                    ? status.dwWin32ExitCode
                    : ERROR_SERVICE_NOT_ACTIVE;
            }
            return false;
        }

        const ULONGLONG now = GetTickCount64();
        if (now >= deadline)
        {
            error = ERROR_TIMEOUT;
            return false;
        }
        DWORD delay = status.dwWaitHint == 0
            ? 100
            : status.dwWaitHint / 10;
        if (delay < 50) delay = 50;
        if (delay > 250) delay = 250;
        Sleep(delay);
    }
}

const wchar_t* ServiceStageText(OAC_SERVICE_FAILURE_STAGE stage) noexcept
{
    switch (stage)
    {
    case OAC_SERVICE_STAGE_BOOTSTRAP: return L"bootstrap";
    case OAC_SERVICE_STAGE_IDENTITY: return L"identity validation";
    case OAC_SERVICE_STAGE_DRIVER_OPEN: return L"driver open";
    case OAC_SERVICE_STAGE_DRIVER_NEGOTIATE: return L"driver negotiation";
    case OAC_SERVICE_STAGE_DRIVER_CLAIM: return L"driver session claim";
    case OAC_SERVICE_STAGE_DRIVER_STATUS: return L"driver status validation";
    case OAC_SERVICE_STAGE_PIPE_CREATE: return L"control-pipe creation";
    case OAC_SERVICE_STAGE_PIPE_THREAD: return L"control worker startup";
    case OAC_SERVICE_STAGE_RUNTIME: return L"control worker runtime";
    case OAC_SERVICE_STAGE_TARGET_JOB: return L"target job initialization";
    case OAC_SERVICE_STAGE_BACKEND: return L"backend session initialization";
    default: return L"unknown stage";
    }
}

const wchar_t* LaunchStageText(uint32_t stage) noexcept
{
    switch (stage)
    {
    case OAC_IPC_LAUNCH_STAGE_AUTHORIZE_CLIENT:
        return L"client authorization";
    case OAC_IPC_LAUNCH_STAGE_OPEN_EXECUTABLE:
        return L"executable validation";
    case OAC_IPC_LAUNCH_STAGE_CREATE_ENVIRONMENT:
        return L"environment creation";
    case OAC_IPC_LAUNCH_STAGE_ARM_TICKET:
        return L"launch authorization";
    case OAC_IPC_LAUNCH_STAGE_CREATE_PROCESS:
        return L"target creation";
    case OAC_IPC_LAUNCH_STAGE_CONFIRM_TARGET:
        return L"target confirmation";
    case OAC_IPC_LAUNCH_STAGE_VALIDATE_STATUS:
        return L"driver status validation";
    case OAC_IPC_LAUNCH_STAGE_ASSIGN_JOB:
        return L"target job assignment";
    case OAC_IPC_LAUNCH_STAGE_RESUME_THREAD:
        return L"target resume";
    case OAC_IPC_LAUNCH_STAGE_VERIFY_MANIFEST:
        return L"manifest verification";
    default:
        return L"unknown launch stage";
    }
}

const wchar_t* LaunchDetailText(uint32_t detail) noexcept
{
    switch (detail)
    {
    case OAC_IPC_LAUNCH_DETAIL_STATUS_UNAVAILABLE:
        return L"driver status unavailable";
    case OAC_IPC_LAUNCH_DETAIL_CANCELLED:
        return L"ticket cancelled";
    case OAC_IPC_LAUNCH_DETAIL_EXPIRED:
        return L"ticket expired";
    case OAC_IPC_LAUNCH_DETAIL_PATH_MISMATCH:
        return L"executable path mismatch";
    case OAC_IPC_LAUNCH_DETAIL_CONFIRMATION_FAILED:
        return L"process identity mismatch";
    case OAC_IPC_LAUNCH_DETAIL_REQUESTED:
        return L"driver session explicitly revoked";
    case OAC_IPC_LAUNCH_DETAIL_FILE_CLEANUP:
        return L"driver handle cleaned up";
    case OAC_IPC_LAUNCH_DETAIL_SERVICE_EXIT:
        return L"service process exited";
    case OAC_IPC_LAUNCH_DETAIL_TARGET_EXIT:
        return L"target exited during creation";
    case OAC_IPC_LAUNCH_DETAIL_POLICY:
        return L"signed policy denied the launch";
    case OAC_IPC_LAUNCH_DETAIL_EVIDENCE_LOSS:
        return L"driver evidence loss";
    case OAC_IPC_LAUNCH_DETAIL_DRIVER_STOP:
        return L"driver stopped";
    case OAC_IPC_LAUNCH_DETAIL_OTHER_REVOCATION:
        return L"driver session revoked";
    case OAC_IPC_LAUNCH_DETAIL_MANIFEST_MISSING:
        return L"game manifest is missing";
    case OAC_IPC_LAUNCH_DETAIL_MANIFEST_INVALID:
        return L"game manifest is malformed";
    case OAC_IPC_LAUNCH_DETAIL_MANIFEST_SIGNATURE:
        return L"game manifest signature is invalid";
    case OAC_IPC_LAUNCH_DETAIL_MANIFEST_BUILD:
        return L"executable identity does not match the game manifest";
    case OAC_IPC_LAUNCH_DETAIL_MANIFEST_EXPIRED:
        return L"game manifest is outside its validity period";
    case OAC_IPC_LAUNCH_DETAIL_MANIFEST_ROLLBACK:
        return L"game manifest was superseded or changed without a new sequence";
    case OAC_IPC_LAUNCH_DETAIL_BACKEND:
        return L"backend lease does not permit a launch";
    default:
        return L"";
    }
}

bool VerifyPipeServer(HANDLE pipe, DWORD& serverProcessId, DWORD& error)
{
    ULONG pipeProcessId = 0;
    ULONG pipeSessionId = MAXDWORD;
    if (!GetNamedPipeServerProcessId(pipe, &pipeProcessId) ||
        !GetNamedPipeServerSessionId(pipe, &pipeSessionId))
    {
        error = GetLastError();
        return false;
    }
    if (pipeProcessId == 0 || pipeSessionId != 0)
    {
        error = ERROR_ACCESS_DENIED;
        return false;
    }

    UniqueServiceHandle manager(OpenSCManagerW(
        nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager)
    {
        error = GetLastError();
        return false;
    }
    UniqueServiceHandle service(OpenServiceW(
        manager.get(), OAC_SERVICE_NAME, SERVICE_QUERY_STATUS));
    if (!service)
    {
        error = GetLastError();
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD returned = 0;
    if (!QueryServiceStatusEx(
            service.get(),
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<BYTE*>(&status),
            static_cast<DWORD>(sizeof(status)),
            &returned))
    {
        error = GetLastError();
        return false;
    }
    if (returned != sizeof(status) ||
        status.dwServiceType != SERVICE_WIN32_OWN_PROCESS ||
        status.dwCurrentState != SERVICE_RUNNING ||
        status.dwProcessId != pipeProcessId)
    {
        error = ERROR_SERVICE_NOT_ACTIVE;
        return false;
    }

    serverProcessId = pipeProcessId;
    return true;
}

DWORD ConnectService(
    UniqueHandle& pipe,
    DWORD& serverProcessId,
    OAC_SERVICE_FAILURE_STAGE& failureStage)
{
    DWORD error = ERROR_SUCCESS;
    if (!EnsureServiceRunning(error, failureStage)) return error;
    if (!WaitNamedPipeW(OAC_PIPE_NAME, 5000))
        return GetLastError();

    pipe.reset(CreateFileW(
        OAC_PIPE_NAME,
        static_cast<DWORD>(OAC_PIPE_CLIENT_ACCESS),
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED |
            SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
        nullptr));
    if (!pipe) return GetLastError();

    if (!VerifyPipeServer(pipe.get(), serverProcessId, error)) return error;

    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(pipe.get(), &mode, nullptr, nullptr))
        return GetLastError();
    return ERROR_SUCCESS;
}

DWORD TransactService(
    HANDLE pipe,
    const void* request,
    DWORD requestSize,
    void* response,
    DWORD responseSize,
    DWORD& returned)
{
    returned = 0;
    UniqueHandle requestEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!requestEvent) return GetLastError();
    OVERLAPPED overlapped{};
    overlapped.hEvent = requestEvent.get();
    if (TransactNamedPipe(
            pipe,
            const_cast<void*>(request),
            requestSize,
            response,
            responseSize,
            &returned,
            &overlapped))
    {
        return ERROR_SUCCESS;
    }

    DWORD error = GetLastError();
    if (error != ERROR_IO_PENDING) return error;
    const DWORD wait = WaitForSingleObject(requestEvent.get(), kRequestTimeoutMs);
    if (wait != WAIT_OBJECT_0)
    {
        error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
        (void)CancelIoEx(pipe, &overlapped);
        (void)GetOverlappedResult(pipe, &overlapped, &returned, TRUE);
        return error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error;
    }
    if (!GetOverlappedResult(pipe, &overlapped, &returned, FALSE))
        return GetLastError();
    return ERROR_SUCCESS;
}

int SendRequest(ULONG requestType)
{
    UniqueHandle pipe;
    DWORD serverProcessId = 0;
    OAC_SERVICE_FAILURE_STAGE failureStage = OAC_SERVICE_STAGE_NONE;
    const DWORD connectionError = ConnectService(
        pipe,
        serverProcessId,
        failureStage);
    if (connectionError != ERROR_SUCCESS)
    {
        std::wcerr << L"OACService connection failed";
        if (failureStage != OAC_SERVICE_STAGE_NONE)
            std::wcerr << L" during " << ServiceStageText(failureStage);
        std::wcerr << L": " << ErrorText(connectionError) << L'\n';
        return 3;
    }

    OAC_IPC_REQUEST request{};
    request.Header.Version = OAC_IPC_VERSION;
    request.Header.Size = static_cast<uint32_t>(sizeof(request));
    request.Header.Type = requestType;
    if (!MakeRequestId(request.Header.RequestId))
    {
        std::wcerr << L"Could not create an IPC request identifier.\n";
        return 3;
    }

    OAC_IPC_RESPONSE response{};
    DWORD returned = 0;
    const DWORD transactionError = TransactService(
        pipe.get(),
        &request,
        static_cast<DWORD>(sizeof(request)),
        &response,
        static_cast<DWORD>(sizeof(response)),
        returned);
    if (transactionError != ERROR_SUCCESS)
    {
        std::wcerr << L"OACService request failed: "
                   << ErrorText(transactionError) << L'\n';
        return 3;
    }

    const ULONG expectedType = requestType == OAC_IPC_TYPE_HELLO_REQUEST
        ? OAC_IPC_TYPE_HELLO_RESPONSE
        : OAC_IPC_TYPE_STATUS_RESPONSE;
    constexpr ULONG knownStatusFlags = OAC_IPC_STATUS_DRIVER_READY |
        OAC_IPC_STATUS_SESSION_CLAIMED |
        OAC_IPC_STATUS_PRIOR_SESSION_LOSS |
        OAC_IPC_STATUS_SCANNER_ACTIVE;
    if (!OacIpcHeaderMatches(
            &response.Header,
            returned,
            static_cast<uint32_t>(sizeof(response)),
            expectedType) ||
        response.Header.RequestId != request.Header.RequestId ||
        (response.StatusFlags & ~knownStatusFlags) != 0)
    {
        std::wcerr << L"OACService returned an invalid IPC response.\n";
        return 4;
    }

    if (response.Win32Error != ERROR_SUCCESS)
    {
        if (response.StatusFlags != 0 || response.ServiceProcessId != 0 ||
            response.ClientProcessId != 0 || response.ClientSessionId != 0 ||
            response.DriverProtocolVersion != 0 ||
            response.DriverCapabilities != 0 ||
            response.SessionLossSequence != 0 ||
            response.LastSessionLossReason != 0 || response.Reserved != 0 ||
            !OacIpcBackendStatusAreZero(&response.Backend) ||
            !OacIpcScanMetricsAreZero(&response.Scanner))
        {
            std::wcerr << L"OACService returned an invalid rejection.\n";
            return 4;
        }
        std::wcerr << L"OACService rejected the request: "
                   << ErrorText(response.Win32Error) << L'\n';
        return 5;
    }

    DWORD ownSessionId = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &ownSessionId) ||
        response.ClientProcessId != GetCurrentProcessId() ||
        response.ClientSessionId != ownSessionId ||
        response.ServiceProcessId != serverProcessId ||
        (response.StatusFlags & OAC_IPC_STATUS_DRIVER_READY) == 0 ||
        response.Reserved != 0 ||
        response.LastSessionLossReason >
            OAC_REVOKE_TARGET_CONFIRMATION_FAILED ||
        ((response.SessionLossSequence == 0) !=
         (response.LastSessionLossReason == OAC_V5_REVOKE_NONE)) ||
        ((response.SessionLossSequence != 0) !=
         ((response.StatusFlags & OAC_IPC_STATUS_PRIOR_SESSION_LOSS) != 0)) ||
        !OacIpcBackendStatusValid(&response.Backend) ||
        !OacIpcScanMetricsValid(&response.Scanner) ||
        (((response.StatusFlags & OAC_IPC_STATUS_SCANNER_ACTIVE) != 0) !=
         (response.Scanner.State == OAC_IPC_SCAN_READY ||
          response.Scanner.State == OAC_IPC_SCAN_RUNNING)))
    {
        std::wcerr << L"OACService returned inconsistent client identity.\n";
        return 4;
    }

    std::wcout << L"OACService status"
               << L"; service-pid=" << response.ServiceProcessId
               << L"; client-session=" << response.ClientSessionId
               << L"; driver-protocol=0x" << std::hex
               << response.DriverProtocolVersion
               << L"; capabilities=0x" << response.DriverCapabilities
               << L"; flags=0x" << response.StatusFlags << std::dec
               << L"; session-loss-sequence=" << response.SessionLossSequence
               << L"; last-session-loss=" << response.LastSessionLossReason
               << L"; backend-lease=" << response.Backend.LeaseState
               << L"; backend-flags=0x" << std::hex
               << response.Backend.Flags << std::dec
               << L"; backend-lease-sequence="
               << response.Backend.LeaseSequence
               << L"; backend-acknowledged="
               << response.Backend.AcknowledgedSequence
               << L"; backend-pending="
               << response.Backend.PendingEvidence
               << L"; backend-error=" << response.Backend.LastError
               << L"; scan-state=" << response.Scanner.State
               << L"; scan-queued=" << response.Scanner.SlicesQueued
               << L"; scan-completed=" << response.Scanner.SlicesCompleted
               << L"; scan-coalesced=" << response.Scanner.SlicesCoalesced
               << L"; scan-cancelled=" << response.Scanner.SlicesCancelled
               << L"; scan-failed=" << response.Scanner.SlicesFailed
               << L"; scan-sweeps=" << response.Scanner.SweepsCompleted
               << L"; scan-regions=" << response.Scanner.MemoryRegionsInspected
               << L"; scan-bytes=" << response.Scanner.MemoryBytesRead
               << L"; scan-threads=" << response.Scanner.ThreadsInspected
               << L"; scan-skipped=" << response.Scanner.ThreadsSkipped
               << L"; health-iterations=" << response.Scanner.HealthIterations
               << L"; health-max-us="
               << response.Scanner.MaximumHealthDelay100ns / 10
               << L"; scan-max-us="
               << response.Scanner.MaximumSliceDuration100ns / 10
               << L"; suspend-max-us="
               << response.Scanner.MaximumThreadSuspension100ns / 10
               << L'\n';
    return 0;
}

int SendLaunchRequest(const std::wstring& executablePath)
{
    if (executablePath.size() >= OAC_IPC_MAX_EXECUTABLE_PATH_CHARS)
    {
        std::wcerr << L"The executable path is too long for the launch request.\n";
        return 2;
    }

    OAC_IPC_LAUNCH_REQUEST request{};
    request.Header.Version = OAC_IPC_PROTOCOL_REVISION;
    request.Header.Size = static_cast<uint32_t>(sizeof(request));
    request.Header.Type = OAC_IPC_TYPE_LAUNCH_REQUEST;
    request.ExecutablePathLength = static_cast<uint32_t>(executablePath.size());
    if (!MakeRequestId(request.Header.RequestId))
    {
        std::wcerr << L"Could not create an IPC request identifier.\n";
        return 3;
    }
    for (size_t index = 0; index < executablePath.size(); ++index)
        request.ExecutablePath[index] = static_cast<uint16_t>(executablePath[index]);
    if (!OacIpcValidateLaunchRequest(
            &request,
            static_cast<uint32_t>(sizeof(request))))
    {
        std::wcerr << L"Launch requires one canonical absolute drive path.\n";
        return 2;
    }

    UniqueHandle pipe;
    DWORD serverProcessId = 0;
    OAC_SERVICE_FAILURE_STAGE failureStage = OAC_SERVICE_STAGE_NONE;
    const DWORD connectionError = ConnectService(
        pipe,
        serverProcessId,
        failureStage);
    if (connectionError != ERROR_SUCCESS)
    {
        std::wcerr << L"OACService connection failed";
        if (failureStage != OAC_SERVICE_STAGE_NONE)
            std::wcerr << L" during " << ServiceStageText(failureStage);
        std::wcerr << L": " << ErrorText(connectionError) << L'\n';
        return 3;
    }

    OAC_IPC_LAUNCH_RESPONSE response{};
    DWORD returned = 0;
    const DWORD transactionError = TransactService(
        pipe.get(),
        &request,
        static_cast<DWORD>(sizeof(request)),
        &response,
        static_cast<DWORD>(sizeof(response)),
        returned);
    if (transactionError != ERROR_SUCCESS)
    {
        std::wcerr << L"OACService launch request failed: "
                   << ErrorText(transactionError) << L'\n';
        return 3;
    }
    if (!OacIpcValidateLaunchResponse(
            &response,
            returned,
            request.Header.RequestId))
    {
        std::wcerr << L"OACService returned an invalid launch response.\n";
        return 4;
    }
    if (response.Win32Error != ERROR_SUCCESS)
    {
        std::wcerr << L"OACService rejected the launch during "
                   << LaunchStageText(response.FailureStage);
        const wchar_t* detail = LaunchDetailText(response.FailureDetail);
        if (detail[0] != L'\0') std::wcerr << L" (" << detail << L")";
        std::wcerr << L": " << ErrorText(response.Win32Error) << L'\n';
        return 5;
    }

    DWORD ownSessionId = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &ownSessionId) ||
        response.ServiceProcessId != serverProcessId ||
        response.ClientProcessId != GetCurrentProcessId() ||
        response.ClientSessionId != ownSessionId)
    {
        std::wcerr << L"OACService returned inconsistent launch identity.\n";
        return 4;
    }

    std::wcout << L"OACService launched target"
               << L"; target-pid=" << response.TargetProcessId
               << L"; binding=confirmed; job=assigned; thread=resumed\n";
    return 0;
}

bool IsLivenessTargetExecutable(const wchar_t* argumentZero)
{
    /* The disposable-VM harness reuses this signed, as-invoker binary under a
     * dedicated role name so job inheritance can be tested without adding a
     * second test executable to the package. The normal launcher name never
     * enters this path. */
    if (argumentZero == nullptr || argumentZero[0] == L'\0') return false;
    const std::wstring path(argumentZero);
    const std::size_t separator = path.find_last_of(L"\\/");
    const std::wstring name = separator == std::wstring::npos
        ? path
        : path.substr(separator + 1);
    return _wcsicmp(name.c_str(), L"OAC-Liveness-Target.exe") == 0;
}

int RunLivenessTarget()
{
    std::wstring executable(32768, L'\0');
    const UINT length = GetSystemDirectoryW(
        executable.data(),
        static_cast<UINT>(executable.size()));
    if (length == 0 || length >= executable.size()) return 65;
    executable.resize(length);
    executable += L"\\PING.EXE";

    std::wstring commandLine = L"\"" + executable +
        L"\" -t 127.0.0.1";
    std::vector<wchar_t> mutableCommandLine(
        commandLine.begin(),
        commandLine.end());
    mutableCommandLine.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(
            executable.c_str(),
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startup,
            &child))
    {
        return 66;
    }
    UniqueHandle childProcess(child.hProcess);
    UniqueHandle childThread(child.hThread);
    return WaitForSingleObject(childProcess.get(), INFINITE) == WAIT_OBJECT_0
        ? 0
        : 67;
}
} // namespace

int wmain(int argumentCount, wchar_t** arguments)
{
    const bool livenessTarget = argumentCount >= 1 &&
        IsLivenessTargetExecutable(arguments[0]);
    if (livenessTarget && argumentCount == 1) return RunLivenessTarget();

    ULONG type = OAC_IPC_TYPE_STATUS_REQUEST;
    if (argumentCount == 2 && std::wstring(arguments[1]) == L"--hello")
        type = OAC_IPC_TYPE_HELLO_REQUEST;
    else if (argumentCount == 2 && std::wstring(arguments[1]) == L"--status")
        type = OAC_IPC_TYPE_STATUS_REQUEST;
    else if (argumentCount == 3 &&
        std::wstring(arguments[1]) == L"--launch")
    {
        return SendLaunchRequest(arguments[2]);
    }
    else if (argumentCount != 1)
    {
        std::wcerr <<
            L"Usage: OAC-Launcher.exe [--hello|--status|--launch <absolute-executable-path>]\n";
        return 2;
    }

    return SendRequest(type);
}
