#include <Windows.h>
#include <bcrypt.h>
#include <ShlObj.h>

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "..\shared\oac_ipc.h"
#include "..\shared\protocol\oac_v5.h"

namespace
{
constexpr DWORD kRequestTimeoutMs = 5000;

class UniqueHandle
{
public:
    explicit UniqueHandle(HANDLE handle = INVALID_HANDLE_VALUE) noexcept
        : handle_(handle)
    {
    }

    ~UniqueHandle()
    {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
            CloseHandle(handle_);
    }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.release()) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept
    {
        if (this != &other) reset(other.release());
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    HANDLE release() noexcept
    {
        const HANDLE result = handle_;
        handle_ = nullptr;
        return result;
    }

    void reset(HANDLE handle = nullptr) noexcept
    {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
            CloseHandle(handle_);
        handle_ = handle;
    }

private:
    HANDLE handle_;
};

class UniqueServiceHandle
{
public:
    explicit UniqueServiceHandle(SC_HANDLE handle = nullptr) noexcept
        : handle_(handle)
    {
    }

    ~UniqueServiceHandle()
    {
        if (handle_ != nullptr) CloseServiceHandle(handle_);
    }

    UniqueServiceHandle(const UniqueServiceHandle&) = delete;
    UniqueServiceHandle& operator=(const UniqueServiceHandle&) = delete;

    [[nodiscard]] SC_HANDLE get() const noexcept { return handle_; }
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return handle_ != nullptr;
    }

private:
    SC_HANDLE handle_;
};

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
        return L"driver policy revoked the session";
    case OAC_IPC_LAUNCH_DETAIL_EVIDENCE_LOSS:
        return L"driver evidence loss";
    case OAC_IPC_LAUNCH_DETAIL_DRIVER_STOP:
        return L"driver stopped";
    case OAC_IPC_LAUNCH_DETAIL_OTHER_REVOCATION:
        return L"driver session revoked";
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
        OAC_IPC_STATUS_PRIOR_SESSION_LOSS;
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
            response.LastSessionLossReason != 0 || response.Reserved != 0)
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
         ((response.StatusFlags & OAC_IPC_STATUS_PRIOR_SESSION_LOSS) != 0)))
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

bool GetCurrentExecutablePath(std::wstring& path)
{
    path.assign(32768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr,
        path.data(),
        static_cast<DWORD>(path.size()));
    if (length == 0 || length >= path.size()) return false;
    path.resize(length);
    return true;
}

bool IsLivenessTargetExecutable()
{
    /* The disposable-VM harness reuses this signed, as-invoker binary under a
     * dedicated role name so job inheritance can be tested without adding a
     * second test executable to the package. The normal launcher name never
     * enters this path. */
    std::wstring path;
    if (!GetCurrentExecutablePath(path)) return false;
    const std::size_t separator = path.find_last_of(L"\\/");
    const std::wstring name = separator == std::wstring::npos
        ? path
        : path.substr(separator + 1);
    return _wcsicmp(name.c_str(), L"OAC-Liveness-Target.exe") == 0;
}

bool GetLivenessMarkerPath(std::wstring& path)
{
    PWSTR localAppData = nullptr;
    const HRESULT result = SHGetKnownFolderPath(
        FOLDERID_LocalAppData,
        KF_FLAG_DEFAULT,
        nullptr,
        &localAppData);
    if (FAILED(result) || localAppData == nullptr)
    {
        CoTaskMemFree(localAppData);
        return false;
    }
    path.assign(localAppData);
    CoTaskMemFree(localAppData);
    if (path.empty()) return false;
    path += L"\\OAC-Liveness-Target.txt";
    return true;
}

int RunLivenessTarget()
{
    std::wstring executable;
    if (!GetCurrentExecutablePath(executable)) return 65;

    std::wstring commandLine = L"\"" + executable +
        L"\" --liveness-child";
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

    std::wstring markerPath;
    if (!GetLivenessMarkerPath(markerPath))
    {
        (void)TerminateProcess(childProcess.get(), ERROR_PROCESS_ABORTED);
        return 67;
    }
    UniqueHandle marker(CreateFileW(
        markerPath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!marker)
    {
        (void)TerminateProcess(childProcess.get(), ERROR_PROCESS_ABORTED);
        return 68;
    }

    const std::string contents =
        "parent_pid=" + std::to_string(GetCurrentProcessId()) + "\r\n" +
        "child_pid=" + std::to_string(child.dwProcessId) + "\r\n";
    DWORD written = 0;
    const BOOL markerWritten = WriteFile(
        marker.get(),
        contents.data(),
        static_cast<DWORD>(contents.size()),
        &written,
        nullptr);
    marker.reset();
    if (!markerWritten || written != static_cast<DWORD>(contents.size()))
    {
        (void)DeleteFileW(markerPath.c_str());
        (void)TerminateProcess(childProcess.get(), ERROR_PROCESS_ABORTED);
        return 69;
    }

    return WaitForSingleObject(childProcess.get(), INFINITE) == WAIT_OBJECT_0
        ? 0
        : 70;
}
} // namespace

int wmain(int argumentCount, wchar_t** arguments)
{
    const bool livenessTarget = IsLivenessTargetExecutable();
    if (livenessTarget && argumentCount == 1) return RunLivenessTarget();
    if (livenessTarget && argumentCount == 2 &&
        std::wstring(arguments[1]) == L"--liveness-child")
    {
        Sleep(INFINITE);
        return 0;
    }

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
