#include <Windows.h>
#include <bcrypt.h>

#include <iomanip>
#include <iostream>
#include <string>

#include "..\shared\oac_ipc.h"

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

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
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

bool EnsureServiceRunning(DWORD& error)
{
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
            error = status.dwWin32ExitCode != ERROR_SUCCESS
                ? status.dwWin32ExitCode
                : ERROR_SERVICE_NOT_ACTIVE;
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

int SendRequest(ULONG requestType)
{
    DWORD serviceError = ERROR_SUCCESS;
    if (!EnsureServiceRunning(serviceError))
    {
        std::wcerr << L"OACService could not be started safely: "
                   << ErrorText(serviceError) << L'\n';
        return 3;
    }
    if (!WaitNamedPipeW(OAC_PIPE_NAME, 5000))
    {
        std::wcerr << L"OACService is unavailable: "
                   << ErrorText(GetLastError()) << L'\n';
        return 3;
    }

    UniqueHandle pipe(CreateFileW(
        OAC_PIPE_NAME,
        static_cast<DWORD>(OAC_PIPE_CLIENT_ACCESS),
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED |
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
        nullptr));
    if (!pipe)
    {
        std::wcerr << L"Could not connect to OACService: "
                   << ErrorText(GetLastError()) << L'\n';
        return 3;
    }

    DWORD serverProcessId = 0;
    DWORD serverError = ERROR_SUCCESS;
    if (!VerifyPipeServer(pipe.get(), serverProcessId, serverError))
    {
        std::wcerr << L"The OAC control pipe is not owned by the running service: "
                   << ErrorText(serverError) << L'\n';
        return 3;
    }

    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(pipe.get(), &mode, nullptr, nullptr))
    {
        std::wcerr << L"Could not select message-mode IPC: "
                   << ErrorText(GetLastError()) << L'\n';
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
    UniqueHandle requestEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!requestEvent)
    {
        std::wcerr << L"Could not create the IPC completion event: "
                   << ErrorText(GetLastError()) << L'\n';
        return 3;
    }
    OVERLAPPED overlapped{};
    overlapped.hEvent = requestEvent.get();
    if (!TransactNamedPipe(
            pipe.get(),
            &request,
            static_cast<DWORD>(sizeof(request)),
            &response,
            static_cast<DWORD>(sizeof(response)),
            &returned,
            &overlapped))
    {
        DWORD error = GetLastError();
        if (error != ERROR_IO_PENDING)
        {
            std::wcerr << L"OACService request failed: "
                       << ErrorText(error) << L'\n';
            return 3;
        }
        const DWORD wait = WaitForSingleObject(
            requestEvent.get(), kRequestTimeoutMs);
        if (wait != WAIT_OBJECT_0)
        {
            error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
            (void)CancelIoEx(pipe.get(), &overlapped);
            (void)GetOverlappedResult(
                pipe.get(), &overlapped, &returned, TRUE);
            std::wcerr << L"OACService request did not complete in time: "
                       << ErrorText(error == ERROR_SUCCESS
                               ? ERROR_GEN_FAILURE
                               : error)
                       << L'\n';
            return 3;
        }
        if (!GetOverlappedResult(
                pipe.get(), &overlapped, &returned, FALSE))
        {
            std::wcerr << L"OACService request failed: "
                       << ErrorText(GetLastError()) << L'\n';
            return 3;
        }
    }

    const ULONG expectedType = requestType == OAC_IPC_TYPE_HELLO_REQUEST
        ? OAC_IPC_TYPE_HELLO_RESPONSE
        : OAC_IPC_TYPE_STATUS_RESPONSE;
    constexpr ULONG knownStatusFlags = OAC_IPC_STATUS_DRIVER_READY |
        OAC_IPC_STATUS_SESSION_CLAIMED;
    if (returned != static_cast<DWORD>(sizeof(response)) ||
        response.Header.Version != OAC_IPC_VERSION ||
        response.Header.Size != static_cast<uint32_t>(sizeof(response)) ||
        response.Header.Type != expectedType ||
        response.Header.Flags != 0 ||
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
            response.DriverCapabilities != 0)
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
        response.StatusFlags != knownStatusFlags)
    {
        std::wcerr << L"OACService returned inconsistent client identity.\n";
        return 4;
    }

    std::wcout << L"OACService ready"
               << L"; service-pid=" << response.ServiceProcessId
               << L"; client-session=" << response.ClientSessionId
               << L"; driver-protocol=0x" << std::hex
               << response.DriverProtocolVersion
               << L"; capabilities=0x" << response.DriverCapabilities
               << L"; flags=0x" << response.StatusFlags << std::dec << L'\n';
    return 0;
}
} // namespace

int wmain(int argumentCount, wchar_t** arguments)
{
    ULONG type = OAC_IPC_TYPE_STATUS_REQUEST;
    if (argumentCount == 2 && std::wstring(arguments[1]) == L"--hello")
        type = OAC_IPC_TYPE_HELLO_REQUEST;
    else if (argumentCount == 2 && std::wstring(arguments[1]) == L"--status")
        type = OAC_IPC_TYPE_STATUS_REQUEST;
    else if (argumentCount != 1)
    {
        std::wcerr << L"Usage: OAC-Launcher.exe [--hello|--status]\n";
        return 2;
    }

    return SendRequest(type);
}
