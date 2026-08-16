#include <Windows.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <new>
#include <string>
#include <vector>

#include "..\shared\oac_protocol.h"
#include "..\shared\protocol\oac_v5.h"
#include "..\shared\protocol\oac_validate.h"

namespace
{
constexpr wchar_t kDevicePath[] = L"\\\\.\\OAC";
constexpr std::size_t kMaximumCpuSnapshotBytes = std::size_t{1024} * 1024;

class TestLog
{
public:
    void Pass(const std::wstring& name, const std::wstring& detail = L"")
    {
        ++total_;
        ++passed_;
        std::wcout << L"[PASS] " << name;
        if (!detail.empty()) std::wcout << L" - " << detail;
        std::wcout << L'\n';
    }

    void Fail(const std::wstring& name, const std::wstring& detail)
    {
        ++total_;
        std::wcerr << L"[FAIL] " << name << L" - " << detail << L'\n';
    }

    [[nodiscard]] int ExitCode() const
    {
        std::wcout << L"SUMMARY passed=" << passed_ << L" total=" << total_ << L'\n';
        return passed_ == total_ ? 0 : 1;
    }

private:
    unsigned total_ = 0;
    unsigned passed_ = 0;
};

std::wstring ErrorText(DWORD error)
{
    wchar_t* message = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<wchar_t*>(&message),
        0,
        nullptr);
    std::wstring result = L"error=" + std::to_wstring(error);
    if (length != 0 && message != nullptr)
    {
        while (length != 0 &&
               (message[std::wcslen(message) - 1] == L'\r' ||
                message[std::wcslen(message) - 1] == L'\n'))
        {
            message[std::wcslen(message) - 1] = L'\0';
        }
        result += L" (";
        result += message;
        result += L")";
    }
    if (message != nullptr) LocalFree(message);
    return result;
}

bool IsExpectedError(DWORD actual, std::initializer_list<DWORD> expected)
{
    for (const DWORD candidate : expected)
        if (actual == candidate) return true;
    return false;
}

void ExpectFailure(
    TestLog& log,
    const std::wstring& name,
    BOOL succeeded,
    DWORD error,
    std::initializer_list<DWORD> expected)
{
    if (!succeeded && IsExpectedError(error, expected))
        log.Pass(name, ErrorText(error));
    else if (succeeded)
        log.Fail(name, L"request unexpectedly succeeded");
    else
        log.Fail(name, L"unexpected " + ErrorText(error));
}

HANDLE OpenDevice(TestLog* log = nullptr)
{
    HANDLE handle = CreateFileW(
        kDevicePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE && log != nullptr)
        log->Fail(L"open device", ErrorText(GetLastError()));
    return handle;
}

OAC_CONFIG_REQUEST ValidConfiguration()
{
    OAC_CONFIG_REQUEST request{};
    request.Version = OAC_PROTOCOL_VERSION;
    request.Size = sizeof(request);
    request.ClientProcessId = GetCurrentProcessId();
    request.Flags = OAC_CONFIG_ENABLE_IMAGE_LOG |
        OAC_CONFIG_DRIVER_GATE;
    return request;
}

OAC_CONFIG_REQUEST TargetConfiguration(DWORD processId)
{
    auto request = ValidConfiguration();
    request.ProtectedProcessId = processId;
    request.Flags |= OAC_CONFIG_PROTECT_PROCESS;
    return request;
}

int RunContender()
{
    HANDLE device = OpenDevice();
    if (device == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"[FAIL] contender open - " << ErrorText(GetLastError()) << L'\n';
        return 2;
    }
    OAC_CONFIG_REQUEST request = ValidConfiguration();
    DWORD returned = 0;
    SetLastError(ERROR_SUCCESS);
    const BOOL succeeded = DeviceIoControl(
        device,
        IOCTL_OAC_CONFIGURE,
        &request,
        sizeof(request),
        nullptr,
        0,
        &returned,
        nullptr);
    const DWORD error = GetLastError();
    CloseHandle(device);
    if (!succeeded && IsExpectedError(error, {ERROR_ACCESS_DENIED, ERROR_BUSY}))
    {
        std::wcout << L"[PASS] contender file rejected - " << ErrorText(error) << L'\n';
        return 0;
    }
    std::wcerr << L"[FAIL] contender file unexpectedly acquired authority; success="
               << succeeded << L" " << ErrorText(error) << L'\n';
    return 3;
}

bool RunContenderProcess(TestLog& log)
{
    std::wstring executable(32768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr,
        executable.data(),
        static_cast<DWORD>(executable.size()));
    if (length == 0 || static_cast<std::size_t>(length) >= executable.size())
    {
        log.Fail(L"unauthorized second-client takeover", L"could not resolve test executable");
        return false;
    }
    executable.resize(length);

    std::wstring command = L"\"";
    command += executable;
    command += L"\" --contender";
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(
            executable.c_str(),
            mutableCommand.data(),
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            nullptr,
            &startup,
            &process))
    {
        log.Fail(L"unauthorized second-client takeover", ErrorText(GetLastError()));
        return false;
    }
    WaitForSingleObject(process.hProcess, 30000);
    DWORD exitCode = STILL_ACTIVE;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (exitCode == 0)
    {
        log.Pass(L"unauthorized second-client takeover", L"access denied while owner remained alive");
        return true;
    }
    log.Fail(L"unauthorized second-client takeover", L"contender exit=" + std::to_wstring(exitCode));
    return false;
}

ULONGLONG NextRequestId()
{
    static ULONGLONG requestId = 0x1020304050607000ULL;
    return ++requestId;
}

BOOL CallIoctl(
    HANDLE device,
    DWORD code,
    void* input,
    DWORD inputLength,
    void* output,
    DWORD outputLength,
    DWORD& returned,
    DWORD& error)
{
    returned = 0;
    SetLastError(ERROR_SUCCESS);
    const BOOL succeeded = DeviceIoControl(
        device,
        code,
        input,
        inputLength,
        output,
        outputLength,
        &returned,
        nullptr);
    error = GetLastError();
    return succeeded;
}

void ExpectIoctlFailure(
    TestLog& log,
    HANDLE device,
    const std::wstring& name,
    DWORD code,
    void* input,
    DWORD inputLength,
    void* output,
    DWORD outputLength,
    std::initializer_list<DWORD> expected)
{
    DWORD returned = 0;
    DWORD error = ERROR_SUCCESS;
    const BOOL succeeded = CallIoctl(
        device,
        code,
        input,
        inputLength,
        output,
        outputLength,
        returned,
        error);
    ExpectFailure(log, name, succeeded, error, expected);
}

OAC_V5_NEGOTIATE_REQUEST ValidV5Negotiate()
{
    OAC_V5_NEGOTIATE_REQUEST request{};
    request.Header.Version = OAC_V5_VERSION;
    request.Header.Size = sizeof(request);
    request.Header.RequestId = NextRequestId();
    request.Header.MessageType = OAC_V5_MESSAGE_NEGOTIATE;
    request.MinimumVersion = OAC_V5_VERSION;
    request.MaximumVersion = OAC_V5_VERSION;
    return request;
}

OAC_V5_CLAIM_REQUEST ValidV5Claim(OAC_V5_SESSION_MODE mode)
{
    OAC_V5_CLAIM_REQUEST request{};
    request.Header.Version = OAC_V5_VERSION;
    request.Header.Size = sizeof(request);
    request.Header.RequestId = NextRequestId();
    request.Header.MessageType = OAC_V5_MESSAGE_CLAIM_SESSION;
    request.Mode = mode;
    return request;
}

OAC_V5_STATUS_REQUEST ValidV5Status(const OAC_V5_CLAIM_RESPONSE& claim)
{
    OAC_V5_STATUS_REQUEST request{};
    request.Header.Version = OAC_V5_VERSION;
    request.Header.Size = sizeof(request);
    request.Header.RequestId = NextRequestId();
    request.Header.SessionId = claim.Header.SessionId;
    request.Header.Generation = claim.Header.Generation;
    request.Header.MessageType = OAC_V5_MESSAGE_GET_STATUS;
    return request;
}

bool NegotiateV5(
    HANDLE device,
    OAC_V5_NEGOTIATE_REQUEST& request,
    OAC_V5_NEGOTIATE_RESPONSE& response,
    DWORD& error)
{
    DWORD returned = 0;
    const BOOL succeeded = CallIoctl(
        device,
        IOCTL_OAC_V5_NEGOTIATE,
        &request,
        sizeof(request),
        &response,
        sizeof(response),
        returned,
        error);
    return succeeded && returned == sizeof(response) &&
        OacV5ValidateNegotiateResponse(&response, returned) == OAC_V5_VALID &&
        OacV5ValidateCorrelation(
            &request.Header,
            &response.Header) == OAC_V5_VALID &&
        response.Header.Status == 0 &&
        response.Header.Reason == OAC_V5_REASON_NONE &&
        response.Header.Flags == 0;
}

bool ClaimV5(
    HANDLE device,
    OAC_V5_CLAIM_REQUEST& request,
    OAC_V5_CLAIM_RESPONSE& response,
    DWORD& error)
{
    DWORD returned = 0;
    const BOOL succeeded = CallIoctl(
        device,
        IOCTL_OAC_V5_CLAIM_SESSION,
        &request,
        sizeof(request),
        &response,
        sizeof(response),
        returned,
        error);
    return succeeded && returned == sizeof(response) &&
        OacV5ValidateClaimResponse(&response, returned) == OAC_V5_VALID &&
        response.Header.RequestId == request.Header.RequestId &&
        response.Header.MessageType == request.Header.MessageType &&
        response.Header.Status == 0 &&
        response.Header.Reason == OAC_V5_REASON_NONE &&
        response.Header.Flags == 0;
}

bool ParseUnsigned(_In_z_ const wchar_t* text, _Out_ ULONGLONG& value)
{
    wchar_t* end = nullptr;
    errno = 0;
    value = _wcstoui64(text, &end, 10);
    return errno == 0 && end != text && end != nullptr && *end == L'\0';
}

bool StartSelfProcess(
    const std::wstring& arguments,
    HANDLE* inheritedHandles,
    std::size_t inheritedHandleCount,
    PROCESS_INFORMATION& process,
    DWORD& error)
{
    std::wstring executable(32768, L'\0');
    const DWORD pathLength = GetModuleFileNameW(
        nullptr,
        executable.data(),
        static_cast<DWORD>(executable.size()));
    if (pathLength == 0 ||
        static_cast<std::size_t>(pathLength) >= executable.size())
    {
        error = pathLength == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
        return false;
    }
    executable.resize(pathLength);

    SIZE_T attributeSize = 0;
    (VOID)InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeSize);
    if (attributeSize == 0)
    {
        error = GetLastError();
        return false;
    }

    std::vector<std::byte> attributeStorage(attributeSize);
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        attributeStorage.data());
    if (!InitializeProcThreadAttributeList(
            startup.lpAttributeList,
            1,
            0,
            &attributeSize))
    {
        error = GetLastError();
        return false;
    }

    if (!UpdateProcThreadAttribute(
            startup.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inheritedHandles,
            sizeof(HANDLE) * inheritedHandleCount,
            nullptr,
            nullptr))
    {
        error = GetLastError();
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        return false;
    }

    std::wstring command = L"\"" + executable + L"\" " + arguments;
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    const BOOL created = CreateProcessW(
        executable.c_str(),
        mutableCommand.data(),
        nullptr,
        nullptr,
        TRUE,
        EXTENDED_STARTUPINFO_PRESENT,
        nullptr,
        nullptr,
        &startup.StartupInfo,
        &process);
    error = created ? ERROR_SUCCESS : GetLastError();
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    return created != FALSE;
}

struct V4Target
{
    HANDLE StopEvent = nullptr;
    HANDLE Process = nullptr;
    HANDLE Thread = nullptr;
    DWORD ProcessId = 0;
};

int RunV4Target(int argc, wchar_t** argv)
{
    if (argc != 3) return 64;
    ULONGLONG handleValue = 0;
    if (!ParseUnsigned(argv[2], handleValue)) return 65;

    const HANDLE stopEvent = reinterpret_cast<HANDLE>(
        static_cast<ULONG_PTR>(handleValue));
    const DWORD wait = WaitForSingleObject(stopEvent, 60000);
    CloseHandle(stopEvent);
    if (wait == WAIT_OBJECT_0) return 0;
    return wait == WAIT_TIMEOUT ? 124 : 66;
}

bool StartV4Target(V4Target& target, DWORD& error)
{
    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    target.StopEvent = CreateEventW(&security, TRUE, FALSE, nullptr);
    if (target.StopEvent == nullptr)
    {
        error = GetLastError();
        return false;
    }

    std::wstring executable(32768, L'\0');
    const DWORD pathLength = GetModuleFileNameW(
        nullptr,
        executable.data(),
        static_cast<DWORD>(executable.size()));
    if (pathLength == 0 || pathLength >= executable.size())
    {
        error = pathLength == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
        CloseHandle(target.StopEvent);
        target.StopEvent = nullptr;
        return false;
    }
    executable.resize(pathLength);

    SIZE_T attributeSize = 0;
    (VOID)InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeSize);
    if (attributeSize == 0)
    {
        error = GetLastError();
        CloseHandle(target.StopEvent);
        target.StopEvent = nullptr;
        return false;
    }
    std::vector<std::byte> attributeStorage(attributeSize);
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        attributeStorage.data());
    if (!InitializeProcThreadAttributeList(
            startup.lpAttributeList,
            1,
            0,
            &attributeSize))
    {
        error = GetLastError();
        CloseHandle(target.StopEvent);
        target.StopEvent = nullptr;
        return false;
    }

    HANDLE inheritedHandles[] = {target.StopEvent};
    if (!UpdateProcThreadAttribute(
            startup.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inheritedHandles,
            sizeof(inheritedHandles),
            nullptr,
            nullptr))
    {
        error = GetLastError();
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        CloseHandle(target.StopEvent);
        target.StopEvent = nullptr;
        return false;
    }

    std::wstring command = L"\"" + executable + L"\" --v4-target " +
        std::to_wstring(static_cast<ULONGLONG>(
            reinterpret_cast<ULONG_PTR>(target.StopEvent)));
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(
        executable.c_str(),
        mutableCommand.data(),
        nullptr,
        nullptr,
        TRUE,
        EXTENDED_STARTUPINFO_PRESENT,
        nullptr,
        nullptr,
        &startup.StartupInfo,
        &process);
    error = created ? ERROR_SUCCESS : GetLastError();
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    (VOID)SetHandleInformation(target.StopEvent, HANDLE_FLAG_INHERIT, 0);
    if (!created)
    {
        CloseHandle(target.StopEvent);
        target.StopEvent = nullptr;
        return false;
    }

    target.Process = process.hProcess;
    target.Thread = process.hThread;
    target.ProcessId = process.dwProcessId;
    return true;
}

bool StopV4Target(V4Target& target)
{
    bool clean = true;
    if (target.StopEvent != nullptr) (VOID)SetEvent(target.StopEvent);
    if (target.Process != nullptr)
    {
        DWORD wait = WaitForSingleObject(target.Process, 10000);
        if (wait == WAIT_TIMEOUT)
        {
            clean = false;
            (VOID)TerminateProcess(target.Process, 124);
            wait = WaitForSingleObject(target.Process, 5000);
        }
        DWORD exitCode = STILL_ACTIVE;
        if (wait != WAIT_OBJECT_0 ||
            !GetExitCodeProcess(target.Process, &exitCode) ||
            exitCode != 0)
        {
            clean = false;
        }
    }

    if (target.Thread != nullptr) CloseHandle(target.Thread);
    if (target.Process != nullptr) CloseHandle(target.Process);
    if (target.StopEvent != nullptr) CloseHandle(target.StopEvent);
    target = {};
    return clean;
}

void RunV4TombstoneTest(TestLog& log)
{
    V4Target target{};
    DWORD error = ERROR_SUCCESS;
    if (!StartV4Target(target, error))
    {
        log.Fail(L"v4 tombstone target start", ErrorText(error));
        return;
    }
    if (target.Process == nullptr || target.Thread == nullptr ||
        target.StopEvent == nullptr || target.ProcessId == 0)
    {
        log.Fail(L"v4 tombstone target start", L"incomplete process state");
        (VOID)StopV4Target(target);
        return;
    }

    HANDLE controller = OpenDevice(&log);
    if (controller == INVALID_HANDLE_VALUE)
    {
        (VOID)StopV4Target(target);
        return;
    }

    DWORD returned = 0;
    auto configuration = TargetConfiguration(target.ProcessId);
    SetLastError(ERROR_SUCCESS);
    BOOL succeeded = DeviceIoControl(
        controller,
        IOCTL_OAC_CONFIGURE,
        &configuration,
        sizeof(configuration),
        nullptr,
        0,
        &returned,
        nullptr);
    if (succeeded)
    {
        log.Pass(
            L"v4 tombstone target bound",
            L"pid=" + std::to_wstring(target.ProcessId));
    }
    else
    {
        log.Fail(L"v4 tombstone target bound", ErrorText(GetLastError()));
        CloseHandle(controller);
        (VOID)StopV4Target(target);
        return;
    }

    OAC_STATUS_RESPONSE status{};
    succeeded = DeviceIoControl(
        controller,
        IOCTL_OAC_GET_STATUS,
        nullptr,
        0,
        &status,
        sizeof(status),
        &returned,
        nullptr);
    if (succeeded && returned == sizeof(status) &&
        status.Version == OAC_PROTOCOL_VERSION &&
        status.Size == sizeof(status) &&
        status.ClientProcessId == GetCurrentProcessId() &&
        status.ProtectedProcessId == target.ProcessId &&
        (status.ConfigurationFlags & OAC_CONFIG_PROTECT_PROCESS) != 0)
    {
        log.Pass(L"v4 tombstone target identity");
    }
    else
    {
        log.Fail(
            L"v4 tombstone target identity",
            succeeded ? L"invalid response" : ErrorText(GetLastError()));
    }

    CloseHandle(controller);
    const bool targetAlive =
        WaitForSingleObject(target.Process, 0) == WAIT_TIMEOUT;
    if (targetAlive)
        log.Pass(L"v4 tombstone target remains alive after cleanup");
    else
        log.Fail(L"v4 tombstone target remains alive after cleanup", L"target exited early");

    HANDLE replacement = OpenDevice(&log);
    if (replacement != INVALID_HANDLE_VALUE)
    {
        configuration = ValidConfiguration();
        SetLastError(ERROR_SUCCESS);
        succeeded = DeviceIoControl(
            replacement,
            IOCTL_OAC_CONFIGURE,
            &configuration,
            sizeof(configuration),
            nullptr,
            0,
            &returned,
            nullptr);
        error = GetLastError();
        if (targetAlive && !succeeded && error == ERROR_BUSY)
        {
            log.Pass(L"v4 live-target tombstone rejects replacement", ErrorText(error));
        }
        else
        {
            log.Fail(
                L"v4 live-target tombstone rejects replacement",
                succeeded ? L"replacement unexpectedly claimed" : ErrorText(error));
        }
        CloseHandle(replacement);
    }

    if (StopV4Target(target))
        log.Pass(L"v4 tombstone target exits within bound");
    else
        log.Fail(L"v4 tombstone target exits within bound", L"forced or incomplete exit");

    HANDLE reclaim = OpenDevice(&log);
    if (reclaim == INVALID_HANDLE_VALUE) return;
    configuration = ValidConfiguration();
    bool reclaimed = false;
    for (ULONG attempt = 0; attempt < 40; ++attempt)
    {
        SetLastError(ERROR_SUCCESS);
        succeeded = DeviceIoControl(
            reclaim,
            IOCTL_OAC_CONFIGURE,
            &configuration,
            sizeof(configuration),
            nullptr,
            0,
            &returned,
            nullptr);
        error = GetLastError();
        if (succeeded)
        {
            reclaimed = true;
            break;
        }
        if (error != ERROR_BUSY) break;
        if (attempt + 1 < 40) Sleep(25);
    }
    if (reclaimed)
        log.Pass(L"v4 target-exit cleanup permits reclaim");
    else
    {
        log.Fail(L"v4 target-exit cleanup permits reclaim", ErrorText(error));
        CloseHandle(reclaim);
        return;
    }

    status = {};
    succeeded = DeviceIoControl(
        reclaim,
        IOCTL_OAC_GET_STATUS,
        nullptr,
        0,
        &status,
        sizeof(status),
        &returned,
        nullptr);
    if (succeeded && returned == sizeof(status) &&
        status.Version == OAC_PROTOCOL_VERSION &&
        status.Size == sizeof(status) &&
        status.ClientProcessId == GetCurrentProcessId() &&
        status.ProtectedProcessId == 0)
    {
        log.Pass(L"v4 reclaimed session has no stale target");
    }
    else
    {
        log.Fail(
            L"v4 reclaimed session has no stale target",
            succeeded ? L"invalid response" : ErrorText(GetLastError()));
    }
    CloseHandle(reclaim);
}

int RunV5HandleContender(int argc, wchar_t** argv)
{
    if (argc != 6) return 64;
    ULONGLONG handleValue = 0;
    OAC_V5_STATUS_REQUEST request{};
    if (!ParseUnsigned(argv[2], handleValue) ||
        !ParseUnsigned(argv[3], request.Header.SessionId.High) ||
        !ParseUnsigned(argv[4], request.Header.SessionId.Low) ||
        !ParseUnsigned(argv[5], request.Header.Generation))
    {
        return 65;
    }

    const HANDLE device = reinterpret_cast<HANDLE>(
        static_cast<ULONG_PTR>(handleValue));
    request.Header.Version = OAC_V5_VERSION;
    request.Header.Size = sizeof(request);
    request.Header.RequestId = NextRequestId();
    request.Header.MessageType = OAC_V5_MESSAGE_GET_STATUS;
    OAC_V5_STATUS_RESPONSE response{};
    DWORD returned = 0;
    DWORD error = ERROR_SUCCESS;
    const BOOL succeeded = CallIoctl(
        device,
        IOCTL_OAC_V5_GET_STATUS,
        &request,
        sizeof(request),
        &response,
        sizeof(response),
        returned,
        error);
    CloseHandle(device);
    if (!succeeded && error == ERROR_ACCESS_DENIED)
    {
        std::wcout << L"[PASS] duplicated v5 handle rejected in another process\n";
        return 0;
    }
    std::wcerr << L"[FAIL] duplicated v5 handle crossed the process boundary; success="
               << succeeded << L" " << ErrorText(error) << L'\n';
    return 3;
}

bool RunV5HandleContenderProcess(
    HANDLE device,
    const OAC_V5_CLAIM_RESPONSE& claim,
    TestLog& log)
{
    HANDLE inherited = INVALID_HANDLE_VALUE;
    if (!DuplicateHandle(
            GetCurrentProcess(),
            device,
            GetCurrentProcess(),
            &inherited,
            0,
            TRUE,
            DUPLICATE_SAME_ACCESS))
    {
        log.Fail(L"duplicated-handle wrong-process rejection", ErrorText(GetLastError()));
        return false;
    }

    std::wstring executable(32768, L'\0');
    const DWORD pathLength = GetModuleFileNameW(
        nullptr,
        executable.data(),
        static_cast<DWORD>(executable.size()));
    if (pathLength == 0 || pathLength >= executable.size())
    {
        CloseHandle(inherited);
        log.Fail(L"duplicated-handle wrong-process rejection", L"could not resolve test executable");
        return false;
    }
    executable.resize(pathLength);

    SIZE_T attributeSize = 0;
    (VOID)InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeSize);
    if (attributeSize == 0)
    {
        CloseHandle(inherited);
        log.Fail(L"duplicated-handle wrong-process rejection", ErrorText(GetLastError()));
        return false;
    }
    std::vector<std::byte> attributeStorage(attributeSize);
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        attributeStorage.data());
    if (!InitializeProcThreadAttributeList(
            startup.lpAttributeList,
            1,
            0,
            &attributeSize))
    {
        CloseHandle(inherited);
        log.Fail(L"duplicated-handle wrong-process rejection", ErrorText(GetLastError()));
        return false;
    }

    HANDLE inheritedHandles[] = {inherited};
    if (!UpdateProcThreadAttribute(
            startup.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inheritedHandles,
            sizeof(inheritedHandles),
            nullptr,
            nullptr))
    {
        const DWORD error = GetLastError();
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        CloseHandle(inherited);
        log.Fail(L"duplicated-handle wrong-process rejection", ErrorText(error));
        return false;
    }

    std::wstring command = L"\"" + executable + L"\" --v5-contender " +
        std::to_wstring(static_cast<ULONGLONG>(
            reinterpret_cast<ULONG_PTR>(inherited))) + L" " +
        std::to_wstring(claim.Header.SessionId.High) + L" " +
        std::to_wstring(claim.Header.SessionId.Low) + L" " +
        std::to_wstring(claim.Header.Generation);
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(
        executable.c_str(),
        mutableCommand.data(),
        nullptr,
        nullptr,
        TRUE,
        EXTENDED_STARTUPINFO_PRESENT,
        nullptr,
        nullptr,
        &startup.StartupInfo,
        &process);
    const DWORD createError = GetLastError();
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    CloseHandle(inherited);
    if (!created)
    {
        log.Fail(L"duplicated-handle wrong-process rejection", ErrorText(createError));
        return false;
    }

    const DWORD wait = WaitForSingleObject(process.hProcess, 30000);
    if (wait == WAIT_TIMEOUT)
    {
        (VOID)TerminateProcess(process.hProcess, 124);
        (VOID)WaitForSingleObject(process.hProcess, 5000);
    }
    DWORD exitCode = STILL_ACTIVE;
    (VOID)GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (wait == WAIT_OBJECT_0 && exitCode == 0)
    {
        log.Pass(L"duplicated-handle wrong-process rejection", L"same file object, different process");
        return true;
    }
    log.Fail(L"duplicated-handle wrong-process rejection",
        wait == WAIT_TIMEOUT ? L"contender timed out" : L"contender exit=" + std::to_wstring(exitCode));
    return false;
}

constexpr ULONG kV5OwnerReportVersion = 1;

struct V5OwnerReport
{
    ULONG Size;
    ULONG Version;
    DWORD Error;
    DWORD HolderProcessId;
    OAC_V5_SESSION_ID SessionId;
    ULONGLONG Generation;
};

int RunV5RetainedHolder(int argc, wchar_t** argv)
{
    if (argc != 10) return 64;

    std::array<ULONGLONG, 8> values{};
    for (std::size_t index = 0; index < values.size(); ++index)
    {
        if (!ParseUnsigned(argv[index + 2], values[index])) return 65;
    }

    const HANDLE device = reinterpret_cast<HANDLE>(
        static_cast<ULONG_PTR>(values[0]));
    const HANDLE releaseEvent = reinterpret_cast<HANDLE>(
        static_cast<ULONG_PTR>(values[1]));
    const HANDLE readyEvent = reinterpret_cast<HANDLE>(
        static_cast<ULONG_PTR>(values[2]));
    const HANDLE probeEvent = reinterpret_cast<HANDLE>(
        static_cast<ULONG_PTR>(values[3]));
    const HANDLE probedEvent = reinterpret_cast<HANDLE>(
        static_cast<ULONG_PTR>(values[4]));

    if (!SetEvent(readyEvent)) return 66;
    const HANDLE startEvents[] = {probeEvent, releaseEvent};
    const DWORD startWait = WaitForMultipleObjects(
        static_cast<DWORD>(std::size(startEvents)),
        startEvents,
        FALSE,
        30000);
    if (startWait != WAIT_OBJECT_0)
    {
        CloseHandle(device);
        CloseHandle(releaseEvent);
        CloseHandle(readyEvent);
        CloseHandle(probeEvent);
        CloseHandle(probedEvent);
        return startWait == WAIT_OBJECT_0 + 1 ? 125 : 124;
    }

    OAC_V5_STATUS_REQUEST request{};
    request.Header.Version = OAC_V5_VERSION;
    request.Header.Size = sizeof(request);
    request.Header.RequestId = NextRequestId();
    request.Header.SessionId.High = values[5];
    request.Header.SessionId.Low = values[6];
    request.Header.Generation = values[7];
    request.Header.MessageType = OAC_V5_MESSAGE_GET_STATUS;
    OAC_V5_STATUS_RESPONSE response{};
    DWORD returned = 0;
    DWORD error = ERROR_SUCCESS;
    const BOOL succeeded = CallIoctl(
        device,
        IOCTL_OAC_V5_GET_STATUS,
        &request,
        sizeof(request),
        &response,
        sizeof(response),
        returned,
        error);
    const bool rejected = !succeeded && error == ERROR_ACCESS_DENIED;
    if (!SetEvent(probedEvent))
    {
        CloseHandle(device);
        CloseHandle(releaseEvent);
        CloseHandle(readyEvent);
        CloseHandle(probeEvent);
        CloseHandle(probedEvent);
        return 67;
    }

    const DWORD releaseWait = WaitForSingleObject(releaseEvent, 30000);
    CloseHandle(device);
    CloseHandle(releaseEvent);
    CloseHandle(readyEvent);
    CloseHandle(probeEvent);
    CloseHandle(probedEvent);
    if (releaseWait != WAIT_OBJECT_0)
        return releaseWait == WAIT_TIMEOUT ? 124 : 68;
    return rejected ? 0 : 3;
}

int RunV5RetainedOwner(int argc, wchar_t** argv)
{
    if (argc != 7) return 64;

    std::array<ULONGLONG, 5> values{};
    for (std::size_t index = 0; index < values.size(); ++index)
    {
        if (!ParseUnsigned(argv[index + 2], values[index])) return 65;
    }

    const HANDLE reportPipe = reinterpret_cast<HANDLE>(
        static_cast<ULONG_PTR>(values[0]));
    const HANDLE releaseEvent = reinterpret_cast<HANDLE>(
        static_cast<ULONG_PTR>(values[1]));
    const HANDLE readyEvent = reinterpret_cast<HANDLE>(
        static_cast<ULONG_PTR>(values[2]));
    const HANDLE probeEvent = reinterpret_cast<HANDLE>(
        static_cast<ULONG_PTR>(values[3]));
    const HANDLE probedEvent = reinterpret_cast<HANDLE>(
        static_cast<ULONG_PTR>(values[4]));

    V5OwnerReport report{};
    report.Size = sizeof(report);
    report.Version = kV5OwnerReportVersion;
    HANDLE device = INVALID_HANDLE_VALUE;
    HANDLE retainedDevice = INVALID_HANDLE_VALUE;
    PROCESS_INFORMATION holder{};
    bool holderStarted = false;
    DWORD error = ERROR_SUCCESS;

    device = OpenDevice();
    if (device == INVALID_HANDLE_VALUE) error = GetLastError();

    OAC_V5_NEGOTIATE_RESPONSE negotiated{};
    OAC_V5_CLAIM_RESPONSE claimed{};
    if (error == ERROR_SUCCESS)
    {
        auto request = ValidV5Negotiate();
        if (!NegotiateV5(device, request, negotiated, error) &&
            error == ERROR_SUCCESS)
        {
            error = ERROR_INVALID_DATA;
        }
    }
    if (error == ERROR_SUCCESS)
    {
        auto request = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
        if (!ClaimV5(device, request, claimed, error) &&
            error == ERROR_SUCCESS)
        {
            error = ERROR_INVALID_DATA;
        }
    }

    if (error == ERROR_SUCCESS)
    {
        if (!DuplicateHandle(
                GetCurrentProcess(),
                device,
                GetCurrentProcess(),
                &retainedDevice,
                0,
                TRUE,
                DUPLICATE_SAME_ACCESS))
        {
            error = GetLastError();
        }
    }

    if (error == ERROR_SUCCESS)
    {
        const HANDLE handles[] = {
            retainedDevice,
            releaseEvent,
            readyEvent,
            probeEvent,
            probedEvent};
        for (HANDLE handle : handles)
        {
            if (!SetHandleInformation(
                    handle,
                    HANDLE_FLAG_INHERIT,
                    HANDLE_FLAG_INHERIT))
            {
                error = GetLastError();
                break;
            }
        }

        if (error == ERROR_SUCCESS)
        {
            const std::wstring arguments =
                L"--v5-retained-holder " +
                std::to_wstring(static_cast<ULONGLONG>(
                    reinterpret_cast<ULONG_PTR>(retainedDevice))) + L" " +
                std::to_wstring(static_cast<ULONGLONG>(
                    reinterpret_cast<ULONG_PTR>(releaseEvent))) + L" " +
                std::to_wstring(static_cast<ULONGLONG>(
                    reinterpret_cast<ULONG_PTR>(readyEvent))) + L" " +
                std::to_wstring(static_cast<ULONGLONG>(
                    reinterpret_cast<ULONG_PTR>(probeEvent))) + L" " +
                std::to_wstring(static_cast<ULONGLONG>(
                    reinterpret_cast<ULONG_PTR>(probedEvent))) + L" " +
                std::to_wstring(claimed.Header.SessionId.High) + L" " +
                std::to_wstring(claimed.Header.SessionId.Low) + L" " +
                std::to_wstring(claimed.Header.Generation);
            HANDLE inheritedHandles[] = {
                retainedDevice,
                releaseEvent,
                readyEvent,
                probeEvent,
                probedEvent};
            holderStarted = StartSelfProcess(
                arguments,
                inheritedHandles,
                std::size(inheritedHandles),
                holder,
                error);
        }
    }

    if (holderStarted)
    {
        report.HolderProcessId = holder.dwProcessId;
        const DWORD readyWait = WaitForSingleObject(readyEvent, 10000);
        if (readyWait != WAIT_OBJECT_0)
            error = readyWait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
        else if (WaitForSingleObject(holder.hProcess, 0) != WAIT_TIMEOUT)
            error = ERROR_PROCESS_ABORTED;
    }

    if (error == ERROR_SUCCESS)
    {
        report.SessionId = claimed.Header.SessionId;
        report.Generation = claimed.Header.Generation;
    }
    report.Error = error;
    DWORD written = 0;
    const BOOL reportSent = WriteFile(
        reportPipe,
        &report,
        sizeof(report),
        &written,
        nullptr);
    const bool sent = reportSent && written == sizeof(report);

    if (holderStarted && (!sent || error != ERROR_SUCCESS))
    {
        (VOID)SetEvent(releaseEvent);
        DWORD wait = WaitForSingleObject(holder.hProcess, 5000);
        if (wait == WAIT_TIMEOUT)
        {
            (VOID)TerminateProcess(holder.hProcess, 124);
            (VOID)WaitForSingleObject(holder.hProcess, 5000);
        }
    }
    if (holder.hThread != nullptr) CloseHandle(holder.hThread);
    if (holder.hProcess != nullptr) CloseHandle(holder.hProcess);
    if (retainedDevice != INVALID_HANDLE_VALUE) CloseHandle(retainedDevice);
    if (device != INVALID_HANDLE_VALUE) CloseHandle(device);
    CloseHandle(reportPipe);
    CloseHandle(releaseEvent);
    CloseHandle(readyEvent);
    CloseHandle(probeEvent);
    CloseHandle(probedEvent);
    return sent && error == ERROR_SUCCESS ? 0 : 2;
}

void RunV5OwnerExitTest(TestLog& log)
{
    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;

    HANDLE reportRead = nullptr;
    HANDLE reportWrite = nullptr;
    HANDLE releaseEvent = CreateEventW(&security, TRUE, FALSE, nullptr);
    HANDLE readyEvent = CreateEventW(&security, TRUE, FALSE, nullptr);
    HANDLE probeEvent = CreateEventW(&security, TRUE, FALSE, nullptr);
    HANDLE probedEvent = CreateEventW(&security, TRUE, FALSE, nullptr);
    DWORD error = ERROR_SUCCESS;
    if (releaseEvent == nullptr || readyEvent == nullptr ||
        probeEvent == nullptr || probedEvent == nullptr ||
        !CreatePipe(&reportRead, &reportWrite, &security, 0) ||
        !SetHandleInformation(reportRead, HANDLE_FLAG_INHERIT, 0))
    {
        error = GetLastError();
        log.Fail(L"v5 retained owner-exit setup", ErrorText(error));
        if (reportRead != nullptr) CloseHandle(reportRead);
        if (reportWrite != nullptr) CloseHandle(reportWrite);
        if (releaseEvent != nullptr) CloseHandle(releaseEvent);
        if (readyEvent != nullptr) CloseHandle(readyEvent);
        if (probeEvent != nullptr) CloseHandle(probeEvent);
        if (probedEvent != nullptr) CloseHandle(probedEvent);
        return;
    }

    const std::wstring arguments =
        L"--v5-retained-owner " +
        std::to_wstring(static_cast<ULONGLONG>(
            reinterpret_cast<ULONG_PTR>(reportWrite))) + L" " +
        std::to_wstring(static_cast<ULONGLONG>(
            reinterpret_cast<ULONG_PTR>(releaseEvent))) + L" " +
        std::to_wstring(static_cast<ULONGLONG>(
            reinterpret_cast<ULONG_PTR>(readyEvent))) + L" " +
        std::to_wstring(static_cast<ULONGLONG>(
            reinterpret_cast<ULONG_PTR>(probeEvent))) + L" " +
        std::to_wstring(static_cast<ULONGLONG>(
            reinterpret_cast<ULONG_PTR>(probedEvent)));
    HANDLE inheritedHandles[] = {
        reportWrite,
        releaseEvent,
        readyEvent,
        probeEvent,
        probedEvent};
    PROCESS_INFORMATION owner{};
    const bool started = StartSelfProcess(
        arguments,
        inheritedHandles,
        std::size(inheritedHandles),
        owner,
        error);
    (VOID)SetHandleInformation(reportWrite, HANDLE_FLAG_INHERIT, 0);
    (VOID)SetHandleInformation(releaseEvent, HANDLE_FLAG_INHERIT, 0);
    (VOID)SetHandleInformation(readyEvent, HANDLE_FLAG_INHERIT, 0);
    (VOID)SetHandleInformation(probeEvent, HANDLE_FLAG_INHERIT, 0);
    (VOID)SetHandleInformation(probedEvent, HANDLE_FLAG_INHERIT, 0);
    CloseHandle(reportWrite);
    reportWrite = nullptr;
    if (!started || owner.hProcess == nullptr || owner.hThread == nullptr)
    {
        if (started)
        {
            error = ERROR_INVALID_HANDLE;
            (VOID)SetEvent(releaseEvent);
        }
        log.Fail(L"v5 retained owner-exit setup", ErrorText(error));
        if (owner.hProcess != nullptr)
        {
            (VOID)TerminateProcess(owner.hProcess, 124);
            (VOID)WaitForSingleObject(owner.hProcess, 5000);
        }
        if (owner.hThread != nullptr) CloseHandle(owner.hThread);
        if (owner.hProcess != nullptr) CloseHandle(owner.hProcess);
        CloseHandle(reportRead);
        CloseHandle(releaseEvent);
        CloseHandle(readyEvent);
        CloseHandle(probeEvent);
        CloseHandle(probedEvent);
        return;
    }

    DWORD ownerWait = WaitForSingleObject(owner.hProcess, 20000);
    bool ownerStopped = ownerWait == WAIT_OBJECT_0;
    if (!ownerStopped)
    {
        (VOID)TerminateProcess(owner.hProcess, 124);
        ownerStopped =
            WaitForSingleObject(owner.hProcess, 5000) == WAIT_OBJECT_0;
    }
    DWORD ownerExit = STILL_ACTIVE;
    (VOID)GetExitCodeProcess(owner.hProcess, &ownerExit);
    V5OwnerReport report{};
    DWORD read = 0;
    const BOOL reportReadOk = ownerStopped && ReadFile(
            reportRead,
            &report,
            sizeof(report),
            &read,
            nullptr);
    const DWORD reportReadError = reportReadOk ? ERROR_SUCCESS : GetLastError();
    CloseHandle(reportRead);
    CloseHandle(owner.hThread);
    CloseHandle(owner.hProcess);

    HANDLE holder = nullptr;
    if (report.HolderProcessId != 0)
    {
        holder = OpenProcess(
            SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            FALSE,
            report.HolderProcessId);
    }
    const bool setupValid =
        ownerWait == WAIT_OBJECT_0 &&
        ownerExit == 0 &&
        reportReadOk &&
        read == sizeof(report) &&
        report.Size == sizeof(report) &&
        report.Version == kV5OwnerReportVersion &&
        report.Error == ERROR_SUCCESS &&
        report.Generation != 0 &&
        !OacV5SessionIdIsZero(&report.SessionId) &&
        WaitForSingleObject(readyEvent, 0) == WAIT_OBJECT_0 &&
        holder != nullptr &&
        WaitForSingleObject(holder, 0) == WAIT_TIMEOUT;
    if (setupValid)
    {
        log.Pass(
            L"v5 owner exits with exact file retained",
            L"holder pid=" + std::to_wstring(report.HolderProcessId));
    }
    else
    {
        std::wstring detail = L"owner exit=" + std::to_wstring(ownerExit) +
            L" report error=" + std::to_wstring(report.Error);
        if (!reportReadOk) detail += L" " + ErrorText(reportReadError);
        log.Fail(L"v5 owner exits with exact file retained", detail);
    }

    bool probed = false;
    if (setupValid && SetEvent(probeEvent))
    {
        probed = WaitForSingleObject(probedEvent, 10000) == WAIT_OBJECT_0 &&
            WaitForSingleObject(holder, 0) == WAIT_TIMEOUT;
    }
    if (!probed && setupValid)
        log.Fail(L"v5 retained holder probes after owner exit", L"probe timed out");

    if (probed)
    {
        HANDLE device = OpenDevice(&log);
        if (device != INVALID_HANDLE_VALUE)
        {
            auto negotiate = ValidV5Negotiate();
            OAC_V5_NEGOTIATE_RESPONSE negotiated{};
            auto claim = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
            OAC_V5_CLAIM_RESPONSE claimed{};
            const bool negotiatedOk = NegotiateV5(
                device,
                negotiate,
                negotiated,
                error);
            const bool claimedOk = negotiatedOk && ClaimV5(
                device,
                claim,
                claimed,
                error);
            if (claimedOk &&
                claimed.Header.Generation > report.Generation &&
                !OacV5SessionIdEqual(
                    &claimed.Header.SessionId,
                    &report.SessionId) &&
                WaitForSingleObject(holder, 0) == WAIT_TIMEOUT)
            {
                log.Pass(
                    L"v5 owner exit permits a fresh generation",
                    L"retained holder still alive");
            }
            else
            {
                if (error == ERROR_SUCCESS) error = ERROR_INVALID_DATA;
                log.Fail(
                    L"v5 owner exit permits a fresh generation",
                    ErrorText(error));
            }
            CloseHandle(device);
        }
    }

    (VOID)SetEvent(releaseEvent);
    if (holder != nullptr)
    {
        DWORD holderWait = WaitForSingleObject(holder, 10000);
        if (holderWait == WAIT_TIMEOUT)
        {
            (VOID)TerminateProcess(holder, 124);
            holderWait = WaitForSingleObject(holder, 5000);
        }
        DWORD holderExit = STILL_ACTIVE;
        (VOID)GetExitCodeProcess(holder, &holderExit);
        if (holderWait == WAIT_OBJECT_0 && holderExit == 0)
            log.Pass(L"v5 retained handle stays unauthorized after owner exit");
        else
            log.Fail(
                L"v5 retained handle stays unauthorized after owner exit",
                L"holder exit=" + std::to_wstring(holderExit));
        CloseHandle(holder);
    }
    CloseHandle(releaseEvent);
    CloseHandle(readyEvent);
    CloseHandle(probeEvent);
    CloseHandle(probedEvent);
}

constexpr ULONG kV5RaceThreads = 4;
constexpr ULONG kV5RaceWarmups = 32;

struct V5CleanupRace;

struct V5RaceWorker
{
    V5CleanupRace* Race;
    ULONG Index;
};

struct V5CleanupRace
{
    HANDLE Device;
    HANDLE LaunchEvent;
    HANDLE RaceEvent;
    HANDLE ClosedEvent;
    HANDLE ReadyEvent;
    OAC_V5_CLAIM_RESPONSE Claim;
    std::array<V5RaceWorker, kV5RaceThreads> Workers;
    volatile LONG ReadyCount;
    volatile LONG WarmupSuccesses;
    volatile LONG FinalSuccesses;
    volatile LONG ExpectedStops;
    volatile LONG Failures;
    volatile LONG FirstError;
    volatile LONG Abort;
};

void MarkV5RaceFailure(V5CleanupRace* race, DWORD error)
{
    if (error == ERROR_SUCCESS) error = ERROR_INVALID_DATA;
    (VOID)InterlockedCompareExchange(
        &race->FirstError,
        static_cast<LONG>(error),
        0);
    (VOID)InterlockedIncrement(&race->Failures);
}

OAC_V5_STATUS_REQUEST V5RaceStatusRequest(
    const OAC_V5_CLAIM_RESPONSE& claim,
    ULONG worker,
    ULONG attempt)
{
    auto request = ValidV5Status(claim);
    request.Header.RequestId = 0xC100000000000000ULL |
        (static_cast<ULONGLONG>(worker + 1) << 32) |
        static_cast<ULONGLONG>(attempt + 1);
    return request;
}

bool V5RaceStatusValid(
    const OAC_V5_STATUS_REQUEST& request,
    const OAC_V5_STATUS_RESPONSE& response,
    DWORD returned,
    bool requireActive)
{
    if (returned != sizeof(response) ||
        OacV5ValidateStatusResponse(&response, returned) != OAC_V5_VALID ||
        OacV5ValidateCorrelation(
            &request.Header,
            &response.Header) != OAC_V5_VALID ||
        response.Header.Status != 0 ||
        response.Header.Reason != OAC_V5_REASON_NONE ||
        response.ServiceProcessId != GetCurrentProcessId() ||
        response.TargetProcessId != 0)
    {
        return false;
    }
    return !requireActive ||
        (response.State == OAC_V5_SESSION_CLAIMED &&
         response.Header.Flags == 0 &&
         response.RevokeReason == OAC_V5_REVOKE_NONE);
}

DWORD WINAPI RunV5RaceWorker(void* parameter)
{
    auto* worker = static_cast<V5RaceWorker*>(parameter);
    V5CleanupRace* race = worker->Race;

    if (WaitForSingleObject(race->LaunchEvent, 10000) != WAIT_OBJECT_0)
    {
        MarkV5RaceFailure(race, ERROR_TIMEOUT);
        return 1;
    }
    if (InterlockedCompareExchange(&race->Abort, 0, 0) != 0) return 1;

    for (ULONG attempt = 0; attempt < kV5RaceWarmups; ++attempt)
    {
        auto request = V5RaceStatusRequest(
            race->Claim,
            worker->Index,
            attempt);
        OAC_V5_STATUS_RESPONSE response{};
        DWORD returned = 0;
        DWORD error = ERROR_SUCCESS;
        const BOOL succeeded = CallIoctl(
            race->Device,
            IOCTL_OAC_V5_GET_STATUS,
            &request,
            sizeof(request),
            &response,
            sizeof(response),
            returned,
            error);
        if (!succeeded || !V5RaceStatusValid(
                request,
                response,
                returned,
                true))
        {
            MarkV5RaceFailure(
                race,
                succeeded ? ERROR_INVALID_DATA : error);
            break;
        }
        (VOID)InterlockedIncrement(&race->WarmupSuccesses);
    }

    if (InterlockedIncrement(&race->ReadyCount) == kV5RaceThreads)
        (VOID)SetEvent(race->ReadyEvent);

    const HANDLE phaseEvent = (worker->Index & 1UL) == 0
        ? race->RaceEvent
        : race->ClosedEvent;
    if (WaitForSingleObject(phaseEvent, 10000) != WAIT_OBJECT_0)
    {
        MarkV5RaceFailure(race, ERROR_TIMEOUT);
        return 1;
    }

    auto request = V5RaceStatusRequest(
        race->Claim,
        worker->Index,
        kV5RaceWarmups);
    OAC_V5_STATUS_RESPONSE response{};
    DWORD returned = 0;
    DWORD error = ERROR_SUCCESS;
    const BOOL succeeded = CallIoctl(
        race->Device,
        IOCTL_OAC_V5_GET_STATUS,
        &request,
        sizeof(request),
        &response,
        sizeof(response),
        returned,
        error);
    if (succeeded)
    {
        if ((worker->Index & 1UL) != 0 ||
            !V5RaceStatusValid(request, response, returned, false))
        {
            MarkV5RaceFailure(race, ERROR_INVALID_DATA);
            return 1;
        }
        (VOID)InterlockedIncrement(&race->FinalSuccesses);
        return 0;
    }
    if (IsExpectedError(
            error,
            {ERROR_ACCESS_DENIED,
             ERROR_INVALID_HANDLE,
             ERROR_OPERATION_ABORTED,
             ERROR_CANCELLED}))
    {
        (VOID)InterlockedIncrement(&race->ExpectedStops);
        return 0;
    }

    MarkV5RaceFailure(race, error);
    return 1;
}

void RunV5CleanupRace(TestLog& log)
{
    DWORD error = ERROR_SUCCESS;
    HANDLE device = OpenDevice(&log);
    if (device == INVALID_HANDLE_VALUE) return;

    auto negotiate = ValidV5Negotiate();
    OAC_V5_NEGOTIATE_RESPONSE negotiated{};
    auto claim = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
    OAC_V5_CLAIM_RESPONSE claimed{};
    if (!NegotiateV5(device, negotiate, negotiated, error) ||
        !ClaimV5(device, claim, claimed, error))
    {
        log.Fail(L"v5 cleanup race setup", ErrorText(error));
        CloseHandle(device);
        return;
    }

    V5CleanupRace* race;
    try
    {
        race = new V5CleanupRace{};
    }
    catch (const std::bad_alloc&)
    {
        log.Fail(L"v5 cleanup race setup", L"allocation failed");
        CloseHandle(device);
        return;
    }
    race->Device = device;
    race->Claim = claimed;
    race->LaunchEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    race->RaceEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    race->ClosedEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    race->ReadyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (race->LaunchEvent == nullptr || race->RaceEvent == nullptr ||
        race->ClosedEvent == nullptr || race->ReadyEvent == nullptr)
    {
        log.Fail(L"v5 cleanup race setup", ErrorText(GetLastError()));
        if (race->LaunchEvent != nullptr) CloseHandle(race->LaunchEvent);
        if (race->RaceEvent != nullptr) CloseHandle(race->RaceEvent);
        if (race->ClosedEvent != nullptr) CloseHandle(race->ClosedEvent);
        if (race->ReadyEvent != nullptr) CloseHandle(race->ReadyEvent);
        CloseHandle(device);
        delete race;
        return;
    }

    std::array<HANDLE, kV5RaceThreads> threads{};
    bool created = true;
    for (ULONG index = 0; index < kV5RaceThreads; ++index)
    {
        race->Workers[index].Race = race;
        race->Workers[index].Index = index;
        threads[index] = CreateThread(
            nullptr,
            0,
            RunV5RaceWorker,
            &race->Workers[index],
            0,
            nullptr);
        if (threads[index] == nullptr)
        {
            created = false;
            error = GetLastError();
            break;
        }
    }
    if (!created)
    {
        (VOID)InterlockedExchange(&race->Abort, 1);
        (VOID)SetEvent(race->LaunchEvent);
        bool stopped = true;
        for (HANDLE thread : threads)
        {
            if (thread == nullptr) continue;
            if (WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0)
                CloseHandle(thread);
            else
                stopped = false;
        }
        log.Fail(L"v5 cleanup race setup", ErrorText(error));
        CloseHandle(device);
        if (!stopped) return;
        CloseHandle(race->LaunchEvent);
        CloseHandle(race->RaceEvent);
        CloseHandle(race->ClosedEvent);
        CloseHandle(race->ReadyEvent);
        delete race;
        return;
    }
    (VOID)SetEvent(race->LaunchEvent);

    const DWORD ready = WaitForSingleObject(race->ReadyEvent, 15000);
    if (ready != WAIT_OBJECT_0)
        MarkV5RaceFailure(race, ready == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError());

    (VOID)SetEvent(race->RaceEvent);
    const BOOL closed = CloseHandle(device);
    if (!closed) MarkV5RaceFailure(race, GetLastError());
    (VOID)SetEvent(race->ClosedEvent);

    DWORD joined = WaitForMultipleObjects(
        static_cast<DWORD>(threads.size()),
        threads.data(),
        TRUE,
        15000);
    if (joined != WAIT_OBJECT_0)
    {
        for (HANDLE thread : threads) (VOID)CancelSynchronousIo(thread);
        joined = WaitForMultipleObjects(
            static_cast<DWORD>(threads.size()),
            threads.data(),
            TRUE,
            5000);
    }
    if (joined != WAIT_OBJECT_0)
    {
        log.Fail(L"v5 cleanup race joins", L"worker timeout; test state retained safely");
        return;
    }

    for (HANDLE thread : threads) CloseHandle(thread);
    CloseHandle(race->LaunchEvent);
    CloseHandle(race->RaceEvent);
    CloseHandle(race->ClosedEvent);
    CloseHandle(race->ReadyEvent);
    const LONG failures = InterlockedCompareExchange(&race->Failures, 0, 0);
    const LONG warmups = InterlockedCompareExchange(
        &race->WarmupSuccesses,
        0,
        0);
    const LONG finalSuccesses = InterlockedCompareExchange(
        &race->FinalSuccesses,
        0,
        0);
    const LONG expectedStops = InterlockedCompareExchange(
        &race->ExpectedStops,
        0,
        0);
    const LONG firstError = InterlockedCompareExchange(&race->FirstError, 0, 0);
    const OAC_V5_CLAIM_RESPONSE oldClaim = race->Claim;
    delete race;

    if (failures == 0 &&
        warmups == static_cast<LONG>(kV5RaceThreads * kV5RaceWarmups) &&
        finalSuccesses + expectedStops == static_cast<LONG>(kV5RaceThreads) &&
        expectedStops >= static_cast<LONG>(kV5RaceThreads / 2))
    {
        log.Pass(
            L"v5 bounded cleanup race",
            L"validated=" + std::to_wstring(warmups + finalSuccesses) +
                L" closed=" + std::to_wstring(expectedStops));
    }
    else
    {
        log.Fail(
            L"v5 bounded cleanup race",
            L"failures=" + std::to_wstring(failures) +
                L" error=" + std::to_wstring(firstError));
    }

    device = OpenDevice(&log);
    if (device == INVALID_HANDLE_VALUE) return;
    negotiate = ValidV5Negotiate();
    negotiated = {};
    claim = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
    claimed = {};
    if (NegotiateV5(device, negotiate, negotiated, error) &&
        ClaimV5(device, claim, claimed, error) &&
        claimed.Header.Generation > oldClaim.Header.Generation &&
        !OacV5SessionIdEqual(
            &claimed.Header.SessionId,
            &oldClaim.Header.SessionId))
    {
        log.Pass(L"v5 cleanup race advances generation");
    }
    else
    {
        log.Fail(L"v5 cleanup race advances generation", ErrorText(error));
    }
    CloseHandle(device);
}

void RunV5Tests(TestLog& log)
{
    DWORD returned = 0;
    DWORD error = ERROR_SUCCESS;

    HANDLE device = OpenDevice(&log);
    if (device == INVALID_HANDLE_VALUE) return;
    log.Pass(L"open v5 unnegotiated file");
    auto claimRequest = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
    OAC_V5_CLAIM_RESPONSE claimResponse{};
    ExpectIoctlFailure(
        log,
        device,
        L"v5 claim requires negotiation",
        IOCTL_OAC_V5_CLAIM_SESSION,
        &claimRequest,
        sizeof(claimRequest),
        &claimResponse,
        sizeof(claimResponse),
        {ERROR_BAD_COMMAND, ERROR_INVALID_STATE});
    CloseHandle(device);

    device = OpenDevice(&log);
    if (device == INVALID_HANDLE_VALUE) return;
    auto negotiateRequest = ValidV5Negotiate();
    OAC_V5_NEGOTIATE_RESPONSE negotiateResponse{};
    if (NegotiateV5(device, negotiateRequest, negotiateResponse, error))
    {
        log.Pass(L"v5 production-claim negotiation");
    }
    else
    {
        log.Fail(L"v5 production-claim negotiation", ErrorText(error));
    }
    claimRequest = ValidV5Claim(OAC_V5_SESSION_PRODUCTION);
    claimResponse = {};
    ExpectIoctlFailure(
        log,
        device,
        L"lab administrator cannot claim production session",
        IOCTL_OAC_V5_CLAIM_SESSION,
        &claimRequest,
        sizeof(claimRequest),
        &claimResponse,
        sizeof(claimResponse),
        {ERROR_ACCESS_DENIED});
    CloseHandle(device);

    device = OpenDevice(&log);
    if (device == INVALID_HANDLE_VALUE) return;
    log.Pass(L"open v5 diagnostic file");
    negotiateRequest = ValidV5Negotiate();
    negotiateResponse = {};
    ExpectIoctlFailure(
        log, device, L"v5 null negotiation", IOCTL_OAC_V5_NEGOTIATE,
        nullptr, 0, &negotiateResponse, sizeof(negotiateResponse),
        {ERROR_INVALID_PARAMETER});
    ExpectIoctlFailure(
        log, device, L"v5 truncated negotiation", IOCTL_OAC_V5_NEGOTIATE,
        &negotiateRequest, sizeof(negotiateRequest) - 1,
        &negotiateResponse, sizeof(negotiateResponse),
        {ERROR_INVALID_PARAMETER});
    std::array<std::byte, sizeof(OAC_V5_NEGOTIATE_REQUEST) + 1> largeNegotiate{};
    std::memcpy(largeNegotiate.data(), &negotiateRequest, sizeof(negotiateRequest));
    ExpectIoctlFailure(
        log, device, L"v5 oversized negotiation", IOCTL_OAC_V5_NEGOTIATE,
        largeNegotiate.data(), static_cast<DWORD>(largeNegotiate.size()),
        &negotiateResponse, sizeof(negotiateResponse),
        {ERROR_INVALID_PARAMETER});
    ExpectIoctlFailure(
        log, device, L"v5 undersized negotiation output", IOCTL_OAC_V5_NEGOTIATE,
        &negotiateRequest, sizeof(negotiateRequest),
        &negotiateResponse, sizeof(negotiateResponse) - 1,
        {ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA});

    auto badNegotiate = ValidV5Negotiate();
    badNegotiate.Header.Version = OAC_PROTOCOL_VERSION;
    ExpectIoctlFailure(
        log, device, L"v5 negotiation version", IOCTL_OAC_V5_NEGOTIATE,
        &badNegotiate, sizeof(badNegotiate), &negotiateResponse,
        sizeof(negotiateResponse), {ERROR_INVALID_PARAMETER});
    badNegotiate = ValidV5Negotiate();
    --badNegotiate.Header.Size;
    ExpectIoctlFailure(
        log, device, L"v5 negotiation stated size", IOCTL_OAC_V5_NEGOTIATE,
        &badNegotiate, sizeof(badNegotiate), &negotiateResponse,
        sizeof(negotiateResponse), {ERROR_INVALID_PARAMETER});
    badNegotiate = ValidV5Negotiate();
    badNegotiate.Header.RequestId = 0;
    ExpectIoctlFailure(
        log, device, L"v5 negotiation zero request ID", IOCTL_OAC_V5_NEGOTIATE,
        &badNegotiate, sizeof(badNegotiate), &negotiateResponse,
        sizeof(negotiateResponse), {ERROR_INVALID_PARAMETER});
    badNegotiate = ValidV5Negotiate();
    badNegotiate.Header.Flags = 1;
    ExpectIoctlFailure(
        log, device, L"v5 negotiation unknown flags", IOCTL_OAC_V5_NEGOTIATE,
        &badNegotiate, sizeof(badNegotiate), &negotiateResponse,
        sizeof(negotiateResponse), {ERROR_INVALID_PARAMETER});
    badNegotiate = ValidV5Negotiate();
    badNegotiate.Header.MessageType = OAC_V5_MESSAGE_CLAIM_SESSION;
    ExpectIoctlFailure(
        log, device, L"v5 negotiation wrong message type", IOCTL_OAC_V5_NEGOTIATE,
        &badNegotiate, sizeof(badNegotiate), &negotiateResponse,
        sizeof(negotiateResponse), {ERROR_INVALID_PARAMETER});
    badNegotiate = ValidV5Negotiate();
    badNegotiate.Header.SessionId.Low = 1;
    ExpectIoctlFailure(
        log, device, L"v5 negotiation session ID", IOCTL_OAC_V5_NEGOTIATE,
        &badNegotiate, sizeof(badNegotiate), &negotiateResponse,
        sizeof(negotiateResponse), {ERROR_INVALID_PARAMETER});
    badNegotiate = ValidV5Negotiate();
    badNegotiate.Header.Generation = 1;
    ExpectIoctlFailure(
        log, device, L"v5 negotiation generation", IOCTL_OAC_V5_NEGOTIATE,
        &badNegotiate, sizeof(badNegotiate), &negotiateResponse,
        sizeof(negotiateResponse), {ERROR_INVALID_PARAMETER});
    badNegotiate = ValidV5Negotiate();
    --badNegotiate.MaximumVersion;
    ExpectIoctlFailure(
        log, device, L"v5 unsupported negotiation range", IOCTL_OAC_V5_NEGOTIATE,
        &badNegotiate, sizeof(badNegotiate), &negotiateResponse,
        sizeof(negotiateResponse), {ERROR_INVALID_PARAMETER});

    negotiateRequest = ValidV5Negotiate();
    negotiateResponse = {};
    if (NegotiateV5(device, negotiateRequest, negotiateResponse, error) &&
        (negotiateResponse.Capabilities & OAC_V5_CAP_SESSION_CONTROL) != 0 &&
        (negotiateResponse.ProtocolFlags &
            (OAC_V5_PROTOCOL_STRICT_LENGTHS |
             OAC_V5_PROTOCOL_V4_DIAGNOSTIC)) ==
            (OAC_V5_PROTOCOL_STRICT_LENGTHS |
             OAC_V5_PROTOCOL_V4_DIAGNOSTIC))
    {
        log.Pass(L"v5 exact negotiation and correlation");
    }
    else
    {
        log.Fail(L"v5 exact negotiation and correlation", ErrorText(error));
    }

    auto legacyConfiguration = ValidConfiguration();
    ExpectIoctlFailure(
        log,
        device,
        L"v5 negotiation excludes v4 configuration",
        IOCTL_OAC_CONFIGURE,
        &legacyConfiguration,
        sizeof(legacyConfiguration),
        nullptr,
        0,
        {ERROR_BAD_COMMAND, ERROR_INVALID_STATE});

    claimRequest = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
    claimResponse = {};
    ExpectIoctlFailure(
        log, device, L"v5 truncated claim", IOCTL_OAC_V5_CLAIM_SESSION,
        &claimRequest, sizeof(claimRequest) - 1,
        &claimResponse, sizeof(claimResponse), {ERROR_INVALID_PARAMETER});
    std::array<std::byte, sizeof(OAC_V5_CLAIM_REQUEST) + 1> largeClaim{};
    std::memcpy(largeClaim.data(), &claimRequest, sizeof(claimRequest));
    ExpectIoctlFailure(
        log, device, L"v5 oversized claim", IOCTL_OAC_V5_CLAIM_SESSION,
        largeClaim.data(), static_cast<DWORD>(largeClaim.size()),
        &claimResponse, sizeof(claimResponse), {ERROR_INVALID_PARAMETER});
    ExpectIoctlFailure(
        log, device, L"v5 undersized claim output", IOCTL_OAC_V5_CLAIM_SESSION,
        &claimRequest, sizeof(claimRequest),
        &claimResponse, sizeof(claimResponse) - 1,
        {ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA});

    auto badClaim = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
    badClaim.Header.Version = OAC_PROTOCOL_VERSION;
    ExpectIoctlFailure(
        log, device, L"v5 claim version", IOCTL_OAC_V5_CLAIM_SESSION,
        &badClaim, sizeof(badClaim), &claimResponse, sizeof(claimResponse),
        {ERROR_INVALID_PARAMETER});
    badClaim = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
    --badClaim.Header.Size;
    ExpectIoctlFailure(
        log, device, L"v5 claim stated size", IOCTL_OAC_V5_CLAIM_SESSION,
        &badClaim, sizeof(badClaim), &claimResponse, sizeof(claimResponse),
        {ERROR_INVALID_PARAMETER});
    badClaim = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
    badClaim.Header.RequestId = 0;
    ExpectIoctlFailure(
        log, device, L"v5 claim zero request ID", IOCTL_OAC_V5_CLAIM_SESSION,
        &badClaim, sizeof(badClaim), &claimResponse, sizeof(claimResponse),
        {ERROR_INVALID_PARAMETER});
    badClaim = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
    badClaim.Header.Flags = 1;
    ExpectIoctlFailure(
        log, device, L"v5 claim unknown flags", IOCTL_OAC_V5_CLAIM_SESSION,
        &badClaim, sizeof(badClaim), &claimResponse, sizeof(claimResponse),
        {ERROR_INVALID_PARAMETER});
    badClaim = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
    badClaim.Header.MessageType = OAC_V5_MESSAGE_NEGOTIATE;
    ExpectIoctlFailure(
        log, device, L"v5 claim wrong message type", IOCTL_OAC_V5_CLAIM_SESSION,
        &badClaim, sizeof(badClaim), &claimResponse, sizeof(claimResponse),
        {ERROR_INVALID_PARAMETER});
    badClaim = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
    badClaim.Header.SessionId.High = 1;
    ExpectIoctlFailure(
        log, device, L"v5 claim session ID", IOCTL_OAC_V5_CLAIM_SESSION,
        &badClaim, sizeof(badClaim), &claimResponse, sizeof(claimResponse),
        {ERROR_INVALID_PARAMETER});
    badClaim = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
    badClaim.Header.Generation = 1;
    ExpectIoctlFailure(
        log, device, L"v5 claim generation", IOCTL_OAC_V5_CLAIM_SESSION,
        &badClaim, sizeof(badClaim), &claimResponse, sizeof(claimResponse),
        {ERROR_INVALID_PARAMETER});
    badClaim = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
    badClaim.Reserved = 1;
    ExpectIoctlFailure(
        log, device, L"v5 claim reserved payload", IOCTL_OAC_V5_CLAIM_SESSION,
        &badClaim, sizeof(badClaim), &claimResponse, sizeof(claimResponse),
        {ERROR_INVALID_PARAMETER});
    badClaim = ValidV5Claim(0);
    ExpectIoctlFailure(
        log, device, L"v5 claim mode", IOCTL_OAC_V5_CLAIM_SESSION,
        &badClaim, sizeof(badClaim), &claimResponse, sizeof(claimResponse),
        {ERROR_INVALID_PARAMETER});

    claimRequest = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
    claimResponse = {};
    if (ClaimV5(device, claimRequest, claimResponse, error) &&
        !OacV5SessionIdIsZero(&claimResponse.Header.SessionId) &&
        claimResponse.Header.Generation != 0 &&
        claimResponse.State == OAC_V5_SESSION_CLAIMED)
    {
        log.Pass(L"v5 diagnostic claim and response identity");
    }
    else
    {
        log.Fail(L"v5 diagnostic claim and response identity", ErrorText(error));
    }

    OAC_STATUS_RESPONSE legacyStatus{};
    ExpectIoctlFailure(
        log,
        device,
        L"v5 session excludes v4 status",
        IOCTL_OAC_GET_STATUS,
        nullptr,
        0,
        &legacyStatus,
        sizeof(legacyStatus),
        {ERROR_ACCESS_DENIED});

    auto repeatedClaim = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
    OAC_V5_CLAIM_RESPONSE repeatedResponse{};
    ExpectIoctlFailure(
        log, device, L"v5 claim twice on one file", IOCTL_OAC_V5_CLAIM_SESSION,
        &repeatedClaim, sizeof(repeatedClaim),
        &repeatedResponse, sizeof(repeatedResponse), {ERROR_BUSY});

    auto statusRequest = ValidV5Status(claimResponse);
    OAC_V5_STATUS_RESPONSE statusResponse{};
    ExpectIoctlFailure(
        log, device, L"v5 truncated status request", IOCTL_OAC_V5_GET_STATUS,
        &statusRequest, sizeof(statusRequest) - 1,
        &statusResponse, sizeof(statusResponse), {ERROR_INVALID_PARAMETER});
    std::array<std::byte, sizeof(OAC_V5_STATUS_REQUEST) + 1> largeStatus{};
    std::memcpy(largeStatus.data(), &statusRequest, sizeof(statusRequest));
    ExpectIoctlFailure(
        log, device, L"v5 oversized status request", IOCTL_OAC_V5_GET_STATUS,
        largeStatus.data(), static_cast<DWORD>(largeStatus.size()),
        &statusResponse, sizeof(statusResponse), {ERROR_INVALID_PARAMETER});
    ExpectIoctlFailure(
        log, device, L"v5 undersized status output", IOCTL_OAC_V5_GET_STATUS,
        &statusRequest, sizeof(statusRequest),
        &statusResponse, sizeof(statusResponse) - 1,
        {ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA});

    auto badStatus = ValidV5Status(claimResponse);
    badStatus.Header.Version = OAC_PROTOCOL_VERSION;
    ExpectIoctlFailure(
        log, device, L"v5 status version", IOCTL_OAC_V5_GET_STATUS,
        &badStatus, sizeof(badStatus), &statusResponse, sizeof(statusResponse),
        {ERROR_INVALID_PARAMETER});
    badStatus = ValidV5Status(claimResponse);
    --badStatus.Header.Size;
    ExpectIoctlFailure(
        log, device, L"v5 status stated size", IOCTL_OAC_V5_GET_STATUS,
        &badStatus, sizeof(badStatus), &statusResponse, sizeof(statusResponse),
        {ERROR_INVALID_PARAMETER});
    badStatus = ValidV5Status(claimResponse);
    badStatus.Header.RequestId = 0;
    ExpectIoctlFailure(
        log, device, L"v5 status zero request ID", IOCTL_OAC_V5_GET_STATUS,
        &badStatus, sizeof(badStatus), &statusResponse, sizeof(statusResponse),
        {ERROR_INVALID_PARAMETER});
    badStatus = ValidV5Status(claimResponse);
    badStatus.Header.Flags = 1;
    ExpectIoctlFailure(
        log, device, L"v5 status unknown flags", IOCTL_OAC_V5_GET_STATUS,
        &badStatus, sizeof(badStatus), &statusResponse, sizeof(statusResponse),
        {ERROR_INVALID_PARAMETER});
    badStatus = ValidV5Status(claimResponse);
    badStatus.Header.MessageType = OAC_V5_MESSAGE_RUN_SCAN;
    ExpectIoctlFailure(
        log, device, L"v5 status wrong message type", IOCTL_OAC_V5_GET_STATUS,
        &badStatus, sizeof(badStatus), &statusResponse, sizeof(statusResponse),
        {ERROR_INVALID_PARAMETER});
    badStatus = ValidV5Status(claimResponse);
    badStatus.Header.SessionId = {};
    ExpectIoctlFailure(
        log, device, L"v5 status zero session ID", IOCTL_OAC_V5_GET_STATUS,
        &badStatus, sizeof(badStatus), &statusResponse, sizeof(statusResponse),
        {ERROR_INVALID_PARAMETER});
    badStatus = ValidV5Status(claimResponse);
    badStatus.Header.Generation = 0;
    ExpectIoctlFailure(
        log, device, L"v5 status zero generation", IOCTL_OAC_V5_GET_STATUS,
        &badStatus, sizeof(badStatus), &statusResponse, sizeof(statusResponse),
        {ERROR_INVALID_PARAMETER});
    badStatus = ValidV5Status(claimResponse);
    ++badStatus.Header.SessionId.Low;
    ExpectIoctlFailure(
        log, device, L"v5 status stale session ID", IOCTL_OAC_V5_GET_STATUS,
        &badStatus, sizeof(badStatus), &statusResponse, sizeof(statusResponse),
        {ERROR_ACCESS_DENIED});
    badStatus = ValidV5Status(claimResponse);
    ++badStatus.Header.Generation;
    ExpectIoctlFailure(
        log, device, L"v5 status stale generation", IOCTL_OAC_V5_GET_STATUS,
        &badStatus, sizeof(badStatus), &statusResponse, sizeof(statusResponse),
        {ERROR_ACCESS_DENIED});

    statusRequest = ValidV5Status(claimResponse);
    statusResponse = {};
    const BOOL statusSucceeded = CallIoctl(
        device,
        IOCTL_OAC_V5_GET_STATUS,
        &statusRequest,
        sizeof(statusRequest),
        &statusResponse,
        sizeof(statusResponse),
        returned,
        error);
    if (statusSucceeded && returned == sizeof(statusResponse) &&
        OacV5ValidateStatusResponse(&statusResponse, returned) == OAC_V5_VALID &&
        OacV5ValidateCorrelation(
            &statusRequest.Header,
            &statusResponse.Header) == OAC_V5_VALID &&
        statusResponse.Header.Status == 0 &&
        statusResponse.Header.Reason == OAC_V5_REASON_NONE &&
        statusResponse.State == OAC_V5_SESSION_CLAIMED &&
        statusResponse.ServiceProcessId == GetCurrentProcessId() &&
        statusResponse.TargetProcessId == 0)
    {
        log.Pass(L"v5 exact status and correlation");
    }
    else
    {
        log.Fail(L"v5 exact status and correlation", ErrorText(error));
    }

    HANDLE second = OpenDevice(&log);
    if (second != INVALID_HANDLE_VALUE)
    {
        auto secondNegotiate = ValidV5Negotiate();
        OAC_V5_NEGOTIATE_RESPONSE secondNegotiated{};
        if (NegotiateV5(second, secondNegotiate, secondNegotiated, error))
            log.Pass(L"v5 second file may negotiate read-only");
        else
            log.Fail(L"v5 second file may negotiate read-only", ErrorText(error));

        auto secondClaim = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
        OAC_V5_CLAIM_RESPONSE secondClaimed{};
        ExpectIoctlFailure(
            log, second, L"v5 second file claim rejected",
            IOCTL_OAC_V5_CLAIM_SESSION, &secondClaim, sizeof(secondClaim),
            &secondClaimed, sizeof(secondClaimed), {ERROR_BUSY});
        auto copiedStatus = ValidV5Status(claimResponse);
        OAC_V5_STATUS_RESPONSE copiedResponse{};
        ExpectIoctlFailure(
            log, second, L"v5 copied session rejected on second file",
            IOCTL_OAC_V5_GET_STATUS, &copiedStatus, sizeof(copiedStatus),
            &copiedResponse, sizeof(copiedResponse), {ERROR_ACCESS_DENIED});
        CloseHandle(second);
    }

    (VOID)RunV5HandleContenderProcess(device, claimResponse, log);
    const OAC_V5_CLAIM_RESPONSE oldClaim = claimResponse;
    CloseHandle(device);

    device = OpenDevice(&log);
    if (device == INVALID_HANDLE_VALUE) return;
    auto staleStatus = ValidV5Status(oldClaim);
    OAC_V5_STATUS_RESPONSE staleResponse{};
    ExpectIoctlFailure(
        log, device, L"v5 closed file does not transfer authority",
        IOCTL_OAC_V5_GET_STATUS, &staleStatus, sizeof(staleStatus),
        &staleResponse, sizeof(staleResponse), {ERROR_ACCESS_DENIED});

    auto newNegotiate = ValidV5Negotiate();
    OAC_V5_NEGOTIATE_RESPONSE newNegotiated{};
    if (NegotiateV5(device, newNegotiate, newNegotiated, error))
        log.Pass(L"v5 replacement file negotiates after cleanup");
    else
        log.Fail(L"v5 replacement file negotiates after cleanup", ErrorText(error));
    auto newClaim = ValidV5Claim(OAC_V5_SESSION_DIAGNOSTIC);
    OAC_V5_CLAIM_RESPONSE newClaimed{};
    if (ClaimV5(device, newClaim, newClaimed, error) &&
        newClaimed.Header.Generation > oldClaim.Header.Generation &&
        !OacV5SessionIdEqual(
            &newClaimed.Header.SessionId,
            &oldClaim.Header.SessionId))
    {
        log.Pass(L"v5 new generation after cleanup");
    }
    else
    {
        log.Fail(L"v5 new generation after cleanup", ErrorText(error));
    }
    CloseHandle(device);
    RunV5CleanupRace(log);
    RunV5OwnerExitTest(log);
}

int RunTests()
{
    TestLog log;
    HANDLE device = OpenDevice(&log);
    if (device == INVALID_HANDLE_VALUE) return log.ExitCode();
    log.Pass(L"open device", kDevicePath);

    DWORD returned = 0;
    OAC_STATUS_RESPONSE ping{};
    BOOL succeeded = DeviceIoControl(
        device,
        IOCTL_OAC_PING,
        nullptr,
        0,
        &ping,
        sizeof(ping),
        &returned,
        nullptr);
    if (succeeded && returned == sizeof(ping) &&
        ping.Version == OAC_PROTOCOL_VERSION && ping.Size == sizeof(ping))
        log.Pass(L"versioned ping", L"protocol=0x" + std::to_wstring(ping.Version));
    else
        log.Fail(L"versioned ping", succeeded ? L"invalid response layout" : ErrorText(GetLastError()));

    std::uint8_t tinyOutput = 0;
    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_PING, nullptr, 0, &tinyOutput, sizeof(tinyOutput),
        &returned, nullptr);
    ExpectFailure(log, L"undersized ping output", succeeded, GetLastError(),
        {ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA});

    auto configuration = ValidConfiguration();
    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_CONFIGURE, &configuration, sizeof(configuration) - 1,
        nullptr, 0, &returned, nullptr);
    ExpectFailure(log, L"truncated configuration", succeeded, GetLastError(),
        {ERROR_BAD_LENGTH, ERROR_INVALID_PARAMETER, ERROR_INSUFFICIENT_BUFFER});

    configuration = ValidConfiguration();
    configuration.Version ^= 1;
    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_CONFIGURE, &configuration, sizeof(configuration),
        nullptr, 0, &returned, nullptr);
    ExpectFailure(log, L"invalid configuration version", succeeded, GetLastError(),
        {ERROR_INVALID_PARAMETER});

    configuration = ValidConfiguration();
    configuration.Reserved = 1;
    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_CONFIGURE, &configuration, sizeof(configuration),
        nullptr, 0, &returned, nullptr);
    ExpectFailure(log, L"nonzero configuration reserved field", succeeded, GetLastError(),
        {ERROR_INVALID_PARAMETER});

    configuration = ValidConfiguration();
    configuration.Flags |= 0x80000000UL;
    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_CONFIGURE, &configuration, sizeof(configuration),
        nullptr, 0, &returned, nullptr);
    ExpectFailure(log, L"unknown configuration flag", succeeded, GetLastError(),
        {ERROR_INVALID_PARAMETER});

    configuration = ValidConfiguration();
    configuration.Flags &= ~OAC_CONFIG_DRIVER_GATE;
    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_CONFIGURE, &configuration, sizeof(configuration),
        nullptr, 0, &returned, nullptr);
    ExpectFailure(log, L"missing mandatory driver-load gate", succeeded, GetLastError(),
        {ERROR_INVALID_PARAMETER});

    configuration = ValidConfiguration();
    ++configuration.ClientProcessId;
    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_CONFIGURE, &configuration, sizeof(configuration),
        nullptr, 0, &returned, nullptr);
    ExpectFailure(log, L"spoofed client identity", succeeded, GetLastError(),
        {ERROR_INVALID_PARAMETER, ERROR_ACCESS_DENIED});

    configuration = ValidConfiguration();
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_CONFIGURE, &configuration, sizeof(configuration),
        nullptr, 0, &returned, nullptr);
    if (succeeded)
        log.Pass(L"valid no-target diagnostic configuration");
    else
        log.Fail(L"valid configuration", ErrorText(GetLastError()));

    RunContenderProcess(log);
    HANDLE second = OpenDevice(&log);
    if (second != INVALID_HANDLE_VALUE)
    {
        OAC_STATUS_RESPONSE secondStatus{};
        SetLastError(ERROR_SUCCESS);
        succeeded = DeviceIoControl(
            second, IOCTL_OAC_GET_STATUS, nullptr, 0,
            &secondStatus, sizeof(secondStatus), &returned, nullptr);
        ExpectFailure(
            log,
            L"v4 status rejected on second file",
            succeeded,
            GetLastError(),
            {ERROR_ACCESS_DENIED});

        auto secondConfiguration = ValidConfiguration();
        SetLastError(ERROR_SUCCESS);
        succeeded = DeviceIoControl(
            second, IOCTL_OAC_CONFIGURE,
            &secondConfiguration, sizeof(secondConfiguration),
            nullptr, 0, &returned, nullptr);
        ExpectFailure(
            log,
            L"v4 configuration rejected on second file",
            succeeded,
            GetLastError(),
            {ERROR_BUSY});
        CloseHandle(second);
    }

    OAC_SCAN_REQUEST scan{};
    scan.Version = OAC_PROTOCOL_VERSION;
    scan.Size = sizeof(scan);
    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_RUN_KERNEL_SCAN, &scan, sizeof(scan) - 1,
        nullptr, 0, &returned, nullptr);
    ExpectFailure(log, L"truncated scan request", succeeded, GetLastError(),
        {ERROR_BAD_LENGTH, ERROR_INVALID_PARAMETER, ERROR_INSUFFICIENT_BUFFER});

    scan.Version ^= 1;
    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_RUN_KERNEL_SCAN, &scan, sizeof(scan),
        nullptr, 0, &returned, nullptr);
    ExpectFailure(log, L"invalid scan version", succeeded, GetLastError(),
        {ERROR_INVALID_PARAMETER});

    scan.Version = OAC_PROTOCOL_VERSION;
    scan.Reserved = 1;
    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_RUN_KERNEL_SCAN, &scan, sizeof(scan),
        nullptr, 0, &returned, nullptr);
    ExpectFailure(log, L"nonzero scan reserved field", succeeded, GetLastError(),
        {ERROR_INVALID_PARAMETER});

    scan.Reserved = 0;
    scan.Flags = 0x80000000UL;
    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_RUN_KERNEL_SCAN, &scan, sizeof(scan),
        nullptr, 0, &returned, nullptr);
    ExpectFailure(log, L"unknown scan flag", succeeded, GetLastError(),
        {ERROR_INVALID_PARAMETER});

    const DWORD unknownIoctl = CTL_CODE(
        FILE_DEVICE_UNKNOWN, 0x8ff, METHOD_BUFFERED, OAC_IOCTL_ACCESS);
    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, unknownIoctl, nullptr, 0, nullptr, 0, &returned, nullptr);
    ExpectFailure(log, L"unknown IOCTL", succeeded, GetLastError(),
        {ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED});

    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_GET_STATUS, nullptr, 0,
        &tinyOutput, sizeof(tinyOutput), &returned, nullptr);
    ExpectFailure(log, L"undersized status output", succeeded, GetLastError(),
        {ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA});

    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_GET_FINDINGS, nullptr, 0,
        &tinyOutput, sizeof(tinyOutput), &returned, nullptr);
    ExpectFailure(log, L"undersized findings output", succeeded, GetLastError(),
        {ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_INVALID_PARAMETER});

    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_CPU_SNAPSHOT, nullptr, 0,
        &tinyOutput, sizeof(tinyOutput), &returned, nullptr);
    ExpectFailure(log, L"undersized CPU output", succeeded, GetLastError(),
        {ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_INVALID_PARAMETER});

    OAC_STATUS_RESPONSE status{};
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_GET_STATUS, nullptr, 0,
        &status, sizeof(status), &returned, nullptr);
    if (succeeded && returned == sizeof(status) &&
        status.Version == OAC_PROTOCOL_VERSION && status.Size == sizeof(status) &&
        status.ClientProcessId == GetCurrentProcessId() &&
        status.ProtectedProcessId == 0 &&
        (status.Capabilities & OAC_CAP_DRIVER_GATE) != 0 &&
        (status.ConfigurationFlags & OAC_CONFIG_DRIVER_GATE) != 0 &&
        status.DriverGateTrips <= status.PostStartLoads)
    {
        log.Pass(L"status identity and layout", L"capabilities=" + std::to_wstring(status.Capabilities));
    }
    else
    {
        log.Fail(L"status identity and layout", succeeded ? L"invalid response" : ErrorText(GetLastError()));
    }

    std::vector<std::byte> cpuBuffer(size_t{64} * 1024);
    DWORD cpuError = ERROR_SUCCESS;
    for (;;)
    {
        returned = 0;
        succeeded = DeviceIoControl(
            device, IOCTL_OAC_CPU_SNAPSHOT, nullptr, 0,
            cpuBuffer.data(), static_cast<DWORD>(cpuBuffer.size()),
            &returned, nullptr);
        if (succeeded) break;
        cpuError = GetLastError();
        if ((cpuError != ERROR_INSUFFICIENT_BUFFER &&
             cpuError != ERROR_MORE_DATA) ||
            cpuBuffer.size() >= kMaximumCpuSnapshotBytes)
        {
            break;
        }
        cpuBuffer.resize(cpuBuffer.size() * 2);
    }
    if (succeeded && returned >= offsetof(OAC_CPU_RESPONSE, Records))
    {
        const auto* response = reinterpret_cast<const OAC_CPU_RESPONSE*>(cpuBuffer.data());
        const std::size_t expected = offsetof(OAC_CPU_RESPONSE, Records) +
            static_cast<std::size_t>(response->Count) * sizeof(OAC_CPU_RECORD);
        const std::size_t capacity =
            (cpuBuffer.size() - offsetof(OAC_CPU_RESPONSE, Records)) /
            sizeof(OAC_CPU_RECORD);
        if (response->Version == OAC_PROTOCOL_VERSION &&
            response->Size == returned && response->Size == expected &&
            response->Count != 0 && response->Count <= response->Capacity &&
            response->Capacity <= capacity)
            log.Pass(L"full CPU snapshot", L"processors=" + std::to_wstring(response->Count));
        else
            log.Fail(L"full CPU snapshot", L"invalid response bounds or metadata");
    }
    else
    {
        log.Fail(L"full CPU snapshot",
            succeeded ? L"short response" : ErrorText(cpuError));
    }

    scan = {};
    scan.Version = OAC_PROTOCOL_VERSION;
    scan.Size = sizeof(scan);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_RUN_KERNEL_SCAN, &scan, sizeof(scan),
        nullptr, 0, &returned, nullptr);
    if (succeeded)
        log.Pass(L"full kernel scan");
    else
        log.Fail(L"full kernel scan", ErrorText(GetLastError()));

    std::vector<std::byte> findingsBuffer(sizeof(OAC_FINDINGS_RESPONSE));
    std::size_t findingsRead = 0;
    unsigned findingBatches = 0;
    ULONG remainingFindings = 0;
    bool findingsValid = true;
    do
    {
        returned = 0;
        succeeded = DeviceIoControl(
            device, IOCTL_OAC_GET_FINDINGS, nullptr, 0,
            findingsBuffer.data(), static_cast<DWORD>(findingsBuffer.size()),
            &returned, nullptr);
        if (!succeeded || returned < offsetof(OAC_FINDINGS_RESPONSE, Findings))
        {
            log.Fail(L"finding retrieval",
                succeeded ? L"short response" : ErrorText(GetLastError()));
            findingsValid = false;
            break;
        }

        const auto* response = reinterpret_cast<const OAC_FINDINGS_RESPONSE*>(
            findingsBuffer.data());
        const std::size_t minimum = offsetof(OAC_FINDINGS_RESPONSE, Findings) +
            static_cast<std::size_t>(response->Count) * sizeof(OAC_FINDING);
        if (response->Version != OAC_PROTOCOL_VERSION ||
            response->Size != returned || response->Size < minimum ||
            response->Count > OAC_MAX_FINDINGS_PER_READ ||
            (response->Remaining != 0 && response->Count == 0))
        {
            log.Fail(L"finding retrieval", L"invalid response bounds or metadata");
            findingsValid = false;
            break;
        }

        findingsRead += response->Count;
        remainingFindings = response->Remaining;
        ++findingBatches;
        if (findingBatches >= 64 && remainingFindings != 0)
        {
            log.Fail(L"finding retrieval", L"drain exceeded the safety iteration limit");
            findingsValid = false;
            break;
        }
    } while (remainingFindings != 0);

    if (findingsValid)
    {
        log.Pass(L"finding retrieval", L"count=" + std::to_wstring(findingsRead) +
            L" batches=" + std::to_wstring(findingBatches));
    }

    CloseHandle(device);
    device = OpenDevice(&log);
    if (device == INVALID_HANDLE_VALUE) return log.ExitCode();

    status = {};
    SetLastError(ERROR_SUCCESS);
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_GET_STATUS, nullptr, 0,
        &status, sizeof(status), &returned, nullptr);
    ExpectFailure(
        log,
        L"v4 close revokes file authority",
        succeeded,
        GetLastError(),
        {ERROR_ACCESS_DENIED});

    configuration = ValidConfiguration();
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_CONFIGURE,
        &configuration, sizeof(configuration),
        nullptr, 0, &returned, nullptr);
    if (succeeded)
        log.Pass(L"v4 replacement file reclaims diagnostic session");
    else
        log.Fail(L"v4 replacement file reclaims diagnostic session", ErrorText(GetLastError()));

    status = {};
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_GET_STATUS, nullptr, 0,
        &status, sizeof(status), &returned, nullptr);
    if (succeeded && returned == sizeof(status) &&
        status.Version == OAC_PROTOCOL_VERSION &&
        status.Size == sizeof(status) &&
        status.ClientProcessId == GetCurrentProcessId() &&
        status.ProtectedProcessId == 0)
    {
        log.Pass(L"v4 replacement file owns fresh configuration");
    }
    else
    {
        log.Fail(
            L"v4 replacement file owns fresh configuration",
            succeeded ? L"invalid response" : ErrorText(GetLastError()));
    }
    CloseHandle(device);

    RunV4TombstoneTest(log);
    RunV5Tests(log);
    return log.ExitCode();
}
} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc >= 2 && std::wstring(argv[1]) == L"--v4-target")
        return RunV4Target(argc, argv);
    if (argc >= 2 && std::wstring(argv[1]) == L"--v5-contender")
        return RunV5HandleContender(argc, argv);
    if (argc >= 2 && std::wstring(argv[1]) == L"--v5-retained-owner")
        return RunV5RetainedOwner(argc, argv);
    if (argc >= 2 && std::wstring(argv[1]) == L"--v5-retained-holder")
        return RunV5RetainedHolder(argc, argv);
    if (argc == 2 && std::wstring(argv[1]) == L"--contender")
        return RunContender();
    if (argc != 1)
    {
        std::wcerr << L"Usage: OAC-Protocol-Test.exe [--contender]\n";
        return 64;
    }
    return RunTests();
}
