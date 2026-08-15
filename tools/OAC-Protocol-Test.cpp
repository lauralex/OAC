#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <string>
#include <vector>

#include "..\shared\oac_protocol.h"

namespace
{
constexpr wchar_t kDevicePath[] = L"\\\\.\\OAC";

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
        0,
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
    request.ProtectedProcessId = GetCurrentProcessId();
    request.ClientProcessId = GetCurrentProcessId();
    request.Flags = OAC_CONFIG_PROTECT_PROCESS |
        OAC_CONFIG_ENABLE_IMAGE_LOG |
        OAC_CONFIG_DRIVER_GATE;
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
    if (!succeeded && error == ERROR_ACCESS_DENIED)
    {
        std::wcout << L"[PASS] contender takeover rejected - " << ErrorText(error) << L'\n';
        return 0;
    }
    std::wcerr << L"[FAIL] contender takeover was not rejected with access denied; success="
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
            TRUE,
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
        log.Pass(L"valid configuration", L"self-protected PID=" + std::to_wstring(GetCurrentProcessId()));
    else
        log.Fail(L"valid configuration", ErrorText(GetLastError()));

    CloseHandle(device);
    RunContenderProcess(log);
    device = OpenDevice(&log);
    if (device == INVALID_HANDLE_VALUE) return log.ExitCode();

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
        status.ProtectedProcessId == GetCurrentProcessId() &&
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
    succeeded = DeviceIoControl(
        device, IOCTL_OAC_CPU_SNAPSHOT, nullptr, 0,
        cpuBuffer.data(), static_cast<DWORD>(cpuBuffer.size()), &returned, nullptr);
    if (succeeded && returned >= offsetof(OAC_CPU_RESPONSE, Records))
    {
        const auto* response = reinterpret_cast<const OAC_CPU_RESPONSE*>(cpuBuffer.data());
        const std::size_t expected = offsetof(OAC_CPU_RESPONSE, Records) +
            static_cast<std::size_t>(response->Count) * sizeof(OAC_CPU_RECORD);
        if (response->Version == OAC_PROTOCOL_VERSION &&
            response->Size == returned && response->Size == expected &&
            response->Count != 0 && response->Count <= response->Capacity)
            log.Pass(L"full CPU snapshot", L"processors=" + std::to_wstring(response->Count));
        else
            log.Fail(L"full CPU snapshot", L"invalid response bounds or metadata");
    }
    else
    {
        log.Fail(L"full CPU snapshot", succeeded ? L"short response" : ErrorText(GetLastError()));
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
    return log.ExitCode();
}
} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2 && std::wstring(argv[1]) == L"--contender")
        return RunContender();
    if (argc != 1)
    {
        std::wcerr << L"Usage: OAC-Protocol-Test.exe [--contender]\n";
        return 64;
    }
    return RunTests();
}
