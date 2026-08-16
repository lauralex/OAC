#include "scanner.hpp"

#include <Windows.h>

#include <cstdint>
#include <exception>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace
{
constexpr DWORD kMinimumMonitorIntervalMs = 250;
constexpr DWORD kMaximumMonitorIntervalMs = 60000;
constexpr ULONGLONG kDriverRescanMs = 2000;
constexpr ULONGLONG kKernelRescanIntervalMs = 15000;
constexpr ULONGLONG kTargetRescanIntervalMs = 30000;
constexpr ULONGLONG kReportCheckpointIntervalMs = 30000;
constexpr UINT kRevokedProcessExitCode = 0xE0AC0001U;

class UniqueHandle
{
public:
    explicit UniqueHandle(HANDLE handle = nullptr) noexcept : handle_(handle) {}
    ~UniqueHandle() { reset(); }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.release()) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept
    {
        if (this != &other) reset(other.release());
        return *this;
    }

    HANDLE get() const noexcept { return handle_; }
    explicit operator bool() const noexcept
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

struct LaunchedTarget
{
    UniqueHandle process;
    UniqueHandle initialThread;
    DWORD processId = 0;
    bool suspended = false;
};

enum class MonitorOutcome : std::uint8_t
{
    TargetExited,
    Revoked,
    Failed
};

void PrintUsage()
{
    std::wcout
        << L"Usage:\n"
        << L"  OAC-Client.exe --preflight [options]\n"
        << L"  OAC-Client.exe --pid <process-id> [--monitor] [options]\n"
        << L"  OAC-Client.exe --launch <executable> [--launch-args <text>] [options]\n"
        << L"Options:\n"
        << L"  --preflight                Scan global state without starting/protecting a game\n"
        << L"  --launch <executable>      Preflight, create suspended, protect, then monitor\n"
        << L"  --launch-args <text>       Command-line arguments for --launch\n"
        << L"  --monitor                  Keep protecting and rescanning an existing PID\n"
        << L"  --monitor-interval-ms <n>  Telemetry poll interval, 250-60000 (default: 250)\n"
        << L"  --apply-hardening          Patch DbgUiRemoteBreakin and set ThreadHideFromDebugger\n"
        << L"  --verbose-handles          Request per-handle kernel telemetry (large output)\n"
        << L"  --no-private-kernel-traces Skip build-gated MmUnloadedDrivers/PiDDB checks\n"
        << L"  --mode <audit|test|production>  Select deployment policy (default: audit)\n"
        << L"  --fail-on <low|medium|high|critical>  Exit/revoke at this severity\n"
        << L"  --require-hvci             Treat inactive HVCI as an explicit policy failure\n"
        << L"  --challenge <hex>          Bind the report to a server-issued 16-64 byte nonce\n"
        << L"  --output <directory>       Report/inventory output directory\n";
}

std::wstring DeploymentModeName(DeploymentMode mode)
{
    switch (mode)
    {
    case DeploymentMode::Test: return L"test";
    case DeploymentMode::Production: return L"production";
    default: return L"audit";
    }
}

bool ParseSeverity(const std::wstring& text, FindingSeverity& severity)
{
    if (text == L"low") severity = FindingSeverity::Low;
    else if (text == L"medium") severity = FindingSeverity::Medium;
    else if (text == L"high") severity = FindingSeverity::High;
    else if (text == L"critical") severity = FindingSeverity::Critical;
    else return false;
    return true;
}

bool ParseChallenge(const std::wstring& text)
{
    if (text.size() < 32 || text.size() > 128 || (text.size() & 1) != 0) return false;
    for (const wchar_t character : text)
        if (!((character >= L'0' && character <= L'9') ||
              (character >= L'a' && character <= L'f') ||
              (character >= L'A' && character <= L'F')))
            return false;
    return true;
}

bool ParseUnsigned(const wchar_t* text, DWORD& value)
{
    if (text == nullptr || *text == L'\0') return false;
    DWORD parsed = 0;
    for (const wchar_t* current = text; *current != L'\0'; ++current)
    {
        if (*current < L'0' || *current > L'9') return false;
        const DWORD digit = static_cast<DWORD>(*current - L'0');
        if (parsed > (MAXDWORD - digit) / 10) return false;
        parsed = parsed * 10 + digit;
    }
    if (parsed == 0) return false;
    value = parsed;
    return true;
}

bool ParseOptions(int argumentCount, wchar_t** arguments, ScanOptions& options)
{
    for (int index = 1; index < argumentCount; ++index)
    {
        const std::wstring argument = arguments[index];
        if (argument == L"--pid" && index + 1 < argumentCount)
        {
            if (!ParseUnsigned(arguments[++index], options.targetProcessId)) return false;
        }
        else if (argument == L"--preflight") options.preflightOnly = true;
        else if (argument == L"--monitor") options.monitor = true;
        else if (argument == L"--launch" && index + 1 < argumentCount)
            options.launchExecutable = arguments[++index];
        else if (argument == L"--launch-args" && index + 1 < argumentCount)
            options.launchArguments = arguments[++index];
        else if (argument == L"--monitor-interval-ms" && index + 1 < argumentCount)
        {
            if (!ParseUnsigned(arguments[++index], options.monitorIntervalMs) ||
                options.monitorIntervalMs < kMinimumMonitorIntervalMs ||
                options.monitorIntervalMs > kMaximumMonitorIntervalMs)
                return false;
        }
        else if (argument == L"--apply-hardening") options.applyHardening = true;
        else if (argument == L"--verbose-handles") options.verboseHandles = true;
        else if (argument == L"--no-private-kernel-traces") options.privateKernelTraces = false;
        else if (argument == L"--require-hvci") options.requireHvci = true;
        else if (argument == L"--mode" && index + 1 < argumentCount)
        {
            const std::wstring mode = arguments[++index];
            if (mode == L"audit") options.deploymentMode = DeploymentMode::Audit;
            else if (mode == L"test") options.deploymentMode = DeploymentMode::Test;
            else if (mode == L"production") options.deploymentMode = DeploymentMode::Production;
            else return false;
        }
        else if (argument == L"--fail-on" && index + 1 < argumentCount)
        {
            if (!ParseSeverity(arguments[++index], options.failureThreshold)) return false;
        }
        else if (argument == L"--challenge" && index + 1 < argumentCount)
        {
            options.challenge = arguments[++index];
            if (!ParseChallenge(options.challenge)) return false;
        }
        else if (argument == L"--output" && index + 1 < argumentCount)
        {
            options.outputDirectory = arguments[++index];
            if (options.outputDirectory.empty()) return false;
        }
        else return false;
    }

    if (options.preflightOnly &&
        (options.targetProcessId != 0 || !options.launchExecutable.empty() || options.monitor))
        return false;
    if (!options.launchExecutable.empty() && options.targetProcessId != 0) return false;
    if (options.launchExecutable.empty() && !options.launchArguments.empty()) return false;
    if (!options.launchExecutable.empty()) options.monitor = true;
    if (options.monitor && options.targetProcessId == 0 && options.launchExecutable.empty())
        return false;
    return true;
}

bool IsAdministrator()
{
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;
    BOOL member = FALSE;
    if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators))
    {
        (void)CheckTokenMembership(nullptr, administrators, &member);
        FreeSid(administrators);
    }
    return member == TRUE;
}

std::wstring LastErrorText(DWORD error)
{
    wchar_t* raw = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, 0, reinterpret_cast<wchar_t*>(&raw), 0, nullptr);
    std::wstring text = length != 0 && raw != nullptr
        ? std::wstring(raw, length)
        : L"Win32 error " + std::to_wstring(error);
    if (raw != nullptr) LocalFree(raw);
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n'))
        text.pop_back();
    return text;
}

bool LaunchSuspended(
    const ScanOptions& options,
    Reporter& reporter,
    LaunchedTarget& target)
{
    std::error_code pathError;
    const std::filesystem::path executable = std::filesystem::absolute(
        options.launchExecutable, pathError);
    if (pathError || !std::filesystem::is_regular_file(executable, pathError) || pathError)
    {
        reporter.Add(FindingSeverity::Critical, L"launcher",
            L"Launch executable is unavailable: " + options.launchExecutable.wstring());
        return false;
    }

    std::wstring commandLine = L"\"" + executable.wstring() + L"\"";
    if (!options.launchArguments.empty()) commandLine += L" " + options.launchArguments;
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const std::wstring workingDirectory = executable.parent_path().wstring();
    if (!CreateProcessW(
            executable.c_str(), mutableCommand.data(), nullptr, nullptr, FALSE,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, nullptr,
            workingDirectory.empty() ? nullptr : workingDirectory.c_str(),
            &startup, &process))
    {
        reporter.Add(FindingSeverity::Critical, L"launcher",
            L"CreateProcessW(CREATE_SUSPENDED) failed: " +
                LastErrorText(GetLastError()));
        return false;
    }

    target.process.reset(process.hProcess);
    target.initialThread.reset(process.hThread);
    target.processId = process.dwProcessId;
    target.suspended = true;
    reporter.Add(FindingSeverity::Info, L"launcher",
        L"Created target suspended pending OAC protection and clean-state gate",
        target.processId);
    return true;
}

bool RevokeTarget(HANDLE process, DWORD processId, Reporter& reporter,
    const std::wstring& reason)
{
    reporter.Add(FindingSeverity::Critical, L"enforcement",
        L"Protected session revoked: " + reason, processId);
    if (!TerminateProcess(process, kRevokedProcessExitCode))
    {
        reporter.Add(FindingSeverity::Critical, L"enforcement",
            L"TerminateProcess failed while revoking the protected session: " +
                LastErrorText(GetLastError()), processId);
        return false;
    }
    (void)WaitForSingleObject(process, 5000);
    return true;
}

MonitorOutcome MonitorTarget(
    HANDLE process,
    const ScanOptions& options,
    Reporter& reporter,
    const std::filesystem::path& reportPath)
{
    ULONGLONG nextKernelScan = GetTickCount64() + kKernelRescanIntervalMs;
    ULONGLONG nextTargetScan = GetTickCount64() + kTargetRescanIntervalMs;
    ULONGLONG nextLoadedDriverScan =
        GetTickCount64() + kDriverRescanMs;
    ULONGLONG nextCheckpoint = GetTickCount64() + kReportCheckpointIntervalMs;

    reporter.Add(FindingSeverity::Info, L"monitor",
        L"Continuous demand-start protection is active; interval=" +
            std::to_wstring(options.monitorIntervalMs) + L" ms",
        options.targetProcessId);

    for (;;)
    {
        const DWORD wait = WaitForSingleObject(process, options.monitorIntervalMs);
        if (wait == WAIT_OBJECT_0)
        {
            DWORD exitCode = 0;
            (void)GetExitCodeProcess(process, &exitCode);
            reporter.Add(FindingSeverity::Info, L"monitor",
                L"Protected target exited; exit-code=" + std::to_wstring(exitCode),
                options.targetProcessId);
            return MonitorOutcome::TargetExited;
        }
        if (wait != WAIT_TIMEOUT)
        {
            reporter.Add(FindingSeverity::Critical, L"monitor",
                L"Target wait failed: " + LastErrorText(GetLastError()),
                options.targetProcessId);
            return MonitorOutcome::Failed;
        }

        const ULONGLONG now = GetTickCount64();
        const bool runKernelScan = now >= nextKernelScan;
        if (runKernelScan) nextKernelScan = now + kKernelRescanIntervalMs;
        const size_t firstFinding = reporter.Findings().size();
        const bool driverHealthy = PollDriverSession(options, reporter, runKernelScan);
        if (now >= nextLoadedDriverScan)
        {
            ScanLoadedDriverPolicy(options, reporter);
            nextLoadedDriverScan = now + kDriverRescanMs;
        }
        if (now >= nextTargetScan)
        {
            RunProcessScan(options, reporter);
            nextTargetScan = now + kTargetRescanIntervalMs;
        }

        const bool newActionable = reporter.SuspiciousCountSince(firstFinding) != 0;
        if (!driverHealthy ||
            (newActionable && options.deploymentMode == DeploymentMode::Production))
        {
            if (options.deploymentMode == DeploymentMode::Production)
            {
                const std::wstring reason = !driverHealthy
                    ? L"kernel monitor lost integrity or telemetry"
                    : L"a new finding reached the configured enforcement threshold";
                (void)RevokeTarget(process, options.targetProcessId, reporter, reason);
                (void)reporter.Save(reportPath);
                return MonitorOutcome::Revoked;
            }
            if (!driverHealthy) return MonitorOutcome::Failed;
        }

        if (now >= nextCheckpoint)
        {
            if (!reporter.Save(reportPath))
            {
                reporter.Add(FindingSeverity::Critical, L"monitor",
                    L"Atomic report checkpoint failed", options.targetProcessId);
                if (options.deploymentMode == DeploymentMode::Production)
                {
                    (void)RevokeTarget(process, options.targetProcessId, reporter,
                        L"the evidence checkpoint could not be persisted");
                    return MonitorOutcome::Revoked;
                }
                return MonitorOutcome::Failed;
            }
            nextCheckpoint = now + kReportCheckpointIntervalMs;
        }
    }
}
} // namespace

int wmain(int argumentCount, wchar_t** arguments)
{
    for (int index = 1; index < argumentCount; ++index)
    {
        if (std::wstring(arguments[index]) == L"--help" ||
            std::wstring(arguments[index]) == L"-h")
        {
            PrintUsage();
            return 0;
        }
    }

    ScanOptions options;
    if (!ParseOptions(argumentCount, arguments, options))
    {
        if (argumentCount > 1) PrintUsage();
        return argumentCount > 1 ? 2 : 0;
    }
    if (options.deploymentMode == DeploymentMode::Production)
    {
        std::wcerr << L"OAC-Client is a lab-only compatibility tool. "
                      L"Use OAC-Launcher and OACService for production control.\n";
        return 2;
    }

    if (options.targetProcessId == 0 && !options.preflightOnly &&
        options.launchExecutable.empty())
    {
        std::wcout << L"Target process ID: ";
        std::wstring input;
        std::getline(std::wcin, input);
        if (!ParseUnsigned(input.c_str(), options.targetProcessId))
        {
            std::wcerr << L"Invalid process ID.\n";
            return 2;
        }
    }

    std::error_code directoryError;
    std::filesystem::create_directories(options.outputDirectory, directoryError);
    if (directoryError)
    {
        std::wcerr << L"Unable to create output directory: "
                   << directoryError.value() << L'\n';
        return 2;
    }
    const auto reportPath = options.outputDirectory / L"oac-report.txt";

    std::wcout << L"OAC demand-start defensive anti-cheat\n"
               << L"The driver is deliberately not boot-start. Every protected launch uses a "
                  L"complete current-state gate before execution is allowed.\n";
    if (options.applyHardening)
        std::wcout << L"Hardening mode is enabled: the target process will be modified.\n";

    Reporter reporter(options.failureThreshold,
        DeploymentModeName(options.deploymentMode), options.challenge);
    reporter.Add(FindingSeverity::Info, L"policy",
        L"Deployment mode=" + DeploymentModeName(options.deploymentMode) +
            L"; HVCI required=" + (options.requireHvci ? std::wstring(L"true") : L"false") +
            L"; server challenge=" +
                (options.challenge.empty() ? std::wstring(L"absent") : L"present") +
            L"; driver start=demand");
    reporter.Add(FindingSeverity::Info, L"policy",
        L"OAC enforcement is independent of the host HVCI and Microsoft vulnerable-driver "
        L"blocklist settings; those controls are defense-in-depth telemetry unless explicitly required");
    if (options.deploymentMode == DeploymentMode::Production && options.challenge.empty())
        reporter.Add(FindingSeverity::Medium, L"policy",
            L"Production scan has no server-issued challenge and is replayable");
    if (!IsAdministrator())
        reporter.Add(FindingSeverity::High, L"client",
            L"Client is not elevated; several system and target checks will be incomplete");

    bool internalFailure = false;
    bool revoked = false;
    LaunchedTarget launched;
    UniqueHandle existingMonitorProcess;

    try
    {
        if (options.preflightOnly || !options.launchExecutable.empty())
        {
            ScanOptions preflight = options;
            preflight.targetProcessId = 0;
            preflight.monitor = false;
            const size_t preflightStart = 0;
            const bool driverHealthy = RunDriverScan(preflight, reporter);
            RunSystemScan(preflight, reporter);

            if (options.preflightOnly)
            {
                reporter.Add(driverHealthy ? FindingSeverity::Info : FindingSeverity::Critical,
                    L"preflight",
                    driverHealthy
                        ? L"Demand-start global preflight completed without creating a target"
                        : L"Demand-start global preflight was incomplete because the kernel session was unhealthy");
            }
            else if (!driverHealthy ||
                reporter.SuspiciousCountSince(preflightStart) != 0)
            {
                reporter.Add(FindingSeverity::Critical, L"preflight",
                    L"Target launch refused because the complete current-state gate was not clean");
            }
            else if (!LaunchSuspended(options, reporter, launched))
            {
                internalFailure = true;
            }
            else
            {
                options.targetProcessId = launched.processId;
            }
        }

        const bool shouldScanTarget = !options.preflightOnly &&
            options.targetProcessId != 0 &&
            (options.launchExecutable.empty() || launched.processId != 0);
        if (shouldScanTarget)
        {
            HANDLE monitorProcess = nullptr;
            if (launched.process)
            {
                monitorProcess = launched.process.get();
            }
            else if (options.monitor)
            {
                DWORD access = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
                if (options.deploymentMode == DeploymentMode::Production)
                    access |= PROCESS_TERMINATE;
                existingMonitorProcess.reset(OpenProcess(
                    access, FALSE, options.targetProcessId));
                monitorProcess = existingMonitorProcess.get();
                if (!existingMonitorProcess)
                {
                    reporter.Add(FindingSeverity::Critical, L"monitor",
                        L"Unable to hold the target process for monitoring: " +
                            LastErrorText(GetLastError()), options.targetProcessId);
                    internalFailure = true;
                }
            }

            const size_t targetGateStart = 0;
            const bool driverHealthy = RunDriverScan(options, reporter);
            if (launched.process)
            {
                ScanLoadedDriverPolicy(options, reporter);
                ScanTargetHandlePolicy(options, reporter);
            }
            else
                RunSystemScan(options, reporter);
            RunProcessScan(options, reporter);

            const bool targetGateClean = driverHealthy &&
                reporter.SuspiciousCountSince(targetGateStart) == 0;
            if (launched.process && !targetGateClean)
            {
                revoked = true;
                (void)RevokeTarget(launched.process.get(), options.targetProcessId,
                    reporter, L"the suspended target failed its protected-process gate");
                launched.suspended = false;
            }
            else if (launched.process)
            {
                const DWORD previous = ResumeThread(launched.initialThread.get());
                if (previous == MAXDWORD)
                {
                    internalFailure = true;
                    revoked = true;
                    (void)RevokeTarget(launched.process.get(), options.targetProcessId,
                        reporter, L"the initial thread could not be resumed safely");
                }
                else
                {
                    launched.suspended = false;
                    launched.initialThread.reset();
                    reporter.Add(FindingSeverity::Info, L"launcher",
                        L"Clean-state gate passed; target initial thread resumed",
                        options.targetProcessId);
                }
            }

            if (!revoked && options.monitor && monitorProcess != nullptr)
            {
                if (!targetGateClean &&
                    options.deploymentMode == DeploymentMode::Production)
                {
                    revoked = true;
                    (void)RevokeTarget(monitorProcess, options.targetProcessId,
                        reporter, L"the initial production scan was actionable");
                }
                else
                {
                    const MonitorOutcome outcome = MonitorTarget(
                        monitorProcess, options, reporter, reportPath);
                    revoked = outcome == MonitorOutcome::Revoked;
                    internalFailure = internalFailure || outcome == MonitorOutcome::Failed;
                }
            }
        }
    }
    catch (const std::exception& error)
    {
        internalFailure = true;
        std::wstring message = L"Scan aborted by a C++ exception: ";
        const char* text = error.what();
        while (text != nullptr && *text != '\0')
            message.push_back(static_cast<unsigned char>(*text++));
        reporter.Add(FindingSeverity::Critical, L"client", message);
        if (launched.suspended && launched.process)
            (void)RevokeTarget(launched.process.get(), launched.processId, reporter,
                L"the launcher failed while the target was suspended");
    }
    catch (...)
    {
        internalFailure = true;
        reporter.Add(FindingSeverity::Critical, L"client",
            L"Scan aborted by an unknown exception");
        if (launched.suspended && launched.process)
            (void)RevokeTarget(launched.process.get(), launched.processId, reporter,
                L"the launcher failed while the target was suspended");
    }

    if (!reporter.Save(reportPath))
    {
        std::wcerr << L"Failed to write report: " << reportPath << L'\n';
        return 3;
    }

    std::error_code absoluteError;
    const auto absoluteReport = std::filesystem::absolute(reportPath, absoluteError);
    std::wcout << L"\nOAC complete: " << reporter.Findings().size() << L" unique findings, "
               << reporter.SuspiciousCount() << L" actionable at the configured threshold.\n"
               << L"Report: " << (absoluteError ? reportPath : absoluteReport) << L'\n';
    if (internalFailure) return 4;
    if (revoked) return 5;
    return reporter.SuspiciousCount() == 0 ? 0 : 1;
}
