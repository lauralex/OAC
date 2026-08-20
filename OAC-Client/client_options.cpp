#include "client_options.hpp"

#include <limits>

namespace
{
constexpr DWORD kMinimumMonitorIntervalMs = 250;
constexpr DWORD kMaximumMonitorIntervalMs = 60000;

bool ParseSeverity(std::wstring_view text, FindingSeverity& severity) noexcept
{
    if (text == L"low") severity = FindingSeverity::Low;
    else if (text == L"medium") severity = FindingSeverity::Medium;
    else if (text == L"high") severity = FindingSeverity::High;
    else if (text == L"critical") severity = FindingSeverity::Critical;
    else return false;
    return true;
}

bool IsChallenge(std::wstring_view text) noexcept
{
    if (text.size() < 32 || text.size() > 128 || (text.size() & 1U) != 0)
        return false;

    for (const wchar_t character : text)
    {
        if (!((character >= L'0' && character <= L'9') ||
              (character >= L'a' && character <= L'f') ||
              (character >= L'A' && character <= L'F')))
            return false;
    }
    return true;
}
}

namespace oac::client
{
bool ParsePositiveDword(std::wstring_view text, DWORD& value) noexcept
{
    if (text.empty()) return false;

    DWORD parsed = 0;
    for (const wchar_t character : text)
    {
        if (character < L'0' || character > L'9') return false;
        const DWORD digit = static_cast<DWORD>(character - L'0');
        if (parsed > (std::numeric_limits<DWORD>::max() - digit) / 10)
            return false;
        parsed = parsed * 10 + digit;
    }
    if (parsed == 0) return false;

    value = parsed;
    return true;
}

bool ParseOptions(
    std::span<const std::wstring_view> arguments,
    ScanOptions& options)
{
    for (size_t index = 0; index < arguments.size(); ++index)
    {
        const std::wstring_view argument = arguments[index];
        if (argument == L"--pid" && index + 1 < arguments.size())
        {
            if (!ParsePositiveDword(arguments[++index], options.targetProcessId))
                return false;
        }
        else if (argument == L"--preflight") options.preflightOnly = true;
        else if (argument == L"--monitor") options.monitor = true;
        else if (argument == L"--launch" && index + 1 < arguments.size())
            options.launchExecutable = std::wstring(arguments[++index]);
        else if (argument == L"--launch-args" && index + 1 < arguments.size())
            options.launchArguments = arguments[++index];
        else if (argument == L"--monitor-interval-ms" &&
                 index + 1 < arguments.size())
        {
            if (!ParsePositiveDword(
                    arguments[++index], options.monitorIntervalMs) ||
                options.monitorIntervalMs < kMinimumMonitorIntervalMs ||
                options.monitorIntervalMs > kMaximumMonitorIntervalMs)
                return false;
        }
        else if (argument == L"--apply-hardening") options.applyHardening = true;
        else if (argument == L"--verbose-handles") options.verboseHandles = true;
        else if (argument == L"--no-private-kernel-traces")
            options.privateKernelTraces = false;
        else if (argument == L"--require-hvci") options.requireHvci = true;
        else if (argument == L"--mode" && index + 1 < arguments.size())
        {
            const std::wstring_view mode = arguments[++index];
            if (mode == L"audit") options.deploymentMode = DeploymentMode::Audit;
            else if (mode == L"test") options.deploymentMode = DeploymentMode::Test;
            else if (mode == L"production")
                options.deploymentMode = DeploymentMode::Production;
            else return false;
        }
        else if (argument == L"--fail-on" && index + 1 < arguments.size())
        {
            if (!ParseSeverity(arguments[++index], options.failureThreshold))
                return false;
        }
        else if (argument == L"--challenge" && index + 1 < arguments.size())
        {
            options.challenge = arguments[++index];
            if (!IsChallenge(options.challenge)) return false;
        }
        else if (argument == L"--output" && index + 1 < arguments.size())
        {
            const std::wstring_view directory = arguments[++index];
            if (directory.empty()) return false;
            options.outputDirectory = std::wstring(directory);
        }
        else return false;
    }

    if (options.preflightOnly &&
        (options.targetProcessId != 0 || !options.launchExecutable.empty() ||
         options.monitor))
        return false;
    if (!options.launchExecutable.empty() && options.targetProcessId != 0)
        return false;
    if (options.launchExecutable.empty() && !options.launchArguments.empty())
        return false;
    if (!options.launchExecutable.empty()) options.monitor = true;
    if (options.monitor && options.targetProcessId == 0 &&
        options.launchExecutable.empty())
        return false;
    return true;
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
}
