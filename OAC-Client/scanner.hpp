#pragma once

#include <Windows.h>

#include <cstdint>
#include <filesystem>
#include <set>
#include <string>
#include <vector>

#include "..\shared\oac_windows.hpp"

enum class FindingSeverity : std::uint8_t
{
    Info,
    Low,
    Medium,
    High,
    Critical
};

enum class DeploymentMode : std::uint8_t
{
    Audit,
    Test,
    Production
};

struct ClientFinding
{
    FindingSeverity severity = FindingSeverity::Info;
    std::wstring category;
    std::wstring message;
    DWORD processId = 0;
    DWORD threadId = 0;
    unsigned long long address = 0;
    unsigned long long sequence = 0;
    unsigned long long timestamp100ns = 0;
    unsigned long long originSequence = 0;
    unsigned long long originTimestamp100ns = 0;
};

class Reporter
{
public:
    Reporter(
        FindingSeverity failureThreshold = FindingSeverity::Medium,
        std::wstring deploymentMode = L"audit",
        std::wstring challenge = L"");

    void Add(
        FindingSeverity severity,
        const std::wstring& category,
        const std::wstring& message,
        DWORD processId = 0,
        DWORD threadId = 0,
        unsigned long long address = 0,
        unsigned long long originSequence = 0,
        unsigned long long originTimestamp100ns = 0);

    bool Save(const std::filesystem::path& path) const;
    const std::vector<ClientFinding>& Findings() const noexcept;
    size_t SuspiciousCount() const noexcept;
    size_t SuspiciousCountSince(size_t firstFinding) const noexcept;

private:
    std::vector<ClientFinding> findings_;
    FindingSeverity failureThreshold_;
    std::wstring deploymentMode_;
    std::wstring challenge_;
    std::vector<unsigned char> runId_;
    std::set<std::wstring> findingKeys_;
    unsigned long long nextSequence_ = 1;
};

struct ScanOptions
{
    DWORD targetProcessId = 0;
    bool verboseHandles = false;
    bool applyHardening = false;
    bool privateKernelTraces = true;
    bool requireHvci = false;
    bool preflightOnly = false;
    bool monitor = false;
    DWORD monitorIntervalMs = 250;
    DeploymentMode deploymentMode = DeploymentMode::Audit;
    FindingSeverity failureThreshold = FindingSeverity::Medium;
    std::wstring challenge;
    std::filesystem::path outputDirectory = L".";
    std::filesystem::path launchExecutable;
    std::wstring launchArguments;
};

bool RunDriverScan(const ScanOptions& options, Reporter& reporter);
bool PollDriverSession(
    const ScanOptions& options,
    Reporter& reporter,
    bool runKernelScan);
void ScanHardwareIdentity(Reporter& reporter);
void ScanPlatformSecurity(const ScanOptions& options, Reporter& reporter);
void RunSystemScan(const ScanOptions& options, Reporter& reporter);
void ScanLoadedDriverPolicy(const ScanOptions& options, Reporter& reporter);
void ScanTargetHandlePolicy(const ScanOptions& options, Reporter& reporter);
void RunProcessScan(const ScanOptions& options, Reporter& reporter);
std::wstring QueryProcessImagePath(DWORD processId);
bool IsTrustedWindowsImagePath(const std::wstring& path);
