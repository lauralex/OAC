#pragma once

#include <Windows.h>

#include <string>
#include <string_view>

namespace oac
{
struct FileTrustReport
{
    std::wstring Path;
    std::wstring BaseName;
    std::string AuthenticodeSha256;
    LONG TrustStatus = TRUST_E_NOSIGNATURE;
    bool UnderWindowsDirectory = false;
};

struct DriverTrustReport : FileTrustReport
{
    bool DeniedFamily = false;
    bool DeniedHash = false;
    bool ReviewFamily = false;
};

DWORD NormalizeFilePath(
    std::wstring_view reportedPath,
    std::wstring& normalized) noexcept;

DWORD EvaluateFileTrust(
    std::wstring_view reportedPath,
    FileTrustReport& report) noexcept;

DWORD EvaluateLockedFileTrust(
    HANDLE file,
    FileTrustReport& report) noexcept;

[[nodiscard]] bool FileTrustAccepted(
    const FileTrustReport& report) noexcept;

DWORD EvaluateDriverTrust(
    std::wstring_view reportedPath,
    DriverTrustReport& report) noexcept;

[[nodiscard]] bool DriverTrustAccepted(
    const DriverTrustReport& report) noexcept;
} // namespace oac
