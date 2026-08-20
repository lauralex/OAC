#include "oac_driver_trust.hpp"

#include <bcrypt.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>
#include <wintrust.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <iomanip>
#include <new>
#include <ranges>
#include <sstream>
#include <string>
#include <vector>

#include "oac_driver_policy.h"
#include "oac_windows.hpp"

namespace
{
using oac::UniqueHandle;

#include "oac_driver_hash_policy.hpp"

using AcquireContext2Fn = BOOL(WINAPI*)(
    HCATADMIN*, const GUID*, LPCWSTR, PCCERT_STRONG_SIGN_PARA, DWORD);
using CalculateHash2Fn = BOOL(WINAPI*)(
    HCATADMIN, HANDLE, DWORD*, BYTE*, DWORD);

bool RewindFile(HANDLE file) noexcept
{
    LARGE_INTEGER beginning{};
    return SetFilePointerEx(file, beginning, nullptr, FILE_BEGIN) != FALSE;
}

bool StartsWithIgnoreCase(
    std::wstring_view value,
    std::wstring_view prefix) noexcept
{
    if (value.size() < prefix.size()) return false;
    const auto asciiLower = [](wchar_t character) noexcept
    {
        return character >= L'A' && character <= L'Z'
            ? static_cast<wchar_t>(character - L'A' + L'a')
            : character;
    };
    return std::equal(
        prefix.begin(),
        prefix.end(),
        value.begin(),
        [asciiLower](wchar_t expected, wchar_t actual) noexcept
        {
            return asciiLower(expected) == asciiLower(actual);
        });
}

std::wstring DevicePathToDosPath(std::wstring_view path)
{
    std::array<wchar_t, 512> mapping{};
    for (wchar_t drive = L'A'; drive <= L'Z'; ++drive)
    {
        const wchar_t deviceName[] = {drive, L':', L'\0'};
        const DWORD length = QueryDosDeviceW(
            deviceName,
            mapping.data(),
            static_cast<DWORD>(mapping.size()));
        if (length == 0) continue;
        const std::wstring_view target(mapping.data());
        if (!StartsWithIgnoreCase(path, target) ||
            (path.size() > target.size() && path[target.size()] != L'\\'))
        {
            continue;
        }
        std::wstring result(deviceName);
        result.append(path.substr(target.size()));
        return result;
    }
    return {};
}

DWORD NormalizeFilePathImpl(
    std::wstring_view reportedPath,
    std::wstring& normalized)
{
    normalized.clear();
    if (reportedPath.empty() || reportedPath.size() >= 32768)
        return ERROR_INVALID_NAME;

    std::array<wchar_t, MAX_PATH + 1> windows{};
    const UINT windowsLength = GetWindowsDirectoryW(
        windows.data(), static_cast<UINT>(windows.size()));
    if (windowsLength == 0 || windowsLength >= windows.size())
    {
        const DWORD error = GetLastError();
        return error == ERROR_SUCCESS ? ERROR_INSUFFICIENT_BUFFER : error;
    }

    if (StartsWithIgnoreCase(reportedPath, L"\\SystemRoot\\"))
    {
        normalized.assign(windows.data(), windowsLength);
        normalized.append(reportedPath.substr(11));
    }
    else if (StartsWithIgnoreCase(reportedPath, L"\\??\\"))
    {
        normalized.assign(reportedPath.substr(4));
    }
    else if (StartsWithIgnoreCase(reportedPath, L"\\Windows\\"))
    {
        if (windowsLength < 2 || windows[1] != L':') return ERROR_INVALID_NAME;
        normalized.assign(windows.data(), 2);
        normalized.append(reportedPath);
    }
    else if (StartsWithIgnoreCase(reportedPath, L"\\Device\\"))
    {
        normalized = DevicePathToDosPath(reportedPath);
        if (normalized.empty()) return ERROR_PATH_NOT_FOUND;
    }
    else
    {
        normalized.assign(reportedPath);
    }

    if (normalized.size() < 3 || normalized[1] != L':' ||
        normalized[2] != L'\\')
    {
        normalized.clear();
        return ERROR_INVALID_NAME;
    }

    std::vector<wchar_t> fullPath(32768);
    const DWORD fullLength = GetFullPathNameW(
        normalized.c_str(),
        static_cast<DWORD>(fullPath.size()),
        fullPath.data(),
        nullptr);
    if (fullLength == 0 || fullLength >= fullPath.size())
    {
        normalized.clear();
        return fullLength == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
    }
    normalized.assign(fullPath.data(), fullLength);
    return ERROR_SUCCESS;
}

bool PathIsUnderWindowsDirectory(const std::wstring& path) noexcept
{
    std::array<wchar_t, MAX_PATH + 1> windows{};
    const UINT length = GetWindowsDirectoryW(
        windows.data(), static_cast<UINT>(windows.size()));
    if (length == 0 || length >= windows.size() || path.size() <= length)
        return false;
    return _wcsnicmp(path.data(), windows.data(), length) == 0 &&
        path[length] == L'\\';
}

DWORD ResolveLockedPath(HANDLE file, std::wstring& resolved)
{
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetFinalPathNameByHandleW(
        file,
        buffer.data(),
        static_cast<DWORD>(buffer.size()),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (length == 0 || length >= buffer.size())
        return length == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;

    std::wstring_view path(buffer.data(), length);
    constexpr std::wstring_view prefix = L"\\\\?\\";
    if (path.starts_with(prefix)) path.remove_prefix(prefix.size());
    if (path.size() < 3 || path[1] != L':' || path[2] != L'\\')
        return ERROR_INVALID_NAME;
    resolved.assign(path);
    return ERROR_SUCCESS;
}

LONG VerifyEmbeddedTrust(
    HANDLE file,
    const std::wstring& path) noexcept
{
    if (!RewindFile(file)) return static_cast<LONG>(TRUST_E_NOSIGNATURE);

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();
    fileInfo.hFile = file;

    WINTRUST_DATA trust{};
    trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &fileInfo;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL |
        WTD_REVOCATION_CHECK_NONE;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &action, &trust);
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)WinVerifyTrust(nullptr, &action, &trust);
    return status;
}

LONG VerifyCatalogTrust(
    HANDLE file,
    const std::wstring& path)
{
    const HMODULE wintrust = GetModuleHandleW(L"wintrust.dll");
    const auto acquireContext2 = oac::ResolveFunction<AcquireContext2Fn>(
        wintrust, "CryptCATAdminAcquireContext2");
    const auto calculateHash2 = oac::ResolveFunction<CalculateHash2Fn>(
        wintrust, "CryptCATAdminCalcHashFromFileHandle2");
    HCATADMIN administrator = nullptr;
    bool modern = acquireContext2 != nullptr && calculateHash2 != nullptr;
    GUID driverAction = DRIVER_ACTION_VERIFY;
    BOOL acquired = modern
        ? acquireContext2(
            &administrator, nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0)
        : CryptCATAdminAcquireContext(&administrator, &driverAction, 0);
    if (!acquired && modern)
    {
        modern = false;
        acquired = CryptCATAdminAcquireContext(
            &administrator, &driverAction, 0);
    }
    if (!acquired) return static_cast<LONG>(TRUST_E_NOSIGNATURE);

    const auto calculateHash = [&](DWORD* size, BYTE* buffer) noexcept -> BOOL
    {
        if (!RewindFile(file)) return FALSE;
        return modern
            ? calculateHash2(administrator, file, size, buffer, 0)
            : CryptCATAdminCalcHashFromFileHandle(
                file, size, buffer, 0);
    };
    DWORD hashSize = 0;
    if (!calculateHash(&hashSize, nullptr) || hashSize == 0 || hashSize > 1024)
    {
        CryptCATAdminReleaseContext(administrator, 0);
        return static_cast<LONG>(TRUST_E_NOSIGNATURE);
    }
    std::vector<BYTE> hash(hashSize);
    if (!calculateHash(&hashSize, hash.data()) || hashSize == 0 ||
        hashSize > hash.size())
    {
        CryptCATAdminReleaseContext(administrator, 0);
        return static_cast<LONG>(TRUST_E_NOSIGNATURE);
    }
    hash.resize(hashSize);

    HCATINFO catalog = CryptCATAdminEnumCatalogFromHash(
        administrator, hash.data(), hashSize, 0, nullptr);
    LONG status = static_cast<LONG>(TRUST_E_NOSIGNATURE);
    for (unsigned attempt = 0; catalog != nullptr && attempt != 128; ++attempt)
    {
        CATALOG_INFO catalogInfo{};
        catalogInfo.cbStruct = sizeof(catalogInfo);
        if (CryptCATCatalogInfoFromContext(catalog, &catalogInfo, 0))
        {
            std::wostringstream tag;
            for (const BYTE value : hash)
            {
                tag << std::uppercase << std::hex << std::setw(2)
                    << std::setfill(L'0') << static_cast<unsigned>(value);
            }
            const std::wstring memberTag = tag.str();
            WINTRUST_CATALOG_INFO member{};
            member.cbStruct = sizeof(member);
            member.pcwszCatalogFilePath = catalogInfo.wszCatalogFile;
            member.pcwszMemberTag = memberTag.c_str();
            member.pcwszMemberFilePath = path.c_str();
            member.hMemberFile = file;

            WINTRUST_DATA trust{};
            trust.cbStruct = sizeof(trust);
            trust.dwUIChoice = WTD_UI_NONE;
            trust.fdwRevocationChecks = WTD_REVOKE_NONE;
            trust.dwUnionChoice = WTD_CHOICE_CATALOG;
            trust.pCatalog = &member;
            trust.dwStateAction = WTD_STATEACTION_VERIFY;
            trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL |
                WTD_REVOCATION_CHECK_NONE;
            GUID action = DRIVER_ACTION_VERIFY;
            status = WinVerifyTrust(nullptr, &action, &trust);
            trust.dwStateAction = WTD_STATEACTION_CLOSE;
            (void)WinVerifyTrust(nullptr, &action, &trust);
            if (status == ERROR_SUCCESS) break;
        }

        HCATINFO previous = catalog;
        catalog = CryptCATAdminEnumCatalogFromHash(
            administrator, hash.data(), hashSize, 0, &previous);
    }
    if (catalog != nullptr)
        CryptCATAdminReleaseCatalogContext(administrator, catalog, 0);
    CryptCATAdminReleaseContext(administrator, 0);
    return status;
}

std::string CalculateAuthenticodeSha256(HANDLE file)
{
    const HMODULE wintrust = GetModuleHandleW(L"wintrust.dll");
    const auto acquireContext2 = oac::ResolveFunction<AcquireContext2Fn>(
        wintrust, "CryptCATAdminAcquireContext2");
    const auto calculateHash2 = oac::ResolveFunction<CalculateHash2Fn>(
        wintrust, "CryptCATAdminCalcHashFromFileHandle2");
    if (acquireContext2 == nullptr || calculateHash2 == nullptr) return {};

    HCATADMIN administrator = nullptr;
    if (!acquireContext2(
            &administrator, nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0))
    {
        return {};
    }
    DWORD size = 0;
    std::array<BYTE, 32> hash{};
    if (!RewindFile(file) ||
        !calculateHash2(administrator, file, &size, nullptr, 0) ||
        size != hash.size() ||
        !RewindFile(file) ||
        !calculateHash2(administrator, file, &size, hash.data(), 0) ||
        size != hash.size())
    {
        CryptCATAdminReleaseContext(administrator, 0);
        return {};
    }
    CryptCATAdminReleaseContext(administrator, 0);

    static constexpr char alphabet[] = "0123456789ABCDEF";
    std::string text(hash.size() * 2, '0');
    for (size_t index = 0; index != hash.size(); ++index)
    {
        text[index * 2] = alphabet[hash[index] >> 4];
        text[index * 2 + 1] = alphabet[hash[index] & 0x0f];
    }
    return text;
}

DWORD EvaluateLockedFileTrustImpl(
    HANDLE file,
    oac::FileTrustReport& report)
{
    if (file == nullptr || file == INVALID_HANDLE_VALUE)
        return ERROR_INVALID_HANDLE;

    oac::FileTrustReport result{};
    DWORD error = ResolveLockedPath(file, result.Path);
    if (error != ERROR_SUCCESS) return error;
    result.BaseName = oac::Lowercase(
        std::filesystem::path(result.Path).filename().wstring());
    if (result.BaseName.empty()) return ERROR_INVALID_NAME;
    result.UnderWindowsDirectory = PathIsUnderWindowsDirectory(result.Path);
    result.AuthenticodeSha256 = CalculateAuthenticodeSha256(file);
    const LONG embedded = VerifyEmbeddedTrust(file, result.Path);
    result.TrustStatus = embedded == ERROR_SUCCESS
        ? embedded
        : VerifyCatalogTrust(file, result.Path);
    report = std::move(result);
    return ERROR_SUCCESS;
}
} // namespace

namespace oac
{
DWORD NormalizeFilePath(
    std::wstring_view reportedPath,
    std::wstring& normalized) noexcept
{
    try
    {
        return NormalizeFilePathImpl(reportedPath, normalized);
    }
    catch (const std::bad_alloc&)
    {
        normalized.clear();
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    catch (...)
    {
        normalized.clear();
        return ERROR_UNHANDLED_EXCEPTION;
    }
}

DWORD EvaluateFileTrust(
    std::wstring_view reportedPath,
    FileTrustReport& report) noexcept
{
    try
    {
        std::wstring normalized;
        DWORD error = NormalizeFilePath(reportedPath, normalized);
        if (error != ERROR_SUCCESS) return error;
        UniqueHandle stabilityLock(CreateFileW(
            normalized.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr));
        if (!stabilityLock) return GetLastError();
        return EvaluateLockedFileTrustImpl(stabilityLock.get(), report);
    }
    catch (const std::bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    catch (...)
    {
        return ERROR_UNHANDLED_EXCEPTION;
    }
}

DWORD EvaluateLockedFileTrust(
    HANDLE file,
    FileTrustReport& report) noexcept
{
    try
    {
        return EvaluateLockedFileTrustImpl(file, report);
    }
    catch (const std::bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    catch (...)
    {
        return ERROR_UNHANDLED_EXCEPTION;
    }
}

bool FileTrustAccepted(const FileTrustReport& report) noexcept
{
    return report.TrustStatus == ERROR_SUCCESS &&
        !report.AuthenticodeSha256.empty();
}

DWORD EvaluateDriverTrust(
    std::wstring_view reportedPath,
    DriverTrustReport& report) noexcept
{
    try
    {
        DriverTrustReport result{};
        FileTrustReport file{};
        const DWORD error = EvaluateFileTrust(reportedPath, file);
        if (error != ERROR_SUCCESS) return error;
        static_cast<FileTrustReport&>(result) = std::move(file);

        static constexpr std::wstring_view deniedFamilies[] =
            {OAC_DRIVER_DENY_BASENAMES_W};
        static constexpr std::wstring_view reviewFamilies[] =
            {OAC_DRIVER_REVIEW_BASENAMES_W};
        result.DeniedFamily =
            std::ranges::find(deniedFamilies, result.BaseName) !=
                std::end(deniedFamilies);
        result.ReviewFamily =
            std::ranges::find(reviewFamilies, result.BaseName) !=
                std::end(reviewFamilies);
        result.DeniedHash = !result.AuthenticodeSha256.empty() &&
            std::ranges::binary_search(
                kOacDeniedDriverAuthenticodeSha256,
                std::string_view(result.AuthenticodeSha256));
        report = std::move(result);
        return ERROR_SUCCESS;
    }
    catch (const std::bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    catch (...)
    {
        return ERROR_UNHANDLED_EXCEPTION;
    }
}

bool DriverTrustAccepted(const DriverTrustReport& report) noexcept
{
    return FileTrustAccepted(report) &&
        !report.DeniedFamily && !report.DeniedHash &&
        !report.ReviewFamily;
}
} // namespace oac
