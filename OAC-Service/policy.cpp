#include "policy.hpp"

#include <Windows.h>

#include <array>
#include <cstring>
#include <string>

#include "..\shared\oac_ipc.h"
#include "..\shared\protocol\oac_v5.h"
#include "signed_record.hpp"

namespace
{
constexpr wchar_t kPolicyFileName[] = L"OAC.policy";
constexpr wchar_t kPolicySignatureFileName[] = L"OAC.policy.p7s";
constexpr wchar_t kPolicySignerValue[] = L"PolicySignerSha256";
constexpr wchar_t kPolicyStatePath[] = L"SOFTWARE\\OAC\\PolicyState";
constexpr wchar_t kPolicyStateValue[] = L"HighWater";

class RegistryKey
{
public:
    ~RegistryKey()
    {
        if (value_ != nullptr) RegCloseKey(value_);
    }
    RegistryKey(const RegistryKey&) = delete;
    RegistryKey& operator=(const RegistryKey&) = delete;
    RegistryKey() = default;
    HKEY* put() noexcept { return &value_; }
    [[nodiscard]] HKEY get() const noexcept { return value_; }

private:
    HKEY value_ = nullptr;
};

DWORD ModuleDirectory(std::wstring& directory)
{
    std::wstring path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0) return GetLastError();
    if (length >= static_cast<DWORD>(path.size()))
        return ERROR_INSUFFICIENT_BUFFER;
    path.resize(length);
    const size_t slash = path.find_last_of(L'\\');
    if (slash == std::wstring::npos || slash == 0)
        return ERROR_INVALID_NAME;
    directory.assign(path, 0, slash);
    return ERROR_SUCCESS;
}

DWORD ApplyUpdateProtection(
    const OAC_SIGNED_POLICY& policy,
    const std::array<unsigned char, OAC_POLICY_HASH_SIZE>& digest)
{
    RegistryKey root;
    LONG status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        kPolicyStatePath,
        0,
        KEY_CREATE_SUB_KEY,
        root.put());
    if (status != ERROR_SUCCESS)
    {
        return static_cast<DWORD>(status);
    }

    const std::wstring keyName =
        oac::HexIdentity(policy.GameId, sizeof(policy.GameId)) + L"-" +
        oac::HexIdentity(policy.ChannelId, sizeof(policy.ChannelId));
    if (keyName.size() != 65)
    {
        return ERROR_INVALID_DATA;
    }
    RegistryKey scope;
    status = RegOpenKeyExW(
        root.get(), keyName.c_str(), 0, KEY_QUERY_VALUE | KEY_SET_VALUE,
        scope.put());
    const bool scopeExists = status == ERROR_SUCCESS;
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND)
    {
        return static_cast<DWORD>(status);
    }

    OAC_POLICY_CACHE_STATE current{};
    DWORD type = 0;
    DWORD size = sizeof(current);
    if (scopeExists)
    {
        status = RegQueryValueExW(
            scope.get(), kPolicyStateValue, nullptr, &type,
            reinterpret_cast<BYTE*>(&current), &size);
        if (status != ERROR_SUCCESS)
            return static_cast<DWORD>(status);
        if (type != REG_BINARY || size != sizeof(current))
            return ERROR_INVALID_DATA;
    }

    OAC_POLICY_CACHE_STATE next{};
    const OAC_POLICY_UPDATE_DECISION decision = OacPolicyEvaluateUpdate(
        &policy,
        digest.data(),
        scopeExists ? &current : nullptr,
        scopeExists ? 1 : 0,
        &next);
    if (decision == OAC_POLICY_UPDATE_REJECT_REPLAY ||
        decision == OAC_POLICY_UPDATE_REJECT_ROLLBACK ||
        decision == OAC_POLICY_UPDATE_REJECT_EQUIVOCATION ||
        decision == OAC_POLICY_UPDATE_INVALID_STATE)
    {
        return ERROR_ACCESS_DISABLED_BY_POLICY;
    }
    if (decision == OAC_POLICY_UPDATE_ACCEPT_NEW ||
        decision == OAC_POLICY_UPDATE_ACCEPT_ROLLBACK)
    {
        if (!scopeExists)
        {
            DWORD disposition = 0;
            status = RegCreateKeyExW(
                root.get(), keyName.c_str(), 0, nullptr,
                REG_OPTION_NON_VOLATILE, KEY_QUERY_VALUE | KEY_SET_VALUE,
                nullptr, scope.put(), &disposition);
            if (status != ERROR_SUCCESS)
                return static_cast<DWORD>(status);
            if (disposition != REG_CREATED_NEW_KEY)
                return ERROR_INVALID_STATE;
        }
        status = RegSetValueExW(
            scope.get(), kPolicyStateValue, 0, REG_BINARY,
            reinterpret_cast<const BYTE*>(&next), sizeof(next));
        if (status == ERROR_SUCCESS) status = RegFlushKey(scope.get());
        if (status != ERROR_SUCCESS)
        {
            return static_cast<DWORD>(status);
        }
    }

    OAC_POLICY_CACHE_STATE observed{};
    type = 0;
    size = sizeof(observed);
    status = RegQueryValueExW(
        scope.get(), kPolicyStateValue, nullptr, &type,
        reinterpret_cast<BYTE*>(&observed), &size);
    if (status != ERROR_SUCCESS || type != REG_BINARY ||
        size != sizeof(observed) ||
        std::memcmp(&observed, &next, sizeof(next)) != 0)
    {
        return status == ERROR_SUCCESS
            ? ERROR_INVALID_DATA
            : static_cast<DWORD>(status);
    }
    return ERROR_SUCCESS;
}
} // namespace

namespace oac
{
DWORD LoadPolicy(VerifiedPolicy& verified)
{
    verified = {};
    std::wstring directory;
    DWORD error = ModuleDirectory(directory);
    if (error != ERROR_SUCCESS) return error;
    const std::wstring policyPath = directory + L"\\" + kPolicyFileName;
    const std::wstring signaturePath =
        directory + L"\\" + kPolicySignatureFileName;

    VerifiedSignedRecord signedRecord;
    error = VerifySignedRecord(
        policyPath,
        signaturePath,
        static_cast<DWORD>(sizeof(OAC_SIGNED_POLICY)),
        kPolicySignerValue,
        signedRecord);
    if (error != ERROR_SUCCESS) return error;
    if (signedRecord.Bytes.size() != sizeof(verified.Record))
        return ERROR_INVALID_DATA;
    std::memcpy(
        &verified.Record, signedRecord.Bytes.data(), sizeof(verified.Record));
    verified.Digest = signedRecord.Digest;
    if (std::memcmp(
            verified.Record.SigningKeyId,
            signedRecord.SignerDigest.data(),
            signedRecord.SignerDigest.size()) != 0)
    {
        return ERROR_ACCESS_DISABLED_BY_POLICY;
    }

    const OAC_SIGNED_POLICY_VALIDATION validation = OacSignedPolicyValidate(
        &verified.Record,
        sizeof(verified.Record),
        CurrentUnixSeconds(),
        OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION,
        OAC_IPC_PROTOCOL_REVISION);
    if (validation != OAC_SIGNED_POLICY_VALID)
    {
        return ERROR_ACCESS_DISABLED_BY_POLICY;
    }

    error = ApplyUpdateProtection(verified.Record, verified.Digest);
    if (error != ERROR_SUCCESS) return error;
    if ((verified.Record.Flags & OAC_SIGNED_POLICY_EMERGENCY_REVOKE) != 0)
    {
        return ERROR_ACCESS_DISABLED_BY_POLICY;
    }
    return ERROR_SUCCESS;
}

bool PolicyScopeMatchesManifest(
    const VerifiedPolicy& policy,
    const OAC_GAME_MANIFEST& manifest) noexcept
{
    return OacSignedPolicyScopeMatches(
        &policy.Record, manifest.GameId, manifest.BuildId) != 0;
}

bool PolicyHasExpiredNow(const VerifiedPolicy& policy) noexcept
{
    const ULONGLONG nowUnixSeconds = CurrentUnixSeconds();
    return nowUnixSeconds == 0 ||
        (policy.Record.ExpiresAtUnixSeconds < nowUnixSeconds &&
         nowUnixSeconds - policy.Record.ExpiresAtUnixSeconds >
            OAC_POLICY_CLOCK_SKEW_SECONDS);
}
}
