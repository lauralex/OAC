#include "policy.hpp"

#include <Windows.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <new>
#include <string>
#include <vector>

#include "backend.hpp"
#include "..\shared\oac_ipc.h"
#include "..\shared\oac_windows.hpp"
#include "..\shared\protocol\oac_v5.h"
#include "signed_record.hpp"

namespace
{
using oac::RegistryKey;

constexpr wchar_t kPolicyFileName[] = L"OAC.policy";
constexpr wchar_t kPolicySignatureFileName[] = L"OAC.policy.p7s";
constexpr wchar_t kPolicySignerValue[] = L"PolicySignerSha256";
constexpr wchar_t kPolicyStatePath[] = L"SOFTWARE\\OAC\\PolicyState";
constexpr wchar_t kPolicyStateValue[] = L"HighWater";
constexpr const wchar_t* kCachedPolicyValues[] =
{
    L"RemotePolicyA",
    L"RemotePolicyB"
};
constexpr const wchar_t* kCachedSignatureValues[] =
{
    L"RemotePolicySignatureA",
    L"RemotePolicySignatureB"
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

std::wstring PolicyScopeName(const OAC_SIGNED_POLICY& policy)
{
    return oac::HexIdentity(policy.GameId, sizeof(policy.GameId)) + L"-" +
        oac::HexIdentity(policy.ChannelId, sizeof(policy.ChannelId));
}

DWORD OpenPolicyScope(
    const OAC_SIGNED_POLICY& policy,
    REGSAM access,
    bool create,
    RegistryKey& scope)
{
    const std::wstring keyName = PolicyScopeName(policy);
    if (keyName.size() != 65) return ERROR_INVALID_DATA;
    RegistryKey root;
    LONG status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        kPolicyStatePath,
        0,
        create ? KEY_CREATE_SUB_KEY : KEY_READ,
        root.put());
    if (status != ERROR_SUCCESS) return static_cast<DWORD>(status);
    if (!create)
    {
        status = RegOpenKeyExW(
            root.get(), keyName.c_str(), 0, access, scope.put());
        return static_cast<DWORD>(status);
    }
    DWORD disposition = 0;
    status = RegCreateKeyExW(
        root.get(), keyName.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
        access, nullptr, scope.put(), &disposition);
    return static_cast<DWORD>(status);
}

DWORD ReadPolicyState(
    HKEY scope,
    bool& exists,
    OAC_POLICY_CACHE_STATE& state)
{
    exists = false;
    state = {};
    DWORD type = 0;
    DWORD size = sizeof(state);
    LONG status = RegQueryValueExW(
        scope, kPolicyStateValue, nullptr, &type,
        reinterpret_cast<BYTE*>(&state), &size);
    if (status == ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;
    if (status != ERROR_SUCCESS) return static_cast<DWORD>(status);
    if (type != REG_BINARY || size != sizeof(state) ||
        !OacPolicyCacheStateValid(&state))
    {
        state = {};
        return ERROR_INVALID_DATA;
    }
    exists = true;
    return ERROR_SUCCESS;
}

DWORD WritePolicyState(HKEY scope, const OAC_POLICY_CACHE_STATE& state)
{
    LONG status = RegSetValueExW(
        scope, kPolicyStateValue, 0, REG_BINARY,
        reinterpret_cast<const BYTE*>(&state), sizeof(state));
    if (status == ERROR_SUCCESS) status = RegFlushKey(scope);
    return static_cast<DWORD>(status);
}

DWORD ReadBinaryValue(
    HKEY scope,
    const wchar_t* name,
    DWORD maximumSize,
    bool& exists,
    std::vector<unsigned char>& bytes)
{
    exists = false;
    bytes.clear();
    DWORD type = 0;
    DWORD size = 0;
    LONG status = RegGetValueW(
        scope, nullptr, name, RRF_RT_REG_BINARY, &type, nullptr, &size);
    if (status == ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;
    if (status != ERROR_SUCCESS) return static_cast<DWORD>(status);
    if (type != REG_BINARY || size == 0 || size > maximumSize)
        return ERROR_INVALID_DATA;
    bytes.resize(size);
    status = RegGetValueW(
        scope, nullptr, name, RRF_RT_REG_BINARY, &type, bytes.data(), &size);
    if (status != ERROR_SUCCESS) return static_cast<DWORD>(status);
    if (type != REG_BINARY || size != bytes.size()) return ERROR_INVALID_DATA;
    exists = true;
    return ERROR_SUCCESS;
}

DWORD WriteBinaryValue(
    HKEY scope,
    const wchar_t* name,
    const std::vector<unsigned char>& bytes)
{
    if (bytes.empty() || bytes.size() > MAXDWORD)
        return ERROR_INVALID_PARAMETER;
    return static_cast<DWORD>(RegSetValueExW(
        scope, name, 0, REG_BINARY, bytes.data(),
        static_cast<DWORD>(bytes.size())));
}

bool PolicyMatchesState(
    const oac::VerifiedPolicy& policy,
    const OAC_POLICY_CACHE_STATE& state) noexcept
{
    return state.CurrentPolicyVersion == policy.Record.PolicyVersion &&
        state.UpdateSequence == policy.Record.UpdateSequence &&
        std::memcmp(
            state.GameId, policy.Record.GameId, sizeof(state.GameId)) == 0 &&
        std::memcmp(
            state.ChannelId,
            policy.Record.ChannelId,
            sizeof(state.ChannelId)) == 0 &&
        std::memcmp(
            state.CurrentBuildId,
            policy.Record.BuildId,
            sizeof(state.CurrentBuildId)) == 0 &&
        std::memcmp(
            state.CurrentPolicyId,
            policy.Record.PolicyId,
            sizeof(state.CurrentPolicyId)) == 0 &&
        std::memcmp(
            state.CurrentPolicySha256,
            policy.Digest.data(),
            policy.Digest.size()) == 0;
}

DWORD ConvertPolicyRecord(
    const oac::VerifiedSignedRecord& signedRecord,
    oac::VerifiedPolicy& policy)
{
    policy = {};
    if (signedRecord.Bytes.size() != sizeof(policy.Record))
        return ERROR_INVALID_DATA;
    std::memcpy(
        &policy.Record, signedRecord.Bytes.data(), sizeof(policy.Record));
    policy.Digest = signedRecord.Digest;
    if (std::memcmp(
            policy.Record.SigningKeyId,
            signedRecord.SignerDigest.data(),
            signedRecord.SignerDigest.size()) != 0)
        return ERROR_ACCESS_DISABLED_BY_POLICY;
    return OacSignedPolicyValidate(
        &policy.Record,
        sizeof(policy.Record),
        oac::CurrentUnixSeconds(),
        OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION,
        OAC_IPC_PROTOCOL_REVISION) == OAC_SIGNED_POLICY_VALID
        ? ERROR_SUCCESS
        : ERROR_ACCESS_DISABLED_BY_POLICY;
}

DWORD VerifyPolicyBytes(
    const std::vector<unsigned char>& recordBytes,
    const std::vector<unsigned char>& signatureBytes,
    oac::VerifiedPolicy& policy)
{
    oac::VerifiedSignedRecord signedRecord;
    DWORD error = oac::VerifySignedRecordBytes(
        recordBytes,
        signatureBytes,
        static_cast<DWORD>(sizeof(OAC_SIGNED_POLICY)),
        kPolicySignerValue,
        signedRecord);
    return error == ERROR_SUCCESS
        ? ConvertPolicyRecord(signedRecord, policy)
        : error;
}

DWORD ReadCachedPolicy(
    HKEY scope,
    DWORD slot,
    bool& exists,
    oac::VerifiedPolicy& policy)
{
    exists = false;
    policy = {};
    if (slot >= ARRAYSIZE(kCachedPolicyValues))
        return ERROR_INVALID_PARAMETER;
    bool recordExists = false;
    bool signatureExists = false;
    std::vector<unsigned char> recordBytes;
    std::vector<unsigned char> signatureBytes;
    DWORD error = ReadBinaryValue(
        scope,
        kCachedPolicyValues[slot],
        sizeof(OAC_SIGNED_POLICY),
        recordExists,
        recordBytes);
    if (error != ERROR_SUCCESS) return error;
    error = ReadBinaryValue(
        scope,
        kCachedSignatureValues[slot],
        OAC_BACKEND_POLICY_SIGNATURE_CAPACITY,
        signatureExists,
        signatureBytes);
    if (error != ERROR_SUCCESS) return error;
    if (!recordExists && !signatureExists) return ERROR_SUCCESS;
    if (!recordExists || !signatureExists ||
        recordBytes.size() != sizeof(OAC_SIGNED_POLICY))
    {
        // An interrupted write is safe while the high-water record still
        // identifies another complete candidate.
        return ERROR_SUCCESS;
    }
    error = VerifyPolicyBytes(recordBytes, signatureBytes, policy);
    if (error == ERROR_SUCCESS) exists = true;
    return error == ERROR_ACCESS_DISABLED_BY_POLICY
        ? ERROR_SUCCESS
        : error;
}

DWORD FindCurrentCachedPolicy(
    HKEY scope,
    const OAC_POLICY_CACHE_STATE& state,
    oac::VerifiedPolicy& policy,
    int& slot)
{
    policy = {};
    slot = -1;
    for (DWORD index = 0; index != ARRAYSIZE(kCachedPolicyValues); ++index)
    {
        bool exists = false;
        oac::VerifiedPolicy candidate;
        DWORD error = ReadCachedPolicy(scope, index, exists, candidate);
        if (error != ERROR_SUCCESS) return error;
        if (!exists || !PolicyMatchesState(candidate, state)) continue;
        if (slot != -1) return ERROR_INVALID_DATA;
        slot = static_cast<int>(index);
        policy = candidate;
    }
    return slot == -1 ? ERROR_NOT_FOUND : ERROR_SUCCESS;
}

bool OfflinePolicyFallbackAllowed(DWORD error) noexcept
{
    return error == ERROR_RETRY || error == ERROR_WINHTTP_TIMEOUT ||
        error == ERROR_WINHTTP_CANNOT_CONNECT ||
        error == ERROR_WINHTTP_NAME_NOT_RESOLVED ||
        error == ERROR_WINHTTP_CONNECTION_ERROR ||
        error == ERROR_WINHTTP_RESEND_REQUEST;
}

DWORD CommitRemotePolicy(
    const std::vector<unsigned char>& recordBytes,
    const std::vector<unsigned char>& signatureBytes,
    const oac::VerifiedPolicy& currentPolicy,
    const oac::VerifiedPolicy& candidate,
    oac::VerifiedPolicy& selected)
{
    RegistryKey scope;
    DWORD error = OpenPolicyScope(
        currentPolicy.Record,
        KEY_QUERY_VALUE | KEY_SET_VALUE,
        false,
        scope);
    if (error != ERROR_SUCCESS) return error;
    bool stateExists = false;
    OAC_POLICY_CACHE_STATE current{};
    error = ReadPolicyState(scope.get(), stateExists, current);
    if (error != ERROR_SUCCESS) return error;
    if (!stateExists || !PolicyMatchesState(currentPolicy, current))
        return ERROR_INVALID_STATE;

    OAC_POLICY_CACHE_STATE next{};
    const OAC_POLICY_UPDATE_DECISION decision = OacPolicyEvaluateUpdate(
        &candidate.Record,
        candidate.Digest.data(),
        &current,
        1,
        &next);
    if (decision == OAC_POLICY_UPDATE_ACCEPT_CURRENT)
    {
        selected = currentPolicy;
        return ERROR_SUCCESS;
    }
    if (decision != OAC_POLICY_UPDATE_ACCEPT_NEW &&
        decision != OAC_POLICY_UPDATE_ACCEPT_ROLLBACK)
        return ERROR_ACCESS_DISABLED_BY_POLICY;

    oac::VerifiedPolicy cachedCurrent;
    int activeSlot = -1;
    error = FindCurrentCachedPolicy(
        scope.get(), current, cachedCurrent, activeSlot);
    if (error == ERROR_NOT_FOUND && PolicyMatchesState(currentPolicy, current))
        error = ERROR_SUCCESS;
    if (error != ERROR_SUCCESS) return error;
    const DWORD targetSlot = activeSlot == 0 ? 1u : 0u;
    error = WriteBinaryValue(
        scope.get(), kCachedPolicyValues[targetSlot], recordBytes);
    if (error == ERROR_SUCCESS)
        error = WriteBinaryValue(
            scope.get(), kCachedSignatureValues[targetSlot], signatureBytes);
    if (error == ERROR_SUCCESS)
        error = static_cast<DWORD>(RegFlushKey(scope.get()));
    if (error != ERROR_SUCCESS) return error;
    error = WritePolicyState(scope.get(), next);
    if (error != ERROR_SUCCESS) return error;

    bool observedStateExists = false;
    OAC_POLICY_CACHE_STATE observed{};
    error = ReadPolicyState(scope.get(), observedStateExists, observed);
    if (error != ERROR_SUCCESS || !observedStateExists ||
        std::memcmp(&observed, &next, sizeof(next)) != 0)
    {
        return error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error;
    }
    bool cachedExists = false;
    oac::VerifiedPolicy cached;
    error = ReadCachedPolicy(
        scope.get(), targetSlot, cachedExists, cached);
    if (error != ERROR_SUCCESS || !cachedExists ||
        !PolicyMatchesState(cached, observed))
        return error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error;
    selected = cached;
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
    VerifiedPolicy installed;
    error = ConvertPolicyRecord(signedRecord, installed);
    if (error != ERROR_SUCCESS) return error;

    RegistryKey scope;
    error = OpenPolicyScope(
        installed.Record,
        KEY_QUERY_VALUE | KEY_SET_VALUE,
        true,
        scope);
    if (error != ERROR_SUCCESS) return error;
    bool stateExists = false;
    OAC_POLICY_CACHE_STATE state{};
    error = ReadPolicyState(scope.get(), stateExists, state);
    if (error != ERROR_SUCCESS) return error;
    if (!stateExists)
    {
        OAC_POLICY_CACHE_STATE initial{};
        if (OacPolicyEvaluateUpdate(
                &installed.Record,
                installed.Digest.data(),
                nullptr,
                0,
                &initial) != OAC_POLICY_UPDATE_ACCEPT_NEW)
            return ERROR_ACCESS_DISABLED_BY_POLICY;
        error = WritePolicyState(scope.get(), initial);
        if (error != ERROR_SUCCESS) return error;
        verified = installed;
    }
    else if (PolicyMatchesState(installed, state))
    {
        verified = installed;
    }
    else
    {
        int slot = -1;
        error = FindCurrentCachedPolicy(scope.get(), state, verified, slot);
        if (error != ERROR_SUCCESS) return ERROR_ACCESS_DISABLED_BY_POLICY;
        if (std::memcmp(
                verified.Record.GameId,
                installed.Record.GameId,
                sizeof(verified.Record.GameId)) != 0 ||
            std::memcmp(
                verified.Record.BuildId,
                installed.Record.BuildId,
                sizeof(verified.Record.BuildId)) != 0 ||
            std::memcmp(
                verified.Record.ChannelId,
                installed.Record.ChannelId,
                sizeof(verified.Record.ChannelId)) != 0)
            return ERROR_ACCESS_DISABLED_BY_POLICY;
    }
    if ((verified.Record.Flags & OAC_SIGNED_POLICY_EMERGENCY_REVOKE) != 0)
    {
        return ERROR_ACCESS_DISABLED_BY_POLICY;
    }
    return ERROR_SUCCESS;
}

DWORD RefreshPolicy(
    VerifiedPolicy& verified,
    BackendTransport& transport) noexcept
{
    try
    {
        OAC_BACKEND_POLICY_REQUEST request{};
        DWORD error = InitializeBackendRequestHeader(
            request.Header,
            sizeof(request),
            OAC_BACKEND_MESSAGE_FETCH_POLICY,
            1,
            nullptr);
        if (error != ERROR_SUCCESS) return error;
        std::memcpy(
            request.GameId, verified.Record.GameId, sizeof(request.GameId));
        std::memcpy(
            request.BuildId, verified.Record.BuildId, sizeof(request.BuildId));
        std::memcpy(
            request.ChannelId,
            verified.Record.ChannelId,
            sizeof(request.ChannelId));
        request.CurrentPolicyVersion = verified.Record.PolicyVersion;
        std::memcpy(
            request.CurrentPolicySha256,
            verified.Digest.data(),
            verified.Digest.size());
        std::array<unsigned char, OAC_BACKEND_DIGEST_SIZE> nonceDigest{};
        error = ComputeBackendSha256(
            request.Header.Nonce,
            sizeof(request.Header.Nonce),
            nonceDigest.data());
        if (error != ERROR_SUCCESS) return error;

        OAC_BACKEND_POLICY_RESPONSE response{};
        error = transport.FetchPolicy(request, response);
        if (error != ERROR_SUCCESS)
            return OfflinePolicyFallbackAllowed(error) &&
                !PolicyHasExpiredNow(verified)
                ? ERROR_SUCCESS
                : error;
        const ULONGLONG now = CurrentUnixSeconds();
        if (now == 0 || !OacBackendValidatePolicyResponse(
                &request,
                &response,
                sizeof(response),
                nonceDigest.data(),
                now,
                OAC_V5_VERSION,
                OAC_IPC_PROTOCOL_REVISION,
                OAC_IPC_PROTOCOL_REVISION))
            return ERROR_INVALID_DATA;

        const auto* recordBegin = reinterpret_cast<const unsigned char*>(
            &response.Policy);
        std::vector<unsigned char> recordBytes(
            recordBegin, recordBegin + sizeof(response.Policy));
        std::vector<unsigned char> signatureBytes(
            response.Signature,
            response.Signature + response.SignatureSize);
        VerifiedPolicy candidate;
        error = VerifyPolicyBytes(recordBytes, signatureBytes, candidate);
        if (error != ERROR_SUCCESS) return error;
        VerifiedPolicy selected;
        error = CommitRemotePolicy(
            recordBytes,
            signatureBytes,
            verified,
            candidate,
            selected);
        if (error != ERROR_SUCCESS) return error;
        verified = selected;
        return (verified.Record.Flags & OAC_SIGNED_POLICY_EMERGENCY_REVOKE) == 0
            ? ERROR_SUCCESS
            : ERROR_ACCESS_DISABLED_BY_POLICY;
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
