#include "manifest.hpp"
#include "signed_record.hpp"

#include <Windows.h>
#include <bcrypt.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include "..\shared\oac_ipc.h"
#include "..\shared\oac_windows.hpp"
#include "..\shared\protocol\oac_v5.h"

namespace
{
using oac::RegistryKey;

static_assert(OAC_MANIFEST_HASH_SIZE == OAC_V5_MANIFEST_DIGEST_SIZE);
constexpr wchar_t kManifestSuffix[] = L".oac-manifest";
constexpr wchar_t kSignatureSuffix[] = L".p7s";
constexpr wchar_t kManifestStatePath[] = L"SOFTWARE\\OAC\\ManifestState";
constexpr wchar_t kManifestSignerValue[] = L"ManifestSignerSha256";
constexpr wchar_t kManifestStateValue[] = L"HighWater";
constexpr ULONGLONG kMaximumExecutableBytes = 1024ULL * 1024ULL * 1024ULL;
constexpr DWORD kInvalidSignatureError =
    static_cast<DWORD>(TRUST_E_BAD_DIGEST);

DWORD BcryptError(NTSTATUS status) noexcept
{
    return BCRYPT_SUCCESS(status)
        ? ERROR_SUCCESS
        : static_cast<DWORD>(HRESULT_FROM_NT(status));
}

class HashProvider
{
public:
    ~HashProvider()
    {
        if (hash_ != nullptr) BCryptDestroyHash(hash_);
        if (algorithm_ != nullptr) BCryptCloseAlgorithmProvider(algorithm_, 0);
    }
    HashProvider(const HashProvider&) = delete;
    HashProvider& operator=(const HashProvider&) = delete;
    HashProvider() = default;

    DWORD Initialize()
    {
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &algorithm_, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) return BcryptError(status);

        DWORD objectSize = 0;
        DWORD returned = 0;
        status = BCryptGetProperty(
            algorithm_,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectSize),
            sizeof(objectSize),
            &returned,
            0);
        if (!BCRYPT_SUCCESS(status) || returned != sizeof(objectSize) ||
            objectSize == 0 || objectSize > 1024u * 1024u)
        {
            return BCRYPT_SUCCESS(status)
                ? ERROR_INVALID_DATA
                : BcryptError(status);
        }
        object_.resize(objectSize);
        status = BCryptCreateHash(
            algorithm_,
            &hash_,
            object_.data(),
            static_cast<ULONG>(object_.size()),
            nullptr,
            0,
            0);
        return BcryptError(status);
    }

    DWORD Append(const void* bytes, ULONG length)
    {
        if (bytes == nullptr && length != 0) return ERROR_INVALID_PARAMETER;
        const NTSTATUS status = BCryptHashData(
            hash_,
            static_cast<PUCHAR>(const_cast<void*>(bytes)),
            length,
            0);
        return BcryptError(status);
    }

    DWORD Finish(std::array<unsigned char, OAC_MANIFEST_HASH_SIZE>& digest)
    {
        const NTSTATUS status = BCryptFinishHash(
            hash_, digest.data(), static_cast<ULONG>(digest.size()), 0);
        return BcryptError(status);
    }

private:
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<unsigned char> object_;
};

DWORD HashBytes(
    const void* bytes,
    size_t length,
    std::array<unsigned char, OAC_MANIFEST_HASH_SIZE>& digest)
{
    if (bytes == nullptr || length == 0 ||
        length > (std::numeric_limits<ULONG>::max)())
        return ERROR_INVALID_PARAMETER;
    HashProvider hash;
    DWORD error = hash.Initialize();
    if (error == ERROR_SUCCESS)
        error = hash.Append(bytes, static_cast<ULONG>(length));
    if (error == ERROR_SUCCESS) error = hash.Finish(digest);
    return error;
}

DWORD HashFile(
    HANDLE file,
    ULONGLONG maximumBytes,
    ULONGLONG& fileSize,
    std::array<unsigned char, OAC_MANIFEST_HASH_SIZE>& digest)
{
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size)) return GetLastError();
    if (size.QuadPart <= 0 ||
        static_cast<ULONGLONG>(size.QuadPart) > maximumBytes)
    {
        return ERROR_FILE_TOO_LARGE;
    }
    LARGE_INTEGER beginning{};
    if (!SetFilePointerEx(file, beginning, nullptr, FILE_BEGIN))
        return GetLastError();

    HashProvider hash;
    DWORD error = hash.Initialize();
    std::vector<unsigned char> buffer(size_t{64} * 1024);
    ULONGLONG total = 0;
    while (error == ERROR_SUCCESS && total < static_cast<ULONGLONG>(size.QuadPart))
    {
        const DWORD wanted = static_cast<DWORD>((std::min)(
            static_cast<ULONGLONG>(buffer.size()),
            static_cast<ULONGLONG>(size.QuadPart) - total));
        DWORD read = 0;
        if (!ReadFile(file, buffer.data(), wanted, &read, nullptr))
        {
            error = GetLastError();
            break;
        }
        if (read == 0)
        {
            error = ERROR_HANDLE_EOF;
            break;
        }
        error = hash.Append(buffer.data(), read);
        total += read;
    }
    if (error == ERROR_SUCCESS && total != static_cast<ULONGLONG>(size.QuadPart))
        error = ERROR_HANDLE_EOF;
    if (error == ERROR_SUCCESS) error = hash.Finish(digest);
    fileSize = total;
    return error;
}

bool CertificateUsesStrongRsa(PCCERT_CONTEXT certificate)
{
    if (certificate == nullptr || certificate->pCertInfo == nullptr ||
        certificate->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId == nullptr ||
        certificate->pCertInfo->SignatureAlgorithm.pszObjId == nullptr ||
        std::strcmp(
            certificate->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
            szOID_RSA_RSA) != 0 ||
        std::strcmp(
            certificate->pCertInfo->SignatureAlgorithm.pszObjId,
            szOID_RSA_SHA256RSA) != 0)
    {
        return false;
    }

    BCRYPT_KEY_HANDLE key = nullptr;
    if (!CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING,
            &certificate->pCertInfo->SubjectPublicKeyInfo,
            0,
            nullptr,
            &key))
    {
        return false;
    }
    DWORD bits = 0;
    DWORD returned = 0;
    const NTSTATUS status = BCryptGetProperty(
        key,
        BCRYPT_KEY_LENGTH,
        reinterpret_cast<PUCHAR>(&bits),
        sizeof(bits),
        &returned,
        0);
    BCryptDestroyKey(key);
    return BCRYPT_SUCCESS(status) && returned == sizeof(bits) && bits >= 3072;
}

DWORD VerifyExecutableTrust(
    HANDLE executable,
    const std::wstring& path,
    std::array<unsigned char, OAC_MANIFEST_HASH_SIZE>& signerDigest,
    std::vector<unsigned char>& signerCertificate)
{
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = path.c_str();
    file.hFile = executable;

    WINTRUST_DATA trust{};
    trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &file;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    trust.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
        WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &policy, &trust);
    DWORD error = status == ERROR_SUCCESS
        ? ERROR_SUCCESS
        : static_cast<DWORD>(status);
    if (error == ERROR_SUCCESS)
    {
        const CRYPT_PROVIDER_DATA* provider =
            WTHelperProvDataFromStateData(trust.hWVTStateData);
        const CRYPT_PROVIDER_SGNR* signer = provider == nullptr
            ? nullptr
            : WTHelperGetProvSignerFromChain(
                const_cast<CRYPT_PROVIDER_DATA*>(provider), 0, FALSE, 0);
        const CRYPT_PROVIDER_CERT* certificate = signer == nullptr
            ? nullptr
            : WTHelperGetProvCertFromChain(
                const_cast<CRYPT_PROVIDER_SGNR*>(signer), 0);
        if (provider == nullptr || provider->csSigners != 1 || signer == nullptr ||
            certificate == nullptr || certificate->pCert == nullptr ||
            !CertificateUsesStrongRsa(certificate->pCert))
        {
            error = kInvalidSignatureError;
        }
        else
        {
            signerCertificate.assign(
                certificate->pCert->pbCertEncoded,
                certificate->pCert->pbCertEncoded +
                    certificate->pCert->cbCertEncoded);
            error = HashBytes(
                signerCertificate.data(), signerCertificate.size(), signerDigest);
        }
    }

    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)WinVerifyTrust(nullptr, &policy, &trust);
    return error;
}

DWORD ApplyRollbackPolicy(
    const OAC_GAME_MANIFEST& manifest,
    const std::array<unsigned char, OAC_MANIFEST_HASH_SIZE>& digest,
    oac::ManifestFailure& failure)
{
    RegistryKey root;
    LONG status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        kManifestStatePath,
        0,
        KEY_CREATE_SUB_KEY,
        root.put());
    if (status != ERROR_SUCCESS)
    {
        failure = oac::ManifestFailure::Rollback;
        return static_cast<DWORD>(status);
    }

    RegistryKey game;
    DWORD disposition = 0;
    const std::wstring keyName =
        oac::HexIdentity(manifest.GameId, OAC_MANIFEST_ID_SIZE);
    status = RegCreateKeyExW(
        root.get(),
        keyName.c_str(),
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_QUERY_VALUE | KEY_SET_VALUE,
        nullptr,
        game.put(),
        &disposition);
    if (status != ERROR_SUCCESS)
    {
        failure = oac::ManifestFailure::Rollback;
        return static_cast<DWORD>(status);
    }

    OAC_MANIFEST_ROLLBACK_STATE current{};
    DWORD type = 0;
    DWORD size = sizeof(current);
    status = RegQueryValueExW(
        game.get(),
        kManifestStateValue,
        nullptr,
        &type,
        reinterpret_cast<BYTE*>(&current),
        &size);
    const bool hasCurrent = status == ERROR_SUCCESS;
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND)
    {
        failure = oac::ManifestFailure::Rollback;
        return static_cast<DWORD>(status);
    }
    if (hasCurrent && (type != REG_BINARY || size != sizeof(current)))
    {
        failure = oac::ManifestFailure::Rollback;
        return ERROR_INVALID_DATA;
    }

    OAC_MANIFEST_ROLLBACK_STATE next{};
    const OAC_MANIFEST_ROLLBACK_DECISION decision = OacManifestEvaluateRollback(
        &manifest,
        digest.data(),
        hasCurrent ? &current : nullptr,
        hasCurrent ? 1 : 0,
        &next);
    if (decision == OAC_MANIFEST_ROLLBACK_REJECT_OLDER ||
        decision == OAC_MANIFEST_ROLLBACK_REJECT_EQUIVOCATION ||
        decision == OAC_MANIFEST_ROLLBACK_INVALID_STATE)
    {
        failure = oac::ManifestFailure::Rollback;
        return ERROR_ACCESS_DISABLED_BY_POLICY;
    }
    if (decision == OAC_MANIFEST_ROLLBACK_ACCEPT_NEW)
    {
        status = RegSetValueExW(
            game.get(),
            kManifestStateValue,
            0,
            REG_BINARY,
            reinterpret_cast<const BYTE*>(&next),
            sizeof(next));
        if (status == ERROR_SUCCESS) status = RegFlushKey(game.get());
        if (status != ERROR_SUCCESS)
        {
            failure = oac::ManifestFailure::Rollback;
            return static_cast<DWORD>(status);
        }
    }

    OAC_MANIFEST_ROLLBACK_STATE observed{};
    type = 0;
    size = sizeof(observed);
    status = RegQueryValueExW(
        game.get(),
        kManifestStateValue,
        nullptr,
        &type,
        reinterpret_cast<BYTE*>(&observed),
        &size);
    if (status != ERROR_SUCCESS || type != REG_BINARY ||
        size != sizeof(observed) ||
        std::memcmp(&observed, &next, sizeof(next)) != 0)
    {
        failure = oac::ManifestFailure::Rollback;
        return status == ERROR_SUCCESS
            ? ERROR_INVALID_DATA
            : static_cast<DWORD>(status);
    }
    return ERROR_SUCCESS;
}
}

namespace oac
{
DWORD AuthorizeGameManifest(
    HANDLE executable,
    const std::wstring& finalExecutablePath,
    VerifiedGameManifest& verified,
    ManifestFailure& failure)
{
    verified = {};
    failure = ManifestFailure::Invalid;
    if (executable == nullptr || executable == INVALID_HANDLE_VALUE ||
        finalExecutablePath.empty())
    {
        return ERROR_INVALID_PARAMETER;
    }

    VerifiedSignedRecord signedManifest;
    DWORD error = VerifySignedRecord(
        finalExecutablePath + kManifestSuffix,
        finalExecutablePath + kManifestSuffix + kSignatureSuffix,
        static_cast<DWORD>(sizeof(OAC_GAME_MANIFEST)),
        kManifestSignerValue,
        signedManifest);
    if (error != ERROR_SUCCESS)
    {
        failure = (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
            ? ManifestFailure::Missing
            : (error == static_cast<DWORD>(TRUST_E_BAD_DIGEST) ||
               error == ERROR_ACCESS_DISABLED_BY_POLICY)
                ? ManifestFailure::Signature
                : ManifestFailure::Invalid;
        return error;
    }
    if (signedManifest.Bytes.size() != sizeof(verified.Record))
        return ERROR_INVALID_DATA;
    std::memcpy(
        &verified.Record,
        signedManifest.Bytes.data(),
        sizeof(verified.Record));
    verified.Digest = signedManifest.Digest;

    std::array<unsigned char, OAC_MANIFEST_HASH_SIZE> signerDigest{};
    std::vector<unsigned char> signerCertificate;
    error = VerifyExecutableTrust(
        executable,
        finalExecutablePath,
        signerDigest,
        signerCertificate);
    if (error != ERROR_SUCCESS)
    {
        failure = ManifestFailure::Signature;
        return error;
    }
    if (signerDigest != signedManifest.SignerDigest ||
        signerCertificate != signedManifest.SignerCertificate)
    {
        failure = ManifestFailure::Signature;
        return ERROR_ACCESS_DISABLED_BY_POLICY;
    }

    const ULONGLONG now = oac::CurrentUnixSeconds();
    const OAC_MANIFEST_VALIDATION validation = OacManifestValidate(
        &verified.Record,
        sizeof(verified.Record),
        now,
        OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION,
        OAC_IPC_PROTOCOL_REVISION);
    if (validation != OAC_MANIFEST_VALID)
    {
        failure = validation == OAC_MANIFEST_EXPIRED
            ? ManifestFailure::Expired
            : validation == OAC_MANIFEST_INCOMPATIBLE_COMPONENT ||
                validation == OAC_MANIFEST_INVALID_FILE_IDENTITY
                ? ManifestFailure::Build
                : ManifestFailure::Invalid;
        return ERROR_ACCESS_DISABLED_BY_POLICY;
    }

    const size_t slash = finalExecutablePath.find_last_of(L'\\');
    const std::wstring leaf = slash == std::wstring::npos
        ? finalExecutablePath
        : finalExecutablePath.substr(slash + 1u);
    if (leaf.empty() ||
        leaf.size() > (std::numeric_limits<ULONG>::max)())
    {
        failure = ManifestFailure::Build;
        return ERROR_BAD_EXE_FORMAT;
    }
    ULONGLONG executableSize = 0;
    std::array<unsigned char, OAC_MANIFEST_HASH_SIZE> executableDigest{};
    error = HashFile(
        executable,
        kMaximumExecutableBytes,
        executableSize,
        executableDigest);
    if (error != ERROR_SUCCESS)
    {
        failure = ManifestFailure::Build;
        return error;
    }
    static_assert(sizeof(wchar_t) == sizeof(uint16_t));
    if (!OacManifestFileIdentityMatches(
            &verified.Record,
            reinterpret_cast<const uint16_t*>(leaf.data()),
            leaf.size(),
            executableSize,
            executableDigest.data(),
            signerDigest.data()))
    {
        failure = ManifestFailure::Build;
        return ERROR_BAD_EXE_FORMAT;
    }

    error = ApplyRollbackPolicy(verified.Record, verified.Digest, failure);
    if (error != ERROR_SUCCESS) return error;
    failure = ManifestFailure::None;
    return ERROR_SUCCESS;
}
}
