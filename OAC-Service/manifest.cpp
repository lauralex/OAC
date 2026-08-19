#include "manifest.hpp"

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
#include "..\shared\protocol\oac_v5.h"

namespace
{
static_assert(OAC_MANIFEST_HASH_SIZE == OAC_V5_MANIFEST_DIGEST_SIZE);
constexpr wchar_t kManifestSuffix[] = L".oac-manifest";
constexpr wchar_t kSignatureSuffix[] = L".p7s";
constexpr wchar_t kManifestStatePath[] = L"SOFTWARE\\OAC\\ManifestState";
constexpr wchar_t kManifestTrustPath[] = L"SOFTWARE\\OAC";
constexpr wchar_t kManifestSignerValue[] = L"ManifestSignerSha256";
constexpr wchar_t kManifestStateValue[] = L"HighWater";
constexpr ULONGLONG kMaximumExecutableBytes = 1024ULL * 1024ULL * 1024ULL;
constexpr DWORD kMaximumSignatureBytes = 64u * 1024u;
constexpr ULONGLONG kWindowsToUnixEpoch100ns = 116444736000000000ULL;
constexpr DWORD kInvalidSignatureError =
    static_cast<DWORD>(TRUST_E_BAD_DIGEST);

class UniqueHandle
{
public:
    explicit UniqueHandle(HANDLE value = INVALID_HANDLE_VALUE) noexcept
        : value_(value) {}
    ~UniqueHandle()
    {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE)
            CloseHandle(value_);
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept : value_(other.value_)
    {
        other.value_ = INVALID_HANDLE_VALUE;
    }
    UniqueHandle& operator=(UniqueHandle&& other) noexcept
    {
        if (this != &other)
        {
            if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE)
                CloseHandle(value_);
            value_ = other.value_;
            other.value_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    [[nodiscard]] HANDLE get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE value_;
};

DWORD BcryptError(NTSTATUS status) noexcept
{
    return BCRYPT_SUCCESS(status)
        ? ERROR_SUCCESS
        : static_cast<DWORD>(HRESULT_FROM_NT(status));
}

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

class CertificateContext
{
public:
    ~CertificateContext()
    {
        if (value_ != nullptr) CertFreeCertificateContext(value_);
    }
    CertificateContext(const CertificateContext&) = delete;
    CertificateContext& operator=(const CertificateContext&) = delete;
    CertificateContext() = default;
    PCCERT_CONTEXT* put() noexcept { return &value_; }
    [[nodiscard]] PCCERT_CONTEXT get() const noexcept { return value_; }

private:
    PCCERT_CONTEXT value_ = nullptr;
};

class CertificateStore
{
public:
    ~CertificateStore()
    {
        if (value_ != nullptr) CertCloseStore(value_, 0);
    }
    CertificateStore(const CertificateStore&) = delete;
    CertificateStore& operator=(const CertificateStore&) = delete;
    CertificateStore() = default;
    HCERTSTORE* put() noexcept { return &value_; }

private:
    HCERTSTORE value_ = nullptr;
};

class CryptographicMessage
{
public:
    ~CryptographicMessage()
    {
        if (value_ != nullptr) CryptMsgClose(value_);
    }
    CryptographicMessage(const CryptographicMessage&) = delete;
    CryptographicMessage& operator=(const CryptographicMessage&) = delete;
    CryptographicMessage() = default;
    HCRYPTMSG* put() noexcept { return &value_; }
    [[nodiscard]] HCRYPTMSG get() const noexcept { return value_; }

private:
    HCRYPTMSG value_ = nullptr;
};

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
    std::vector<unsigned char> buffer(64u * 1024u);
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

DWORD OpenDataFile(const std::wstring& path, UniqueHandle& file)
{
    file = UniqueHandle();
    const HANDLE raw = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
            FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
    if (raw == INVALID_HANDLE_VALUE) return GetLastError();

    if (GetFileType(raw) != FILE_TYPE_DISK)
    {
        CloseHandle(raw);
        return ERROR_FILE_INVALID;
    }
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!GetFileInformationByHandleEx(
            raw, FileAttributeTagInfo, &attributes, sizeof(attributes)))
    {
        const DWORD error = GetLastError();
        CloseHandle(raw);
        return error;
    }
    if ((attributes.FileAttributes &
            (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
    {
        CloseHandle(raw);
        return ERROR_FILE_INVALID;
    }
    file = UniqueHandle(raw);
    return ERROR_SUCCESS;
}

DWORD ReadDataFile(HANDLE file, DWORD exactSize, DWORD maximumSize,
    std::vector<unsigned char>& bytes)
{
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size)) return GetLastError();
    if (size.QuadPart <= 0 || size.QuadPart > maximumSize ||
        (exactSize != 0 && size.QuadPart != exactSize))
    {
        return ERROR_INVALID_DATA;
    }
    bytes.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    if (!ReadFile(
            file,
            bytes.data(),
            static_cast<DWORD>(bytes.size()),
            &read,
            nullptr))
    {
        return GetLastError();
    }
    return read == bytes.size() ? ERROR_SUCCESS : ERROR_HANDLE_EOF;
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

bool SameCertificate(
    PCCERT_CONTEXT certificate,
    const std::vector<unsigned char>& expected)
{
    return certificate != nullptr &&
        certificate->cbCertEncoded == expected.size() &&
        std::memcmp(
            certificate->pbCertEncoded,
            expected.data(),
            expected.size()) == 0;
}

DWORD VerifyDetachedSignature(
    const std::vector<unsigned char>& signature,
    const OAC_GAME_MANIFEST& manifest,
    const std::vector<unsigned char>& expectedCertificate)
{
    CRYPT_DATA_BLOB blob{};
    blob.cbData = static_cast<DWORD>(signature.size());
    blob.pbData = const_cast<BYTE*>(signature.data());
    DWORD encoding = 0;
    DWORD content = 0;
    DWORD format = 0;
    CertificateStore store;
    CryptographicMessage message;
    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_BLOB,
            &blob,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &encoding,
            &content,
            &format,
            store.put(),
            message.put(),
            nullptr) ||
        message.get() == nullptr ||
        content != CERT_QUERY_CONTENT_PKCS7_SIGNED ||
        format != CERT_QUERY_FORMAT_BINARY ||
        encoding != (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING))
    {
        return kInvalidSignatureError;
    }

    DWORD signerCount = 0;
    DWORD signerCountSize = sizeof(signerCount);
    if (!CryptMsgGetParam(
            message.get(),
            CMSG_SIGNER_COUNT_PARAM,
            0,
            &signerCount,
            &signerCountSize) ||
        signerCountSize != sizeof(signerCount) || signerCount != 1)
    {
        return kInvalidSignatureError;
    }
    DWORD signerInfoSize = 0;
    if (!CryptMsgGetParam(
            message.get(), CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize) ||
        signerInfoSize < sizeof(CMSG_SIGNER_INFO) ||
        signerInfoSize > kMaximumSignatureBytes)
    {
        return kInvalidSignatureError;
    }
    std::vector<unsigned char> signerInfoBytes(signerInfoSize);
    if (!CryptMsgGetParam(
            message.get(),
            CMSG_SIGNER_INFO_PARAM,
            0,
            signerInfoBytes.data(),
            &signerInfoSize))
    {
        return kInvalidSignatureError;
    }
    const auto* signerInfo = reinterpret_cast<const CMSG_SIGNER_INFO*>(
        signerInfoBytes.data());
    if (signerInfo->HashAlgorithm.pszObjId == nullptr ||
        std::strcmp(signerInfo->HashAlgorithm.pszObjId, szOID_NIST_sha256) != 0 ||
        signerInfo->HashEncryptionAlgorithm.pszObjId == nullptr ||
        (std::strcmp(
             signerInfo->HashEncryptionAlgorithm.pszObjId,
             szOID_RSA_RSA) != 0 &&
         std::strcmp(
             signerInfo->HashEncryptionAlgorithm.pszObjId,
             szOID_RSA_SHA256RSA) != 0) ||
        signerInfo->UnauthAttrs.cAttr != 0)
    {
        return kInvalidSignatureError;
    }

    CRYPT_VERIFY_MESSAGE_PARA parameters{};
    parameters.cbSize = sizeof(parameters);
    parameters.dwMsgAndCertEncodingType =
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    const BYTE* contents[] =
    {
        reinterpret_cast<const BYTE*>(&manifest)
    };
    DWORD contentSizes[] = {static_cast<DWORD>(sizeof(manifest))};
    CertificateContext signerCertificate;
    if (!CryptVerifyDetachedMessageSignature(
            &parameters,
            0,
            signature.data(),
            static_cast<DWORD>(signature.size()),
            ARRAYSIZE(contents),
            contents,
            contentSizes,
            signerCertificate.put()) ||
        !SameCertificate(signerCertificate.get(), expectedCertificate))
    {
        return kInvalidSignatureError;
    }

    CertificateContext unexpectedSigner;
    if (CryptVerifyDetachedMessageSignature(
            &parameters,
            1,
            signature.data(),
            static_cast<DWORD>(signature.size()),
            ARRAYSIZE(contents),
            contents,
            contentSizes,
            unexpectedSigner.put()) ||
        GetLastError() != static_cast<DWORD>(CRYPT_E_NO_SIGNER))
    {
        return kInvalidSignatureError;
    }
    return ERROR_SUCCESS;
}

ULONGLONG CurrentUnixSeconds()
{
    FILETIME fileTime{};
    GetSystemTimePreciseAsFileTime(&fileTime);
    const ULONGLONG ticks =
        (static_cast<ULONGLONG>(fileTime.dwHighDateTime) << 32) |
        fileTime.dwLowDateTime;
    return ticks <= kWindowsToUnixEpoch100ns
        ? 0
        : (ticks - kWindowsToUnixEpoch100ns) / 10000000ULL;
}

std::wstring GameKeyName(const unsigned char gameId[OAC_MANIFEST_ID_SIZE])
{
    constexpr wchar_t digits[] = L"0123456789ABCDEF";
    std::wstring name;
    name.reserve(OAC_MANIFEST_ID_SIZE * 2u);
    for (size_t index = 0; index < OAC_MANIFEST_ID_SIZE; ++index)
    {
        name.push_back(digits[gameId[index] >> 4]);
        name.push_back(digits[gameId[index] & 0xFu]);
    }
    return name;
}

DWORD ReadPinnedManifestSigner(
    std::array<unsigned char, OAC_MANIFEST_HASH_SIZE>& signerDigest)
{
    RegistryKey root;
    LONG status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        kManifestTrustPath,
        0,
        KEY_QUERY_VALUE,
        root.put());
    if (status != ERROR_SUCCESS) return static_cast<DWORD>(status);

    DWORD type = 0;
    DWORD size = static_cast<DWORD>(signerDigest.size());
    status = RegQueryValueExW(
        root.get(),
        kManifestSignerValue,
        nullptr,
        &type,
        signerDigest.data(),
        &size);
    if (status != ERROR_SUCCESS) return static_cast<DWORD>(status);
    if (type != REG_BINARY || size != signerDigest.size() ||
        std::all_of(
            signerDigest.begin(),
            signerDigest.end(),
            [](unsigned char value) { return value == 0; }))
    {
        return ERROR_INVALID_DATA;
    }
    return ERROR_SUCCESS;
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
    const std::wstring keyName = GameKeyName(manifest.GameId);
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

    UniqueHandle manifestFile;
    DWORD error = OpenDataFile(
        finalExecutablePath + kManifestSuffix, manifestFile);
    if (error != ERROR_SUCCESS)
    {
        failure = (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
            ? ManifestFailure::Missing
            : ManifestFailure::Invalid;
        return error;
    }
    UniqueHandle signatureFile;
    error = OpenDataFile(
        finalExecutablePath + kManifestSuffix + kSignatureSuffix,
        signatureFile);
    if (error != ERROR_SUCCESS)
    {
        failure = (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
            ? ManifestFailure::Missing
            : ManifestFailure::Invalid;
        return error;
    }

    std::vector<unsigned char> manifestBytes;
    error = ReadDataFile(
        manifestFile.get(),
        sizeof(OAC_GAME_MANIFEST),
        sizeof(OAC_GAME_MANIFEST),
        manifestBytes);
    if (error != ERROR_SUCCESS) return error;
    std::memcpy(
        &verified.Record, manifestBytes.data(), sizeof(verified.Record));
    error = HashBytes(
        &verified.Record, sizeof(verified.Record), verified.Digest);
    if (error != ERROR_SUCCESS) return error;

    std::vector<unsigned char> signature;
    error = ReadDataFile(
        signatureFile.get(), 0, kMaximumSignatureBytes, signature);
    if (error != ERROR_SUCCESS) return error;

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
    std::array<unsigned char, OAC_MANIFEST_HASH_SIZE> pinnedSigner{};
    error = ReadPinnedManifestSigner(pinnedSigner);
    if (error != ERROR_SUCCESS || signerDigest != pinnedSigner)
    {
        failure = ManifestFailure::Signature;
        return error == ERROR_SUCCESS
            ? ERROR_ACCESS_DISABLED_BY_POLICY
            : error;
    }
    error = VerifyDetachedSignature(
        signature, verified.Record, signerCertificate);
    if (error != ERROR_SUCCESS)
    {
        failure = ManifestFailure::Signature;
        return error;
    }

    const ULONGLONG now = CurrentUnixSeconds();
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
