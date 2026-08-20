#include "signed_record.hpp"

#include <bcrypt.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace
{
constexpr wchar_t kTrustPath[] = L"SOFTWARE\\OAC";
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

private:
    HANDLE value_;
};

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
        if (!BCRYPT_SUCCESS(status)) return Error(status);
        DWORD objectSize = 0;
        DWORD returned = 0;
        status = BCryptGetProperty(
            algorithm_, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize),
            &returned, 0);
        if (!BCRYPT_SUCCESS(status) || returned != sizeof(objectSize) ||
            objectSize == 0 || objectSize > 1024u * 1024u)
        {
            return BCRYPT_SUCCESS(status) ? ERROR_INVALID_DATA : Error(status);
        }
        object_.resize(objectSize);
        status = BCryptCreateHash(
            algorithm_, &hash_, object_.data(),
            static_cast<ULONG>(object_.size()), nullptr, 0, 0);
        return Error(status);
    }

    DWORD Append(const void* bytes, ULONG length)
    {
        if (bytes == nullptr && length != 0) return ERROR_INVALID_PARAMETER;
        return Error(BCryptHashData(
            hash_, static_cast<PUCHAR>(const_cast<void*>(bytes)), length, 0));
    }

    DWORD Finish(std::array<unsigned char, OAC_POLICY_HASH_SIZE>& digest)
    {
        return Error(BCryptFinishHash(
            hash_, digest.data(), static_cast<ULONG>(digest.size()), 0));
    }

private:
    static DWORD Error(NTSTATUS status) noexcept
    {
        return BCRYPT_SUCCESS(status)
            ? ERROR_SUCCESS
            : static_cast<DWORD>(HRESULT_FROM_NT(status));
    }

    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<unsigned char> object_;
};

DWORD OpenRegularFile(const std::wstring& path, UniqueHandle& file)
{
    const HANDLE raw = CreateFileW(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
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

DWORD ReadFileBytes(
    HANDLE file,
    DWORD exactSize,
    DWORD maximumSize,
    std::vector<unsigned char>& bytes)
{
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size)) return GetLastError();
    if (size.QuadPart <= 0 || size.QuadPart > maximumSize ||
        (exactSize != 0 && size.QuadPart != exactSize))
        return ERROR_INVALID_DATA;
    bytes.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    if (!ReadFile(
            file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr))
        return GetLastError();
    return read == bytes.size() ? ERROR_SUCCESS : ERROR_HANDLE_EOF;
}

DWORD HashBytes(
    const std::vector<unsigned char>& bytes,
    std::array<unsigned char, OAC_POLICY_HASH_SIZE>& digest)
{
    if (bytes.empty() ||
        bytes.size() > (std::numeric_limits<ULONG>::max)())
        return ERROR_INVALID_PARAMETER;
    HashProvider hash;
    DWORD error = hash.Initialize();
    if (error == ERROR_SUCCESS)
        error = hash.Append(bytes.data(), static_cast<ULONG>(bytes.size()));
    if (error == ERROR_SUCCESS) error = hash.Finish(digest);
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
        return false;
    BCRYPT_KEY_HANDLE key = nullptr;
    if (!CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING,
            &certificate->pCertInfo->SubjectPublicKeyInfo,
            0, nullptr, &key))
        return false;
    DWORD bits = 0;
    DWORD returned = 0;
    const NTSTATUS status = BCryptGetProperty(
        key, BCRYPT_KEY_LENGTH, reinterpret_cast<PUCHAR>(&bits),
        sizeof(bits), &returned, 0);
    BCryptDestroyKey(key);
    return BCRYPT_SUCCESS(status) && returned == sizeof(bits) && bits >= 3072;
}

DWORD ReadPinnedSigner(
    const wchar_t* valueName,
    std::array<unsigned char, OAC_POLICY_HASH_SIZE>& digest)
{
    if (valueName == nullptr || *valueName == L'\0')
        return ERROR_INVALID_PARAMETER;
    RegistryKey root;
    LONG status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE, kTrustPath, 0, KEY_QUERY_VALUE, root.put());
    if (status != ERROR_SUCCESS) return static_cast<DWORD>(status);
    DWORD type = 0;
    DWORD size = static_cast<DWORD>(digest.size());
    status = RegQueryValueExW(
        root.get(), valueName, nullptr, &type, digest.data(), &size);
    if (status != ERROR_SUCCESS) return static_cast<DWORD>(status);
    if (type != REG_BINARY || size != digest.size() ||
        std::all_of(digest.begin(), digest.end(),
            [](unsigned char value) { return value == 0; }))
        return ERROR_INVALID_DATA;
    return ERROR_SUCCESS;
}

DWORD VerifyDetachedSignature(
    const std::vector<unsigned char>& signature,
    const std::vector<unsigned char>& contents,
    std::vector<unsigned char>& signerCertificate)
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
            CERT_QUERY_OBJECT_BLOB, &blob,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &content, &format,
            store.put(), message.put(), nullptr) ||
        message.get() == nullptr || content != CERT_QUERY_CONTENT_PKCS7_SIGNED ||
        format != CERT_QUERY_FORMAT_BINARY ||
        encoding != (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING))
        return kInvalidSignatureError;

    DWORD signerCount = 0;
    DWORD signerCountSize = sizeof(signerCount);
    if (!CryptMsgGetParam(
            message.get(), CMSG_SIGNER_COUNT_PARAM, 0,
            &signerCount, &signerCountSize) ||
        signerCountSize != sizeof(signerCount) || signerCount != 1)
        return kInvalidSignatureError;
    DWORD signerInfoSize = 0;
    if (!CryptMsgGetParam(
            message.get(), CMSG_SIGNER_INFO_PARAM, 0, nullptr,
            &signerInfoSize) ||
        signerInfoSize < sizeof(CMSG_SIGNER_INFO) ||
        signerInfoSize > kMaximumSignatureBytes)
        return kInvalidSignatureError;
    std::vector<unsigned char> signerInfoBytes(signerInfoSize);
    if (!CryptMsgGetParam(
            message.get(), CMSG_SIGNER_INFO_PARAM, 0,
            signerInfoBytes.data(), &signerInfoSize))
        return kInvalidSignatureError;
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
        return kInvalidSignatureError;

    CRYPT_VERIFY_MESSAGE_PARA parameters{};
    parameters.cbSize = sizeof(parameters);
    parameters.dwMsgAndCertEncodingType =
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    const BYTE* contentPointers[] = {contents.data()};
    DWORD contentSizes[] = {static_cast<DWORD>(contents.size())};
    CertificateContext signer;
    if (!CryptVerifyDetachedMessageSignature(
            &parameters, 0, signature.data(),
            static_cast<DWORD>(signature.size()), ARRAYSIZE(contentPointers),
            contentPointers, contentSizes, signer.put()) ||
        !CertificateUsesStrongRsa(signer.get()))
        return kInvalidSignatureError;
    CertificateContext unexpected;
    if (CryptVerifyDetachedMessageSignature(
            &parameters, 1, signature.data(),
            static_cast<DWORD>(signature.size()), ARRAYSIZE(contentPointers),
            contentPointers, contentSizes, unexpected.put()) ||
        GetLastError() != static_cast<DWORD>(CRYPT_E_NO_SIGNER))
        return kInvalidSignatureError;

    signerCertificate.assign(
        signer.get()->pbCertEncoded,
        signer.get()->pbCertEncoded + signer.get()->cbCertEncoded);
    return ERROR_SUCCESS;
}
} // namespace

namespace oac
{
DWORD VerifySignedRecord(
    const std::wstring& recordPath,
    const std::wstring& signaturePath,
    DWORD exactRecordSize,
    const wchar_t* signerRegistryValue,
    VerifiedSignedRecord& verified)
{
    verified = {};
    if (recordPath.empty() || signaturePath.empty() || exactRecordSize == 0 ||
        signerRegistryValue == nullptr || *signerRegistryValue == L'\0')
        return ERROR_INVALID_PARAMETER;

    UniqueHandle recordFile;
    DWORD error = OpenRegularFile(recordPath, recordFile);
    if (error != ERROR_SUCCESS) return error;
    UniqueHandle signatureFile;
    error = OpenRegularFile(signaturePath, signatureFile);
    if (error != ERROR_SUCCESS) return error;
    error = ReadFileBytes(
        recordFile.get(), exactRecordSize, exactRecordSize, verified.Bytes);
    if (error != ERROR_SUCCESS) return error;
    std::vector<unsigned char> signature;
    error = ReadFileBytes(
        signatureFile.get(), 0, kMaximumSignatureBytes, signature);
    if (error != ERROR_SUCCESS) return error;
    error = HashBytes(verified.Bytes, verified.Digest);
    if (error != ERROR_SUCCESS) return error;
    error = VerifyDetachedSignature(
        signature, verified.Bytes, verified.SignerCertificate);
    if (error != ERROR_SUCCESS) return error;
    error = HashBytes(verified.SignerCertificate, verified.SignerDigest);
    if (error != ERROR_SUCCESS) return error;
    std::array<unsigned char, OAC_POLICY_HASH_SIZE> pinnedSigner{};
    error = ReadPinnedSigner(signerRegistryValue, pinnedSigner);
    if (error != ERROR_SUCCESS) return error;
    return verified.SignerDigest == pinnedSigner
        ? ERROR_SUCCESS
        : ERROR_ACCESS_DISABLED_BY_POLICY;
}

ULONGLONG CurrentUnixSeconds() noexcept
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

std::wstring HexIdentity(const unsigned char* bytes, size_t count)
{
    constexpr wchar_t digits[] = L"0123456789ABCDEF";
    std::wstring name;
    if (bytes == nullptr || count == 0) return name;
    name.reserve(count * 2u);
    for (size_t index = 0; index < count; ++index)
    {
        name.push_back(digits[bytes[index] >> 4]);
        name.push_back(digits[bytes[index] & 0x0Fu]);
    }
    return name;
}
}
