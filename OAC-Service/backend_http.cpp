#include "backend_http.hpp"

#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <new>
#include <string>

#include "backend.hpp"
#include "..\shared\oac_windows.hpp"

namespace
{
using oac::BackendTransport;
using oac::RegistryKey;

constexpr wchar_t kBackendStatePath[] = L"SOFTWARE\\OAC";
constexpr wchar_t kBackendUrlValue[] = L"BackendUrl";
constexpr wchar_t kClientPinsValue[] = L"BackendClientCertificatePins";
constexpr wchar_t kServerPinsValue[] = L"BackendServerCertificatePins";
constexpr wchar_t kUserAgent[] = L"OACService";
constexpr DWORD kDigestSize = OAC_BACKEND_DIGEST_SIZE;
constexpr DWORD kMaximumUrlCharacters = 2048;
constexpr DWORD kConnectTimeoutMilliseconds = 5000;
constexpr DWORD kSendTimeoutMilliseconds = 10000;
constexpr DWORD kReceiveTimeoutMilliseconds = 10000;
constexpr std::size_t kWorkCapacity = 2;

class InternetHandle
{
public:
    explicit InternetHandle(HINTERNET value = nullptr) noexcept : value_(value) {}
    ~InternetHandle() { reset(); }
    InternetHandle(const InternetHandle&) = delete;
    InternetHandle& operator=(const InternetHandle&) = delete;
    InternetHandle(InternetHandle&& other) noexcept : value_(other.release()) {}
    InternetHandle& operator=(InternetHandle&& other) noexcept
    {
        if (this != &other) reset(other.release());
        return *this;
    }
    [[nodiscard]] HINTERNET get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept { return value_ != nullptr; }
    HINTERNET release() noexcept
    {
        HINTERNET value = value_;
        value_ = nullptr;
        return value;
    }
    void reset(HINTERNET value = nullptr) noexcept
    {
        if (value_ != nullptr) WinHttpCloseHandle(value_);
        value_ = value;
    }

private:
    HINTERNET value_ = nullptr;
};

class CertificateContext
{
public:
    ~CertificateContext() { reset(); }
    CertificateContext() = default;
    CertificateContext(const CertificateContext&) = delete;
    CertificateContext& operator=(const CertificateContext&) = delete;
    [[nodiscard]] PCCERT_CONTEXT get() const noexcept { return value_; }
    void reset(PCCERT_CONTEXT value = nullptr) noexcept
    {
        if (value_ != nullptr) CertFreeCertificateContext(value_);
        value_ = value;
    }

private:
    PCCERT_CONTEXT value_ = nullptr;
};

struct CertificatePins
{
    std::array<std::array<unsigned char, kDigestSize>, 2> Values{};
    DWORD Count = 0;
};

struct HttpConfiguration
{
    std::wstring Host;
    INTERNET_PORT Port = 0;
    CertificatePins ClientPins{};
    CertificatePins ServerPins{};
};

bool BytesAreZero(const unsigned char* bytes, std::size_t count) noexcept
{
    if (bytes == nullptr) return true;
    unsigned char combined = 0;
    for (std::size_t index = 0; index != count; ++index)
        combined = static_cast<unsigned char>(combined | bytes[index]);
    return combined == 0;
}

DWORD HashCertificate(
    PCCERT_CONTEXT certificate,
    std::array<unsigned char, kDigestSize>& digest) noexcept
{
    if (certificate == nullptr) return ERROR_INVALID_PARAMETER;
    DWORD size = static_cast<DWORD>(digest.size());
    if (!CryptHashCertificate2(
            BCRYPT_SHA256_ALGORITHM,
            0,
            nullptr,
            certificate->pbCertEncoded,
            certificate->cbCertEncoded,
            digest.data(),
            &size))
    {
        return GetLastError();
    }
    return size == digest.size() ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

bool PinsContain(
    const CertificatePins& pins,
    const std::array<unsigned char, kDigestSize>& digest) noexcept
{
    bool matched = false;
    for (DWORD index = 0; index != pins.Count; ++index)
        matched = matched || pins.Values[index] == digest;
    return matched;
}

DWORD ReadStringValue(
    HKEY key,
    const wchar_t* name,
    std::wstring& value)
{
    DWORD type = 0;
    DWORD size = 0;
    LONG status = RegGetValueW(
        key, nullptr, name, RRF_RT_REG_SZ, &type, nullptr, &size);
    if (status != ERROR_SUCCESS) return static_cast<DWORD>(status);
    if (type != REG_SZ || size < sizeof(wchar_t) ||
        size > kMaximumUrlCharacters * sizeof(wchar_t) ||
        size % sizeof(wchar_t) != 0)
    {
        return ERROR_INVALID_DATA;
    }
    std::wstring buffer(size / sizeof(wchar_t), L'\0');
    status = RegGetValueW(
        key, nullptr, name, RRF_RT_REG_SZ, &type, buffer.data(), &size);
    if (status != ERROR_SUCCESS) return static_cast<DWORD>(status);
    const std::size_t characters = size / sizeof(wchar_t);
    if (characters == 0 || buffer[characters - 1] != L'\0' ||
        buffer.find(L'\0') != characters - 1)
    {
        return ERROR_INVALID_DATA;
    }
    buffer.resize(characters - 1);
    value = std::move(buffer);
    return value.empty() ? ERROR_INVALID_DATA : ERROR_SUCCESS;
}

DWORD ReadPinsValue(
    HKEY key,
    const wchar_t* name,
    CertificatePins& pins) noexcept
{
    pins = {};
    DWORD type = 0;
    DWORD size = sizeof(pins.Values);
    LONG status = RegGetValueW(
        key, nullptr, name, RRF_RT_REG_BINARY, &type, pins.Values.data(), &size);
    if (status != ERROR_SUCCESS) return static_cast<DWORD>(status);
    if (type != REG_BINARY ||
        (size != kDigestSize && size != 2 * kDigestSize))
    {
        return ERROR_INVALID_DATA;
    }
    pins.Count = size / kDigestSize;
    for (DWORD index = 0; index != pins.Count; ++index)
    {
        if (BytesAreZero(pins.Values[index].data(), pins.Values[index].size()))
            return ERROR_INVALID_DATA;
    }
    if (pins.Count == 2 && pins.Values[0] == pins.Values[1])
        return ERROR_INVALID_DATA;
    return ERROR_SUCCESS;
}

DWORD ParseOrigin(const std::wstring& origin, HttpConfiguration& configuration)
{
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUserNameLength = static_cast<DWORD>(-1);
    components.dwPasswordLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(origin.c_str(), static_cast<DWORD>(origin.size()), 0,
            &components))
    {
        return GetLastError();
    }
    const bool rootPath = components.dwUrlPathLength == 0 ||
        (components.dwUrlPathLength == 1 && components.lpszUrlPath != nullptr &&
         components.lpszUrlPath[0] == L'/');
    if (components.nScheme != INTERNET_SCHEME_HTTPS ||
        components.dwHostNameLength == 0 || components.dwHostNameLength > 253 ||
        components.dwUserNameLength != 0 || components.dwPasswordLength != 0 ||
        components.dwExtraInfoLength != 0 || !rootPath || components.nPort == 0)
    {
        return ERROR_INVALID_DATA;
    }
    configuration.Host.assign(
        components.lpszHostName, components.dwHostNameLength);
    configuration.Port = components.nPort;
    return ERROR_SUCCESS;
}

DWORD ReadConfiguration(HttpConfiguration& configuration)
{
    configuration = {};
    RegistryKey key;
    LONG status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE, kBackendStatePath, 0, KEY_QUERY_VALUE, key.put());
    if (status != ERROR_SUCCESS) return static_cast<DWORD>(status);
    std::wstring origin;
    DWORD error = ReadStringValue(key.get(), kBackendUrlValue, origin);
    if (error == ERROR_SUCCESS) error = ParseOrigin(origin, configuration);
    if (error == ERROR_SUCCESS)
        error = ReadPinsValue(key.get(), kClientPinsValue, configuration.ClientPins);
    if (error == ERROR_SUCCESS)
        error = ReadPinsValue(key.get(), kServerPinsValue, configuration.ServerPins);
    return error;
}

bool CertificateHasClientAuthentication(PCCERT_CONTEXT certificate) noexcept
{
    DWORD size = 0;
    if (certificate == nullptr || !CertGetEnhancedKeyUsage(
            certificate, 0, nullptr, &size) ||
        size < sizeof(CERT_ENHKEY_USAGE) || size > 64 * 1024)
    {
        return false;
    }
    std::unique_ptr<unsigned char[]> buffer(
        new (std::nothrow) unsigned char[size]);
    if (buffer == nullptr || !CertGetEnhancedKeyUsage(
            certificate, 0,
            reinterpret_cast<PCERT_ENHKEY_USAGE>(buffer.get()), &size))
    {
        return false;
    }
    const auto* usages = reinterpret_cast<const CERT_ENHKEY_USAGE*>(buffer.get());
    bool clientAuthentication = false;
    for (DWORD index = 0; index != usages->cUsageIdentifier; ++index)
    {
        if (usages->rgpszUsageIdentifier[index] != nullptr &&
            std::strcmp(
                usages->rgpszUsageIdentifier[index], szOID_PKIX_KP_CLIENT_AUTH) == 0)
        {
            clientAuthentication = true;
        }
    }
    BYTE intendedUsage = 0;
    return clientAuthentication && CertGetIntendedKeyUsage(
        X509_ASN_ENCODING, certificate->pCertInfo, &intendedUsage,
        sizeof(intendedUsage)) &&
        (intendedUsage & CERT_DIGITAL_SIGNATURE_KEY_USAGE) != 0 &&
        (intendedUsage & CERT_KEY_CERT_SIGN_KEY_USAGE) == 0;
}

bool CertificateIsEndEntity(PCCERT_CONTEXT certificate) noexcept
{
    if (certificate == nullptr || certificate->pCertInfo == nullptr) return false;
    PCERT_EXTENSION extension = CertFindExtension(
        szOID_BASIC_CONSTRAINTS2,
        certificate->pCertInfo->cExtension,
        certificate->pCertInfo->rgExtension);
    if (extension == nullptr) return false;
    CERT_BASIC_CONSTRAINTS2_INFO* constraints = nullptr;
    DWORD size = 0;
    if (!CryptDecodeObjectEx(
            X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
            extension->Value.pbData, extension->Value.cbData,
            CRYPT_DECODE_ALLOC_FLAG, nullptr,
            static_cast<void*>(&constraints), &size) ||
        constraints == nullptr)
    {
        return false;
    }
    const bool endEntity = constraints->fCA == FALSE;
    LocalFree(constraints);
    return endEntity;
}

bool CertificateHasStrongKey(PCCERT_CONTEXT certificate) noexcept
{
    if (certificate == nullptr || certificate->pCertInfo == nullptr) return false;
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
    NTSTATUS status = BCryptGetProperty(
        key, BCRYPT_KEY_LENGTH, reinterpret_cast<PUCHAR>(&bits),
        sizeof(bits), &returned, 0);
    BCryptDestroyKey(key);
    const char* algorithm =
        certificate->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    return BCRYPT_SUCCESS(status) && returned == sizeof(bits) &&
        algorithm != nullptr &&
        ((std::strcmp(algorithm, szOID_RSA_RSA) == 0 && bits >= 3072) ||
         (std::strcmp(algorithm, szOID_ECC_PUBLIC_KEY) == 0 && bits >= 256));
}

bool CertificateHasPrivateKey(PCCERT_CONTEXT certificate) noexcept
{
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
    DWORD specification = 0;
    BOOL release = FALSE;
    if (!CryptAcquireCertificatePrivateKey(
            certificate,
            CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_CACHE_FLAG,
            nullptr,
            &key,
            &specification,
            &release))
    {
        return false;
    }
    if (release)
    {
        if (specification == CERT_NCRYPT_KEY_SPEC)
            NCryptFreeObject(key);
        else
            CryptReleaseContext(static_cast<HCRYPTPROV>(key), 0);
    }
    return true;
}

bool CertificateIsUsableClient(PCCERT_CONTEXT certificate) noexcept
{
    return certificate != nullptr &&
        CertVerifyTimeValidity(nullptr, certificate->pCertInfo) == 0 &&
        CertificateHasClientAuthentication(certificate) &&
        CertificateIsEndEntity(certificate) &&
        CertificateHasStrongKey(certificate) &&
        CertificateHasPrivateKey(certificate);
}

DWORD FindClientCertificate(
    const CertificatePins& pins,
    CertificateContext& selected) noexcept
{
    HCERTSTORE store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
        L"MY");
    if (store == nullptr) return GetLastError();

    PCCERT_CONTEXT best = nullptr;
    DWORD bestPriority = pins.Count;
    bool duplicate = false;
    PCCERT_CONTEXT current = nullptr;
    while ((current = CertEnumCertificatesInStore(store, current)) != nullptr)
    {
        std::array<unsigned char, kDigestSize> digest{};
        if (HashCertificate(current, digest) != ERROR_SUCCESS ||
            !CertificateIsUsableClient(current))
        {
            continue;
        }
        for (DWORD priority = 0; priority != pins.Count; ++priority)
        {
            if (pins.Values[priority] != digest) continue;
            if (priority < bestPriority)
            {
                if (best != nullptr) CertFreeCertificateContext(best);
                best = CertDuplicateCertificateContext(current);
                bestPriority = priority;
                duplicate = false;
            }
            else if (priority == bestPriority)
            {
                duplicate = true;
            }
        }
    }
    CertCloseStore(store, 0);
    if (best == nullptr) return ERROR_NOT_FOUND;
    if (duplicate)
    {
        CertFreeCertificateContext(best);
        return ERROR_ACCESS_DENIED;
    }
    selected.reset(best);
    return ERROR_SUCCESS;
}

DWORD HttpStatusError(DWORD status) noexcept
{
    if (status == HTTP_STATUS_DENIED || status == HTTP_STATUS_FORBIDDEN)
        return ERROR_ACCESS_DENIED;
    if (status == HTTP_STATUS_NOT_FOUND) return ERROR_NOT_FOUND;
    if (status == HTTP_STATUS_CONFLICT) return ERROR_ALREADY_EXISTS;
    if (status == HTTP_STATUS_GONE) return ERROR_TIMEOUT;
    if (status == HTTP_STATUS_BAD_REQUEST || status == HTTP_STATUS_REQUEST_TOO_LARGE)
        return ERROR_INVALID_DATA;
    return status >= 500 ? ERROR_RETRY : ERROR_BAD_NET_RESP;
}

class HttpBackendTransport final : public BackendTransport
{
public:
    HttpBackendTransport() noexcept
    {
        InitializeSRWLock(&lock_);
        InitializeConditionVariable(&wake_);
    }

    ~HttpBackendTransport() override { Close(); }

    DWORD Initialize()
    {
        DWORD error = ReadConfiguration(configuration_);
        if (error != ERROR_SUCCESS) return error;
        error = FindClientCertificate(configuration_.ClientPins, clientCertificate_);
        if (error != ERROR_SUCCESS) return error;

        session_.reset(WinHttpOpen(
            kUserAgent,
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0));
        if (!session_) return GetLastError();
        if (!WinHttpSetTimeouts(
                session_.get(),
                kConnectTimeoutMilliseconds,
                kConnectTimeoutMilliseconds,
                kSendTimeoutMilliseconds,
                kReceiveTimeoutMilliseconds))
        {
            return GetLastError();
        }
        DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 |
            WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
        if (!WinHttpSetOption(
                session_.get(), WINHTTP_OPTION_SECURE_PROTOCOLS,
                &protocols, sizeof(protocols)))
        {
            return GetLastError();
        }
        connection_.reset(WinHttpConnect(
            session_.get(), configuration_.Host.c_str(), configuration_.Port, 0));
        return connection_ ? ERROR_SUCCESS : GetLastError();
    }

    DWORD FetchPolicy(
        const OAC_BACKEND_POLICY_REQUEST& request,
        OAC_BACKEND_POLICY_RESPONSE& response) noexcept override
    {
        response = {};
        return Send(L"/policy", &request, sizeof(request), &response, sizeof(response));
    }

    DWORD Open(
        const OAC_BACKEND_OPEN_REQUEST& request,
        OAC_BACKEND_OPEN_RESPONSE& response) noexcept override
    {
        response = {};
        if (InterlockedCompareExchange(&open_, FALSE, FALSE) != FALSE)
            return ERROR_INVALID_STATE;
        DWORD error = Send(
            L"/session", &request, sizeof(request), &response, sizeof(response));
        if (error != ERROR_SUCCESS) return error;
        InterlockedExchange(&open_, TRUE);
        worker_ = CreateThread(nullptr, 0, WorkerEntry, this, 0, nullptr);
        if (worker_ == nullptr)
        {
            error = GetLastError();
            InterlockedExchange(&open_, FALSE);
            return error;
        }
        return ERROR_SUCCESS;
    }

    DWORD SubmitRenewal(
        const OAC_BACKEND_RENEW_REQUEST& request) noexcept override
    {
        WorkItem item{};
        item.Kind = WorkKind::Renewal;
        item.Renewal = request;
        return Submit(item);
    }

    DWORD SubmitEvidence(
        const OAC_BACKEND_EVIDENCE_METADATA& metadata,
        const OAC_BACKEND_EVIDENCE_ITEM* items,
        std::size_t itemCount) noexcept override
    {
        if (items == nullptr || itemCount == 0 ||
            itemCount > OAC_BACKEND_MAX_EVIDENCE_RECORDS)
        {
            return ERROR_INVALID_PARAMETER;
        }
        WorkItem item{};
        item.Kind = WorkKind::Evidence;
        item.Evidence = metadata;
        item.EvidenceCount = static_cast<ULONG>(itemCount);
        std::copy_n(items, itemCount, item.Items.begin());
        return Submit(item);
    }

    bool TakeRenewal(
        OAC_BACKEND_RENEW_RESPONSE& response,
        DWORD& error) noexcept override
    {
        AcquireSRWLockExclusive(&lock_);
        const bool ready = renewalReady_;
        if (ready)
        {
            response = renewalResponse_;
            error = renewalError_;
            renewalResponse_ = {};
            renewalError_ = ERROR_SUCCESS;
            renewalReady_ = false;
        }
        ReleaseSRWLockExclusive(&lock_);
        return ready;
    }

    bool TakeUpload(
        OAC_BACKEND_UPLOAD_RESPONSE& response,
        DWORD& error) noexcept override
    {
        AcquireSRWLockExclusive(&lock_);
        const bool ready = uploadReady_;
        if (ready)
        {
            response = uploadResponse_;
            error = uploadError_;
            uploadResponse_ = {};
            uploadError_ = ERROR_SUCCESS;
            uploadReady_ = false;
        }
        ReleaseSRWLockExclusive(&lock_);
        return ready;
    }

    void Close() noexcept override
    {
        AcquireSRWLockExclusive(&lock_);
        stopping_ = true;
        WakeAllConditionVariable(&wake_);
        ReleaseSRWLockExclusive(&lock_);
        if (worker_ != nullptr)
        {
            WaitForSingleObject(worker_, INFINITE);
            CloseHandle(worker_);
            worker_ = nullptr;
        }
        InterlockedExchange(&open_, FALSE);
        connection_.reset();
        session_.reset();
        clientCertificate_.reset();
        SecureZeroMemory(queue_.data(), sizeof(queue_));
        queueCount_ = 0;
        renewalResponse_ = {};
        uploadResponse_ = {};
        renewalReady_ = false;
        uploadReady_ = false;
    }

    [[nodiscard]] bool Authenticated() const noexcept override
    {
        return InterlockedCompareExchange(
            const_cast<volatile LONG*>(&open_), FALSE, FALSE) != FALSE;
    }

    [[nodiscard]] bool TestDouble() const noexcept override { return false; }

private:
    enum class WorkKind : ULONG
    {
        None = 0,
        Renewal = 1,
        Evidence = 2
    };

    struct WorkItem
    {
        WorkKind Kind = WorkKind::None;
        OAC_BACKEND_RENEW_REQUEST Renewal{};
        OAC_BACKEND_EVIDENCE_METADATA Evidence{};
        std::array<OAC_BACKEND_EVIDENCE_ITEM,
            OAC_BACKEND_MAX_EVIDENCE_RECORDS> Items{};
        ULONG EvidenceCount = 0;
    };

    static DWORD WINAPI WorkerEntry(void* context) noexcept
    {
        auto* transport = static_cast<HttpBackendTransport*>(context);
        return transport != nullptr ? transport->WorkerLoop() : ERROR_INVALID_PARAMETER;
    }

    DWORD WorkerLoop() noexcept
    {
        using EvidenceBody = std::array<unsigned char,
            sizeof(OAC_BACKEND_EVIDENCE_METADATA) +
                OAC_BACKEND_MAX_EVIDENCE_RECORDS *
                    sizeof(OAC_BACKEND_EVIDENCE_ITEM)>;
        std::unique_ptr<WorkItem> item;
        std::unique_ptr<EvidenceBody> body;
        try
        {
            item = std::make_unique<WorkItem>();
            body = std::make_unique<EvidenceBody>();
        }
        catch (const std::bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        for (;;)
        {
            AcquireSRWLockExclusive(&lock_);
            while (!stopping_ && queueCount_ == 0)
                SleepConditionVariableSRW(&wake_, &lock_, INFINITE, 0);
            if (stopping_)
            {
                ReleaseSRWLockExclusive(&lock_);
                return ERROR_SUCCESS;
            }
            if (queueCount_ == 0 || queueCount_ > queue_.size())
            {
                ReleaseSRWLockExclusive(&lock_);
                return ERROR_INVALID_DATA;
            }
            *item = queue_[0];
            if (queueCount_ == queue_.size())
            {
                queue_[0] = queue_[1];
                queue_[1] = {};
                queueCount_ = 1;
            }
            else
            {
                queue_[0] = {};
                queueCount_ = 0;
            }
            ReleaseSRWLockExclusive(&lock_);

            if (item->Kind == WorkKind::Renewal)
            {
                OAC_BACKEND_RENEW_RESPONSE response{};
                const DWORD error = Send(
                    L"/renew", &item->Renewal, sizeof(item->Renewal),
                    &response, sizeof(response));
                AcquireSRWLockExclusive(&lock_);
                renewalResponse_ = response;
                renewalError_ = error;
                renewalReady_ = true;
                ReleaseSRWLockExclusive(&lock_);
            }
            else if (item->Kind == WorkKind::Evidence)
            {
                body->fill(0);
                std::memcpy(
                    body->data(), &item->Evidence, sizeof(item->Evidence));
                const std::size_t itemBytes =
                    item->EvidenceCount * sizeof(item->Items[0]);
                std::memcpy(
                    body->data() + sizeof(item->Evidence),
                    item->Items.data(), itemBytes);
                OAC_BACKEND_UPLOAD_RESPONSE response{};
                const DWORD error = Send(
                    L"/evidence", body->data(),
                    sizeof(item->Evidence) + itemBytes,
                    &response, sizeof(response));
                AcquireSRWLockExclusive(&lock_);
                uploadResponse_ = response;
                uploadError_ = error;
                uploadReady_ = true;
                ReleaseSRWLockExclusive(&lock_);
                SecureZeroMemory(body->data(), body->size());
            }
            SecureZeroMemory(item.get(), sizeof(*item));
        }
    }

    DWORD Submit(const WorkItem& item) noexcept
    {
        AcquireSRWLockExclusive(&lock_);
        DWORD error = ERROR_SUCCESS;
        if (!Authenticated() || stopping_)
            error = ERROR_INVALID_STATE;
        else if (queueCount_ == queue_.size())
            error = ERROR_BUSY;
        else
        {
            for (std::size_t index = 0; index != queueCount_; ++index)
            {
                if (queue_[index].Kind == item.Kind)
                    error = ERROR_IO_PENDING;
            }
            if (item.Kind == WorkKind::Renewal && renewalReady_)
                error = ERROR_IO_PENDING;
            if (item.Kind == WorkKind::Evidence && uploadReady_)
                error = ERROR_IO_PENDING;
        }
        if (error == ERROR_SUCCESS)
        {
            queue_[queueCount_++] = item;
            WakeConditionVariable(&wake_);
        }
        ReleaseSRWLockExclusive(&lock_);
        return error;
    }

    DWORD Send(
        const wchar_t* path,
        const void* requestBody,
        std::size_t requestSize,
        void* responseBody,
        std::size_t responseSize) noexcept
    {
        if (!connection_ || clientCertificate_.get() == nullptr || path == nullptr ||
            requestBody == nullptr || responseBody == nullptr || requestSize == 0 ||
            requestSize > MAXDWORD || responseSize == 0 || responseSize > MAXDWORD)
        {
            return ERROR_INVALID_PARAMETER;
        }
        const wchar_t* acceptedTypes[] = {L"application/octet-stream", nullptr};
        InternetHandle request(WinHttpOpenRequest(
            connection_.get(), L"POST", path, nullptr, WINHTTP_NO_REFERER,
            acceptedTypes, WINHTTP_FLAG_SECURE));
        if (!request) return GetLastError();
        DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        if (!WinHttpSetOption(
                request.get(), WINHTTP_OPTION_REDIRECT_POLICY,
                &redirectPolicy, sizeof(redirectPolicy)) ||
            !WinHttpSetOption(
                request.get(), WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                const_cast<CERT_CONTEXT*>(clientCertificate_.get()),
                sizeof(CERT_CONTEXT)))
        {
            return GetLastError();
        }
        constexpr wchar_t headers[] =
            L"Content-Type: application/octet-stream\r\n"
            L"Accept: application/octet-stream\r\n"
            L"Cache-Control: no-store\r\n";
        constexpr DWORD headerCharacters = ARRAYSIZE(headers) - 1;
        if (!WinHttpSendRequest(
                request.get(), headers, headerCharacters,
                const_cast<void*>(requestBody), static_cast<DWORD>(requestSize),
                static_cast<DWORD>(requestSize), 0) ||
            !WinHttpReceiveResponse(request.get(), nullptr))
        {
            return GetLastError();
        }

        CertificateContext serverCertificate;
        PCCERT_CONTEXT rawServerCertificate = nullptr;
        DWORD certificateSize = sizeof(PCCERT_CONTEXT);
        if (!WinHttpQueryOption(
                request.get(), WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                static_cast<void*>(&rawServerCertificate), &certificateSize) ||
            rawServerCertificate == nullptr)
        {
            return GetLastError();
        }
        serverCertificate.reset(rawServerCertificate);
        std::array<unsigned char, kDigestSize> serverDigest{};
        DWORD error = HashCertificate(serverCertificate.get(), serverDigest);
        if (error != ERROR_SUCCESS ||
            !PinsContain(configuration_.ServerPins, serverDigest))
        {
            return error == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : error;
        }

        DWORD status = 0;
        DWORD statusSize = sizeof(status);
        if (!WinHttpQueryHeaders(
                request.get(),
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
                WINHTTP_NO_HEADER_INDEX))
        {
            return GetLastError();
        }
        if (status != HTTP_STATUS_OK) return HttpStatusError(status);

        DWORD contentLength = 0;
        DWORD contentLengthSize = sizeof(contentLength);
        if (!WinHttpQueryHeaders(
                request.get(),
                WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &contentLength, &contentLengthSize,
                WINHTTP_NO_HEADER_INDEX) || contentLength != responseSize)
        {
            return ERROR_BAD_NET_RESP;
        }
        wchar_t contentType[64]{};
        DWORD contentTypeSize = sizeof(contentType);
        if (!WinHttpQueryHeaders(
                request.get(), WINHTTP_QUERY_CONTENT_TYPE,
                WINHTTP_HEADER_NAME_BY_INDEX, contentType, &contentTypeSize,
                WINHTTP_NO_HEADER_INDEX) ||
            _wcsicmp(contentType, L"application/octet-stream") != 0)
        {
            return ERROR_BAD_NET_RESP;
        }

        std::size_t received = 0;
        while (received != responseSize)
        {
            DWORD read = 0;
            if (!WinHttpReadData(
                    request.get(),
                    static_cast<unsigned char*>(responseBody) + received,
                    static_cast<DWORD>(responseSize - received),
                    &read))
            {
                return GetLastError();
            }
            if (read == 0) return ERROR_HANDLE_EOF;
            received += read;
        }
        DWORD extra = 0;
        if (!WinHttpQueryDataAvailable(request.get(), &extra) || extra != 0)
            return ERROR_BAD_NET_RESP;
        return ERROR_SUCCESS;
    }

    HttpConfiguration configuration_{};
    CertificateContext clientCertificate_;
    InternetHandle session_;
    InternetHandle connection_;
    SRWLOCK lock_{};
    CONDITION_VARIABLE wake_{};
    HANDLE worker_ = nullptr;
    std::array<WorkItem, kWorkCapacity> queue_{};
    std::size_t queueCount_ = 0;
    OAC_BACKEND_RENEW_RESPONSE renewalResponse_{};
    OAC_BACKEND_UPLOAD_RESPONSE uploadResponse_{};
    DWORD renewalError_ = ERROR_SUCCESS;
    DWORD uploadError_ = ERROR_SUCCESS;
    volatile LONG open_ = FALSE;
    bool renewalReady_ = false;
    bool uploadReady_ = false;
    bool stopping_ = false;
};
} // namespace

namespace oac
{
std::unique_ptr<BackendTransport> CreateHttpBackendTransport(
    DWORD& error) noexcept
{
    error = ERROR_SUCCESS;
    try
    {
        auto transport = std::make_unique<HttpBackendTransport>();
        error = transport->Initialize();
        return error == ERROR_SUCCESS ? std::move(transport) : nullptr;
    }
    catch (const std::bad_alloc&)
    {
        error = ERROR_NOT_ENOUGH_MEMORY;
        return {};
    }
    catch (...)
    {
        error = ERROR_UNHANDLED_EXCEPTION;
        return {};
    }
}
}
