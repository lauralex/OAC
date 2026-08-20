#include "runtime_module.hpp"

#include <bcrypt.h>

#include <algorithm>
#include <cstddef>
#include <limits>
#include <new>
#include <vector>

#include "..\shared\oac_windows.hpp"

namespace
{
constexpr ULONGLONG kMaximumRuntimeModuleBytes = 1024ULL * 1024ULL * 1024ULL;

DWORD BcryptError(NTSTATUS status) noexcept
{
    return BCRYPT_SUCCESS(status)
        ? ERROR_SUCCESS
        : static_cast<DWORD>(HRESULT_FROM_NT(status));
}

class Sha256Hash final
{
public:
    ~Sha256Hash()
    {
        if (hash_ != nullptr) BCryptDestroyHash(hash_);
        if (algorithm_ != nullptr) BCryptCloseAlgorithmProvider(algorithm_, 0);
    }

    Sha256Hash(const Sha256Hash&) = delete;
    Sha256Hash& operator=(const Sha256Hash&) = delete;
    Sha256Hash() = default;

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

    DWORD Append(const void* bytes, ULONG length) noexcept
    {
        return BcryptError(BCryptHashData(
            hash_,
            static_cast<PUCHAR>(const_cast<void*>(bytes)),
            length,
            0));
    }

    DWORD Finish(
        std::array<unsigned char, OAC_MANIFEST_HASH_SIZE>& digest) noexcept
    {
        return BcryptError(BCryptFinishHash(
            hash_, digest.data(), static_cast<ULONG>(digest.size()), 0));
    }

private:
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<unsigned char> object_;
};

DWORD HashFile(
    HANDLE file,
    std::array<unsigned char, OAC_MANIFEST_HASH_SIZE>& digest)
{
    if (file == nullptr || file == INVALID_HANDLE_VALUE)
        return ERROR_INVALID_HANDLE;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size)) return GetLastError();
    if (size.QuadPart <= 0 ||
        static_cast<ULONGLONG>(size.QuadPart) > kMaximumRuntimeModuleBytes)
    {
        return ERROR_FILE_TOO_LARGE;
    }

    LARGE_INTEGER beginning{};
    if (!SetFilePointerEx(file, beginning, nullptr, FILE_BEGIN))
        return GetLastError();

    Sha256Hash hash;
    DWORD error = hash.Initialize();
    if (error != ERROR_SUCCESS) return error;
    std::vector<unsigned char> buffer(size_t{64} * 1024);
    ULONGLONG total = 0;
    while (error == ERROR_SUCCESS && total < static_cast<ULONGLONG>(size.QuadPart))
    {
        const DWORD wanted = static_cast<DWORD>((std::min)(
            static_cast<ULONGLONG>(buffer.size()),
            static_cast<ULONGLONG>(size.QuadPart) - total));
        DWORD received = 0;
        if (!ReadFile(file, buffer.data(), wanted, &received, nullptr))
        {
            error = GetLastError();
            break;
        }
        if (received == 0)
        {
            error = ERROR_HANDLE_EOF;
            break;
        }
        error = hash.Append(buffer.data(), received);
        total += received;
    }
    if (error == ERROR_SUCCESS && total != static_cast<ULONGLONG>(size.QuadPart))
        error = ERROR_HANDLE_EOF;
    if (error == ERROR_SUCCESS) error = hash.Finish(digest);
    return error;
}
} // namespace

namespace oac
{
DWORD EvaluateRuntimeModule(
    std::wstring_view reportedPath,
    const OAC_GAME_MANIFEST& manifest,
    RuntimeModuleEvaluation& evaluation) noexcept
{
    evaluation = {};
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
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr));
        if (!stabilityLock) return GetLastError();

        error = EvaluateLockedFileTrust(
            stabilityLock.get(), evaluation.Trust);
        if (error != ERROR_SUCCESS) return error;
        error = HashFile(stabilityLock.get(), evaluation.Sha256);
        if (error != ERROR_SUCCESS) return error;

        evaluation.TrustedWindowsModule =
            evaluation.Trust.UnderWindowsDirectory &&
            FileTrustAccepted(evaluation.Trust);
        evaluation.Allowed = OacManifestRuntimeModuleAllowed(
            &manifest,
            evaluation.Sha256.data(),
            evaluation.TrustedWindowsModule ? 1 : 0) != 0;
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
} // namespace oac
