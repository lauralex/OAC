#include "scanner.hpp"

#include <bcrypt.h>
#include <objbase.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <sstream>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Ole32.lib")

namespace
{
constexpr size_t kSha256Bytes = 32;

const wchar_t* SeverityName(FindingSeverity severity)
{
    switch (severity)
    {
    case FindingSeverity::Critical: return L"CRITICAL";
    case FindingSeverity::High: return L"HIGH";
    case FindingSeverity::Medium: return L"MEDIUM";
    case FindingSeverity::Low: return L"LOW";
    default: return L"INFO";
    }
}

std::wstring SanitizeLine(std::wstring value)
{
    std::replace(value.begin(), value.end(), L'\r', L' ');
    std::replace(value.begin(), value.end(), L'\n', L' ');
    return value;
}

unsigned long long CurrentTimestamp100ns()
{
    using PreciseTimeFn = VOID(WINAPI*)(LPFILETIME);
    static const PreciseTimeFn precise = oac::ResolveFunction<PreciseTimeFn>(
        GetModuleHandleW(L"kernel32.dll"), "GetSystemTimePreciseAsFileTime");
    FILETIME time{};
    if (precise != nullptr) precise(&time);
    else GetSystemTimeAsFileTime(&time);
    ULARGE_INTEGER value{};
    value.LowPart = time.dwLowDateTime;
    value.HighPart = time.dwHighDateTime;
    return value.QuadPart;
}

std::string Hex(std::span<const unsigned char> bytes)
{
    static constexpr char alphabet[] = "0123456789ABCDEF";
    std::string result(bytes.size() * 2, '0');
    for (size_t index = 0; index < bytes.size(); ++index)
    {
        result[index * 2] = alphabet[bytes[index] >> 4];
        result[index * 2 + 1] = alphabet[bytes[index] & 0x0f];
    }
    return result;
}

class Sha256Hasher
{
public:
    Sha256Hasher()
    {
        DWORD objectBytes = 0;
        DWORD hashBytes = 0;
        DWORD returned = 0;
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
                &algorithm_, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) ||
            !BCRYPT_SUCCESS(BCryptGetProperty(algorithm_, BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes),
                &returned, 0)) || returned != sizeof(objectBytes) || objectBytes == 0 ||
            !BCRYPT_SUCCESS(BCryptGetProperty(algorithm_, BCRYPT_HASH_LENGTH,
                reinterpret_cast<PUCHAR>(&hashBytes), sizeof(hashBytes),
                &returned, 0)) || returned != sizeof(hashBytes) ||
            hashBytes != kSha256Bytes)
            return;
        object_.resize(objectBytes);
        if (!BCRYPT_SUCCESS(BCryptCreateHash(algorithm_, &hash_, object_.data(),
                static_cast<ULONG>(object_.size()), nullptr, 0, 0)))
            return;
        valid_ = true;
    }

    ~Sha256Hasher()
    {
        if (hash_ != nullptr) BCryptDestroyHash(hash_);
        if (algorithm_ != nullptr) BCryptCloseAlgorithmProvider(algorithm_, 0);
        if (!object_.empty()) SecureZeroMemory(object_.data(), object_.size());
    }

    Sha256Hasher(const Sha256Hasher&) = delete;
    Sha256Hasher& operator=(const Sha256Hasher&) = delete;

    bool Update(std::span<const unsigned char> bytes)
    {
        if (!valid_) return false;
        size_t offset = 0;
        while (offset < bytes.size())
        {
            const ULONG chunk = static_cast<ULONG>(std::min<size_t>(
                bytes.size() - offset, std::numeric_limits<ULONG>::max()));
            if (!BCRYPT_SUCCESS(BCryptHashData(hash_,
                    const_cast<PUCHAR>(bytes.data() + offset), chunk, 0)))
            {
                valid_ = false;
                return false;
            }
            offset += chunk;
        }
        return true;
    }

    std::optional<std::array<unsigned char, kSha256Bytes>> Finish()
    {
        if (!valid_) return std::nullopt;
        std::array<unsigned char, kSha256Bytes> digest{};
        if (!BCRYPT_SUCCESS(BCryptFinishHash(hash_, digest.data(),
                static_cast<ULONG>(digest.size()), 0)))
            return std::nullopt;
        valid_ = false;
        return digest;
    }

private:
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<unsigned char> object_;
    bool valid_ = false;
};

std::optional<std::array<unsigned char, kSha256Bytes>> Sha256(
    std::span<const unsigned char> bytes)
{
    Sha256Hasher hasher;
    if (!hasher.Update(bytes)) return std::nullopt;
    return hasher.Finish();
}

std::optional<std::array<unsigned char, kSha256Bytes>> Sha256File(
    const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) return std::nullopt;
    Sha256Hasher hasher;
    std::vector<unsigned char> buffer(size_t{64} * 1024);
    while (input)
    {
        input.read(reinterpret_cast<char*>(buffer.data()),
            static_cast<std::streamsize>(buffer.size()));
        const std::streamsize count = input.gcount();
        if (count > 0 && !hasher.Update(std::span(buffer.data(),
                static_cast<size_t>(count))))
            return std::nullopt;
    }
    if (!input.eof()) return std::nullopt;
    return hasher.Finish();
}

template<typename T>
void AppendScalar(std::vector<unsigned char>& destination, const T& value)
{
    static_assert(std::is_trivially_copyable_v<T>);
    const auto* bytes = reinterpret_cast<const unsigned char*>(&value);
    destination.insert(destination.end(), bytes, bytes + sizeof(value));
}

std::optional<std::array<unsigned char, kSha256Bytes>> InitialChain(
    std::span<const unsigned char> runId,
    const std::wstring& challenge)
{
    static constexpr unsigned char domain[] = "OAC-REPORT-CHAIN-V4";
    Sha256Hasher hasher;
    const std::string challengeUtf8 = oac::Utf8(challenge);
    if (!hasher.Update(std::span(domain, sizeof(domain) - 1)) ||
        !hasher.Update(runId) ||
        !hasher.Update(std::span(
            reinterpret_cast<const unsigned char*>(challengeUtf8.data()),
            challengeUtf8.size())))
        return std::nullopt;
    return hasher.Finish();
}

std::optional<std::array<unsigned char, kSha256Bytes>> NextChain(
    const std::array<unsigned char, kSha256Bytes>& previous,
    const ClientFinding& finding)
{
    const std::string category = oac::Utf8(finding.category);
    const std::string message = oac::Utf8(finding.message);
    if (category.size() > std::numeric_limits<ULONG>::max() ||
        message.size() > std::numeric_limits<ULONG>::max()) return std::nullopt;
    std::vector<unsigned char> canonical;
    canonical.reserve(previous.size() + category.size() + message.size() + 64);
    canonical.insert(canonical.end(), previous.begin(), previous.end());
    AppendScalar(canonical, finding.sequence);
    AppendScalar(canonical, finding.timestamp100ns);
    AppendScalar(canonical, finding.originSequence);
    AppendScalar(canonical, finding.originTimestamp100ns);
    const ULONG severity = static_cast<ULONG>(finding.severity);
    AppendScalar(canonical, severity);
    AppendScalar(canonical, finding.processId);
    AppendScalar(canonical, finding.threadId);
    AppendScalar(canonical, finding.address);
    const ULONG categoryBytes = static_cast<ULONG>(category.size());
    const ULONG messageBytes = static_cast<ULONG>(message.size());
    AppendScalar(canonical, categoryBytes);
    canonical.insert(canonical.end(), category.begin(), category.end());
    AppendScalar(canonical, messageBytes);
    canonical.insert(canonical.end(), message.begin(), message.end());
    return Sha256(canonical);
}

struct ArtifactDigest
{
    std::filesystem::path name;
    unsigned long long size = 0;
    std::array<unsigned char, kSha256Bytes> digest{};
};

std::vector<ArtifactDigest> InventoryArtifacts(const std::filesystem::path& reportPath)
{
    std::vector<ArtifactDigest> artifacts;
    const std::filesystem::path directory = reportPath.has_parent_path()
        ? reportPath.parent_path() : std::filesystem::path(L".");
    std::error_code error;
    for (std::filesystem::directory_iterator iterator(directory, error), end;
         !error && iterator != end; iterator.increment(error))
    {
        if (!iterator->is_regular_file(error) || error) continue;
        const std::filesystem::path filename = iterator->path().filename();
        const std::wstring name = filename.wstring();
        if (!name.starts_with(L"oac-") || filename == reportPath.filename() ||
            name.ends_with(L".sha256") || name.find(L".tmp-") != std::wstring::npos)
            continue;
        const auto digest = Sha256File(iterator->path());
        const auto size = iterator->file_size(error);
        if (!digest.has_value() || error) continue;
        artifacts.push_back({filename, size, *digest});
    }
    std::ranges::sort(artifacts,
        [](const ArtifactDigest& left, const ArtifactDigest& right)
        {
            return left.name.native() < right.name.native();
        });
    return artifacts;
}

bool AtomicWrite(
    const std::filesystem::path& path,
    std::string_view bytes,
    std::string_view suffix)
{
    std::filesystem::path temporary = path;
    temporary += L".tmp-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::wstring(suffix.begin(), suffix.end());
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) return false;
        output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        output.flush();
        if (!output.good())
        {
            output.close();
            std::error_code ignored;
            std::filesystem::remove(temporary, ignored);
            return false;
        }
    }
    if (!MoveFileExW(temporary.c_str(), path.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        return false;
    }
    return true;
}
} // namespace

Reporter::Reporter(
    FindingSeverity failureThreshold,
    std::wstring deploymentMode,
    std::wstring challenge)
    : failureThreshold_(failureThreshold),
      deploymentMode_(SanitizeLine(std::move(deploymentMode))),
      challenge_(SanitizeLine(std::move(challenge))),
      runId_(16)
{
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, runId_.data(),
            static_cast<ULONG>(runId_.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    {
        GUID fallback{};
        if (SUCCEEDED(CoCreateGuid(&fallback)))
            memcpy(runId_.data(), &fallback, std::min(runId_.size(), sizeof(fallback)));
        else
        {
            const unsigned long long timestamp = CurrentTimestamp100ns();
            memcpy(runId_.data(), &timestamp,
                std::min(runId_.size(), sizeof(timestamp)));
        }
    }
}

void Reporter::Add(
    FindingSeverity severity,
    const std::wstring& category,
    const std::wstring& message,
    DWORD processId,
    DWORD threadId,
    unsigned long long address,
    unsigned long long originSequence,
    unsigned long long originTimestamp100ns)
{
    ClientFinding finding;
    finding.severity = severity;
    finding.category = SanitizeLine(category);
    finding.message = SanitizeLine(message);
    finding.processId = processId;
    finding.threadId = threadId;
    finding.address = address;
    finding.originSequence = originSequence;
    finding.originTimestamp100ns = originTimestamp100ns;

    std::wostringstream key;
    key << static_cast<unsigned>(finding.severity) << L'\x1f'
        << finding.category << L'\x1f' << finding.message << L'\x1f'
        << finding.processId << L'\x1f' << finding.threadId << L'\x1f'
        << finding.address << L'\x1f' << finding.originSequence << L'\x1f'
        << finding.originTimestamp100ns;
    if (!findingKeys_.insert(key.str()).second) return;

    finding.sequence = nextSequence_++;
    finding.timestamp100ns = CurrentTimestamp100ns();
    findings_.push_back(std::move(finding));

    const auto& stored = findings_.back();
    std::wcout << L'[' << SeverityName(stored.severity) << L"][" << stored.category << L"] "
               << stored.message;
    if (stored.processId != 0) std::wcout << L" pid=" << stored.processId;
    if (stored.threadId != 0) std::wcout << L" tid=" << stored.threadId;
    if (stored.address != 0)
        std::wcout << L" address=0x" << std::hex << stored.address << std::dec;
    std::wcout << L'\n';
}

bool Reporter::Save(const std::filesystem::path& path) const
{
    const auto artifacts = InventoryArtifacts(path);
    const auto initial = InitialChain(runId_, challenge_);
    if (!initial.has_value()) return false;
    auto chain = *initial;

    std::ostringstream output;
    output << "OAC defensive scan report\r\n"
           << "schema=4\r\n"
           << "generated_timestamp_100ns=" << CurrentTimestamp100ns() << "\r\n"
           << "deployment_mode=" << oac::Utf8(deploymentMode_) << "\r\n"
           << "failure_threshold=" << oac::Utf8(SeverityName(failureThreshold_)) << "\r\n"
           << "run_id=" << Hex(runId_) << "\r\n"
           << "challenge=" << (challenge_.empty() ? "none" : oac::Utf8(challenge_)) << "\r\n"
           << "findings=" << findings_.size()
           << " actionable=" << SuspiciousCount() << "\r\n"
           << "artifact_count=" << artifacts.size() << "\r\n\r\n"
           << "artifacts:\r\n";
    for (const auto& artifact : artifacts)
        output << oac::Utf8(artifact.name.wstring()) << " size=" << artifact.size
               << " sha256=" << Hex(artifact.digest) << "\r\n";
    output << "\r\nfindings:\r\n";

    for (const auto& finding : findings_)
    {
        const auto next = NextChain(chain, finding);
        if (!next.has_value()) return false;
        chain = *next;
        const std::string chainHex = Hex(chain);
        const std::wstring chainWide(chainHex.begin(), chainHex.end());
        std::wostringstream line;
        line << L"seq=" << finding.sequence
             << L" timestamp_100ns=" << finding.timestamp100ns
             << L" chain=" << chainWide
             << L" [" << SeverityName(finding.severity) << L"][" << finding.category << L"] "
             << finding.message;
        if (finding.originSequence != 0)
            line << L" origin_seq=" << finding.originSequence;
        if (finding.originTimestamp100ns != 0)
            line << L" origin_timestamp_100ns=" << finding.originTimestamp100ns;
        if (finding.processId != 0) line << L" pid=" << finding.processId;
        if (finding.threadId != 0) line << L" tid=" << finding.threadId;
        if (finding.address != 0)
            line << L" address=0x" << std::hex << finding.address;
        line << L"\r\n";
        output << oac::Utf8(line.str());
    }
    output << "\r\nchain_root=" << Hex(chain) << "\r\n"
           << "integrity_scope=unkeyed SHA-256 chain plus artifact digests; "
              "use a server challenge and authenticated upload for production authenticity\r\n";

    const std::string report = output.str();
    const auto reportDigest = Sha256(std::span(
        reinterpret_cast<const unsigned char*>(report.data()), report.size()));
    if (!reportDigest.has_value()) return false;
    const std::string suffix = Hex(std::span(runId_.data(), 4));
    if (!AtomicWrite(path, report, suffix)) return false;

    const std::filesystem::path sidecar = path.wstring() + L".sha256";
    const std::string sidecarText = Hex(*reportDigest) + " *" +
        oac::Utf8(path.filename().wstring()) + "\r\n";
    return AtomicWrite(sidecar, sidecarText, suffix);
}

const std::vector<ClientFinding>& Reporter::Findings() const noexcept
{
    return findings_;
}

size_t Reporter::SuspiciousCount() const noexcept
{
    return SuspiciousCountSince(0);
}

size_t Reporter::SuspiciousCountSince(size_t firstFinding) const noexcept
{
    size_t count = 0;
    firstFinding = std::min(firstFinding, findings_.size());
    for (size_t index = firstFinding; index < findings_.size(); ++index)
        if (findings_[index].severity >= failureThreshold_) ++count;
    return count;
}
