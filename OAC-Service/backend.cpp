#include "backend.hpp"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <new>
#include <utility>

namespace
{
constexpr wchar_t kBackendStatePath[] = L"SOFTWARE\\OAC";
constexpr wchar_t kBackendModeValue[] = L"BackendMode";
constexpr wchar_t kBackendScenarioValue[] = L"BackendScenario";
constexpr DWORD kMockBackendMode = 1;

bool BytesAreZero(const void* value, std::size_t size) noexcept
{
    const auto* bytes = static_cast<const std::byte*>(value);
    if (bytes == nullptr) return true;
    for (std::size_t index = 0; index != size; ++index)
    {
        if (bytes[index] != std::byte{}) return false;
    }
    return true;
}

bool SameBytes(
    const void* left,
    const void* right,
    std::size_t size) noexcept
{
    return left != nullptr && right != nullptr &&
        std::memcmp(left, right, size) == 0;
}

DWORD RandomBytes(void* destination, std::size_t size) noexcept
{
    if (destination == nullptr || size == 0 || size > MAXDWORD)
        return ERROR_INVALID_PARAMETER;
    const NTSTATUS status = BCryptGenRandom(
        nullptr,
        static_cast<PUCHAR>(destination),
        static_cast<ULONG>(size),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(status) ? ERROR_SUCCESS : ERROR_GEN_FAILURE;
}

DWORD Sha256(
    const void* data,
    std::size_t size,
    std::uint8_t digest[OAC_BACKEND_DIGEST_SIZE]) noexcept
{
    if (data == nullptr || digest == nullptr || size > MAXDWORD)
        return ERROR_INVALID_PARAMETER;

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD error = ERROR_SUCCESS;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
        return ERROR_GEN_FAILURE;
    status = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0);
    if (BCRYPT_SUCCESS(status))
    {
        status = BCryptHashData(
            hash,
            const_cast<PUCHAR>(static_cast<const UCHAR*>(data)),
            static_cast<ULONG>(size),
            0);
    }
    if (BCRYPT_SUCCESS(status))
    {
        status = BCryptFinishHash(
            hash, digest, OAC_BACKEND_DIGEST_SIZE, 0);
    }
    if (!BCRYPT_SUCCESS(status)) error = ERROR_GEN_FAILURE;
    if (hash != nullptr) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return error;
}

ULONGLONG CurrentUnixSeconds() noexcept
{
    FILETIME time{};
    GetSystemTimeAsFileTime(&time);
    const ULONGLONG ticks =
        (static_cast<ULONGLONG>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
    constexpr ULONGLONG kUnixEpoch = 116444736000000000ULL;
    return ticks >= kUnixEpoch ? (ticks - kUnixEpoch) / 10000000ULL : 0;
}

bool AddDeadline(
    ULONGLONG currentMilliseconds,
    ULONG durationMilliseconds,
    ULONGLONG& deadline) noexcept
{
    if (durationMilliseconds == 0 ||
        currentMilliseconds > ~0ULL - durationMilliseconds)
    {
        return false;
    }
    deadline = currentMilliseconds + durationMilliseconds;
    return true;
}

DWORD InitializeRequestHeader(
    OAC_BACKEND_REQUEST_HEADER& header,
    ULONG size,
    ULONG type,
    ULONGLONG sequence,
    const std::uint8_t sessionId[OAC_BACKEND_SESSION_ID_SIZE]) noexcept
{
    header = {};
    header.Revision = OAC_BACKEND_PROTOCOL_REVISION;
    header.Size = size;
    header.MessageType = type;
    header.RequestSequence = sequence;
    if (sessionId != nullptr)
        std::memcpy(header.SessionId, sessionId, sizeof(header.SessionId));
    DWORD error = RandomBytes(header.Nonce, sizeof(header.Nonce));
    if (error != ERROR_SUCCESS) return error;
    const ULONGLONG now = CurrentUnixSeconds();
    if (now == 0 || now > ~0ULL - OAC_BACKEND_REQUEST_VALIDITY_SECONDS)
        return ERROR_INVALID_TIME;
    header.IssuedAtUnixSeconds = now;
    header.ExpiresAtUnixSeconds = now + OAC_BACKEND_REQUEST_VALIDITY_SECONDS;
    return ERROR_SUCCESS;
}

void InitializeResponseHeader(
    OAC_BACKEND_RESPONSE_HEADER& header,
    ULONG size,
    ULONG type,
    const OAC_BACKEND_REQUEST_HEADER& request,
    OAC_BACKEND_RESULT result,
    const std::uint8_t sessionId[OAC_BACKEND_SESSION_ID_SIZE],
    const std::uint8_t requestNonceSha256[OAC_BACKEND_DIGEST_SIZE]) noexcept
{
    header = {};
    header.Revision = OAC_BACKEND_PROTOCOL_REVISION;
    header.Size = size;
    header.MessageType = type;
    header.RequestSequence = request.RequestSequence;
    header.Result = result;
    if (sessionId != nullptr)
        std::memcpy(header.SessionId, sessionId, sizeof(header.SessionId));
    std::memcpy(
        header.RequestNonceSha256,
        requestNonceSha256,
        sizeof(header.RequestNonceSha256));
}

DWORD ReadBackendConfiguration(
    DWORD& mode,
    oac::BackendScenario& scenario) noexcept
{
    DWORD modeType = 0;
    DWORD modeSize = sizeof(mode);
    LSTATUS status = RegGetValueW(
        HKEY_LOCAL_MACHINE,
        kBackendStatePath,
        kBackendModeValue,
        RRF_RT_REG_DWORD,
        &modeType,
        &mode,
        &modeSize);
    if (status != ERROR_SUCCESS) return static_cast<DWORD>(status);

    DWORD rawScenario = 0;
    DWORD scenarioType = 0;
    DWORD scenarioSize = sizeof(rawScenario);
    status = RegGetValueW(
        HKEY_LOCAL_MACHINE,
        kBackendStatePath,
        kBackendScenarioValue,
        RRF_RT_REG_DWORD,
        &scenarioType,
        &rawScenario,
        &scenarioSize);
    if (status != ERROR_SUCCESS) return static_cast<DWORD>(status);
    if (modeType != REG_DWORD || scenarioType != REG_DWORD ||
        modeSize != sizeof(mode) || scenarioSize != sizeof(rawScenario) ||
        rawScenario > static_cast<DWORD>(oac::BackendScenario::RevokeLease))
    {
        return ERROR_INVALID_DATA;
    }
    scenario = static_cast<oac::BackendScenario>(rawScenario);
    return ERROR_SUCCESS;
}
} // namespace

namespace oac
{
MockBackendTransport::MockBackendTransport(BackendScenario scenario) noexcept
    : scenario_(scenario)
{
}

MockBackendTransport::~MockBackendTransport()
{
    Close();
}

DWORD MockBackendTransport::Open(
    const OAC_BACKEND_OPEN_REQUEST& request,
    OAC_BACKEND_OPEN_RESPONSE& response) noexcept
{
    response = {};
    if (open_ ||
        !OacBackendValidateOpenRequest(
            &request, sizeof(request), CurrentUnixSeconds()))
    {
        return ERROR_INVALID_DATA;
    }

    std::array<std::uint8_t, OAC_BACKEND_DIGEST_SIZE> nonceDigest{};
    DWORD error = Sha256(
        request.Header.Nonce, sizeof(request.Header.Nonce), nonceDigest.data());
    if (error != ERROR_SUCCESS) return error;
    if (!OacBackendAcceptNonceDigest(&replayWindow_, nonceDigest.data()))
        return ERROR_RETRY;
    if (scenario_ == BackendScenario::ReplayOpen)
    {
        return OacBackendAcceptNonceDigest(&replayWindow_, nonceDigest.data())
            ? ERROR_INVALID_DATA
            : ERROR_RETRY;
    }
    error = RandomBytes(sessionId_.data(), sessionId_.size());
    if (error != ERROR_SUCCESS || BytesAreZero(sessionId_.data(), sessionId_.size()))
        return error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error;

    std::array<std::uint8_t, OAC_BACKEND_NONCE_SIZE> serverNonce{};
    error = RandomBytes(serverNonce.data(), serverNonce.size());
    if (error != ERROR_SUCCESS || BytesAreZero(serverNonce.data(), serverNonce.size()))
        return error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error;

    OAC_BACKEND_BINDING_MATERIAL binding{};
    std::memcpy(binding.SessionId, sessionId_.data(), sessionId_.size());
    std::memcpy(
        binding.RequestNonceSha256, nonceDigest.data(), nonceDigest.size());
    std::memcpy(binding.ServerNonce, serverNonce.data(), serverNonce.size());
    error = Sha256(&binding, sizeof(binding), bindingSha256_.data());
    SecureZeroMemory(&binding, sizeof(binding));
    if (error != ERROR_SUCCESS) return error;

    InitializeResponseHeader(
        response.Header,
        sizeof(response),
        OAC_BACKEND_MESSAGE_OPEN_SESSION,
        request.Header,
        OAC_BACKEND_RESULT_ACCEPTED,
        sessionId_.data(),
        nonceDigest.data());
    std::memcpy(
        response.ServerNonce, serverNonce.data(), sizeof(response.ServerNonce));
    response.LeaseSequence = 1;
    response.LeaseMilliseconds = request.MaximumLeaseMilliseconds;
    response.GraceMilliseconds = request.MaximumGraceMilliseconds;
    response.RenewalIntervalMilliseconds = request.RenewalIntervalMilliseconds;

    leaseSequence_ = response.LeaseSequence;
    leaseMilliseconds_ = response.LeaseMilliseconds;
    graceMilliseconds_ = response.GraceMilliseconds;
    renewalMilliseconds_ = response.RenewalIntervalMilliseconds;
    lastRequestSequence_ = request.Header.RequestSequence;
    open_ = true;
    SecureZeroMemory(serverNonce.data(), serverNonce.size());
    return ERROR_SUCCESS;
}

DWORD MockBackendTransport::SubmitRenewal(
    const OAC_BACKEND_RENEW_REQUEST& request) noexcept
{
    if (!open_ || renewalReady_ ||
        !OacBackendValidateRenewRequest(
            &request, sizeof(request), CurrentUnixSeconds()) ||
        !SameBytes(
            request.Header.SessionId, sessionId_.data(), sessionId_.size()) ||
        request.Header.RequestSequence <= lastRequestSequence_ ||
        request.CurrentLeaseSequence != leaseSequence_)
    {
        return ERROR_INVALID_DATA;
    }
    std::array<std::uint8_t, OAC_BACKEND_DIGEST_SIZE> nonceDigest{};
    DWORD error = Sha256(
        request.Header.Nonce, sizeof(request.Header.Nonce), nonceDigest.data());
    if (error != ERROR_SUCCESS) return error;
    if (!OacBackendAcceptNonceDigest(&replayWindow_, nonceDigest.data()))
        return ERROR_RETRY;
    lastRequestSequence_ = request.Header.RequestSequence;
    if (scenario_ == BackendScenario::StopRenewing)
        return ERROR_SUCCESS;

    renewalResponse_ = {};
    InitializeResponseHeader(
        renewalResponse_.Header,
        sizeof(renewalResponse_),
        OAC_BACKEND_MESSAGE_RENEW_LEASE,
        request.Header,
        OAC_BACKEND_RESULT_ACCEPTED,
        sessionId_.data(),
        nonceDigest.data());
    renewalResponse_.LeaseSequence = ++leaseSequence_;
    if (scenario_ == BackendScenario::RevokeLease)
    {
        renewalResponse_.Revoked = 1;
    }
    else
    {
        renewalResponse_.LeaseMilliseconds = leaseMilliseconds_;
        renewalResponse_.GraceMilliseconds = graceMilliseconds_;
        renewalResponse_.RenewalIntervalMilliseconds = renewalMilliseconds_;
    }
    renewalReady_ = true;
    return ERROR_SUCCESS;
}

DWORD MockBackendTransport::SubmitEvidence(
    const OAC_BACKEND_EVIDENCE_METADATA& metadata,
    const OAC_BACKEND_EVIDENCE_ITEM* items,
    std::size_t itemCount) noexcept
{
    if (!open_ || uploadReady_ || metadata.Header.RequestSequence <=
            lastRequestSequence_ ||
        !SameBytes(
            metadata.Header.SessionId, sessionId_.data(), sessionId_.size()) ||
        !OacBackendValidateEvidenceBatch(
            &metadata,
            sizeof(metadata),
            items,
            itemCount,
            CurrentUnixSeconds(),
            bindingSha256_.data()))
    {
        return ERROR_INVALID_DATA;
    }
    std::array<std::uint8_t, OAC_BACKEND_DIGEST_SIZE> nonceDigest{};
    DWORD error = Sha256(
        metadata.Header.Nonce,
        sizeof(metadata.Header.Nonce),
        nonceDigest.data());
    if (error != ERROR_SUCCESS) return error;
    if (!OacBackendAcceptNonceDigest(&replayWindow_, nonceDigest.data()))
        return ERROR_RETRY;

    lastRequestSequence_ = metadata.Header.RequestSequence;
    uploadResponse_ = {};
    InitializeResponseHeader(
        uploadResponse_.Header,
        sizeof(uploadResponse_),
        OAC_BACKEND_MESSAGE_UPLOAD_EVIDENCE,
        metadata.Header,
        OAC_BACKEND_RESULT_ACCEPTED,
        sessionId_.data(),
        nonceDigest.data());
    if (scenario_ != BackendScenario::HoldAcknowledgement)
        acknowledgement_ = metadata.LastServiceSequence;
    uploadResponse_.AcknowledgedThrough = acknowledgement_;
    uploadReady_ = true;
    return ERROR_SUCCESS;
}

bool MockBackendTransport::TakeRenewal(
    OAC_BACKEND_RENEW_RESPONSE& response) noexcept
{
    if (!renewalReady_) return false;
    response = renewalResponse_;
    renewalResponse_ = {};
    renewalReady_ = false;
    return true;
}

bool MockBackendTransport::TakeUpload(
    OAC_BACKEND_UPLOAD_RESPONSE& response) noexcept
{
    if (!uploadReady_) return false;
    response = uploadResponse_;
    uploadResponse_ = {};
    uploadReady_ = false;
    return true;
}

void MockBackendTransport::Close() noexcept
{
    open_ = false;
    renewalReady_ = false;
    uploadReady_ = false;
    replayWindow_ = {};
    lastRequestSequence_ = 0;
    leaseSequence_ = 0;
    acknowledgement_ = 0;
    leaseMilliseconds_ = 0;
    graceMilliseconds_ = 0;
    renewalMilliseconds_ = 0;
    renewalResponse_ = {};
    uploadResponse_ = {};
    SecureZeroMemory(sessionId_.data(), sessionId_.size());
    SecureZeroMemory(bindingSha256_.data(), bindingSha256_.size());
}

BackendSession::~BackendSession()
{
    Stop();
}

DWORD BackendSession::Start(
    const VerifiedPolicy& policy,
    std::unique_ptr<BackendTransport> transport) noexcept
{
    if (started_ || transport == nullptr ||
        !OacBackendPolicyValid(
            policy.Record.BackendLeaseMilliseconds,
            policy.Record.BackendGraceMilliseconds,
            policy.Record.BackendRenewalMilliseconds,
            policy.Record.EvidenceAckTimeoutMilliseconds))
    {
        return ERROR_INVALID_PARAMETER;
    }

    OAC_BACKEND_OPEN_REQUEST request{};
    DWORD error = InitializeRequestHeader(
        request.Header,
        sizeof(request),
        OAC_BACKEND_MESSAGE_OPEN_SESSION,
        1,
        nullptr);
    if (error != ERROR_SUCCESS) return error;
    std::memcpy(request.GameId, policy.Record.GameId, sizeof(request.GameId));
    std::memcpy(request.BuildId, policy.Record.BuildId, sizeof(request.BuildId));
    std::memcpy(request.PolicyId, policy.Record.PolicyId, sizeof(request.PolicyId));
    std::memcpy(
        request.PolicySha256, policy.Digest.data(), sizeof(request.PolicySha256));
    request.MaximumLeaseMilliseconds = policy.Record.BackendLeaseMilliseconds;
    request.MaximumGraceMilliseconds = policy.Record.BackendGraceMilliseconds;
    request.RenewalIntervalMilliseconds =
        policy.Record.BackendRenewalMilliseconds;
    request.EvidenceAckTimeoutMilliseconds =
        policy.Record.EvidenceAckTimeoutMilliseconds;

    std::array<std::uint8_t, OAC_BACKEND_DIGEST_SIZE> nonceDigest{};
    error = Sha256(
        request.Header.Nonce, sizeof(request.Header.Nonce), nonceDigest.data());
    if (error != ERROR_SUCCESS) return error;
    OAC_BACKEND_OPEN_RESPONSE response{};
    error = transport->Open(request, response);
    if (error != ERROR_SUCCESS || !transport->Authenticated() ||
        !OacBackendValidateOpenResponse(
            &request, &response, sizeof(response), nonceDigest.data()))
    {
        transport->Close();
        return error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error;
    }

    OAC_BACKEND_BINDING_MATERIAL binding{};
    std::memcpy(
        binding.SessionId, response.Header.SessionId, sizeof(binding.SessionId));
    std::memcpy(
        binding.RequestNonceSha256, nonceDigest.data(), nonceDigest.size());
    std::memcpy(
        binding.ServerNonce, response.ServerNonce, sizeof(binding.ServerNonce));
    std::array<std::uint8_t, OAC_BACKEND_DIGEST_SIZE> bindingSha256{};
    error = Sha256(&binding, sizeof(binding), bindingSha256.data());
    SecureZeroMemory(&binding, sizeof(binding));
    if (error != ERROR_SUCCESS ||
        BytesAreZero(bindingSha256.data(), bindingSha256.size()))
    {
        transport->Close();
        return error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error;
    }

    const ULONGLONG now = GetTickCount64();
    ULONGLONG validUntil = 0;
    if (!AddDeadline(now, response.LeaseMilliseconds, validUntil) ||
        response.GraceMilliseconds > ~0ULL - validUntil)
    {
        transport->Close();
        return ERROR_ARITHMETIC_OVERFLOW;
    }
    ULONGLONG renewAt = 0;
    if (!AddDeadline(now, response.RenewalIntervalMilliseconds, renewAt))
    {
        transport->Close();
        return ERROR_ARITHMETIC_OVERFLOW;
    }

    transport_ = std::move(transport);
    std::memcpy(sessionId_.data(), response.Header.SessionId, sessionId_.size());
    bindingSha256_ = bindingSha256;
    requestSequence_ = request.Header.RequestSequence;
    leaseSequence_ = response.LeaseSequence;
    leaseValidUntil_ = validUntil;
    leaseGraceUntil_ = validUntil + response.GraceMilliseconds;
    renewAt_ = renewAt;
    maximumLeaseMilliseconds_ = policy.Record.BackendLeaseMilliseconds;
    maximumGraceMilliseconds_ = policy.Record.BackendGraceMilliseconds;
    renewalMilliseconds_ = policy.Record.BackendRenewalMilliseconds;
    acknowledgementTimeoutMilliseconds_ =
        policy.Record.EvidenceAckTimeoutMilliseconds;
    leaseState_ = OAC_LEASE_HEALTHY;
    started_ = true;
    return ERROR_SUCCESS;
}

DWORD BackendSession::Enqueue(
    const OAC_BACKEND_EVIDENCE_ITEM& item,
    ULONGLONG currentMilliseconds) noexcept
{
    if (!started_ || currentMilliseconds == 0 ||
        item.Record.ServiceSequence == 0 ||
        (lastEnqueuedSequence_ != 0 &&
         item.Record.ServiceSequence != lastEnqueuedSequence_ + 1))
    {
        return ERROR_INVALID_DATA;
    }
    if (pendingCount_ == pending_.size())
    {
        lastError_ = ERROR_BUFFER_OVERFLOW;
        return lastError_;
    }
    pending_[pendingCount_].Item = item;
    pending_[pendingCount_].EnqueuedMilliseconds = currentMilliseconds;
    ++pendingCount_;
    lastEnqueuedSequence_ = item.Record.ServiceSequence;
    return ERROR_SUCCESS;
}

DWORD BackendSession::ProcessCompletions(
    ULONGLONG currentMilliseconds) noexcept
{
    OAC_BACKEND_RENEW_RESPONSE renewal{};
    if (transport_->TakeRenewal(renewal))
    {
        if (!renewalOutstanding_ ||
            !OacBackendValidateRenewResponse(
                &renewalRequest_,
                &renewal,
                sizeof(renewal),
                renewalNonceSha256_.data(),
                maximumLeaseMilliseconds_,
                maximumGraceMilliseconds_,
                renewalMilliseconds_))
        {
            return ERROR_INVALID_DATA;
        }
        renewalOutstanding_ = false;
        leaseSequence_ = renewal.LeaseSequence;
        if (renewal.Revoked)
        {
            leaseState_ = OAC_LEASE_REVOKED;
            return ERROR_ACCESS_DISABLED_BY_POLICY;
        }
        if (!AddDeadline(
                currentMilliseconds,
                renewal.LeaseMilliseconds,
                leaseValidUntil_) ||
            renewal.GraceMilliseconds > ~0ULL - leaseValidUntil_ ||
            !AddDeadline(
                currentMilliseconds,
                renewal.RenewalIntervalMilliseconds,
                renewAt_))
        {
            return ERROR_ARITHMETIC_OVERFLOW;
        }
        leaseGraceUntil_ = leaseValidUntil_ + renewal.GraceMilliseconds;
    }

    OAC_BACKEND_UPLOAD_RESPONSE upload{};
    if (transport_->TakeUpload(upload))
    {
        if (!uploadOutstanding_ ||
            !OacBackendValidateUploadResponse(
                &uploadRequest_,
                &upload,
                sizeof(upload),
                uploadNonceSha256_.data(),
                acknowledgedSequence_))
        {
            return ERROR_INVALID_DATA;
        }
        uploadOutstanding_ = false;
        ApplyAcknowledgement(upload.AcknowledgedThrough);
    }
    return ERROR_SUCCESS;
}

DWORD BackendSession::SubmitRenewal() noexcept
{
    if (renewalOutstanding_) return ERROR_SUCCESS;
    if (requestSequence_ == ~0ULL) return ERROR_ARITHMETIC_OVERFLOW;
    renewalRequest_ = {};
    DWORD error = InitializeRequestHeader(
        renewalRequest_.Header,
        sizeof(renewalRequest_),
        OAC_BACKEND_MESSAGE_RENEW_LEASE,
        ++requestSequence_,
        sessionId_.data());
    if (error != ERROR_SUCCESS) return error;
    renewalRequest_.CurrentLeaseSequence = leaseSequence_;
    error = Sha256(
        renewalRequest_.Header.Nonce,
        sizeof(renewalRequest_.Header.Nonce),
        renewalNonceSha256_.data());
    if (error != ERROR_SUCCESS) return error;
    error = transport_->SubmitRenewal(renewalRequest_);
    if (error == ERROR_SUCCESS) renewalOutstanding_ = true;
    return error;
}

DWORD BackendSession::SubmitEvidence() noexcept
{
    if (uploadOutstanding_ || pendingCount_ == 0) return ERROR_SUCCESS;
    if (requestSequence_ == ~0ULL) return ERROR_ARITHMETIC_OVERFLOW;
    const ULONG count = std::min<ULONG>(
        pendingCount_, OAC_BACKEND_MAX_EVIDENCE_RECORDS);
    uploadRequest_ = {};
    DWORD error = InitializeRequestHeader(
        uploadRequest_.Header,
        sizeof(uploadRequest_),
        OAC_BACKEND_MESSAGE_UPLOAD_EVIDENCE,
        ++requestSequence_,
        sessionId_.data());
    if (error != ERROR_SUCCESS) return error;
    std::memcpy(
        uploadRequest_.BindingSha256,
        bindingSha256_.data(),
        bindingSha256_.size());
    uploadRequest_.FirstServiceSequence = pending_[0].Item.Record.ServiceSequence;
    uploadRequest_.LastServiceSequence =
        pending_[count - 1].Item.Record.ServiceSequence;
    uploadRequest_.RecordCount = count;
    error = Sha256(
        uploadRequest_.Header.Nonce,
        sizeof(uploadRequest_.Header.Nonce),
        uploadNonceSha256_.data());
    if (error != ERROR_SUCCESS) return error;

    std::array<OAC_BACKEND_EVIDENCE_ITEM,
        OAC_BACKEND_MAX_EVIDENCE_RECORDS> items{};
    for (ULONG index = 0; index != count; ++index)
        items[index] = pending_[index].Item;
    error = transport_->SubmitEvidence(uploadRequest_, items.data(), count);
    if (error == ERROR_SUCCESS) uploadOutstanding_ = true;
    return error;
}

void BackendSession::ApplyAcknowledgement(
    ULONGLONG acknowledgedThrough) noexcept
{
    ULONG removeCount = 0;
    while (removeCount < pendingCount_ &&
        pending_[removeCount].Item.Record.ServiceSequence <= acknowledgedThrough)
    {
        if (pending_[removeCount].Item.SourceChannel ==
            OAC_EVIDENCE_CHANNEL_ALERT)
        {
            alertAcknowledgedSequence_ =
                pending_[removeCount].Item.Record.Sequence;
        }
        ++removeCount;
    }
    if (removeCount != 0)
    {
        const ULONG remaining = pendingCount_ - removeCount;
        for (ULONG index = 0; index != remaining; ++index)
            pending_[index] = pending_[index + removeCount];
        for (ULONG index = pendingCount_ - removeCount;
             index != pendingCount_;
             ++index)
        {
            pending_[index] = {};
        }
        pendingCount_ -= removeCount;
    }
    acknowledgedSequence_ = acknowledgedThrough;
}

DWORD BackendSession::Poll(ULONGLONG currentMilliseconds) noexcept
{
    if (!started_ || transport_ == nullptr || currentMilliseconds == 0)
        return ERROR_INVALID_STATE;
    if (lastError_ != ERROR_SUCCESS) return lastError_;

    DWORD error = ProcessCompletions(currentMilliseconds);
    if (error == ERROR_SUCCESS && currentMilliseconds >= renewAt_)
        error = SubmitRenewal();
    if (error == ERROR_SUCCESS) error = SubmitEvidence();
    if (error == ERROR_SUCCESS) error = ProcessCompletions(currentMilliseconds);
    if (error != ERROR_SUCCESS)
    {
        lastError_ = error;
        return error;
    }

    leaseState_ = OacEvaluateLease(
        currentMilliseconds,
        leaseValidUntil_,
        leaseGraceUntil_,
        leaseState_ == OAC_LEASE_REVOKED);
    if (OacLeaseRequiresTermination(leaseState_))
    {
        lastError_ = leaseState_ == OAC_LEASE_REVOKED
            ? ERROR_ACCESS_DISABLED_BY_POLICY
            : ERROR_TIMEOUT;
        return lastError_;
    }

    const ULONGLONG oldest = pendingCount_ == 0
        ? 0
        : pending_[0].EnqueuedMilliseconds;
    const OAC_BACKEND_EVIDENCE_STATE evidenceState =
        OacBackendEvaluateEvidenceState(
            currentMilliseconds,
            oldest,
            acknowledgementTimeoutMilliseconds_,
            pendingCount_,
            static_cast<ULONG>(pending_.size()),
            0);
    if (evidenceState == OAC_BACKEND_EVIDENCE_ACK_TIMEOUT)
        lastError_ = ERROR_TIMEOUT;
    else if (evidenceState == OAC_BACKEND_EVIDENCE_INVALID)
        lastError_ = ERROR_INVALID_DATA;
    return lastError_;
}

void BackendSession::Stop() noexcept
{
    if (transport_ != nullptr) transport_->Close();
    transport_.reset();
    Reset();
}

void BackendSession::Reset() noexcept
{
    SecureZeroMemory(sessionId_.data(), sessionId_.size());
    SecureZeroMemory(bindingSha256_.data(), bindingSha256_.size());
    for (auto& item : pending_) item = {};
    renewalRequest_ = {};
    uploadRequest_ = {};
    SecureZeroMemory(
        renewalNonceSha256_.data(), renewalNonceSha256_.size());
    SecureZeroMemory(uploadNonceSha256_.data(), uploadNonceSha256_.size());
    requestSequence_ = 0;
    leaseSequence_ = 0;
    leaseValidUntil_ = 0;
    leaseGraceUntil_ = 0;
    renewAt_ = 0;
    acknowledgedSequence_ = 0;
    alertAcknowledgedSequence_ = 0;
    lastEnqueuedSequence_ = 0;
    pendingCount_ = 0;
    maximumLeaseMilliseconds_ = 0;
    maximumGraceMilliseconds_ = 0;
    renewalMilliseconds_ = 0;
    acknowledgementTimeoutMilliseconds_ = 0;
    leaseState_ = OAC_LEASE_INVALID;
    lastError_ = ERROR_SUCCESS;
    renewalOutstanding_ = false;
    uploadOutstanding_ = false;
    started_ = false;
}

bool BackendSession::AllowsLaunch(ULONGLONG currentMilliseconds) const noexcept
{
    return currentMilliseconds != 0 && started_ &&
        lastError_ == ERROR_SUCCESS && transport_ != nullptr &&
        transport_->Authenticated() &&
        OacEvaluateLease(
            currentMilliseconds,
            leaseValidUntil_,
            leaseGraceUntil_,
            leaseState_ == OAC_LEASE_REVOKED) == OAC_LEASE_HEALTHY;
}

BackendStatus BackendSession::Status() const noexcept
{
    BackendStatus status{};
    status.LeaseState = leaseState_;
    status.LeaseSequence = leaseSequence_;
    status.AcknowledgedSequence = acknowledgedSequence_;
    status.AlertAcknowledgedSequence = alertAcknowledgedSequence_;
    status.PendingEvidence = pendingCount_;
    status.LastError = lastError_;
    status.Authenticated = transport_ != nullptr && transport_->Authenticated();
    status.TestDouble = transport_ != nullptr && transport_->TestDouble();
    return status;
}

std::unique_ptr<BackendTransport> CreateConfiguredBackendTransport(
    DWORD& error) noexcept
{
    error = ERROR_SUCCESS;
    DWORD mode = 0;
    BackendScenario scenario = BackendScenario::Normal;
    error = ReadBackendConfiguration(mode, scenario);
    if (error != ERROR_SUCCESS) return {};
    if (mode != kMockBackendMode)
    {
        error = ERROR_NOT_SUPPORTED;
        return {};
    }
    try
    {
        return std::make_unique<MockBackendTransport>(scenario);
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
} // namespace oac
