#pragma once

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "..\shared\oac_backend.h"
#include "..\shared\oac_lease.h"
#include "policy.hpp"

namespace oac
{
enum class BackendScenario : std::uint32_t
{
    Normal = 0,
    HoldAcknowledgement = 1,
    StopRenewing = 2,
    ReplayOpen = 3,
    RevokeLease = 4
};

struct BackendStatus
{
    OAC_LEASE_STATE LeaseState = OAC_LEASE_INVALID;
    ULONGLONG LeaseSequence = 0;
    ULONGLONG AcknowledgedSequence = 0;
    ULONGLONG AlertAcknowledgedSequence = 0;
    ULONG PendingEvidence = 0;
    DWORD LastError = ERROR_SUCCESS;
    bool Authenticated = false;
    bool TestDouble = false;
};

/*
 * A production implementation owns its network worker and authenticated
 * channel. Submit and completion methods must copy their inputs, perform no
 * blocking network I/O, and return within the service health-loop budget.
 */
class BackendTransport
{
public:
    virtual ~BackendTransport() = default;
    virtual DWORD FetchPolicy(
        const OAC_BACKEND_POLICY_REQUEST& request,
        OAC_BACKEND_POLICY_RESPONSE& response) noexcept = 0;
    virtual DWORD Open(
        const OAC_BACKEND_OPEN_REQUEST& request,
        OAC_BACKEND_OPEN_RESPONSE& response) noexcept = 0;
    virtual DWORD SubmitRenewal(
        const OAC_BACKEND_RENEW_REQUEST& request) noexcept = 0;
    virtual DWORD SubmitEvidence(
        const OAC_BACKEND_EVIDENCE_METADATA& metadata,
        const OAC_BACKEND_EVIDENCE_ITEM* items,
        std::size_t itemCount) noexcept = 0;
    virtual bool TakeRenewal(
        OAC_BACKEND_RENEW_RESPONSE& response,
        DWORD& error) noexcept = 0;
    virtual bool TakeUpload(
        OAC_BACKEND_UPLOAD_RESPONSE& response,
        DWORD& error) noexcept = 0;
    virtual void Close() noexcept = 0;
    [[nodiscard]] virtual bool Authenticated() const noexcept = 0;
    [[nodiscard]] virtual bool TestDouble() const noexcept = 0;
};

class MockBackendTransport final : public BackendTransport
{
public:
    explicit MockBackendTransport(BackendScenario scenario) noexcept;
    ~MockBackendTransport() override;

    DWORD FetchPolicy(
        const OAC_BACKEND_POLICY_REQUEST& request,
        OAC_BACKEND_POLICY_RESPONSE& response) noexcept override;
    DWORD Open(
        const OAC_BACKEND_OPEN_REQUEST& request,
        OAC_BACKEND_OPEN_RESPONSE& response) noexcept override;
    DWORD SubmitRenewal(
        const OAC_BACKEND_RENEW_REQUEST& request) noexcept override;
    DWORD SubmitEvidence(
        const OAC_BACKEND_EVIDENCE_METADATA& metadata,
        const OAC_BACKEND_EVIDENCE_ITEM* items,
        std::size_t itemCount) noexcept override;
    bool TakeRenewal(
        OAC_BACKEND_RENEW_RESPONSE& response,
        DWORD& error) noexcept override;
    bool TakeUpload(
        OAC_BACKEND_UPLOAD_RESPONSE& response,
        DWORD& error) noexcept override;
    void Close() noexcept override;
    [[nodiscard]] bool Authenticated() const noexcept override { return open_; }
    [[nodiscard]] bool TestDouble() const noexcept override { return true; }

private:
    BackendScenario scenario_;
    OAC_BACKEND_REPLAY_WINDOW replayWindow_{};
    std::array<std::uint8_t, OAC_BACKEND_SESSION_ID_SIZE> sessionId_{};
    std::array<std::uint8_t, OAC_BACKEND_DIGEST_SIZE> bindingSha256_{};
    ULONGLONG lastRequestSequence_ = 0;
    ULONGLONG leaseSequence_ = 0;
    ULONGLONG acknowledgement_ = 0;
    ULONG leaseMilliseconds_ = 0;
    ULONG graceMilliseconds_ = 0;
    ULONG renewalMilliseconds_ = 0;
    OAC_BACKEND_RENEW_RESPONSE renewalResponse_{};
    OAC_BACKEND_UPLOAD_RESPONSE uploadResponse_{};
    bool renewalReady_ = false;
    bool uploadReady_ = false;
    bool open_ = false;
};

class BackendSession final
{
public:
    BackendSession() = default;
    ~BackendSession();

    BackendSession(const BackendSession&) = delete;
    BackendSession& operator=(const BackendSession&) = delete;

    DWORD Start(
        const VerifiedPolicy& policy,
        std::unique_ptr<BackendTransport> transport) noexcept;
    DWORD Enqueue(
        const OAC_BACKEND_EVIDENCE_ITEM& item,
        ULONGLONG currentMilliseconds) noexcept;
    DWORD Poll(ULONGLONG currentMilliseconds) noexcept;
    void Stop() noexcept;

    [[nodiscard]] bool AllowsLaunch(
        ULONGLONG currentMilliseconds) const noexcept;
    [[nodiscard]] const std::array<std::uint8_t,
        OAC_BACKEND_DIGEST_SIZE>& BindingSha256() const noexcept
    {
        return bindingSha256_;
    }
    [[nodiscard]] BackendStatus Status() const noexcept;

private:
    static constexpr std::size_t kQueueCapacity = 64;

    struct PendingEvidence
    {
        OAC_BACKEND_EVIDENCE_ITEM Item{};
        ULONGLONG EnqueuedMilliseconds = 0;
    };

    DWORD ProcessCompletions(ULONGLONG currentMilliseconds) noexcept;
    DWORD SubmitRenewal() noexcept;
    DWORD SubmitEvidence() noexcept;
    void ApplyAcknowledgement(ULONGLONG acknowledgedThrough) noexcept;
    void Reset() noexcept;

    std::unique_ptr<BackendTransport> transport_;
    std::array<PendingEvidence, kQueueCapacity> pending_{};
    std::array<std::uint8_t, OAC_BACKEND_SESSION_ID_SIZE> sessionId_{};
    std::array<std::uint8_t, OAC_BACKEND_DIGEST_SIZE> bindingSha256_{};
    OAC_BACKEND_RENEW_REQUEST renewalRequest_{};
    OAC_BACKEND_EVIDENCE_METADATA uploadRequest_{};
    std::array<std::uint8_t, OAC_BACKEND_DIGEST_SIZE> renewalNonceSha256_{};
    std::array<std::uint8_t, OAC_BACKEND_DIGEST_SIZE> uploadNonceSha256_{};
    ULONGLONG requestSequence_ = 0;
    ULONGLONG leaseSequence_ = 0;
    ULONGLONG leaseValidUntil_ = 0;
    ULONGLONG leaseGraceUntil_ = 0;
    ULONGLONG renewAt_ = 0;
    ULONGLONG acknowledgedSequence_ = 0;
    ULONGLONG alertAcknowledgedSequence_ = 0;
    ULONGLONG lastEnqueuedSequence_ = 0;
    ULONG pendingCount_ = 0;
    ULONG maximumLeaseMilliseconds_ = 0;
    ULONG maximumGraceMilliseconds_ = 0;
    ULONG renewalMilliseconds_ = 0;
    ULONG acknowledgementTimeoutMilliseconds_ = 0;
    OAC_LEASE_STATE leaseState_ = OAC_LEASE_INVALID;
    DWORD lastError_ = ERROR_SUCCESS;
    bool renewalOutstanding_ = false;
    bool uploadOutstanding_ = false;
    bool started_ = false;
};

DWORD ComputeBackendSha256(
    const void* bytes,
    std::size_t size,
    std::uint8_t digest[OAC_BACKEND_DIGEST_SIZE]) noexcept;
DWORD InitializeBackendRequestHeader(
    OAC_BACKEND_REQUEST_HEADER& header,
    ULONG size,
    ULONG type,
    ULONGLONG sequence,
    const std::uint8_t sessionId[OAC_BACKEND_SESSION_ID_SIZE]) noexcept;

std::unique_ptr<BackendTransport> CreateConfiguredBackendTransport(
    DWORD& error) noexcept;
} // namespace oac
