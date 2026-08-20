#include "oac_backend.h"

#include <string.h>

#include "protocol/oac_validate.h"

static int OacBackendBytesAreZero(const uint8_t* bytes, size_t length)
{
    size_t index;

    if (bytes == NULL) return 0;
    for (index = 0; index < length; ++index)
    {
        if (bytes[index] != 0) return 0;
    }
    return 1;
}

static int OacBackendBytesEqual(
    const uint8_t* left,
    const uint8_t* right,
    size_t length)
{
    return left != NULL && right != NULL && memcmp(left, right, length) == 0;
}

static int OacBackendResultValid(OAC_BACKEND_RESULT result)
{
    return result <= OAC_BACKEND_RESULT_INVALID;
}

static int OacBackendLeasePolicyValid(
    uint32_t leaseMilliseconds,
    uint32_t graceMilliseconds,
    uint32_t renewalIntervalMilliseconds)
{
    return leaseMilliseconds >= OAC_BACKEND_MIN_LEASE_MILLISECONDS &&
        leaseMilliseconds <= OAC_BACKEND_MAX_LEASE_MILLISECONDS &&
        graceMilliseconds <= OAC_BACKEND_MAX_GRACE_MILLISECONDS &&
        renewalIntervalMilliseconds != 0 &&
        renewalIntervalMilliseconds < leaseMilliseconds;
}

static int OacBackendRequestHeaderValid(
    const OAC_BACKEND_REQUEST_HEADER* header,
    uint32_t expectedSize,
    uint32_t expectedType,
    uint64_t nowUnixSeconds,
    int requireSession)
{
    const int sessionIsZero = header != NULL && OacBackendBytesAreZero(
        header->SessionId, sizeof(header->SessionId));

    return header != NULL && header->Revision == OAC_BACKEND_PROTOCOL_REVISION &&
        header->Size == expectedSize && header->MessageType == expectedType &&
        header->Flags == 0 && header->RequestSequence != 0 &&
        !OacBackendBytesAreZero(header->Nonce, sizeof(header->Nonce)) &&
        nowUnixSeconds != 0 && header->IssuedAtUnixSeconds != 0 &&
        header->ExpiresAtUnixSeconds > header->IssuedAtUnixSeconds &&
        header->ExpiresAtUnixSeconds - header->IssuedAtUnixSeconds <=
            OAC_BACKEND_REQUEST_VALIDITY_SECONDS &&
        (header->IssuedAtUnixSeconds <= nowUnixSeconds ||
         header->IssuedAtUnixSeconds - nowUnixSeconds <=
            OAC_BACKEND_CLOCK_SKEW_SECONDS) &&
        nowUnixSeconds <= header->ExpiresAtUnixSeconds &&
        requireSession != sessionIsZero;
}

static int OacBackendResponseHeaderValid(
    const OAC_BACKEND_RESPONSE_HEADER* header,
    uint32_t expectedSize,
    uint32_t expectedType,
    uint64_t requestSequence,
    const uint8_t expectedSessionId[OAC_BACKEND_SESSION_ID_SIZE],
    const uint8_t requestNonceSha256[OAC_BACKEND_DIGEST_SIZE])
{
    return header != NULL && header->Revision == OAC_BACKEND_PROTOCOL_REVISION &&
        header->Size == expectedSize && header->MessageType == expectedType &&
        header->Flags == 0 && header->RequestSequence == requestSequence &&
        OacBackendResultValid(header->Result) && header->Reserved == 0 &&
        (expectedSessionId != NULL
            ? OacBackendBytesEqual(
                header->SessionId,
                expectedSessionId,
                OAC_BACKEND_SESSION_ID_SIZE)
            : !OacBackendBytesAreZero(
                header->SessionId,
                OAC_BACKEND_SESSION_ID_SIZE)) &&
        OacBackendBytesEqual(
            header->RequestNonceSha256,
            requestNonceSha256,
            OAC_BACKEND_DIGEST_SIZE);
}

int OacBackendPolicyValid(
    uint32_t leaseMilliseconds,
    uint32_t graceMilliseconds,
    uint32_t renewalIntervalMilliseconds,
    uint32_t evidenceAckTimeoutMilliseconds)
{
    return OacBackendLeasePolicyValid(
            leaseMilliseconds,
            graceMilliseconds,
            renewalIntervalMilliseconds) &&
        evidenceAckTimeoutMilliseconds >=
            OAC_BACKEND_MIN_ACK_TIMEOUT_MILLISECONDS &&
        evidenceAckTimeoutMilliseconds <=
            OAC_BACKEND_MAX_ACK_TIMEOUT_MILLISECONDS;
}

int OacBackendValidateOpenRequest(
    const OAC_BACKEND_OPEN_REQUEST* request,
    size_t length,
    uint64_t nowUnixSeconds)
{
    return request != NULL && length == sizeof(*request) &&
        OacBackendRequestHeaderValid(
            &request->Header,
            (uint32_t)sizeof(*request),
            OAC_BACKEND_MESSAGE_OPEN_SESSION,
            nowUnixSeconds,
            0) &&
        !OacBackendBytesAreZero(request->GameId, sizeof(request->GameId)) &&
        !OacBackendBytesAreZero(request->BuildId, sizeof(request->BuildId)) &&
        !OacBackendBytesAreZero(request->PolicyId, sizeof(request->PolicyId)) &&
        !OacBackendBytesAreZero(
            request->PolicySha256, sizeof(request->PolicySha256)) &&
        OacBackendPolicyValid(
            request->MaximumLeaseMilliseconds,
            request->MaximumGraceMilliseconds,
            request->RenewalIntervalMilliseconds,
            request->EvidenceAckTimeoutMilliseconds);
}

int OacBackendValidateOpenResponse(
    const OAC_BACKEND_OPEN_REQUEST* request,
    const OAC_BACKEND_OPEN_RESPONSE* response,
    size_t length,
    const uint8_t requestNonceSha256[OAC_BACKEND_DIGEST_SIZE])
{
    return request != NULL && response != NULL &&
        requestNonceSha256 != NULL && length == sizeof(*response) &&
        OacBackendResponseHeaderValid(
            &response->Header,
            (uint32_t)sizeof(*response),
            OAC_BACKEND_MESSAGE_OPEN_SESSION,
            request->Header.RequestSequence,
            NULL,
            requestNonceSha256) &&
        response->Header.Result == OAC_BACKEND_RESULT_ACCEPTED &&
        !OacBackendBytesAreZero(
            response->Header.SessionId, sizeof(response->Header.SessionId)) &&
        !OacBackendBytesAreZero(
            response->ServerNonce, sizeof(response->ServerNonce)) &&
        response->LeaseSequence != 0 && response->Reserved == 0 &&
        response->EvidenceAcknowledgedThrough == 0 &&
        OacBackendPolicyValid(
            response->LeaseMilliseconds,
            response->GraceMilliseconds,
            response->RenewalIntervalMilliseconds,
            request->EvidenceAckTimeoutMilliseconds) &&
        response->LeaseMilliseconds <= request->MaximumLeaseMilliseconds &&
        response->GraceMilliseconds <= request->MaximumGraceMilliseconds &&
        response->RenewalIntervalMilliseconds ==
            request->RenewalIntervalMilliseconds;
}

int OacBackendValidateRenewRequest(
    const OAC_BACKEND_RENEW_REQUEST* request,
    size_t length,
    uint64_t nowUnixSeconds)
{
    return request != NULL && length == sizeof(*request) &&
        OacBackendRequestHeaderValid(
            &request->Header,
            (uint32_t)sizeof(*request),
            OAC_BACKEND_MESSAGE_RENEW_LEASE,
            nowUnixSeconds,
            1) &&
        request->CurrentLeaseSequence != 0;
}

int OacBackendValidateRenewResponse(
    const OAC_BACKEND_RENEW_REQUEST* request,
    const OAC_BACKEND_RENEW_RESPONSE* response,
    size_t length,
    const uint8_t requestNonceSha256[OAC_BACKEND_DIGEST_SIZE],
    uint32_t maximumLeaseMilliseconds,
    uint32_t maximumGraceMilliseconds,
    uint32_t renewalIntervalMilliseconds)
{
    if (request == NULL || response == NULL || requestNonceSha256 == NULL ||
        length != sizeof(*response) ||
        !OacBackendResponseHeaderValid(
            &response->Header,
            (uint32_t)sizeof(*response),
            OAC_BACKEND_MESSAGE_RENEW_LEASE,
            request->Header.RequestSequence,
            request->Header.SessionId,
            requestNonceSha256) ||
        response->Header.Result != OAC_BACKEND_RESULT_ACCEPTED ||
        response->LeaseSequence <= request->CurrentLeaseSequence ||
        response->Revoked > 1)
    {
        return 0;
    }
    if (response->Revoked)
    {
        return response->LeaseMilliseconds == 0 &&
            response->GraceMilliseconds == 0 &&
            response->RenewalIntervalMilliseconds == 0;
    }
    return OacBackendLeasePolicyValid(
            response->LeaseMilliseconds,
            response->GraceMilliseconds,
            response->RenewalIntervalMilliseconds) &&
        response->LeaseMilliseconds <= maximumLeaseMilliseconds &&
        response->GraceMilliseconds <= maximumGraceMilliseconds &&
        response->RenewalIntervalMilliseconds == renewalIntervalMilliseconds;
}

int OacBackendValidateEvidenceBatch(
    const OAC_BACKEND_EVIDENCE_METADATA* metadata,
    size_t metadataLength,
    const OAC_BACKEND_EVIDENCE_ITEM* items,
    size_t itemCount,
    uint64_t nowUnixSeconds,
    const uint8_t expectedBindingSha256[OAC_BACKEND_DIGEST_SIZE])
{
    size_t index;

    if (metadata == NULL || items == NULL || expectedBindingSha256 == NULL ||
        metadataLength != sizeof(*metadata) ||
        !OacBackendRequestHeaderValid(
            &metadata->Header,
            (uint32_t)sizeof(*metadata),
            OAC_BACKEND_MESSAGE_UPLOAD_EVIDENCE,
            nowUnixSeconds,
            1) ||
        !OacBackendBytesEqual(
            metadata->BindingSha256,
            expectedBindingSha256,
            OAC_BACKEND_DIGEST_SIZE) ||
        metadata->RecordCount == 0 ||
        metadata->RecordCount > OAC_BACKEND_MAX_EVIDENCE_RECORDS ||
        itemCount != metadata->RecordCount || metadata->Reserved != 0 ||
        metadata->FirstServiceSequence == 0 ||
        metadata->FirstServiceSequence >
            UINT64_MAX - (metadata->RecordCount - 1u) ||
        metadata->LastServiceSequence != metadata->FirstServiceSequence +
            (metadata->RecordCount - 1u))
    {
        return 0;
    }

    for (index = 0; index < itemCount; ++index)
    {
        const OAC_BACKEND_EVIDENCE_ITEM* item = &items[index];
        if (item->Reserved != 0 ||
            (item->SourceChannel != OAC_EVIDENCE_CHANNEL_ALERT &&
             item->SourceChannel != OAC_EVIDENCE_CHANNEL_EVENT &&
             item->SourceChannel != OAC_BACKEND_EVIDENCE_SOURCE_SERVICE) ||
            item->Record.ServiceSequence !=
                metadata->FirstServiceSequence + index ||
            OacV5ValidateEventRecord(&item->Record, sizeof(item->Record)) !=
                OAC_V5_VALID ||
            item->Decision.RuleId != item->Record.RuleId ||
            item->Decision.PolicySeverity != item->Record.PolicySeverity ||
            !OacPolicyActionValid(item->Decision.Action) ||
            !OacPolicyConfidenceValid(item->Decision.Confidence) ||
            !OacV5PolicySeverityValid(item->Decision.PolicySeverity) ||
            item->Decision.PolicySeverity == OAC_V5_POLICY_NOT_EVALUATED)
        {
            return 0;
        }
    }
    return 1;
}

OAC_BACKEND_ACK_DECISION OacBackendEvaluateAcknowledgement(
    uint64_t previousAcknowledgement,
    uint64_t submittedThrough,
    uint64_t acknowledgedThrough)
{
    if (submittedThrough < previousAcknowledgement)
        return OAC_BACKEND_ACK_INVALID;
    if (acknowledgedThrough < previousAcknowledgement)
        return OAC_BACKEND_ACK_REJECT_REPLAY;
    if (acknowledgedThrough > submittedThrough)
        return OAC_BACKEND_ACK_REJECT_UNDELIVERED;
    return acknowledgedThrough == previousAcknowledgement
        ? OAC_BACKEND_ACK_ACCEPT_CURRENT
        : OAC_BACKEND_ACK_ACCEPT_PROGRESS;
}

int OacBackendValidateUploadResponse(
    const OAC_BACKEND_EVIDENCE_METADATA* request,
    const OAC_BACKEND_UPLOAD_RESPONSE* response,
    size_t length,
    const uint8_t requestNonceSha256[OAC_BACKEND_DIGEST_SIZE],
    uint64_t previousAcknowledgement)
{
    const OAC_BACKEND_ACK_DECISION decision = request != NULL && response != NULL
        ? OacBackendEvaluateAcknowledgement(
            previousAcknowledgement,
            request->LastServiceSequence,
            response->AcknowledgedThrough)
        : OAC_BACKEND_ACK_INVALID;

    return request != NULL && response != NULL &&
        requestNonceSha256 != NULL && length == sizeof(*response) &&
        OacBackendResponseHeaderValid(
            &response->Header,
            (uint32_t)sizeof(*response),
            OAC_BACKEND_MESSAGE_UPLOAD_EVIDENCE,
            request->Header.RequestSequence,
            request->Header.SessionId,
            requestNonceSha256) &&
        response->Header.Result == OAC_BACKEND_RESULT_ACCEPTED &&
        (decision == OAC_BACKEND_ACK_ACCEPT_CURRENT ||
         decision == OAC_BACKEND_ACK_ACCEPT_PROGRESS);
}

int OacBackendAcceptNonceDigest(
    OAC_BACKEND_REPLAY_WINDOW* window,
    const uint8_t nonceSha256[OAC_BACKEND_DIGEST_SIZE])
{
    uint32_t index;

    if (window == NULL || nonceSha256 == NULL ||
        window->Count > OAC_BACKEND_REPLAY_WINDOW_SIZE ||
        window->Next >= OAC_BACKEND_REPLAY_WINDOW_SIZE ||
        (window->Count < OAC_BACKEND_REPLAY_WINDOW_SIZE &&
         window->Next != window->Count) ||
        OacBackendBytesAreZero(nonceSha256, OAC_BACKEND_DIGEST_SIZE))
    {
        return 0;
    }
    for (index = 0; index < window->Count; ++index)
    {
        if (OacBackendBytesEqual(
                window->Digests[index],
                nonceSha256,
                OAC_BACKEND_DIGEST_SIZE))
        {
            return 0;
        }
    }
    memcpy(
        window->Digests[window->Next],
        nonceSha256,
        OAC_BACKEND_DIGEST_SIZE);
    window->Next = (window->Next + 1) % OAC_BACKEND_REPLAY_WINDOW_SIZE;
    if (window->Count < OAC_BACKEND_REPLAY_WINDOW_SIZE) ++window->Count;
    return 1;
}

OAC_BACKEND_EVIDENCE_STATE OacBackendEvaluateEvidenceState(
    uint64_t currentMilliseconds,
    uint64_t oldestPendingMilliseconds,
    uint32_t acknowledgementTimeoutMilliseconds,
    uint32_t pendingCount,
    uint32_t capacity,
    int appendBlocked)
{
    if (capacity == 0 || pendingCount > capacity ||
        acknowledgementTimeoutMilliseconds <
            OAC_BACKEND_MIN_ACK_TIMEOUT_MILLISECONDS ||
        acknowledgementTimeoutMilliseconds >
            OAC_BACKEND_MAX_ACK_TIMEOUT_MILLISECONDS)
    {
        return OAC_BACKEND_EVIDENCE_INVALID;
    }
    if (appendBlocked)
        return pendingCount == capacity
            ? OAC_BACKEND_EVIDENCE_QUEUE_FULL
            : OAC_BACKEND_EVIDENCE_INVALID;
    if (pendingCount == 0)
        return oldestPendingMilliseconds == 0
            ? OAC_BACKEND_EVIDENCE_CLEAR
            : OAC_BACKEND_EVIDENCE_INVALID;
    if (oldestPendingMilliseconds == 0 ||
        currentMilliseconds < oldestPendingMilliseconds)
    {
        return OAC_BACKEND_EVIDENCE_INVALID;
    }
    return currentMilliseconds - oldestPendingMilliseconds >=
            acknowledgementTimeoutMilliseconds
        ? OAC_BACKEND_EVIDENCE_ACK_TIMEOUT
        : OAC_BACKEND_EVIDENCE_PENDING;
}
