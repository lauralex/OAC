#pragma once

/*
 * Canonical records at the authenticated backend-transport boundary. The
 * transport authenticates and encrypts these records; this header defines
 * their strict in-process representation and correlation rules without
 * selecting a network library or embedding a reusable client secret.
 */

#include <stddef.h>
#include <stdint.h>

#include "oac_signed_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OAC_BACKEND_PROTOCOL_REVISION 0x00010000u
#define OAC_BACKEND_SESSION_ID_SIZE 16u
#define OAC_BACKEND_NONCE_SIZE 32u
#define OAC_BACKEND_DIGEST_SIZE 32u
#define OAC_BACKEND_MAX_EVIDENCE_RECORDS 16u
#define OAC_BACKEND_REPLAY_WINDOW_SIZE 64u
#define OAC_BACKEND_REQUEST_VALIDITY_SECONDS 60ULL
#define OAC_BACKEND_CLOCK_SKEW_SECONDS 30ULL

#define OAC_BACKEND_MIN_LEASE_MILLISECONDS 1000u
#define OAC_BACKEND_MAX_LEASE_MILLISECONDS 60000u
#define OAC_BACKEND_MAX_GRACE_MILLISECONDS 60000u
#define OAC_BACKEND_MIN_ACK_TIMEOUT_MILLISECONDS 1000u
#define OAC_BACKEND_MAX_ACK_TIMEOUT_MILLISECONDS 60000u

#define OAC_BACKEND_MESSAGE_OPEN_SESSION 1u
#define OAC_BACKEND_MESSAGE_RENEW_LEASE 2u
#define OAC_BACKEND_MESSAGE_UPLOAD_EVIDENCE 3u

typedef uint32_t OAC_BACKEND_RESULT;
#define OAC_BACKEND_RESULT_ACCEPTED 0u
#define OAC_BACKEND_RESULT_REPLAY 1u
#define OAC_BACKEND_RESULT_EXPIRED 2u
#define OAC_BACKEND_RESULT_REVOKED 3u
#define OAC_BACKEND_RESULT_INVALID 4u

typedef uint32_t OAC_BACKEND_ACK_DECISION;
#define OAC_BACKEND_ACK_ACCEPT_CURRENT 0u
#define OAC_BACKEND_ACK_ACCEPT_PROGRESS 1u
#define OAC_BACKEND_ACK_REJECT_REPLAY 2u
#define OAC_BACKEND_ACK_REJECT_UNDELIVERED 3u
#define OAC_BACKEND_ACK_INVALID 4u

typedef uint32_t OAC_BACKEND_EVIDENCE_STATE;
#define OAC_BACKEND_EVIDENCE_CLEAR 0u
#define OAC_BACKEND_EVIDENCE_PENDING 1u
#define OAC_BACKEND_EVIDENCE_ACK_TIMEOUT 2u
#define OAC_BACKEND_EVIDENCE_QUEUE_FULL 3u
#define OAC_BACKEND_EVIDENCE_INVALID 4u

#pragma pack(push, 1)
typedef struct OAC_BACKEND_REQUEST_HEADER_TAG
{
    uint32_t Revision;
    uint32_t Size;
    uint32_t MessageType;
    uint32_t Flags;
    uint64_t RequestSequence;
    uint8_t SessionId[OAC_BACKEND_SESSION_ID_SIZE];
    uint8_t Nonce[OAC_BACKEND_NONCE_SIZE];
    uint64_t IssuedAtUnixSeconds;
    uint64_t ExpiresAtUnixSeconds;
} OAC_BACKEND_REQUEST_HEADER;

typedef struct OAC_BACKEND_RESPONSE_HEADER_TAG
{
    uint32_t Revision;
    uint32_t Size;
    uint32_t MessageType;
    uint32_t Flags;
    uint64_t RequestSequence;
    OAC_BACKEND_RESULT Result;
    uint32_t Reserved;
    uint8_t SessionId[OAC_BACKEND_SESSION_ID_SIZE];
    uint8_t RequestNonceSha256[OAC_BACKEND_DIGEST_SIZE];
} OAC_BACKEND_RESPONSE_HEADER;

typedef struct OAC_BACKEND_OPEN_REQUEST_TAG
{
    OAC_BACKEND_REQUEST_HEADER Header;
    uint8_t GameId[OAC_POLICY_ID_SIZE];
    uint8_t BuildId[OAC_POLICY_ID_SIZE];
    uint8_t PolicyId[OAC_POLICY_ID_SIZE];
    uint8_t PolicySha256[OAC_BACKEND_DIGEST_SIZE];
    uint32_t MaximumLeaseMilliseconds;
    uint32_t MaximumGraceMilliseconds;
    uint32_t RenewalIntervalMilliseconds;
    uint32_t EvidenceAckTimeoutMilliseconds;
} OAC_BACKEND_OPEN_REQUEST;

typedef struct OAC_BACKEND_OPEN_RESPONSE_TAG
{
    OAC_BACKEND_RESPONSE_HEADER Header;
    uint8_t ServerNonce[OAC_BACKEND_NONCE_SIZE];
    uint64_t LeaseSequence;
    uint32_t LeaseMilliseconds;
    uint32_t GraceMilliseconds;
    uint32_t RenewalIntervalMilliseconds;
    uint32_t Reserved;
    uint64_t EvidenceAcknowledgedThrough;
} OAC_BACKEND_OPEN_RESPONSE;

typedef struct OAC_BACKEND_RENEW_REQUEST_TAG
{
    OAC_BACKEND_REQUEST_HEADER Header;
    uint64_t CurrentLeaseSequence;
} OAC_BACKEND_RENEW_REQUEST;

typedef struct OAC_BACKEND_RENEW_RESPONSE_TAG
{
    OAC_BACKEND_RESPONSE_HEADER Header;
    uint64_t LeaseSequence;
    uint32_t LeaseMilliseconds;
    uint32_t GraceMilliseconds;
    uint32_t RenewalIntervalMilliseconds;
    uint32_t Revoked;
} OAC_BACKEND_RENEW_RESPONSE;

typedef struct OAC_BACKEND_EVIDENCE_METADATA_TAG
{
    OAC_BACKEND_REQUEST_HEADER Header;
    uint8_t BindingSha256[OAC_BACKEND_DIGEST_SIZE];
    uint64_t FirstServiceSequence;
    uint64_t LastServiceSequence;
    uint32_t RecordCount;
    uint32_t Reserved;
} OAC_BACKEND_EVIDENCE_METADATA;

typedef struct OAC_BACKEND_EVIDENCE_ITEM_TAG
{
    OAC_V5_EVENT_RECORD Record;
    OAC_POLICY_DECISION Decision;
    uint32_t SourceChannel;
    uint32_t Reserved;
} OAC_BACKEND_EVIDENCE_ITEM;

typedef struct OAC_BACKEND_UPLOAD_RESPONSE_TAG
{
    OAC_BACKEND_RESPONSE_HEADER Header;
    uint64_t AcknowledgedThrough;
} OAC_BACKEND_UPLOAD_RESPONSE;

typedef struct OAC_BACKEND_BINDING_MATERIAL_TAG
{
    uint8_t SessionId[OAC_BACKEND_SESSION_ID_SIZE];
    uint8_t RequestNonceSha256[OAC_BACKEND_DIGEST_SIZE];
    uint8_t ServerNonce[OAC_BACKEND_NONCE_SIZE];
} OAC_BACKEND_BINDING_MATERIAL;

typedef struct OAC_BACKEND_REPLAY_WINDOW_TAG
{
    uint32_t Count;
    uint32_t Next;
    uint8_t Digests[OAC_BACKEND_REPLAY_WINDOW_SIZE][OAC_BACKEND_DIGEST_SIZE];
} OAC_BACKEND_REPLAY_WINDOW;
#pragma pack(pop)

int OacBackendPolicyValid(
    uint32_t leaseMilliseconds,
    uint32_t graceMilliseconds,
    uint32_t renewalIntervalMilliseconds,
    uint32_t evidenceAckTimeoutMilliseconds);
int OacBackendValidateOpenRequest(
    const OAC_BACKEND_OPEN_REQUEST* request,
    size_t length,
    uint64_t nowUnixSeconds);
int OacBackendValidateOpenResponse(
    const OAC_BACKEND_OPEN_REQUEST* request,
    const OAC_BACKEND_OPEN_RESPONSE* response,
    size_t length,
    const uint8_t requestNonceSha256[OAC_BACKEND_DIGEST_SIZE]);
int OacBackendValidateRenewRequest(
    const OAC_BACKEND_RENEW_REQUEST* request,
    size_t length,
    uint64_t nowUnixSeconds);
int OacBackendValidateRenewResponse(
    const OAC_BACKEND_RENEW_REQUEST* request,
    const OAC_BACKEND_RENEW_RESPONSE* response,
    size_t length,
    const uint8_t requestNonceSha256[OAC_BACKEND_DIGEST_SIZE],
    uint32_t maximumLeaseMilliseconds,
    uint32_t maximumGraceMilliseconds,
    uint32_t renewalIntervalMilliseconds);
int OacBackendValidateEvidenceBatch(
    const OAC_BACKEND_EVIDENCE_METADATA* metadata,
    size_t metadataLength,
    const OAC_BACKEND_EVIDENCE_ITEM* items,
    size_t itemCount,
    uint64_t nowUnixSeconds,
    const uint8_t expectedBindingSha256[OAC_BACKEND_DIGEST_SIZE]);
OAC_BACKEND_ACK_DECISION OacBackendEvaluateAcknowledgement(
    uint64_t previousAcknowledgement,
    uint64_t submittedThrough,
    uint64_t acknowledgedThrough);
int OacBackendValidateUploadResponse(
    const OAC_BACKEND_EVIDENCE_METADATA* request,
    const OAC_BACKEND_UPLOAD_RESPONSE* response,
    size_t length,
    const uint8_t requestNonceSha256[OAC_BACKEND_DIGEST_SIZE],
    uint64_t previousAcknowledgement);
int OacBackendAcceptNonceDigest(
    OAC_BACKEND_REPLAY_WINDOW* window,
    const uint8_t nonceSha256[OAC_BACKEND_DIGEST_SIZE]);
OAC_BACKEND_EVIDENCE_STATE OacBackendEvaluateEvidenceState(
    uint64_t currentMilliseconds,
    uint64_t oldestPendingMilliseconds,
    uint32_t acknowledgementTimeoutMilliseconds,
    uint32_t pendingCount,
    uint32_t capacity,
    int appendBlocked);

#ifdef __cplusplus
}
#endif

#if defined(__cplusplus)
#define OAC_BACKEND_STATIC_ASSERT(condition, message) static_assert(condition, message)
#else
#define OAC_BACKEND_STATIC_ASSERT(condition, message) _Static_assert(condition, message)
#endif

OAC_BACKEND_STATIC_ASSERT(sizeof(OAC_BACKEND_REQUEST_HEADER) == 88,
    "backend request header layout changed");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_REQUEST_HEADER, RequestSequence) == 16,
    "backend request sequence moved");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_REQUEST_HEADER, SessionId) == 24,
    "backend request session moved");
OAC_BACKEND_STATIC_ASSERT(offsetof(OAC_BACKEND_REQUEST_HEADER, Nonce) == 40,
    "backend request nonce moved");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_REQUEST_HEADER, IssuedAtUnixSeconds) == 72,
    "backend request issuance moved");
OAC_BACKEND_STATIC_ASSERT(sizeof(OAC_BACKEND_RESPONSE_HEADER) == 80,
    "backend response header layout changed");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_RESPONSE_HEADER, Result) == 24,
    "backend response result moved");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_RESPONSE_HEADER, SessionId) == 32,
    "backend response session moved");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_RESPONSE_HEADER, RequestNonceSha256) == 48,
    "backend response correlation moved");
OAC_BACKEND_STATIC_ASSERT(sizeof(OAC_BACKEND_OPEN_REQUEST) == 184,
    "backend open request layout changed");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_OPEN_REQUEST, GameId) == 88,
    "backend open identity moved");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_OPEN_REQUEST, MaximumLeaseMilliseconds) == 168,
    "backend open policy moved");
OAC_BACKEND_STATIC_ASSERT(sizeof(OAC_BACKEND_OPEN_RESPONSE) == 144,
    "backend open response layout changed");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_OPEN_RESPONSE, ServerNonce) == 80,
    "backend open nonce moved");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_OPEN_RESPONSE, LeaseSequence) == 112,
    "backend open lease moved");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_OPEN_RESPONSE, EvidenceAcknowledgedThrough) == 136,
    "backend open acknowledgement moved");
OAC_BACKEND_STATIC_ASSERT(sizeof(OAC_BACKEND_RENEW_REQUEST) == 96,
    "backend renew request layout changed");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_RENEW_REQUEST, CurrentLeaseSequence) == 88,
    "backend renewal sequence moved");
OAC_BACKEND_STATIC_ASSERT(sizeof(OAC_BACKEND_RENEW_RESPONSE) == 104,
    "backend renew response layout changed");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_RENEW_RESPONSE, LeaseSequence) == 80,
    "backend renewed lease moved");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_RENEW_RESPONSE, Revoked) == 100,
    "backend revocation moved");
OAC_BACKEND_STATIC_ASSERT(sizeof(OAC_BACKEND_EVIDENCE_METADATA) == 144,
    "backend evidence metadata layout changed");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_EVIDENCE_METADATA, BindingSha256) == 88,
    "backend evidence binding moved");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_EVIDENCE_METADATA, FirstServiceSequence) == 120,
    "backend evidence sequence moved");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_EVIDENCE_METADATA, RecordCount) == 136,
    "backend evidence count moved");
OAC_BACKEND_STATIC_ASSERT(sizeof(OAC_BACKEND_EVIDENCE_ITEM) == 584,
    "backend evidence item layout changed");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_EVIDENCE_ITEM, Decision) == 560,
    "backend evidence decision moved");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_EVIDENCE_ITEM, SourceChannel) == 576,
    "backend evidence source moved");
OAC_BACKEND_STATIC_ASSERT(sizeof(OAC_BACKEND_UPLOAD_RESPONSE) == 88,
    "backend upload response layout changed");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_UPLOAD_RESPONSE, AcknowledgedThrough) == 80,
    "backend upload acknowledgement moved");
OAC_BACKEND_STATIC_ASSERT(sizeof(OAC_BACKEND_BINDING_MATERIAL) == 80,
    "backend binding material layout changed");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_BINDING_MATERIAL, ServerNonce) == 48,
    "backend binding nonce moved");
OAC_BACKEND_STATIC_ASSERT(sizeof(OAC_BACKEND_REPLAY_WINDOW) == 2056,
    "backend replay window layout changed");
OAC_BACKEND_STATIC_ASSERT(
    offsetof(OAC_BACKEND_REPLAY_WINDOW, Digests) == 8,
    "backend replay digests moved");

#undef OAC_BACKEND_STATIC_ASSERT
