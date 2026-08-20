#pragma once

/*
 * Canonical signed policy records. The detached CMS signature is stored in a
 * separate .p7s file. All integers are little-endian and unused bytes must be
 * zero so the record has one unambiguous digest.
 */

#include <stddef.h>
#include <stdint.h>

#include "oac_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OAC_SIGNED_POLICY_SCHEMA 3u
#define OAC_SIGNED_POLICY_RULE_CAPACITY 40u
#define OAC_SIGNED_POLICY_SIZE 2480u
#define OAC_POLICY_CACHE_SCHEMA 1u
#define OAC_POLICY_CACHE_SIZE 160u
#define OAC_POLICY_ID_SIZE 16u
#define OAC_POLICY_HASH_SIZE 32u
#define OAC_POLICY_CLOCK_SKEW_SECONDS 300ULL
#define OAC_POLICY_MAX_VALIDITY_SECONDS (31ULL * 24ULL * 60ULL * 60ULL)

#define OAC_SIGNED_POLICY_EMERGENCY_REVOKE       0x00000001u
#define OAC_SIGNED_POLICY_ROLLBACK_AUTHORIZATION 0x00000002u
#define OAC_SIGNED_POLICY_FLAGS                   0x00000003u

typedef uint32_t OAC_POLICY_EMERGENCY_REASON;
#define OAC_POLICY_EMERGENCY_NONE             0u
#define OAC_POLICY_EMERGENCY_OPERATOR         1u
#define OAC_POLICY_EMERGENCY_SIGNER_COMPROMISE 2u
#define OAC_POLICY_EMERGENCY_BUILD_WITHDRAWN   3u

typedef enum OAC_SIGNED_POLICY_VALIDATION_TAG
{
    OAC_SIGNED_POLICY_VALID = 0,
    OAC_SIGNED_POLICY_INVALID_POINTER = 1,
    OAC_SIGNED_POLICY_INVALID_LENGTH = 2,
    OAC_SIGNED_POLICY_INVALID_MAGIC = 3,
    OAC_SIGNED_POLICY_INVALID_SCHEMA = 4,
    OAC_SIGNED_POLICY_INVALID_RESERVED = 5,
    OAC_SIGNED_POLICY_INVALID_IDENTITY = 6,
    OAC_SIGNED_POLICY_INVALID_TIME = 7,
    OAC_SIGNED_POLICY_EXPIRED = 8,
    OAC_SIGNED_POLICY_INCOMPATIBLE_COMPONENT = 9,
    OAC_SIGNED_POLICY_INVALID_RULES = 10,
    OAC_SIGNED_POLICY_INVALID_OPERATION = 11
} OAC_SIGNED_POLICY_VALIDATION;

typedef enum OAC_POLICY_UPDATE_DECISION_TAG
{
    OAC_POLICY_UPDATE_ACCEPT_NEW = 0,
    OAC_POLICY_UPDATE_ACCEPT_CURRENT = 1,
    OAC_POLICY_UPDATE_ACCEPT_ROLLBACK = 2,
    OAC_POLICY_UPDATE_REJECT_REPLAY = 3,
    OAC_POLICY_UPDATE_REJECT_ROLLBACK = 4,
    OAC_POLICY_UPDATE_REJECT_EQUIVOCATION = 5,
    OAC_POLICY_UPDATE_INVALID_STATE = 6
} OAC_POLICY_UPDATE_DECISION;

#pragma pack(push, 1)
typedef struct OAC_SIGNED_POLICY_TAG
{
    uint8_t Magic[8];
    uint32_t SchemaVersion;
    uint32_t Size;
    uint32_t Flags;
    OAC_POLICY_MODE Mode;
    uint8_t PolicyId[OAC_POLICY_ID_SIZE];
    uint8_t GameId[OAC_POLICY_ID_SIZE];
    uint8_t BuildId[OAC_POLICY_ID_SIZE];
    uint8_t ChannelId[OAC_POLICY_ID_SIZE];
    uint64_t PolicyVersion;
    uint64_t UpdateSequence;
    uint64_t IssuedAtUnixSeconds;
    uint64_t ExpiresAtUnixSeconds;
    uint32_t RequiredDriverProtocol;
    uint32_t RequiredServiceProtocol;
    uint32_t RequiredLauncherProtocol;
    uint32_t RuleCatalogRevision;
    uint32_t RuleCount;
    OAC_POLICY_EMERGENCY_REASON EmergencyReason;
    uint8_t SigningKeyId[OAC_POLICY_HASH_SIZE];
    uint64_t RollbackFromPolicyVersion;
    uint8_t RollbackFromPolicySha256[OAC_POLICY_HASH_SIZE];
    OAC_POLICY_RULE Rules[OAC_SIGNED_POLICY_RULE_CAPACITY];
    uint32_t BackendLeaseMilliseconds;
    uint32_t BackendGraceMilliseconds;
    uint32_t BackendRenewalMilliseconds;
    uint32_t EvidenceAckTimeoutMilliseconds;
    uint8_t Reserved[8];
} OAC_SIGNED_POLICY;

typedef struct OAC_POLICY_CACHE_STATE_TAG
{
    uint8_t Magic[8];
    uint32_t SchemaVersion;
    uint32_t Size;
    uint8_t GameId[OAC_POLICY_ID_SIZE];
    uint8_t ChannelId[OAC_POLICY_ID_SIZE];
    uint8_t CurrentBuildId[OAC_POLICY_ID_SIZE];
    uint8_t CurrentPolicyId[OAC_POLICY_ID_SIZE];
    uint64_t HighestPolicyVersion;
    uint64_t CurrentPolicyVersion;
    uint64_t UpdateSequence;
    uint8_t CurrentPolicySha256[OAC_POLICY_HASH_SIZE];
    uint8_t Reserved[24];
} OAC_POLICY_CACHE_STATE;
#pragma pack(pop)

OAC_SIGNED_POLICY_VALIDATION OacSignedPolicyValidate(
    const OAC_SIGNED_POLICY* policy,
    size_t policyLength,
    uint64_t nowUnixSeconds,
    uint32_t driverProtocol,
    uint32_t serviceProtocol,
    uint32_t launcherProtocol);
int OacSignedPolicyScopeMatches(
    const OAC_SIGNED_POLICY* policy,
    const uint8_t gameId[OAC_POLICY_ID_SIZE],
    const uint8_t buildId[OAC_POLICY_ID_SIZE]);
int OacPolicyCacheStateValid(const OAC_POLICY_CACHE_STATE* state);
OAC_POLICY_UPDATE_DECISION OacPolicyEvaluateUpdate(
    const OAC_SIGNED_POLICY* policy,
    const uint8_t policySha256[OAC_POLICY_HASH_SIZE],
    const OAC_POLICY_CACHE_STATE* current,
    int hasCurrent,
    OAC_POLICY_CACHE_STATE* next);

#ifdef __cplusplus
}
#endif

#if defined(__cplusplus)
#define OAC_SIGNED_POLICY_STATIC_ASSERT(condition, message) \
    static_assert(condition, message)
#else
#define OAC_SIGNED_POLICY_STATIC_ASSERT(condition, message) \
    _Static_assert(condition, message)
#endif

OAC_SIGNED_POLICY_STATIC_ASSERT(
    sizeof(OAC_SIGNED_POLICY) == OAC_SIGNED_POLICY_SIZE,
    "signed policy layout changed");
OAC_SIGNED_POLICY_STATIC_ASSERT(offsetof(OAC_SIGNED_POLICY, PolicyId) == 24,
    "signed policy identity moved");
OAC_SIGNED_POLICY_STATIC_ASSERT(
    offsetof(OAC_SIGNED_POLICY, PolicyVersion) == 88,
    "signed policy version moved");
OAC_SIGNED_POLICY_STATIC_ASSERT(
    offsetof(OAC_SIGNED_POLICY, SigningKeyId) == 144,
    "signed policy key identity moved");
OAC_SIGNED_POLICY_STATIC_ASSERT(offsetof(OAC_SIGNED_POLICY, Rules) == 216,
    "signed policy rules moved");
OAC_SIGNED_POLICY_STATIC_ASSERT(
    offsetof(OAC_SIGNED_POLICY, BackendLeaseMilliseconds) == 2456,
    "signed policy backend parameters moved");
OAC_SIGNED_POLICY_STATIC_ASSERT(
    offsetof(OAC_SIGNED_POLICY, Reserved) == 2472,
    "signed policy reserved bytes moved");
OAC_SIGNED_POLICY_STATIC_ASSERT(
    sizeof(OAC_POLICY_CACHE_STATE) == OAC_POLICY_CACHE_SIZE,
    "policy cache layout changed");
OAC_SIGNED_POLICY_STATIC_ASSERT(
    offsetof(OAC_POLICY_CACHE_STATE, HighestPolicyVersion) == 80,
    "policy cache high-water mark moved");
OAC_SIGNED_POLICY_STATIC_ASSERT(
    offsetof(OAC_POLICY_CACHE_STATE, CurrentPolicySha256) == 104,
    "policy cache digest moved");

#undef OAC_SIGNED_POLICY_STATIC_ASSERT
