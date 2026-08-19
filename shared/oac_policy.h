#pragma once

/*
 * Central production policy model. Collection code supplies typed observation
 * fields from the production protocol; display text is deliberately absent
 * from every policy input.
 */

#include <stddef.h>
#include <stdint.h>

#include "protocol/oac_v5.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OAC_POLICY_RULE_COUNT 14u
#define OAC_POLICY_MAX_THUMBPRINT_BYTES 32u

typedef uint32_t OAC_POLICY_MODE;
#define OAC_POLICY_MODE_OBSERVE 1u
#define OAC_POLICY_MODE_ENFORCE 2u
#define OAC_POLICY_MODE_STRICT  3u
#define OAC_POLICY_DEFAULT_MODE OAC_POLICY_MODE_ENFORCE

typedef uint32_t OAC_POLICY_ACTION;
#define OAC_POLICY_ACTION_NO_ACTION             0u
#define OAC_POLICY_ACTION_RECORD                1u
#define OAC_POLICY_ACTION_CORROBORATE           2u
#define OAC_POLICY_ACTION_WARN                  3u
#define OAC_POLICY_ACTION_DENY_LAUNCH           4u
#define OAC_POLICY_ACTION_REVOKE_SESSION        5u
#define OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW 6u

typedef uint32_t OAC_POLICY_CONFIDENCE;
#define OAC_POLICY_CONFIDENCE_INFORMATIONAL 0u
#define OAC_POLICY_CONFIDENCE_WEAK          1u
#define OAC_POLICY_CONFIDENCE_MODERATE      2u
#define OAC_POLICY_CONFIDENCE_STRONG        3u
#define OAC_POLICY_CONFIDENCE_CONCLUSIVE_FOR_LOCAL_POLICY 4u

typedef uint32_t OAC_POLICY_SIGNATURE_SOURCE;
#define OAC_POLICY_SIGNATURE_UNAVAILABLE 0u
#define OAC_POLICY_SIGNATURE_UNSIGNED    1u
#define OAC_POLICY_SIGNATURE_EMBEDDED    2u
#define OAC_POLICY_SIGNATURE_CATALOG     3u

typedef uint32_t OAC_POLICY_CHAIN_STATE;
#define OAC_POLICY_CHAIN_UNAVAILABLE 0u
#define OAC_POLICY_CHAIN_NOT_CHECKED 1u
#define OAC_POLICY_CHAIN_VALID       2u
#define OAC_POLICY_CHAIN_INVALID     3u

typedef uint32_t OAC_POLICY_REVOCATION_STATE;
#define OAC_POLICY_REVOCATION_UNAVAILABLE 0u
#define OAC_POLICY_REVOCATION_NOT_CHECKED 1u
#define OAC_POLICY_REVOCATION_GOOD        2u
#define OAC_POLICY_REVOCATION_REVOKED     3u

typedef uint32_t OAC_POLICY_TIMESTAMP_STATE;
#define OAC_POLICY_TIMESTAMP_UNAVAILABLE 0u
#define OAC_POLICY_TIMESTAMP_MISSING     1u
#define OAC_POLICY_TIMESTAMP_VALID       2u
#define OAC_POLICY_TIMESTAMP_INVALID     3u

#define OAC_POLICY_SIGNER_MICROSOFT          0x00000001u
#define OAC_POLICY_SIGNER_APPROVED_PUBLISHER 0x00000002u
#define OAC_POLICY_SIGNER_APPROVED_FILE      0x00000004u
#define OAC_POLICY_SIGNER_POLICY_MATCH       0x00000008u
#define OAC_POLICY_SIGNER_FLAGS              0x0000000Fu

#define OAC_POLICY_RULE_SIGNER_AWARE 0x00000001u
#define OAC_POLICY_RULE_FLAGS        0x00000001u

typedef struct OAC_POLICY_SIGNER_CLASSIFICATION_TAG
{
    OAC_POLICY_SIGNATURE_SOURCE SignatureSource;
    OAC_POLICY_CHAIN_STATE ChainState;
    OAC_POLICY_REVOCATION_STATE RevocationState;
    OAC_POLICY_TIMESTAMP_STATE TimestampState;
    uint32_t Flags;
    uint32_t ThumbprintLength;
    uint8_t Thumbprint[OAC_POLICY_MAX_THUMBPRINT_BYTES];
    uint32_t Reserved[2];
} OAC_POLICY_SIGNER_CLASSIFICATION;

typedef struct OAC_POLICY_RULE_TAG
{
    OAC_V5_RULE_ID RuleId;
    OAC_V5_EVENT_TYPE EventType;
    OAC_V5_CATEGORY Category;
    OAC_V5_OBSERVATION_SEVERITY MinimumObservationSeverity;
    OAC_V5_OBSERVATION_SEVERITY MaximumObservationSeverity;
    OAC_POLICY_CONFIDENCE Confidence;
    OAC_POLICY_ACTION ObserveAction;
    OAC_POLICY_ACTION EnforceAction;
    OAC_POLICY_ACTION StrictAction;
    uint64_t RequiredEvidenceFlags;
    uint32_t Flags;
    uint32_t Reserved;
} OAC_POLICY_RULE;

typedef struct OAC_POLICY_DECISION_TAG
{
    OAC_V5_RULE_ID RuleId;
    OAC_POLICY_ACTION Action;
    OAC_POLICY_CONFIDENCE Confidence;
    OAC_V5_POLICY_SEVERITY PolicySeverity;
} OAC_POLICY_DECISION;

const OAC_POLICY_RULE* OacPolicyRuleCatalog(size_t* count);
int OacPolicyModeValid(OAC_POLICY_MODE mode);
int OacPolicyActionValid(OAC_POLICY_ACTION action);
int OacPolicyConfidenceValid(OAC_POLICY_CONFIDENCE confidence);
int OacPolicySignerClassificationValid(
    const OAC_POLICY_SIGNER_CLASSIFICATION* signer);
int OacPolicyEvaluate(
    OAC_POLICY_MODE mode,
    const OAC_V5_EVENT_RECORD* observation,
    const OAC_POLICY_SIGNER_CLASSIFICATION* signer,
    OAC_POLICY_DECISION* decision);
int OacPolicyApplyDecision(
    OAC_V5_EVENT_RECORD* observation,
    const OAC_POLICY_DECISION* decision);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#define OAC_POLICY_STATIC_ASSERT(Expression, Message) \
    static_assert((Expression), Message)
#else
#define OAC_POLICY_STATIC_ASSERT(Expression, Message) \
    _Static_assert((Expression), Message)
#endif

#if defined(__clang__)
#define OAC_POLICY_OFFSETOF(Type, Field) __builtin_offsetof(Type, Field)
#else
#define OAC_POLICY_OFFSETOF(Type, Field) offsetof(Type, Field)
#endif

OAC_POLICY_STATIC_ASSERT(sizeof(OAC_POLICY_SIGNER_CLASSIFICATION) == 64,
    "signer classification layout changed");
OAC_POLICY_STATIC_ASSERT(OAC_POLICY_OFFSETOF(OAC_POLICY_SIGNER_CLASSIFICATION,
    Thumbprint) == 24, "signer thumbprint moved");
OAC_POLICY_STATIC_ASSERT(OAC_POLICY_OFFSETOF(OAC_POLICY_SIGNER_CLASSIFICATION,
    Reserved) == 56, "signer reserved fields moved");
OAC_POLICY_STATIC_ASSERT(sizeof(OAC_POLICY_RULE) == 56,
    "policy rule layout changed");
OAC_POLICY_STATIC_ASSERT(OAC_POLICY_OFFSETOF(OAC_POLICY_RULE, EventType) == 4,
    "rule event type moved");
OAC_POLICY_STATIC_ASSERT(OAC_POLICY_OFFSETOF(OAC_POLICY_RULE, Category) == 8,
    "rule category moved");
OAC_POLICY_STATIC_ASSERT(OAC_POLICY_OFFSETOF(OAC_POLICY_RULE,
    RequiredEvidenceFlags) == 40, "rule evidence flags moved");
OAC_POLICY_STATIC_ASSERT(OAC_POLICY_OFFSETOF(OAC_POLICY_RULE, Flags) == 48,
    "rule flags moved");
OAC_POLICY_STATIC_ASSERT(sizeof(OAC_POLICY_DECISION) == 16,
    "policy decision layout changed");
OAC_POLICY_STATIC_ASSERT(OAC_POLICY_OFFSETOF(OAC_POLICY_DECISION, Action) == 4,
    "decision action moved");
OAC_POLICY_STATIC_ASSERT(OAC_POLICY_OFFSETOF(OAC_POLICY_DECISION,
    PolicySeverity) == 12,
    "decision policy severity moved");

#undef OAC_POLICY_OFFSETOF
#undef OAC_POLICY_STATIC_ASSERT
