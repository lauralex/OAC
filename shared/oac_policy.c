#include "oac_policy.h"

#include "protocol/oac_validate.h"

static const OAC_POLICY_RULE g_OacPolicyRules[OAC_POLICY_RULE_COUNT] =
{
    {
        OAC_V5_RULE_SESSION_CLAIMED,
        OAC_V5_EVENT_SESSION_STATE_CHANGED,
        OAC_V5_CATEGORY_SERVICE,
        OAC_V5_OBSERVATION_INFO,
        OAC_V5_OBSERVATION_INFO,
        OAC_POLICY_CONFIDENCE_INFORMATIONAL,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_SESSION_LOST,
        OAC_V5_EVENT_REVOCATION,
        OAC_V5_CATEGORY_SERVICE,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_CONCLUSIVE_FOR_LOCAL_POLICY,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_SESSION_REVOKED,
        OAC_V5_EVENT_REVOCATION,
        OAC_V5_CATEGORY_SERVICE,
        OAC_V5_OBSERVATION_INFO,
        OAC_V5_OBSERVATION_INFO,
        OAC_POLICY_CONFIDENCE_STRONG,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_RECORD,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_INVALID_REQUEST,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_GENERAL,
        OAC_V5_OBSERVATION_LOW,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_MODERATE,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_CORROBORATE,
        OAC_POLICY_ACTION_WARN,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_TARGET_BOUND,
        OAC_V5_EVENT_SESSION_STATE_CHANGED,
        OAC_V5_CATEGORY_PROCESS,
        OAC_V5_OBSERVATION_INFO,
        OAC_V5_OBSERVATION_INFO,
        OAC_POLICY_CONFIDENCE_INFORMATIONAL,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_TARGET_EXITED,
        OAC_V5_EVENT_SESSION_STATE_CHANGED,
        OAC_V5_CATEGORY_PROCESS,
        OAC_V5_OBSERVATION_INFO,
        OAC_V5_OBSERVATION_INFO,
        OAC_POLICY_CONFIDENCE_INFORMATIONAL,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_V5_EVIDENCE_KERNEL_SOURCE | OAC_V5_EVIDENCE_CALLBACK_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_PREFLIGHT_STARTED,
        OAC_V5_EVENT_SCAN_STARTED,
        OAC_V5_CATEGORY_INTEGRITY,
        OAC_V5_OBSERVATION_INFO,
        OAC_V5_OBSERVATION_INFO,
        OAC_POLICY_CONFIDENCE_INFORMATIONAL,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_PREFLIGHT_COMPLETED,
        OAC_V5_EVENT_SCAN_COMPLETED,
        OAC_V5_CATEGORY_INTEGRITY,
        OAC_V5_OBSERVATION_INFO,
        OAC_V5_OBSERVATION_INFO,
        OAC_POLICY_CONFIDENCE_INFORMATIONAL,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_PREFLIGHT_INCOMPLETE,
        OAC_V5_EVENT_SCAN_INCOMPLETE,
        OAC_V5_CATEGORY_INTEGRITY,
        OAC_V5_OBSERVATION_HIGH,
        OAC_V5_OBSERVATION_HIGH,
        OAC_POLICY_CONFIDENCE_STRONG,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_V5_EVIDENCE_KERNEL_SOURCE | OAC_V5_EVIDENCE_INCOMPLETE,
        0,
        0
    },
    {
        OAC_V5_RULE_HANDLE_RIGHTS_STRIPPED,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_HANDLE,
        OAC_V5_OBSERVATION_LOW,
        OAC_V5_OBSERVATION_MEDIUM,
        OAC_POLICY_CONFIDENCE_MODERATE,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_CORROBORATE,
        OAC_POLICY_ACTION_WARN,
        OAC_V5_EVIDENCE_KERNEL_SOURCE | OAC_V5_EVIDENCE_CALLBACK_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_PROCESS_IMAGE_LOADED,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_MODULE,
        OAC_V5_OBSERVATION_INFO,
        OAC_V5_OBSERVATION_HIGH,
        OAC_POLICY_CONFIDENCE_WEAK,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_CORROBORATE,
        OAC_V5_EVIDENCE_KERNEL_SOURCE | OAC_V5_EVIDENCE_CALLBACK_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_SYSTEM_STATE_PREFLIGHT,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_PROCESS,
        OAC_V5_OBSERVATION_MEDIUM,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_STRONG,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_SYSTEM_THREAD_PREFLIGHT,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_THREAD,
        OAC_V5_OBSERVATION_HIGH,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_CONCLUSIVE_FOR_LOCAL_POLICY,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_DANGEROUS_KERNEL_HANDLE,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_HANDLE,
        OAC_V5_OBSERVATION_HIGH,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_STRONG,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_THREAD_OUTSIDE_IMAGE,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_THREAD,
        OAC_V5_OBSERVATION_HIGH,
        OAC_V5_OBSERVATION_HIGH,
        OAC_POLICY_CONFIDENCE_STRONG,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_V5_EVIDENCE_SERVICE_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_TARGET_THREAD_LIFECYCLE,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_THREAD,
        OAC_V5_OBSERVATION_INFO,
        OAC_V5_OBSERVATION_INFO,
        OAC_POLICY_CONFIDENCE_INFORMATIONAL,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_POLICY_ACTION_NO_ACTION,
        OAC_V5_EVIDENCE_KERNEL_SOURCE | OAC_V5_EVIDENCE_CALLBACK_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_RUNTIME_MODULE_DENIED,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_MODULE,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_CONCLUSIVE_FOR_LOCAL_POLICY,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_V5_EVIDENCE_KERNEL_SOURCE |
            OAC_V5_EVIDENCE_CALLBACK_SOURCE |
            OAC_V5_EVIDENCE_SERVICE_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_THREAD_STACK_ANOMALY,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_THREAD,
        OAC_V5_OBSERVATION_HIGH,
        OAC_V5_OBSERVATION_HIGH,
        OAC_POLICY_CONFIDENCE_STRONG,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_V5_EVIDENCE_SERVICE_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_KERNEL_IMAGE_LOADED,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_DRIVER,
        OAC_V5_OBSERVATION_MEDIUM,
        OAC_V5_OBSERVATION_MEDIUM,
        OAC_POLICY_CONFIDENCE_MODERATE,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_CORROBORATE,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_V5_EVIDENCE_KERNEL_SOURCE | OAC_V5_EVIDENCE_CALLBACK_SOURCE,
        OAC_POLICY_RULE_SIGNER_AWARE,
        0
    },
    {
        OAC_V5_RULE_DRIVER_DENY_MATCH,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_DRIVER,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_CONCLUSIVE_FOR_LOCAL_POLICY,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_V5_EVIDENCE_KERNEL_SOURCE | OAC_V5_EVIDENCE_CALLBACK_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_DRIVER_GATE_TRIP,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_DRIVER,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_CONCLUSIVE_FOR_LOCAL_POLICY,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_V5_EVIDENCE_KERNEL_SOURCE | OAC_V5_EVIDENCE_CALLBACK_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_DRIVER_PREFLIGHT,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_DRIVER,
        OAC_V5_OBSERVATION_MEDIUM,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_STRONG,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_DRIVER_HASH_DENIED,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_DRIVER,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_CONCLUSIVE_FOR_LOCAL_POLICY,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_V5_EVIDENCE_SERVICE_SOURCE |
            OAC_V5_EVIDENCE_SIGNATURE_CHECKED,
        0,
        0
    },
    {
        OAC_V5_RULE_DRIVER_TRUST_FAILED,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_DRIVER,
        OAC_V5_OBSERVATION_HIGH,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_STRONG,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_V5_EVIDENCE_SERVICE_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_DRIVER_REVIEW_REQUIRED,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_DRIVER,
        OAC_V5_OBSERVATION_HIGH,
        OAC_V5_OBSERVATION_HIGH,
        OAC_POLICY_CONFIDENCE_STRONG,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_V5_EVIDENCE_SERVICE_SOURCE |
            OAC_V5_EVIDENCE_SIGNATURE_CHECKED,
        0,
        0
    },
    {
        OAC_V5_RULE_DRIVER_FAMILY_DENIED,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_DRIVER,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_CONCLUSIVE_FOR_LOCAL_POLICY,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_V5_EVIDENCE_SERVICE_SOURCE |
            OAC_V5_EVIDENCE_SIGNATURE_CHECKED,
        0,
        0
    },
    {
        OAC_V5_RULE_KERNEL_INTEGRITY,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_INTEGRITY,
        OAC_V5_OBSERVATION_HIGH,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_STRONG,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_CPU_STATE,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_INTEGRITY,
        OAC_V5_OBSERVATION_LOW,
        OAC_V5_OBSERVATION_HIGH,
        OAC_POLICY_CONFIDENCE_WEAK,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_CORROBORATE,
        OAC_POLICY_ACTION_WARN,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_EXECUTABLE_NONIMAGE_MEMORY,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_MEMORY,
        OAC_V5_OBSERVATION_HIGH,
        OAC_V5_OBSERVATION_HIGH,
        OAC_POLICY_CONFIDENCE_MODERATE,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_V5_EVIDENCE_SERVICE_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_WRITABLE_EXECUTABLE_MEMORY,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_MEMORY,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_CONCLUSIVE_FOR_LOCAL_POLICY,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_V5_EVIDENCE_SERVICE_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_UNBACKED_PE_IMAGE,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_MEMORY,
        OAC_V5_OBSERVATION_HIGH,
        OAC_V5_OBSERVATION_HIGH,
        OAC_POLICY_CONFIDENCE_STRONG,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_V5_EVIDENCE_SERVICE_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_DIRECT_SYSCALL_STUB,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_MEMORY,
        OAC_V5_OBSERVATION_HIGH,
        OAC_V5_OBSERVATION_HIGH,
        OAC_POLICY_CONFIDENCE_STRONG,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_V5_EVIDENCE_SERVICE_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_DEBUGGER_PREFLIGHT,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_DEBUGGER,
        OAC_V5_OBSERVATION_HIGH,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_STRONG,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_THREAD_DEBUG_REGISTERS,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_DEBUGGER,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_CONCLUSIVE_FOR_LOCAL_POLICY,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_V5_EVIDENCE_SERVICE_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_INSTRUMENTATION_CALLBACK,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_DEBUGGER,
        OAC_V5_OBSERVATION_HIGH,
        OAC_V5_OBSERVATION_HIGH,
        OAC_POLICY_CONFIDENCE_STRONG,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW,
        OAC_POLICY_ACTION_REVOKE_SESSION,
        OAC_V5_EVIDENCE_SERVICE_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_VIRTUALIZATION,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_VIRTUALIZATION,
        OAC_V5_OBSERVATION_LOW,
        OAC_V5_OBSERVATION_HIGH,
        OAC_POLICY_CONFIDENCE_WEAK,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_CORROBORATE,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    },
    {
        OAC_V5_RULE_PLATFORM_PREFLIGHT,
        OAC_V5_EVENT_OBSERVATION,
        OAC_V5_CATEGORY_VIRTUALIZATION,
        OAC_V5_OBSERVATION_HIGH,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_POLICY_CONFIDENCE_MODERATE,
        OAC_POLICY_ACTION_RECORD,
        OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_V5_EVIDENCE_KERNEL_SOURCE,
        0,
        0
    }
};

_Static_assert(
    sizeof(g_OacPolicyRules) / sizeof(g_OacPolicyRules[0]) ==
        OAC_POLICY_RULE_COUNT,
    "policy catalog count changed");

static int OacPolicyBytesAreZero(const uint8_t* bytes, size_t count)
{
    size_t index;
    if (bytes == NULL) return 0;
    for (index = 0; index < count; ++index)
    {
        if (bytes[index] != 0) return 0;
    }
    return 1;
}

static const OAC_POLICY_RULE* OacPolicyFindRule(
    const OAC_POLICY_RULE* rules,
    size_t count,
    OAC_V5_RULE_ID ruleId)
{
    size_t low = 0;
    size_t high = count;

    while (low < high)
    {
        size_t middle = low + (high - low) / 2;
        const OAC_POLICY_RULE* rule = &rules[middle];
        if (rule->RuleId == ruleId) return rule;
        if (rule->RuleId < ruleId)
            low = middle + 1;
        else
            high = middle;
    }
    return NULL;
}

static OAC_POLICY_ACTION OacPolicyModeAction(
    const OAC_POLICY_RULE* rule,
    OAC_POLICY_MODE mode)
{
    if (mode == OAC_POLICY_MODE_OBSERVE) return rule->ObserveAction;
    if (mode == OAC_POLICY_MODE_ENFORCE) return rule->EnforceAction;
    return rule->StrictAction;
}

static OAC_V5_POLICY_SEVERITY OacPolicySeverityForAction(
    OAC_POLICY_ACTION action)
{
    switch (action)
    {
    case OAC_POLICY_ACTION_NO_ACTION:
    case OAC_POLICY_ACTION_RECORD:
        return OAC_V5_POLICY_INFO;
    case OAC_POLICY_ACTION_CORROBORATE:
        return OAC_V5_POLICY_LOW;
    case OAC_POLICY_ACTION_WARN:
        return OAC_V5_POLICY_MEDIUM;
    case OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW:
        return OAC_V5_POLICY_HIGH;
    case OAC_POLICY_ACTION_DENY_LAUNCH:
    case OAC_POLICY_ACTION_REVOKE_SESSION:
        return OAC_V5_POLICY_CRITICAL;
    default:
        return OAC_V5_POLICY_NOT_EVALUATED;
    }
}

static int OacPolicyActionIsViolation(OAC_POLICY_ACTION action)
{
    return action == OAC_POLICY_ACTION_WARN ||
        action == OAC_POLICY_ACTION_DENY_LAUNCH ||
        action == OAC_POLICY_ACTION_REVOKE_SESSION ||
        action == OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW;
}

static int OacPolicySignerHasIdentity(
    const OAC_POLICY_SIGNER_CLASSIFICATION* signer)
{
    size_t index;
    if (signer->ThumbprintLength != 20 && signer->ThumbprintLength != 32)
        return 0;
    for (index = 0; index < signer->ThumbprintLength; ++index)
    {
        if (signer->Thumbprint[index] != 0) return 1;
    }
    return 0;
}

static void OacPolicyEvaluateKernelImage(
    OAC_POLICY_MODE mode,
    const OAC_POLICY_SIGNER_CLASSIFICATION* signer,
    OAC_POLICY_ACTION* action,
    OAC_POLICY_CONFIDENCE* confidence)
{
    const uint32_t approved = OAC_POLICY_SIGNER_MICROSOFT |
        OAC_POLICY_SIGNER_APPROVED_PUBLISHER |
        OAC_POLICY_SIGNER_APPROVED_FILE |
        OAC_POLICY_SIGNER_POLICY_MATCH;

    if (mode == OAC_POLICY_MODE_OBSERVE)
    {
        *action = OAC_POLICY_ACTION_RECORD;
        *confidence = OAC_POLICY_CONFIDENCE_MODERATE;
        return;
    }
    if (mode == OAC_POLICY_MODE_STRICT)
    {
        *action = OAC_POLICY_ACTION_REVOKE_SESSION;
        *confidence = OAC_POLICY_CONFIDENCE_STRONG;
        return;
    }
    if (signer->SignatureSource == OAC_POLICY_SIGNATURE_UNAVAILABLE)
    {
        *action = OAC_POLICY_ACTION_CORROBORATE;
        *confidence = OAC_POLICY_CONFIDENCE_MODERATE;
        return;
    }
    if (signer->SignatureSource == OAC_POLICY_SIGNATURE_UNSIGNED ||
        signer->ChainState == OAC_POLICY_CHAIN_INVALID ||
        signer->RevocationState == OAC_POLICY_REVOCATION_REVOKED ||
        signer->TimestampState == OAC_POLICY_TIMESTAMP_INVALID)
    {
        *action = OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW;
        *confidence = OAC_POLICY_CONFIDENCE_STRONG;
        return;
    }
    if (signer->ChainState == OAC_POLICY_CHAIN_VALID &&
        signer->RevocationState == OAC_POLICY_REVOCATION_GOOD &&
        (signer->Flags & approved) != 0)
    {
        *action = OAC_POLICY_ACTION_RECORD;
        *confidence = (signer->Flags &
            (OAC_POLICY_SIGNER_APPROVED_FILE |
             OAC_POLICY_SIGNER_POLICY_MATCH)) != 0
            ? OAC_POLICY_CONFIDENCE_STRONG
            : OAC_POLICY_CONFIDENCE_MODERATE;
        return;
    }
    *action = OAC_POLICY_ACTION_CORROBORATE;
    *confidence = OAC_POLICY_CONFIDENCE_MODERATE;
}

const OAC_POLICY_RULE* OacPolicyRuleCatalog(size_t* count)
{
    if (count == NULL) return NULL;
    *count = OAC_POLICY_RULE_COUNT;
    return g_OacPolicyRules;
}

int OacPolicyRuleSetValid(
    const OAC_POLICY_RULE* rules,
    size_t count)
{
    size_t index;
    if (rules == NULL || count != OAC_POLICY_RULE_COUNT) return 0;
    for (index = 0; index < count; ++index)
    {
        const OAC_POLICY_RULE* rule = &rules[index];
        if (rule->RuleId != g_OacPolicyRules[index].RuleId ||
            !OacV5EventTypeValid(rule->EventType) ||
            !OacV5CategoryValid(rule->Category) ||
            !OacV5ObservationSeverityValid(
                rule->MinimumObservationSeverity) ||
            !OacV5ObservationSeverityValid(
                rule->MaximumObservationSeverity) ||
            rule->MinimumObservationSeverity >
                rule->MaximumObservationSeverity ||
            !OacPolicyConfidenceValid(rule->Confidence) ||
            !OacPolicyActionValid(rule->ObserveAction) ||
            !OacPolicyActionValid(rule->EnforceAction) ||
            !OacPolicyActionValid(rule->StrictAction) ||
            (rule->RequiredEvidenceFlags & ~OAC_V5_EVIDENCE_FLAGS) != 0 ||
            rule->RequiredEvidenceFlags == 0 ||
            (rule->Flags & ~OAC_POLICY_RULE_FLAGS) != 0 ||
            rule->Reserved != 0)
        {
            return 0;
        }
    }
    return 1;
}

int OacPolicyModeValid(OAC_POLICY_MODE mode)
{
    return mode >= OAC_POLICY_MODE_OBSERVE &&
        mode <= OAC_POLICY_MODE_STRICT;
}

int OacPolicyActionValid(OAC_POLICY_ACTION action)
{
    return action <= OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW;
}

int OacPolicyConfidenceValid(OAC_POLICY_CONFIDENCE confidence)
{
    return confidence <=
        OAC_POLICY_CONFIDENCE_CONCLUSIVE_FOR_LOCAL_POLICY;
}

int OacPolicySignerClassificationValid(
    const OAC_POLICY_SIGNER_CLASSIFICATION* signer)
{
    size_t tail;

    if (signer == NULL ||
        signer->SignatureSource > OAC_POLICY_SIGNATURE_CATALOG ||
        signer->ChainState > OAC_POLICY_CHAIN_INVALID ||
        signer->RevocationState > OAC_POLICY_REVOCATION_REVOKED ||
        signer->TimestampState > OAC_POLICY_TIMESTAMP_INVALID ||
        (signer->Flags & ~OAC_POLICY_SIGNER_FLAGS) != 0 ||
        signer->ThumbprintLength > OAC_POLICY_MAX_THUMBPRINT_BYTES ||
        signer->Reserved[0] != 0 || signer->Reserved[1] != 0)
    {
        return 0;
    }
    tail = signer->ThumbprintLength;
    if (!OacPolicyBytesAreZero(
            signer->Thumbprint + tail,
            OAC_POLICY_MAX_THUMBPRINT_BYTES - tail))
    {
        return 0;
    }

    if (signer->SignatureSource == OAC_POLICY_SIGNATURE_UNAVAILABLE)
    {
        return signer->ChainState == OAC_POLICY_CHAIN_UNAVAILABLE &&
            signer->RevocationState == OAC_POLICY_REVOCATION_UNAVAILABLE &&
            signer->TimestampState == OAC_POLICY_TIMESTAMP_UNAVAILABLE &&
            signer->Flags == 0 && signer->ThumbprintLength == 0;
    }
    if (signer->SignatureSource == OAC_POLICY_SIGNATURE_UNSIGNED)
    {
        return signer->ChainState == OAC_POLICY_CHAIN_NOT_CHECKED &&
            signer->RevocationState == OAC_POLICY_REVOCATION_NOT_CHECKED &&
            signer->TimestampState == OAC_POLICY_TIMESTAMP_MISSING &&
            signer->Flags == 0 && signer->ThumbprintLength == 0;
    }
    if (!OacPolicySignerHasIdentity(signer)) return 0;
    if ((signer->Flags != 0 &&
         signer->ChainState != OAC_POLICY_CHAIN_VALID) ||
        (signer->Flags != 0 &&
         signer->RevocationState == OAC_POLICY_REVOCATION_REVOKED))
    {
        return 0;
    }
    return 1;
}

int OacPolicyEvaluate(
    OAC_POLICY_MODE mode,
    const OAC_V5_EVENT_RECORD* observation,
    const OAC_POLICY_SIGNER_CLASSIFICATION* signer,
    OAC_POLICY_DECISION* decision)
{
    return OacPolicyEvaluateRules(
        mode,
        g_OacPolicyRules,
        OAC_POLICY_RULE_COUNT,
        observation,
        signer,
        decision);
}

int OacPolicyEvaluateRules(
    OAC_POLICY_MODE mode,
    const OAC_POLICY_RULE* rules,
    size_t ruleCount,
    const OAC_V5_EVENT_RECORD* observation,
    const OAC_POLICY_SIGNER_CLASSIFICATION* signer,
    OAC_POLICY_DECISION* decision)
{
    OAC_POLICY_SIGNER_CLASSIFICATION unavailableSigner = { 0 };
    const OAC_POLICY_RULE* rule;
    OAC_POLICY_DECISION result = { 0 };
    OAC_POLICY_ACTION action;
    OAC_POLICY_CONFIDENCE confidence;

    if (!OacPolicyModeValid(mode) ||
        !OacPolicyRuleSetValid(rules, ruleCount) ||
        observation == NULL || decision == NULL ||
        OacV5ValidateEventRecord(observation, sizeof(*observation)) !=
            OAC_V5_VALID ||
        observation->PolicySeverity != OAC_V5_POLICY_NOT_EVALUATED ||
        observation->EventType == OAC_V5_EVENT_POLICY_VIOLATION)
    {
        return 0;
    }
    rule = OacPolicyFindRule(rules, ruleCount, observation->RuleId);
    if (rule == NULL || observation->EventType != rule->EventType ||
        observation->Category != rule->Category ||
        observation->ObservationSeverity < rule->MinimumObservationSeverity ||
        observation->ObservationSeverity > rule->MaximumObservationSeverity ||
        (observation->EvidenceFlags & rule->RequiredEvidenceFlags) !=
            rule->RequiredEvidenceFlags)
    {
        return 0;
    }

    if (signer == NULL) signer = &unavailableSigner;
    if (!OacPolicySignerClassificationValid(signer) ||
        ((rule->Flags & OAC_POLICY_RULE_SIGNER_AWARE) == 0 &&
         signer->SignatureSource != OAC_POLICY_SIGNATURE_UNAVAILABLE))
    {
        return 0;
    }

    action = OacPolicyModeAction(rule, mode);
    confidence = rule->Confidence;
    if ((rule->Flags & OAC_POLICY_RULE_SIGNER_AWARE) != 0)
    {
        OacPolicyEvaluateKernelImage(
            mode,
            signer,
            &action,
            &confidence);
    }
    if (mode != OAC_POLICY_MODE_OBSERVE &&
        (observation->EvidenceFlags &
            (OAC_V5_EVIDENCE_TRUNCATED | OAC_V5_EVIDENCE_INCOMPLETE)) != 0 &&
        action != OAC_POLICY_ACTION_DENY_LAUNCH &&
        action != OAC_POLICY_ACTION_REVOKE_SESSION)
    {
        action = OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW;
        confidence = OAC_POLICY_CONFIDENCE_STRONG;
    }

    result.RuleId = rule->RuleId;
    result.Action = action;
    result.Confidence = confidence;
    result.PolicySeverity = OacPolicySeverityForAction(action);
    if (!OacPolicyActionValid(result.Action) ||
        !OacPolicyConfidenceValid(result.Confidence) ||
        !OacV5PolicySeverityValid(result.PolicySeverity))
    {
        return 0;
    }
    *decision = result;
    return 1;
}

int OacPolicyApplyDecision(
    OAC_V5_EVENT_RECORD* observation,
    const OAC_POLICY_DECISION* decision)
{
    OAC_V5_EVENT_RECORD updated;

    if (observation == NULL || decision == NULL ||
        observation->RuleId != decision->RuleId ||
        observation->PolicySeverity != OAC_V5_POLICY_NOT_EVALUATED ||
        !OacPolicyActionValid(decision->Action) ||
        !OacPolicyConfidenceValid(decision->Confidence) ||
        !OacV5PolicySeverityValid(decision->PolicySeverity) ||
        decision->PolicySeverity == OAC_V5_POLICY_NOT_EVALUATED ||
        decision->PolicySeverity !=
            OacPolicySeverityForAction(decision->Action))
    {
        return 0;
    }
    updated = *observation;
    updated.PolicySeverity = decision->PolicySeverity;
    if (updated.EventType == OAC_V5_EVENT_OBSERVATION &&
        OacPolicyActionIsViolation(decision->Action))
    {
        updated.EventType = OAC_V5_EVENT_POLICY_VIOLATION;
    }
    if (OacV5ValidateEventRecord(&updated, sizeof(updated)) != OAC_V5_VALID)
        return 0;
    *observation = updated;
    return 1;
}
