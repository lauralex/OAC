#include "oac_signed_policy.h"

#include <string.h>

static const uint8_t g_PolicyMagic[8] =
    {'O', 'A', 'C', 'P', 'O', 'L', 'C', 'Y'};
static const uint8_t g_CacheMagic[8] =
    {'O', 'A', 'C', 'P', 'S', 'T', 'A', 'T'};

static int OacBytesAreZero(const uint8_t* bytes, size_t count)
{
    size_t index;
    if (bytes == NULL) return 0;
    for (index = 0; index < count; ++index)
    {
        if (bytes[index] != 0) return 0;
    }
    return 1;
}

static int OacIdentityIsPresent(const uint8_t* bytes, size_t count)
{
    return bytes != NULL && !OacBytesAreZero(bytes, count);
}

static int OacEmergencyReasonValid(OAC_POLICY_EMERGENCY_REASON reason)
{
    return reason == OAC_POLICY_EMERGENCY_NONE ||
        reason == OAC_POLICY_EMERGENCY_OPERATOR ||
        reason == OAC_POLICY_EMERGENCY_SIGNER_COMPROMISE ||
        reason == OAC_POLICY_EMERGENCY_BUILD_WITHDRAWN;
}

OAC_SIGNED_POLICY_VALIDATION OacSignedPolicyValidate(
    const OAC_SIGNED_POLICY* policy,
    size_t policyLength,
    uint64_t nowUnixSeconds,
    uint32_t driverProtocol,
    uint32_t serviceProtocol,
    uint32_t launcherProtocol)
{
    const int emergency = policy != NULL &&
        (policy->Flags & OAC_SIGNED_POLICY_EMERGENCY_REVOKE) != 0;
    const int rollback = policy != NULL &&
        (policy->Flags & OAC_SIGNED_POLICY_ROLLBACK_AUTHORIZATION) != 0;

    if (policy == NULL) return OAC_SIGNED_POLICY_INVALID_POINTER;
    if (policyLength != sizeof(*policy))
        return OAC_SIGNED_POLICY_INVALID_LENGTH;
    if (memcmp(policy->Magic, g_PolicyMagic, sizeof(g_PolicyMagic)) != 0)
        return OAC_SIGNED_POLICY_INVALID_MAGIC;
    if (policy->SchemaVersion != OAC_SIGNED_POLICY_SCHEMA ||
        policy->Size != sizeof(*policy))
        return OAC_SIGNED_POLICY_INVALID_SCHEMA;
    if ((policy->Flags & ~OAC_SIGNED_POLICY_FLAGS) != 0 ||
        !OacBytesAreZero(policy->Reserved, sizeof(policy->Reserved)))
        return OAC_SIGNED_POLICY_INVALID_RESERVED;
    if (!OacPolicyModeValid(policy->Mode) || policy->PolicyVersion == 0 ||
        policy->UpdateSequence == 0 ||
        !OacIdentityIsPresent(policy->PolicyId, sizeof(policy->PolicyId)) ||
        !OacIdentityIsPresent(policy->GameId, sizeof(policy->GameId)) ||
        !OacIdentityIsPresent(policy->BuildId, sizeof(policy->BuildId)) ||
        !OacIdentityIsPresent(policy->ChannelId, sizeof(policy->ChannelId)) ||
        !OacIdentityIsPresent(
            policy->SigningKeyId, sizeof(policy->SigningKeyId)))
        return OAC_SIGNED_POLICY_INVALID_IDENTITY;
    if (policy->IssuedAtUnixSeconds == 0 ||
        policy->ExpiresAtUnixSeconds <= policy->IssuedAtUnixSeconds ||
        policy->ExpiresAtUnixSeconds - policy->IssuedAtUnixSeconds >
            OAC_POLICY_MAX_VALIDITY_SECONDS ||
        nowUnixSeconds == 0 ||
        (policy->IssuedAtUnixSeconds > nowUnixSeconds &&
         policy->IssuedAtUnixSeconds - nowUnixSeconds >
            OAC_POLICY_CLOCK_SKEW_SECONDS))
        return OAC_SIGNED_POLICY_INVALID_TIME;
    if (policy->ExpiresAtUnixSeconds < nowUnixSeconds &&
        nowUnixSeconds - policy->ExpiresAtUnixSeconds >
            OAC_POLICY_CLOCK_SKEW_SECONDS)
        return OAC_SIGNED_POLICY_EXPIRED;
    if (policy->RequiredDriverProtocol == 0 ||
        policy->RequiredServiceProtocol == 0 ||
        policy->RequiredLauncherProtocol == 0 ||
        policy->RequiredDriverProtocol > driverProtocol ||
        policy->RequiredServiceProtocol > serviceProtocol ||
        policy->RequiredLauncherProtocol > launcherProtocol)
        return OAC_SIGNED_POLICY_INCOMPATIBLE_COMPONENT;
    if (policy->RuleCatalogRevision !=
            OAC_POLICY_RULE_CATALOG_REVISION ||
        policy->RuleCount != OAC_POLICY_RULE_COUNT ||
        !OacPolicyRuleSetValid(policy->Rules, policy->RuleCount))
        return OAC_SIGNED_POLICY_INVALID_RULES;
    if ((emergency && rollback) ||
        !OacEmergencyReasonValid(policy->EmergencyReason) ||
        (emergency && policy->EmergencyReason == OAC_POLICY_EMERGENCY_NONE) ||
        (!emergency && policy->EmergencyReason != OAC_POLICY_EMERGENCY_NONE) ||
        (rollback &&
            (policy->RollbackFromPolicyVersion == 0 ||
             !OacIdentityIsPresent(
                 policy->RollbackFromPolicySha256,
                 sizeof(policy->RollbackFromPolicySha256)))) ||
        (!rollback &&
            (policy->RollbackFromPolicyVersion != 0 ||
             !OacBytesAreZero(
                 policy->RollbackFromPolicySha256,
                 sizeof(policy->RollbackFromPolicySha256)))))
        return OAC_SIGNED_POLICY_INVALID_OPERATION;
    return OAC_SIGNED_POLICY_VALID;
}

int OacSignedPolicyScopeMatches(
    const OAC_SIGNED_POLICY* policy,
    const uint8_t gameId[OAC_POLICY_ID_SIZE],
    const uint8_t buildId[OAC_POLICY_ID_SIZE])
{
    return policy != NULL && gameId != NULL && buildId != NULL &&
        memcmp(policy->GameId, gameId, OAC_POLICY_ID_SIZE) == 0 &&
        memcmp(policy->BuildId, buildId, OAC_POLICY_ID_SIZE) == 0;
}

int OacPolicyCacheStateValid(const OAC_POLICY_CACHE_STATE* state)
{
    return state != NULL &&
        memcmp(state->Magic, g_CacheMagic, sizeof(g_CacheMagic)) == 0 &&
        state->SchemaVersion == OAC_POLICY_CACHE_SCHEMA &&
        state->Size == sizeof(*state) &&
        OacIdentityIsPresent(state->GameId, sizeof(state->GameId)) &&
        OacIdentityIsPresent(state->ChannelId, sizeof(state->ChannelId)) &&
        OacIdentityIsPresent(
            state->CurrentBuildId, sizeof(state->CurrentBuildId)) &&
        OacIdentityIsPresent(
            state->CurrentPolicyId, sizeof(state->CurrentPolicyId)) &&
        state->HighestPolicyVersion != 0 &&
        state->CurrentPolicyVersion != 0 &&
        state->CurrentPolicyVersion <= state->HighestPolicyVersion &&
        state->UpdateSequence != 0 &&
        OacIdentityIsPresent(
            state->CurrentPolicySha256,
            sizeof(state->CurrentPolicySha256)) &&
        OacBytesAreZero(state->Reserved, sizeof(state->Reserved));
}

static void OacInitializeCacheState(
    const OAC_SIGNED_POLICY* policy,
    const uint8_t digest[OAC_POLICY_HASH_SIZE],
    uint64_t highestVersion,
    OAC_POLICY_CACHE_STATE* next)
{
    memset(next, 0, sizeof(*next));
    memcpy(next->Magic, g_CacheMagic, sizeof(g_CacheMagic));
    next->SchemaVersion = OAC_POLICY_CACHE_SCHEMA;
    next->Size = sizeof(*next);
    memcpy(next->GameId, policy->GameId, sizeof(next->GameId));
    memcpy(next->ChannelId, policy->ChannelId, sizeof(next->ChannelId));
    memcpy(next->CurrentBuildId, policy->BuildId,
        sizeof(next->CurrentBuildId));
    memcpy(next->CurrentPolicyId, policy->PolicyId,
        sizeof(next->CurrentPolicyId));
    next->HighestPolicyVersion = highestVersion;
    next->CurrentPolicyVersion = policy->PolicyVersion;
    next->UpdateSequence = policy->UpdateSequence;
    memcpy(next->CurrentPolicySha256, digest,
        sizeof(next->CurrentPolicySha256));
}

OAC_POLICY_UPDATE_DECISION OacPolicyEvaluateUpdate(
    const OAC_SIGNED_POLICY* policy,
    const uint8_t policySha256[OAC_POLICY_HASH_SIZE],
    const OAC_POLICY_CACHE_STATE* current,
    int hasCurrent,
    OAC_POLICY_CACHE_STATE* next)
{
    const int rollback = policy != NULL &&
        (policy->Flags & OAC_SIGNED_POLICY_ROLLBACK_AUTHORIZATION) != 0;
    if (policy == NULL || policySha256 == NULL || next == NULL ||
        !OacIdentityIsPresent(policySha256, OAC_POLICY_HASH_SIZE) ||
        (hasCurrent != 0 && hasCurrent != 1) ||
        (hasCurrent && !OacPolicyCacheStateValid(current)))
        return OAC_POLICY_UPDATE_INVALID_STATE;

    if (!hasCurrent)
    {
        if (rollback) return OAC_POLICY_UPDATE_REJECT_ROLLBACK;
        OacInitializeCacheState(
            policy, policySha256, policy->PolicyVersion, next);
        return OAC_POLICY_UPDATE_ACCEPT_NEW;
    }
    if (memcmp(current->GameId, policy->GameId, OAC_POLICY_ID_SIZE) != 0 ||
        memcmp(current->ChannelId, policy->ChannelId, OAC_POLICY_ID_SIZE) != 0)
        return OAC_POLICY_UPDATE_INVALID_STATE;
    if (policy->UpdateSequence == current->UpdateSequence)
    {
        if (policy->PolicyVersion == current->CurrentPolicyVersion &&
            memcmp(
                policySha256,
                current->CurrentPolicySha256,
                OAC_POLICY_HASH_SIZE) == 0)
        {
            *next = *current;
            return OAC_POLICY_UPDATE_ACCEPT_CURRENT;
        }
        return OAC_POLICY_UPDATE_REJECT_EQUIVOCATION;
    }
    if (policy->UpdateSequence < current->UpdateSequence)
        return OAC_POLICY_UPDATE_REJECT_REPLAY;

    if (rollback)
    {
        if (policy->PolicyVersion >= current->CurrentPolicyVersion ||
            policy->RollbackFromPolicyVersion !=
                current->CurrentPolicyVersion ||
            memcmp(
                policy->RollbackFromPolicySha256,
                current->CurrentPolicySha256,
                OAC_POLICY_HASH_SIZE) != 0)
            return OAC_POLICY_UPDATE_REJECT_ROLLBACK;
        OacInitializeCacheState(
            policy,
            policySha256,
            current->HighestPolicyVersion,
            next);
        return OAC_POLICY_UPDATE_ACCEPT_ROLLBACK;
    }

    if (policy->PolicyVersion <= current->HighestPolicyVersion)
        return OAC_POLICY_UPDATE_REJECT_REPLAY;
    OacInitializeCacheState(
        policy, policySha256, policy->PolicyVersion, next);
    return OAC_POLICY_UPDATE_ACCEPT_NEW;
}
