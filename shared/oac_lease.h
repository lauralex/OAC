#pragma once

/*
 * Backend-independent lease policy. The service will supply authenticated
 * deadlines when the backend milestone is implemented; this helper keeps the
 * transition and termination rules deterministic and directly testable now.
 */

#include <stdint.h>

typedef uint32_t OAC_LEASE_STATE;

#define OAC_LEASE_INVALID  0u
#define OAC_LEASE_HEALTHY  1u
#define OAC_LEASE_DEGRADED 2u
#define OAC_LEASE_EXPIRED  3u
#define OAC_LEASE_REVOKED  4u

static inline OAC_LEASE_STATE OacEvaluateLease(
    uint64_t currentTime,
    uint64_t validUntil,
    uint64_t graceUntil,
    int revoked)
{
    if (revoked) return OAC_LEASE_REVOKED;
    if (validUntil == 0 || graceUntil < validUntil)
        return OAC_LEASE_INVALID;
    if (currentTime < validUntil) return OAC_LEASE_HEALTHY;
    if (currentTime < graceUntil) return OAC_LEASE_DEGRADED;
    return OAC_LEASE_EXPIRED;
}

static inline int OacLeaseRequiresTermination(OAC_LEASE_STATE state)
{
    return state != OAC_LEASE_HEALTHY && state != OAC_LEASE_DEGRADED;
}
