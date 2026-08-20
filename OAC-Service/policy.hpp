#pragma once

#include <Windows.h>

#include <array>

#include "..\shared\oac_manifest.h"
#include "..\shared\oac_signed_policy.h"

namespace oac
{
struct VerifiedPolicy
{
    OAC_SIGNED_POLICY Record{};
    std::array<unsigned char, OAC_POLICY_HASH_SIZE> Digest{};
};

DWORD LoadPolicy(VerifiedPolicy& verified);
bool PolicyScopeMatchesManifest(
    const VerifiedPolicy& policy,
    const OAC_GAME_MANIFEST& manifest) noexcept;
bool PolicyHasExpiredNow(const VerifiedPolicy& policy) noexcept;
}
