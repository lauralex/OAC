#pragma once

#include <Windows.h>

#include <array>
#include <string_view>

#include "..\shared\oac_driver_trust.hpp"
#include "..\shared\oac_manifest.h"

namespace oac
{
struct RuntimeModuleEvaluation
{
    FileTrustReport Trust{};
    std::array<unsigned char, OAC_MANIFEST_HASH_SIZE> Sha256{};
    bool TrustedWindowsModule = false;
    bool Allowed = false;
};

DWORD EvaluateRuntimeModule(
    std::wstring_view reportedPath,
    const OAC_GAME_MANIFEST& manifest,
    RuntimeModuleEvaluation& evaluation) noexcept;
} // namespace oac
