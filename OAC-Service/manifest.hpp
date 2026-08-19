#pragma once

#include <Windows.h>

#include <array>
#include <string>

#include "..\shared\oac_manifest.h"

namespace oac
{
enum class ManifestFailure
{
    None,
    Missing,
    Invalid,
    Signature,
    Build,
    Expired,
    Rollback
};

struct VerifiedGameManifest
{
    OAC_GAME_MANIFEST Record{};
    std::array<unsigned char, OAC_MANIFEST_HASH_SIZE> Digest{};
};

DWORD AuthorizeGameManifest(
    HANDLE executable,
    const std::wstring& finalExecutablePath,
    VerifiedGameManifest& verified,
    ManifestFailure& failure);
}
