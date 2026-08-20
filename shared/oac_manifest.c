#include "oac_manifest.h"

#include <string.h>

static const uint8_t g_ManifestMagic[OAC_MANIFEST_MAGIC_SIZE] =
{
    'O', 'A', 'C', 'G', 'M', 'A', 'N', 0
};

static const uint8_t g_ManifestStateMagic[OAC_MANIFEST_MAGIC_SIZE] =
{
    'O', 'A', 'C', 'M', 'S', 'T', 'A', 'T'
};

static int OacBytesAreZero(const uint8_t* bytes, size_t length)
{
    size_t index;

    if (bytes == NULL) return 0;
    for (index = 0; index < length; ++index)
    {
        if (bytes[index] != 0) return 0;
    }
    return 1;
}

static int OacBytesAreNonzero(const uint8_t* bytes, size_t length)
{
    return !OacBytesAreZero(bytes, length);
}

static int OacManifestModulePolicyValid(
    const OAC_GAME_MANIFEST* manifest)
{
    uint32_t index;

    if (manifest->ModuleHashCount > OAC_MANIFEST_MODULE_HASH_CAPACITY)
        return 0;
    for (index = 0; index < manifest->ModuleHashCount; ++index)
    {
        if (!OacBytesAreNonzero(
                manifest->ModuleSha256[index], OAC_MANIFEST_HASH_SIZE) ||
            (index != 0 && memcmp(
                manifest->ModuleSha256[index - 1],
                manifest->ModuleSha256[index],
                OAC_MANIFEST_HASH_SIZE) >= 0))
        {
            return 0;
        }
    }
    for (; index < OAC_MANIFEST_MODULE_HASH_CAPACITY; ++index)
    {
        if (!OacBytesAreZero(
                manifest->ModuleSha256[index], OAC_MANIFEST_HASH_SIZE))
        {
            return 0;
        }
    }
    return 1;
}

static uint16_t OacAsciiLower(uint16_t value)
{
    if (value >= (uint16_t)'A' && value <= (uint16_t)'Z')
    {
        return (uint16_t)(value + ((uint16_t)'a' - (uint16_t)'A'));
    }
    return value;
}

static int OacManifestExecutableNameValid(
    const uint16_t* name,
    uint32_t length)
{
    uint32_t index;

    if (name == NULL || length < 5 ||
        length >= OAC_MANIFEST_EXECUTABLE_NAME_CHARS)
    {
        return 0;
    }
    for (index = 0; index < length; ++index)
    {
        const uint16_t value = name[index];

        if (value == 0 || value < 0x20 || value == (uint16_t)'/' ||
            value == (uint16_t)'\\' || value == (uint16_t)':')
        {
            return 0;
        }
        if (value >= 0xD800 && value <= 0xDBFF)
        {
            ++index;
            if (index >= length || name[index] < 0xDC00 ||
                name[index] > 0xDFFF)
            {
                return 0;
            }
        }
        else if (value >= 0xDC00 && value <= 0xDFFF)
        {
            return 0;
        }
    }
    if (name[length - 1] == (uint16_t)'.' ||
        name[length - 1] == (uint16_t)' ')
    {
        return 0;
    }
    if (OacAsciiLower(name[length - 4]) != (uint16_t)'.' ||
        OacAsciiLower(name[length - 3]) != (uint16_t)'e' ||
        OacAsciiLower(name[length - 2]) != (uint16_t)'x' ||
        OacAsciiLower(name[length - 1]) != (uint16_t)'e')
    {
        return 0;
    }
    for (index = length; index < OAC_MANIFEST_EXECUTABLE_NAME_CHARS; ++index)
    {
        if (name[index] != 0) return 0;
    }
    return 1;
}

static int OacManifestNameMatches(
    const OAC_GAME_MANIFEST* manifest,
    const uint16_t* executableName,
    size_t executableNameLength)
{
    size_t index;

    if (executableName == NULL ||
        executableNameLength != manifest->ExecutableNameLength)
    {
        return 0;
    }
    for (index = 0; index < executableNameLength; ++index)
    {
        if (OacAsciiLower(manifest->ExecutableName[index]) !=
            OacAsciiLower(executableName[index]))
        {
            return 0;
        }
    }
    return 1;
}

OAC_MANIFEST_VALIDATION OacManifestValidate(
    const OAC_GAME_MANIFEST* manifest,
    size_t length,
    uint64_t nowUnixSeconds,
    uint32_t driverProtocol,
    uint32_t serviceProtocol,
    uint32_t launcherProtocol)
{
    if (manifest == NULL) return OAC_MANIFEST_INVALID_POINTER;
    if (length != sizeof(*manifest)) return OAC_MANIFEST_INVALID_LENGTH;
    if (memcmp(
            manifest->Magic,
            g_ManifestMagic,
            sizeof(g_ManifestMagic)) != 0)
    {
        return OAC_MANIFEST_INVALID_MAGIC;
    }
    if (manifest->SchemaVersion != OAC_MANIFEST_SCHEMA ||
        manifest->Size != sizeof(*manifest))
    {
        return OAC_MANIFEST_INVALID_SCHEMA;
    }
    if ((manifest->Flags & ~OAC_MANIFEST_FLAGS) != 0 ||
        manifest->Reserved0 != 0 || manifest->Reserved1 != 0)
    {
        return OAC_MANIFEST_INVALID_RESERVED;
    }
    if (!OacBytesAreNonzero(manifest->ManifestId, sizeof(manifest->ManifestId)) ||
        !OacBytesAreNonzero(manifest->GameId, sizeof(manifest->GameId)) ||
        !OacBytesAreNonzero(manifest->BuildId, sizeof(manifest->BuildId)) ||
        manifest->Sequence == 0)
    {
        return OAC_MANIFEST_INVALID_IDENTITY;
    }
    if (nowUnixSeconds == 0 || manifest->IssuedAtUnixSeconds == 0 ||
        manifest->ExpiresAtUnixSeconds <= manifest->IssuedAtUnixSeconds ||
        manifest->ExpiresAtUnixSeconds - manifest->IssuedAtUnixSeconds >
            OAC_MANIFEST_MAX_VALIDITY_SECONDS ||
        (manifest->IssuedAtUnixSeconds > nowUnixSeconds &&
         manifest->IssuedAtUnixSeconds - nowUnixSeconds >
            OAC_MANIFEST_CLOCK_SKEW_SECONDS))
    {
        return OAC_MANIFEST_INVALID_TIME;
    }
    if (manifest->ExpiresAtUnixSeconds <= nowUnixSeconds)
    {
        return OAC_MANIFEST_EXPIRED;
    }
    if (manifest->RequiredDriverProtocol == 0 ||
        manifest->RequiredServiceProtocol == 0 ||
        manifest->RequiredLauncherProtocol == 0 ||
        manifest->RequiredDriverProtocol > driverProtocol ||
        manifest->RequiredServiceProtocol > serviceProtocol ||
        manifest->RequiredLauncherProtocol > launcherProtocol)
    {
        return OAC_MANIFEST_INCOMPATIBLE_COMPONENT;
    }
    if (!OacManifestExecutableNameValid(
            manifest->ExecutableName,
            manifest->ExecutableNameLength))
    {
        return OAC_MANIFEST_INVALID_EXECUTABLE_NAME;
    }
    if (manifest->ExecutableSize == 0 ||
        !OacBytesAreNonzero(
            manifest->ExecutableSha256,
            sizeof(manifest->ExecutableSha256)) ||
        !OacBytesAreNonzero(
            manifest->SigningKeyId,
            sizeof(manifest->SigningKeyId)))
    {
        return OAC_MANIFEST_INVALID_FILE_IDENTITY;
    }
    if (!OacManifestModulePolicyValid(manifest))
        return OAC_MANIFEST_INVALID_MODULE_POLICY;
    return OAC_MANIFEST_VALID;
}

int OacManifestFileIdentityMatches(
    const OAC_GAME_MANIFEST* manifest,
    const uint16_t* executableName,
    size_t executableNameLength,
    uint64_t executableSize,
    const uint8_t executableSha256[OAC_MANIFEST_HASH_SIZE],
    const uint8_t signerCertificateSha256[OAC_MANIFEST_HASH_SIZE])
{
    return manifest != NULL && executableSha256 != NULL &&
        signerCertificateSha256 != NULL &&
        manifest->ExecutableSize == executableSize &&
        OacManifestNameMatches(
            manifest,
            executableName,
            executableNameLength) &&
        memcmp(
            manifest->ExecutableSha256,
            executableSha256,
            OAC_MANIFEST_HASH_SIZE) == 0 &&
        memcmp(
            manifest->SigningKeyId,
            signerCertificateSha256,
            OAC_MANIFEST_HASH_SIZE) == 0;
}

int OacManifestRuntimeModuleAllowed(
    const OAC_GAME_MANIFEST* manifest,
    const uint8_t moduleSha256[OAC_MANIFEST_HASH_SIZE],
    int trustedWindowsModule)
{
    size_t low = 0;
    size_t high;

    if (manifest == NULL || moduleSha256 == NULL ||
        (trustedWindowsModule != 0 && trustedWindowsModule != 1) ||
        (manifest->Flags & ~OAC_MANIFEST_FLAGS) != 0 ||
        manifest->Reserved0 != 0 || manifest->Reserved1 != 0 ||
        !OacManifestModulePolicyValid(manifest))
    {
        return 0;
    }
    if (memcmp(
            manifest->ExecutableSha256,
            moduleSha256,
            OAC_MANIFEST_HASH_SIZE) == 0)
    {
        return 1;
    }
    if (trustedWindowsModule &&
        (manifest->Flags & OAC_MANIFEST_ALLOW_TRUSTED_WINDOWS_MODULES) != 0)
    {
        return 1;
    }

    high = manifest->ModuleHashCount;
    while (low < high)
    {
        const size_t middle = low + (high - low) / 2;
        const int comparison = memcmp(
            manifest->ModuleSha256[middle],
            moduleSha256,
            OAC_MANIFEST_HASH_SIZE);
        if (comparison == 0) return 1;
        if (comparison < 0)
            low = middle + 1;
        else
            high = middle;
    }
    return 0;
}

int OacManifestRollbackStateValid(
    const OAC_MANIFEST_ROLLBACK_STATE* state)
{
    return state != NULL &&
        memcmp(
            state->Magic,
            g_ManifestStateMagic,
            sizeof(g_ManifestStateMagic)) == 0 &&
        state->SchemaVersion == OAC_MANIFEST_STATE_SCHEMA &&
        state->Size == sizeof(*state) && state->Sequence != 0 &&
        OacBytesAreNonzero(state->GameId, sizeof(state->GameId)) &&
        OacBytesAreNonzero(state->BuildId, sizeof(state->BuildId)) &&
        OacBytesAreNonzero(
            state->ManifestSha256,
            sizeof(state->ManifestSha256)) &&
        OacBytesAreZero(state->Reserved, sizeof(state->Reserved));
}

OAC_MANIFEST_ROLLBACK_DECISION OacManifestEvaluateRollback(
    const OAC_GAME_MANIFEST* manifest,
    const uint8_t manifestSha256[OAC_MANIFEST_HASH_SIZE],
    const OAC_MANIFEST_ROLLBACK_STATE* currentState,
    int hasCurrentState,
    OAC_MANIFEST_ROLLBACK_STATE* nextState)
{
    OAC_MANIFEST_ROLLBACK_DECISION decision;

    if (manifest == NULL || manifestSha256 == NULL || nextState == NULL ||
        !OacBytesAreNonzero(manifestSha256, OAC_MANIFEST_HASH_SIZE) ||
        (hasCurrentState != 0 && hasCurrentState != 1))
    {
        return OAC_MANIFEST_ROLLBACK_INVALID_STATE;
    }
    memset(nextState, 0, sizeof(*nextState));
    decision = OAC_MANIFEST_ROLLBACK_ACCEPT_NEW;
    if (hasCurrentState)
    {
        if (!OacManifestRollbackStateValid(currentState) ||
            memcmp(
                currentState->GameId,
                manifest->GameId,
                OAC_MANIFEST_ID_SIZE) != 0)
        {
            return OAC_MANIFEST_ROLLBACK_INVALID_STATE;
        }
        if (manifest->Sequence < currentState->Sequence)
        {
            return OAC_MANIFEST_ROLLBACK_REJECT_OLDER;
        }
        if (manifest->Sequence == currentState->Sequence)
        {
            if (memcmp(
                    currentState->ManifestSha256,
                    manifestSha256,
                    OAC_MANIFEST_HASH_SIZE) != 0 ||
                memcmp(
                    currentState->BuildId,
                    manifest->BuildId,
                    OAC_MANIFEST_ID_SIZE) != 0)
            {
                return OAC_MANIFEST_ROLLBACK_REJECT_EQUIVOCATION;
            }
            *nextState = *currentState;
            return OAC_MANIFEST_ROLLBACK_ACCEPT_CURRENT;
        }
    }

    memcpy(nextState->Magic, g_ManifestStateMagic, sizeof(g_ManifestStateMagic));
    nextState->SchemaVersion = OAC_MANIFEST_STATE_SCHEMA;
    nextState->Size = sizeof(*nextState);
    memcpy(nextState->GameId, manifest->GameId, OAC_MANIFEST_ID_SIZE);
    memcpy(nextState->BuildId, manifest->BuildId, OAC_MANIFEST_ID_SIZE);
    nextState->Sequence = manifest->Sequence;
    memcpy(
        nextState->ManifestSha256,
        manifestSha256,
        OAC_MANIFEST_HASH_SIZE);
    return decision;
}
