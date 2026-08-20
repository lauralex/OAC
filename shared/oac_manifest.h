#pragma once

/*
 * Canonical signed game-manifest records. The on-disk representation is the
 * packed structure below: fixed-width little-endian integers, UTF-16 code
 * units, and zeroed unused storage. The detached CMS signature is stored in a
 * separate .p7s file and is never part of these canonical bytes.
 */

#include <stddef.h>
#include <stdint.h>

#define OAC_MANIFEST_SCHEMA 2u
#define OAC_MANIFEST_SIZE 960u
#define OAC_MANIFEST_MAGIC_SIZE 8u
#define OAC_MANIFEST_ID_SIZE 16u
#define OAC_MANIFEST_HASH_SIZE 32u
#define OAC_MANIFEST_EXECUTABLE_NAME_CHARS 128u
#define OAC_MANIFEST_MODULE_HASH_CAPACITY 16u
#define OAC_MANIFEST_CLOCK_SKEW_SECONDS 300ULL
#define OAC_MANIFEST_MAX_VALIDITY_SECONDS (31ULL * 24ULL * 60ULL * 60ULL)

#define OAC_MANIFEST_ALLOW_TRUSTED_WINDOWS_MODULES 0x00000001u
#define OAC_MANIFEST_FLAGS OAC_MANIFEST_ALLOW_TRUSTED_WINDOWS_MODULES

#define OAC_MANIFEST_STATE_SCHEMA 1u
#define OAC_MANIFEST_STATE_SIZE 96u

typedef enum OAC_MANIFEST_VALIDATION_TAG
{
    OAC_MANIFEST_VALID = 0,
    OAC_MANIFEST_INVALID_POINTER = 1,
    OAC_MANIFEST_INVALID_LENGTH = 2,
    OAC_MANIFEST_INVALID_MAGIC = 3,
    OAC_MANIFEST_INVALID_SCHEMA = 4,
    OAC_MANIFEST_INVALID_RESERVED = 5,
    OAC_MANIFEST_INVALID_IDENTITY = 6,
    OAC_MANIFEST_INVALID_TIME = 7,
    OAC_MANIFEST_EXPIRED = 8,
    OAC_MANIFEST_INCOMPATIBLE_COMPONENT = 9,
    OAC_MANIFEST_INVALID_EXECUTABLE_NAME = 10,
    OAC_MANIFEST_INVALID_FILE_IDENTITY = 11,
    OAC_MANIFEST_INVALID_MODULE_POLICY = 12
} OAC_MANIFEST_VALIDATION;

typedef enum OAC_MANIFEST_ROLLBACK_DECISION_TAG
{
    OAC_MANIFEST_ROLLBACK_ACCEPT_NEW = 0,
    OAC_MANIFEST_ROLLBACK_ACCEPT_CURRENT = 1,
    OAC_MANIFEST_ROLLBACK_REJECT_OLDER = 2,
    OAC_MANIFEST_ROLLBACK_REJECT_EQUIVOCATION = 3,
    OAC_MANIFEST_ROLLBACK_INVALID_STATE = 4
} OAC_MANIFEST_ROLLBACK_DECISION;

#pragma pack(push, 1)
typedef struct OAC_GAME_MANIFEST_TAG
{
    uint8_t Magic[OAC_MANIFEST_MAGIC_SIZE];
    uint32_t SchemaVersion;
    uint32_t Size;
    uint32_t Flags;
    uint32_t ExecutableNameLength;
    uint8_t ManifestId[OAC_MANIFEST_ID_SIZE];
    uint8_t GameId[OAC_MANIFEST_ID_SIZE];
    uint8_t BuildId[OAC_MANIFEST_ID_SIZE];
    uint64_t Sequence;
    uint64_t IssuedAtUnixSeconds;
    uint64_t ExpiresAtUnixSeconds;
    uint64_t ExecutableSize;
    uint32_t RequiredDriverProtocol;
    uint32_t RequiredServiceProtocol;
    uint32_t RequiredLauncherProtocol;
    uint32_t Reserved0;
    uint8_t ExecutableSha256[OAC_MANIFEST_HASH_SIZE];
    uint8_t SigningKeyId[OAC_MANIFEST_HASH_SIZE];
    uint16_t ExecutableName[OAC_MANIFEST_EXECUTABLE_NAME_CHARS];
    uint32_t ModuleHashCount;
    uint32_t Reserved1;
    uint8_t ModuleSha256[OAC_MANIFEST_MODULE_HASH_CAPACITY]
        [OAC_MANIFEST_HASH_SIZE];
} OAC_GAME_MANIFEST;

typedef struct OAC_MANIFEST_ROLLBACK_STATE_TAG
{
    uint8_t Magic[OAC_MANIFEST_MAGIC_SIZE];
    uint32_t SchemaVersion;
    uint32_t Size;
    uint8_t GameId[OAC_MANIFEST_ID_SIZE];
    uint8_t BuildId[OAC_MANIFEST_ID_SIZE];
    uint64_t Sequence;
    uint8_t ManifestSha256[OAC_MANIFEST_HASH_SIZE];
    uint8_t Reserved[8];
} OAC_MANIFEST_ROLLBACK_STATE;
#pragma pack(pop)

#if defined(__cplusplus)
static_assert(sizeof(OAC_GAME_MANIFEST) == OAC_MANIFEST_SIZE,
    "OAC_GAME_MANIFEST layout changed");
static_assert(offsetof(OAC_GAME_MANIFEST, ManifestId) == 24,
    "manifest identity moved");
static_assert(offsetof(OAC_GAME_MANIFEST, GameId) == 40,
    "manifest game identity moved");
static_assert(offsetof(OAC_GAME_MANIFEST, BuildId) == 56,
    "manifest build identity moved");
static_assert(offsetof(OAC_GAME_MANIFEST, Sequence) == 72,
    "manifest sequence moved");
static_assert(offsetof(OAC_GAME_MANIFEST, IssuedAtUnixSeconds) == 80,
    "manifest issuance moved");
static_assert(offsetof(OAC_GAME_MANIFEST, ExpiresAtUnixSeconds) == 88,
    "manifest expiration moved");
static_assert(offsetof(OAC_GAME_MANIFEST, ExecutableSize) == 96,
    "manifest executable size moved");
static_assert(offsetof(OAC_GAME_MANIFEST, RequiredDriverProtocol) == 104,
    "manifest driver requirement moved");
static_assert(offsetof(OAC_GAME_MANIFEST, RequiredServiceProtocol) == 108,
    "manifest service requirement moved");
static_assert(offsetof(OAC_GAME_MANIFEST, RequiredLauncherProtocol) == 112,
    "manifest launcher requirement moved");
static_assert(offsetof(OAC_GAME_MANIFEST, ExecutableSha256) == 120,
    "manifest executable hash moved");
static_assert(offsetof(OAC_GAME_MANIFEST, SigningKeyId) == 152,
    "manifest signing-key identity moved");
static_assert(offsetof(OAC_GAME_MANIFEST, ExecutableName) == 184,
    "manifest executable name moved");
static_assert(offsetof(OAC_GAME_MANIFEST, ModuleHashCount) == 440,
    "manifest module count moved");
static_assert(offsetof(OAC_GAME_MANIFEST, ModuleSha256) == 448,
    "manifest module hashes moved");
static_assert(sizeof(OAC_MANIFEST_ROLLBACK_STATE) == OAC_MANIFEST_STATE_SIZE,
    "OAC_MANIFEST_ROLLBACK_STATE layout changed");
static_assert(offsetof(OAC_MANIFEST_ROLLBACK_STATE, GameId) == 16,
    "manifest-state game identity moved");
static_assert(offsetof(OAC_MANIFEST_ROLLBACK_STATE, BuildId) == 32,
    "manifest-state build identity moved");
static_assert(offsetof(OAC_MANIFEST_ROLLBACK_STATE, Sequence) == 48,
    "manifest-state sequence moved");
static_assert(offsetof(OAC_MANIFEST_ROLLBACK_STATE, ManifestSha256) == 56,
    "manifest-state digest moved");
#else
_Static_assert(sizeof(OAC_GAME_MANIFEST) == OAC_MANIFEST_SIZE,
    "OAC_GAME_MANIFEST layout changed");
_Static_assert(offsetof(OAC_GAME_MANIFEST, ManifestId) == 24,
    "manifest identity moved");
_Static_assert(offsetof(OAC_GAME_MANIFEST, GameId) == 40,
    "manifest game identity moved");
_Static_assert(offsetof(OAC_GAME_MANIFEST, BuildId) == 56,
    "manifest build identity moved");
_Static_assert(offsetof(OAC_GAME_MANIFEST, Sequence) == 72,
    "manifest sequence moved");
_Static_assert(offsetof(OAC_GAME_MANIFEST, IssuedAtUnixSeconds) == 80,
    "manifest issuance moved");
_Static_assert(offsetof(OAC_GAME_MANIFEST, ExpiresAtUnixSeconds) == 88,
    "manifest expiration moved");
_Static_assert(offsetof(OAC_GAME_MANIFEST, ExecutableSize) == 96,
    "manifest executable size moved");
_Static_assert(offsetof(OAC_GAME_MANIFEST, RequiredDriverProtocol) == 104,
    "manifest driver requirement moved");
_Static_assert(offsetof(OAC_GAME_MANIFEST, RequiredServiceProtocol) == 108,
    "manifest service requirement moved");
_Static_assert(offsetof(OAC_GAME_MANIFEST, RequiredLauncherProtocol) == 112,
    "manifest launcher requirement moved");
_Static_assert(offsetof(OAC_GAME_MANIFEST, ExecutableSha256) == 120,
    "manifest executable hash moved");
_Static_assert(offsetof(OAC_GAME_MANIFEST, SigningKeyId) == 152,
    "manifest signing-key identity moved");
_Static_assert(offsetof(OAC_GAME_MANIFEST, ExecutableName) == 184,
    "manifest executable name moved");
_Static_assert(offsetof(OAC_GAME_MANIFEST, ModuleHashCount) == 440,
    "manifest module count moved");
_Static_assert(offsetof(OAC_GAME_MANIFEST, ModuleSha256) == 448,
    "manifest module hashes moved");
_Static_assert(sizeof(OAC_MANIFEST_ROLLBACK_STATE) == OAC_MANIFEST_STATE_SIZE,
    "OAC_MANIFEST_ROLLBACK_STATE layout changed");
_Static_assert(offsetof(OAC_MANIFEST_ROLLBACK_STATE, GameId) == 16,
    "manifest-state game identity moved");
_Static_assert(offsetof(OAC_MANIFEST_ROLLBACK_STATE, BuildId) == 32,
    "manifest-state build identity moved");
_Static_assert(offsetof(OAC_MANIFEST_ROLLBACK_STATE, Sequence) == 48,
    "manifest-state sequence moved");
_Static_assert(offsetof(OAC_MANIFEST_ROLLBACK_STATE, ManifestSha256) == 56,
    "manifest-state digest moved");
#endif

#ifdef __cplusplus
extern "C" {
#endif

OAC_MANIFEST_VALIDATION OacManifestValidate(
    const OAC_GAME_MANIFEST* manifest,
    size_t length,
    uint64_t nowUnixSeconds,
    uint32_t driverProtocol,
    uint32_t serviceProtocol,
    uint32_t launcherProtocol);

int OacManifestFileIdentityMatches(
    const OAC_GAME_MANIFEST* manifest,
    const uint16_t* executableName,
    size_t executableNameLength,
    uint64_t executableSize,
    const uint8_t executableSha256[OAC_MANIFEST_HASH_SIZE],
    const uint8_t signerCertificateSha256[OAC_MANIFEST_HASH_SIZE]);

int OacManifestRuntimeModuleAllowed(
    const OAC_GAME_MANIFEST* manifest,
    const uint8_t moduleSha256[OAC_MANIFEST_HASH_SIZE],
    int trustedWindowsModule);

OAC_MANIFEST_ROLLBACK_DECISION OacManifestEvaluateRollback(
    const OAC_GAME_MANIFEST* manifest,
    const uint8_t manifestSha256[OAC_MANIFEST_HASH_SIZE],
    const OAC_MANIFEST_ROLLBACK_STATE* currentState,
    int hasCurrentState,
    OAC_MANIFEST_ROLLBACK_STATE* nextState);

int OacManifestRollbackStateValid(
    const OAC_MANIFEST_ROLLBACK_STATE* state);

#ifdef __cplusplus
}
#endif
