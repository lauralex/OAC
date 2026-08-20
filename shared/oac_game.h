#pragma once

/*
 * Canonical game/server integration records. Authenticated game servers emit
 * these records from authoritative state; clients must not be treated as the
 * authority for positions, ticks, or replay identity.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OAC_GAME_SCHEMA 1u
#define OAC_GAME_ID_SIZE 16u
#define OAC_GAME_PLAYER_ID_SIZE 32u
#define OAC_GAME_REPLAY_DIGEST_SIZE 32u
#define OAC_GAME_SCOPE_SIZE 128u
#define OAC_GAME_EVENT_HEADER_SIZE 168u
#define OAC_GAME_MOVEMENT_EVENT_SIZE 256u
#define OAC_GAME_SESSION_CONTEXT_SIZE 160u
#define OAC_GAME_MOVEMENT_RULES_SIZE 96u
#define OAC_GAME_DETECTOR_STATE_SIZE 224u
#define OAC_GAME_DETECTOR_RESULT_SIZE 96u

#define OAC_GAME_RISK_MAX 1000u
#define OAC_GAME_MAX_TICK_RATE 1000u
#define OAC_GAME_MAX_SPEED_MM_PER_SECOND 1000000u
#define OAC_GAME_MAX_POSITION_TOLERANCE_MM 1000000u
#define OAC_GAME_MAX_TICK_GAP 60000u

typedef uint32_t OAC_GAME_EVENT_TYPE;
#define OAC_GAME_EVENT_MOVEMENT 1u

typedef uint32_t OAC_GAME_EVENT_FLAGS;
#define OAC_GAME_EVENT_SERVER_AUTHORITY 0x00000001u
#define OAC_GAME_EVENT_VALID_FLAGS OAC_GAME_EVENT_SERVER_AUTHORITY

typedef uint32_t OAC_GAME_MOVEMENT_FLAGS;
#define OAC_GAME_MOVEMENT_SERVER_CORRECTION 0x00000001u
#define OAC_GAME_MOVEMENT_VALID_FLAGS OAC_GAME_MOVEMENT_SERVER_CORRECTION

typedef uint32_t OAC_GAME_FINDINGS;
#define OAC_GAME_FINDING_SEQUENCE_GAP 0x00000001u
#define OAC_GAME_FINDING_TICK_GAP 0x00000002u
#define OAC_GAME_FINDING_MOVEMENT_ENVELOPE 0x00000004u
#define OAC_GAME_FINDING_REPORTED_VELOCITY 0x00000008u
#define OAC_GAME_VALID_FINDINGS 0x0000000Fu

typedef uint32_t OAC_GAME_VALIDATION;
#define OAC_GAME_VALID 0u
#define OAC_GAME_INVALID_POINTER 1u
#define OAC_GAME_INVALID_LENGTH 2u
#define OAC_GAME_INVALID_SCHEMA 3u
#define OAC_GAME_INVALID_RESERVED 4u
#define OAC_GAME_INVALID_IDENTITY 5u
#define OAC_GAME_INVALID_EVENT_TYPE 6u
#define OAC_GAME_INVALID_SEQUENCE 7u
#define OAC_GAME_INVALID_TIME 8u
#define OAC_GAME_INVALID_REPLAY 9u
#define OAC_GAME_INVALID_MOVEMENT 10u

typedef uint32_t OAC_GAME_DECISION;
#define OAC_GAME_DECISION_ACCEPT 0u
#define OAC_GAME_DECISION_OBSERVE 1u
#define OAC_GAME_DECISION_REVIEW 2u
#define OAC_GAME_DECISION_REJECT 3u
#define OAC_GAME_DECISION_REPLAY 4u
#define OAC_GAME_DECISION_INVALID 5u

typedef uint32_t OAC_GAME_REASON;
#define OAC_GAME_REASON_NONE 0u
#define OAC_GAME_REASON_SEQUENCE_GAP 1u
#define OAC_GAME_REASON_TICK_GAP 2u
#define OAC_GAME_REASON_MOVEMENT_ENVELOPE 3u
#define OAC_GAME_REASON_REPORTED_VELOCITY 4u
#define OAC_GAME_REASON_REPLAY 5u
#define OAC_GAME_REASON_IDENTITY_MISMATCH 6u
#define OAC_GAME_REASON_MALFORMED_EVENT 7u
#define OAC_GAME_REASON_INVALID_RULES 8u
#define OAC_GAME_REASON_INVALID_STATE 9u
#define OAC_GAME_REASON_INVALID_ENDPOINT_RISK 10u

typedef struct OAC_GAME_SCOPE_TAG
{
    uint8_t GameId[OAC_GAME_ID_SIZE];
    uint8_t BuildId[OAC_GAME_ID_SIZE];
    uint8_t BackendSessionId[OAC_GAME_ID_SIZE];
    uint8_t MatchId[OAC_GAME_ID_SIZE];
    uint8_t PlayerPseudonym[OAC_GAME_PLAYER_ID_SIZE];
    uint8_t ReplaySha256[OAC_GAME_REPLAY_DIGEST_SIZE];
} OAC_GAME_SCOPE;

typedef struct OAC_GAME_EVENT_HEADER_TAG
{
    uint32_t SchemaVersion;
    uint32_t Size;
    OAC_GAME_EVENT_TYPE EventType;
    OAC_GAME_EVENT_FLAGS Flags;
    OAC_GAME_SCOPE Scope;
    uint64_t Sequence;
    uint64_t ServerTick;
    uint64_t ReplayOffset;
} OAC_GAME_EVENT_HEADER;

typedef struct OAC_GAME_MOVEMENT_EVENT_TAG
{
    OAC_GAME_EVENT_HEADER Header;
    /* X and Y are horizontal axes; Z is the vertical axis. */
    int64_t PositionMillimeters[3];
    int32_t VelocityMillimetersPerSecond[3];
    OAC_GAME_MOVEMENT_FLAGS MovementFlags;
    uint8_t Reserved[48];
} OAC_GAME_MOVEMENT_EVENT;

typedef struct OAC_GAME_SESSION_CONTEXT_TAG
{
    uint32_t SchemaVersion;
    uint32_t Size;
    OAC_GAME_SCOPE Scope;
    uint64_t NextSequence;
    uint8_t Reserved[16];
} OAC_GAME_SESSION_CONTEXT;

typedef struct OAC_GAME_MOVEMENT_RULES_TAG
{
    uint32_t SchemaVersion;
    uint32_t Size;
    uint32_t Flags;
    uint32_t ServerTicksPerSecond;
    uint8_t GameId[OAC_GAME_ID_SIZE];
    uint8_t BuildId[OAC_GAME_ID_SIZE];
    uint32_t MaximumHorizontalSpeedMmPerSecond;
    uint32_t MaximumVerticalSpeedMmPerSecond;
    uint32_t PositionToleranceMillimeters;
    uint32_t MaximumTickGap;
    uint32_t SequenceGapRisk;
    uint32_t TickGapRisk;
    uint32_t MovementRisk;
    uint32_t VelocityRisk;
    uint32_t ReviewThreshold;
    uint32_t RejectThreshold;
    uint8_t Reserved[8];
} OAC_GAME_MOVEMENT_RULES;

typedef struct OAC_GAME_DETECTOR_STATE_TAG
{
    uint32_t SchemaVersion;
    uint32_t Size;
    uint32_t Flags;
    uint32_t HasPosition;
    OAC_GAME_SCOPE Scope;
    uint64_t LastSequence;
    uint64_t LastServerTick;
    uint64_t LastReplayOffset;
    int64_t LastPositionMillimeters[3];
    uint32_t BehaviorRisk;
    uint32_t EventsEvaluated;
    uint32_t AnomaliesObserved;
    uint32_t Reserved0;
    uint8_t Reserved[16];
} OAC_GAME_DETECTOR_STATE;

typedef struct OAC_GAME_DETECTOR_RESULT_TAG
{
    uint32_t SchemaVersion;
    uint32_t Size;
    OAC_GAME_DECISION Decision;
    OAC_GAME_REASON Reason;
    uint64_t Sequence;
    uint64_t ServerTick;
    uint32_t EndpointRisk;
    uint32_t BehaviorRisk;
    uint32_t CombinedRisk;
    uint32_t RiskDelta;
    OAC_GAME_FINDINGS Findings;
    uint32_t Reserved;
    uint64_t AllowedHorizontalDeltaMillimeters;
    uint64_t AllowedVerticalDeltaMillimeters;
    uint64_t ObservedDeltaMillimeters[3];
} OAC_GAME_DETECTOR_RESULT;

int OacGameInitializeSession(
    OAC_GAME_SESSION_CONTEXT* context,
    const uint8_t gameId[OAC_GAME_ID_SIZE],
    const uint8_t buildId[OAC_GAME_ID_SIZE],
    const uint8_t backendSessionId[OAC_GAME_ID_SIZE],
    const uint8_t matchId[OAC_GAME_ID_SIZE],
    const uint8_t playerPseudonym[OAC_GAME_PLAYER_ID_SIZE],
    const uint8_t replaySha256[OAC_GAME_REPLAY_DIGEST_SIZE]);

int OacGameCreateMovementEvent(
    OAC_GAME_SESSION_CONTEXT* context,
    uint64_t serverTick,
    uint64_t replayOffset,
    const int64_t positionMillimeters[3],
    const int32_t velocityMillimetersPerSecond[3],
    OAC_GAME_MOVEMENT_FLAGS movementFlags,
    OAC_GAME_MOVEMENT_EVENT* event);

OAC_GAME_VALIDATION OacGameValidateMovementEvent(
    const OAC_GAME_MOVEMENT_EVENT* event,
    size_t length);

int OacGameMovementRulesValid(
    const OAC_GAME_MOVEMENT_RULES* rules);

int OacGameInitializeDetector(
    const OAC_GAME_MOVEMENT_RULES* rules,
    const OAC_GAME_SESSION_CONTEXT* context,
    OAC_GAME_DETECTOR_STATE* state);

/* Endpoint risk is 0..OAC_GAME_RISK_MAX and cannot trigger Review or Reject
 * unless the detector has already recorded nonzero behavior risk. */
OAC_GAME_DECISION OacGameEvaluateMovement(
    const OAC_GAME_MOVEMENT_RULES* rules,
    const OAC_GAME_MOVEMENT_EVENT* event,
    size_t length,
    uint32_t endpointRisk,
    OAC_GAME_DETECTOR_STATE* state,
    OAC_GAME_DETECTOR_RESULT* result);

#ifdef __cplusplus
}
#endif

#if defined(__cplusplus)
#define OAC_GAME_STATIC_ASSERT(condition, message) static_assert(condition, message)
#else
#define OAC_GAME_STATIC_ASSERT(condition, message) _Static_assert(condition, message)
#endif

OAC_GAME_STATIC_ASSERT(sizeof(OAC_GAME_EVENT_HEADER) == OAC_GAME_EVENT_HEADER_SIZE,
    "game event header layout changed");
OAC_GAME_STATIC_ASSERT(sizeof(OAC_GAME_SCOPE) == OAC_GAME_SCOPE_SIZE,
    "game identity scope layout changed");
OAC_GAME_STATIC_ASSERT(offsetof(OAC_GAME_SCOPE, PlayerPseudonym) == 64,
    "game scope player identity moved");
OAC_GAME_STATIC_ASSERT(offsetof(OAC_GAME_SCOPE, ReplaySha256) == 96,
    "game scope replay identity moved");
OAC_GAME_STATIC_ASSERT(offsetof(OAC_GAME_EVENT_HEADER, Scope) == 16,
    "game event identity moved");
OAC_GAME_STATIC_ASSERT(offsetof(OAC_GAME_EVENT_HEADER, Sequence) == 144,
    "game event sequence moved");
OAC_GAME_STATIC_ASSERT(offsetof(OAC_GAME_EVENT_HEADER, ReplayOffset) == 160,
    "game event replay offset moved");
OAC_GAME_STATIC_ASSERT(sizeof(OAC_GAME_MOVEMENT_EVENT) == OAC_GAME_MOVEMENT_EVENT_SIZE,
    "movement event layout changed");
OAC_GAME_STATIC_ASSERT(offsetof(OAC_GAME_MOVEMENT_EVENT, PositionMillimeters) == 168,
    "movement position moved");
OAC_GAME_STATIC_ASSERT(offsetof(OAC_GAME_MOVEMENT_EVENT, MovementFlags) == 204,
    "movement flags moved");
OAC_GAME_STATIC_ASSERT(sizeof(OAC_GAME_SESSION_CONTEXT) == OAC_GAME_SESSION_CONTEXT_SIZE,
    "game session context layout changed");
OAC_GAME_STATIC_ASSERT(offsetof(OAC_GAME_SESSION_CONTEXT, NextSequence) == 136,
    "game session sequence moved");
OAC_GAME_STATIC_ASSERT(sizeof(OAC_GAME_MOVEMENT_RULES) == OAC_GAME_MOVEMENT_RULES_SIZE,
    "movement rules layout changed");
OAC_GAME_STATIC_ASSERT(offsetof(OAC_GAME_MOVEMENT_RULES, GameId) == 16,
    "movement rules identity moved");
OAC_GAME_STATIC_ASSERT(offsetof(OAC_GAME_MOVEMENT_RULES, ReviewThreshold) == 80,
    "movement review threshold moved");
OAC_GAME_STATIC_ASSERT(sizeof(OAC_GAME_DETECTOR_STATE) == OAC_GAME_DETECTOR_STATE_SIZE,
    "game detector state layout changed");
OAC_GAME_STATIC_ASSERT(offsetof(OAC_GAME_DETECTOR_STATE, LastSequence) == 144,
    "game detector sequence moved");
OAC_GAME_STATIC_ASSERT(offsetof(OAC_GAME_DETECTOR_STATE, BehaviorRisk) == 192,
    "game detector risk moved");
OAC_GAME_STATIC_ASSERT(sizeof(OAC_GAME_DETECTOR_RESULT) == OAC_GAME_DETECTOR_RESULT_SIZE,
    "game detector result layout changed");
OAC_GAME_STATIC_ASSERT(offsetof(OAC_GAME_DETECTOR_RESULT, EndpointRisk) == 32,
    "game detector endpoint risk moved");
OAC_GAME_STATIC_ASSERT(offsetof(
    OAC_GAME_DETECTOR_RESULT, AllowedHorizontalDeltaMillimeters) == 56,
    "game detector movement bound moved");

#undef OAC_GAME_STATIC_ASSERT
