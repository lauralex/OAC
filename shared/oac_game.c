#include "oac_game.h"

#include <limits.h>
#include <string.h>

static int OacGameBytesAreZero(const uint8_t* bytes, size_t length)
{
    size_t index;

    if (bytes == NULL) return 1;
    for (index = 0; index < length; ++index)
    {
        if (bytes[index] != 0) return 0;
    }
    return 1;
}

static int OacGameSameBytes(
    const uint8_t* left,
    const uint8_t* right,
    size_t length)
{
    return left != NULL && right != NULL &&
        memcmp(left, right, length) == 0;
}

static uint64_t OacGameMagnitude64(int64_t value)
{
    return value >= 0 ? (uint64_t)value : (uint64_t)(-(value + 1)) + 1u;
}

static uint64_t OacGameDistance64(int64_t left, int64_t right)
{
    const uint64_t leftMagnitude = OacGameMagnitude64(left);
    const uint64_t rightMagnitude = OacGameMagnitude64(right);

    if ((left < 0) == (right < 0))
    {
        return leftMagnitude >= rightMagnitude
            ? leftMagnitude - rightMagnitude
            : rightMagnitude - leftMagnitude;
    }
    if (UINT64_MAX - leftMagnitude < rightMagnitude) return UINT64_MAX;
    return leftMagnitude + rightMagnitude;
}

static uint32_t OacGameAddRisk(uint32_t current, uint32_t addition)
{
    return current >= OAC_GAME_RISK_MAX ||
            addition >= OAC_GAME_RISK_MAX - current
        ? OAC_GAME_RISK_MAX
        : current + addition;
}

static OAC_GAME_REASON OacGamePrimaryReason(OAC_GAME_FINDINGS findings)
{
    if ((findings & OAC_GAME_FINDING_REPORTED_VELOCITY) != 0)
        return OAC_GAME_REASON_REPORTED_VELOCITY;
    if ((findings & OAC_GAME_FINDING_MOVEMENT_ENVELOPE) != 0)
        return OAC_GAME_REASON_MOVEMENT_ENVELOPE;
    if ((findings & OAC_GAME_FINDING_TICK_GAP) != 0)
        return OAC_GAME_REASON_TICK_GAP;
    if ((findings & OAC_GAME_FINDING_SEQUENCE_GAP) != 0)
        return OAC_GAME_REASON_SEQUENCE_GAP;
    return OAC_GAME_REASON_NONE;
}

static uint64_t OacGameAllowedDelta(
    uint32_t speed,
    uint64_t tickDelta,
    uint32_t ticksPerSecond,
    uint32_t tolerance)
{
    const uint64_t scaled = (uint64_t)speed * tickDelta;
    const uint64_t rounded =
        (scaled + (uint64_t)ticksPerSecond - 1u) / ticksPerSecond;

    return rounded + tolerance;
}

static int OacGameSessionValid(const OAC_GAME_SESSION_CONTEXT* context)
{
    return context != NULL &&
        context->SchemaVersion == OAC_GAME_SCHEMA &&
        context->Size == sizeof(*context) && context->NextSequence != 0 &&
        context->NextSequence != UINT64_MAX &&
        !OacGameBytesAreZero(
            context->Scope.GameId, sizeof(context->Scope.GameId)) &&
        !OacGameBytesAreZero(
            context->Scope.BuildId, sizeof(context->Scope.BuildId)) &&
        !OacGameBytesAreZero(
            context->Scope.BackendSessionId,
            sizeof(context->Scope.BackendSessionId)) &&
        !OacGameBytesAreZero(
            context->Scope.MatchId, sizeof(context->Scope.MatchId)) &&
        !OacGameBytesAreZero(
            context->Scope.PlayerPseudonym,
            sizeof(context->Scope.PlayerPseudonym)) &&
        !OacGameBytesAreZero(
            context->Scope.ReplaySha256,
            sizeof(context->Scope.ReplaySha256)) &&
        OacGameBytesAreZero(context->Reserved, sizeof(context->Reserved));
}

static int OacGameStateValid(const OAC_GAME_DETECTOR_STATE* state)
{
    return state != NULL && state->SchemaVersion == OAC_GAME_SCHEMA &&
        state->Size == sizeof(*state) && state->Flags == 0 &&
        state->HasPosition <= 1 && state->BehaviorRisk <= OAC_GAME_RISK_MAX &&
        !OacGameBytesAreZero(
            state->Scope.GameId, sizeof(state->Scope.GameId)) &&
        !OacGameBytesAreZero(
            state->Scope.BuildId, sizeof(state->Scope.BuildId)) &&
        !OacGameBytesAreZero(
            state->Scope.BackendSessionId,
            sizeof(state->Scope.BackendSessionId)) &&
        !OacGameBytesAreZero(
            state->Scope.MatchId, sizeof(state->Scope.MatchId)) &&
        !OacGameBytesAreZero(
            state->Scope.PlayerPseudonym,
            sizeof(state->Scope.PlayerPseudonym)) &&
        !OacGameBytesAreZero(
            state->Scope.ReplaySha256,
            sizeof(state->Scope.ReplaySha256)) && state->Reserved0 == 0 &&
        OacGameBytesAreZero(state->Reserved, sizeof(state->Reserved)) &&
        state->AnomaliesObserved <= state->EventsEvaluated &&
        ((state->HasPosition == 0 && state->LastSequence == 0 &&
          state->LastServerTick == 0 && state->LastReplayOffset == 0 &&
          state->LastPositionMillimeters[0] == 0 &&
          state->LastPositionMillimeters[1] == 0 &&
          state->LastPositionMillimeters[2] == 0 &&
          state->BehaviorRisk == 0 && state->EventsEvaluated == 0 &&
          state->AnomaliesObserved == 0) ||
         (state->HasPosition == 1 && state->LastSequence != 0 &&
          state->LastServerTick != 0 && state->LastReplayOffset != 0 &&
          state->EventsEvaluated != 0 &&
          ((state->BehaviorRisk == 0 && state->AnomaliesObserved == 0) ||
           (state->BehaviorRisk != 0 && state->AnomaliesObserved != 0))));
}

static int OacGameEventMatchesState(
    const OAC_GAME_EVENT_HEADER* header,
    const OAC_GAME_DETECTOR_STATE* state)
{
    return header != NULL && state != NULL &&
        memcmp(&header->Scope, &state->Scope, sizeof(header->Scope)) == 0;
}

static OAC_GAME_DECISION OacGameRiskDecision(
    const OAC_GAME_MOVEMENT_RULES* rules,
    uint32_t behaviorRisk,
    uint32_t combinedRisk)
{
    if (behaviorRisk == 0)
        return combinedRisk == 0
            ? OAC_GAME_DECISION_ACCEPT
            : OAC_GAME_DECISION_OBSERVE;
    if (combinedRisk >= rules->RejectThreshold)
        return OAC_GAME_DECISION_REJECT;
    if (combinedRisk >= rules->ReviewThreshold)
        return OAC_GAME_DECISION_REVIEW;
    return OAC_GAME_DECISION_OBSERVE;
}

int OacGameInitializeSession(
    OAC_GAME_SESSION_CONTEXT* context,
    const uint8_t gameId[OAC_GAME_ID_SIZE],
    const uint8_t buildId[OAC_GAME_ID_SIZE],
    const uint8_t backendSessionId[OAC_GAME_ID_SIZE],
    const uint8_t matchId[OAC_GAME_ID_SIZE],
    const uint8_t playerPseudonym[OAC_GAME_PLAYER_ID_SIZE],
    const uint8_t replaySha256[OAC_GAME_REPLAY_DIGEST_SIZE])
{
    OAC_GAME_SESSION_CONTEXT candidate;

    if (context == NULL || gameId == NULL || buildId == NULL ||
        backendSessionId == NULL || matchId == NULL ||
        playerPseudonym == NULL || replaySha256 == NULL ||
        OacGameBytesAreZero(gameId, OAC_GAME_ID_SIZE) ||
        OacGameBytesAreZero(buildId, OAC_GAME_ID_SIZE) ||
        OacGameBytesAreZero(backendSessionId, OAC_GAME_ID_SIZE) ||
        OacGameBytesAreZero(matchId, OAC_GAME_ID_SIZE) ||
        OacGameBytesAreZero(playerPseudonym, OAC_GAME_PLAYER_ID_SIZE) ||
        OacGameBytesAreZero(replaySha256, OAC_GAME_REPLAY_DIGEST_SIZE))
    {
        return 0;
    }

    memset(&candidate, 0, sizeof(candidate));
    candidate.SchemaVersion = OAC_GAME_SCHEMA;
    candidate.Size = sizeof(candidate);
    memcpy(candidate.Scope.GameId, gameId, sizeof(candidate.Scope.GameId));
    memcpy(candidate.Scope.BuildId, buildId, sizeof(candidate.Scope.BuildId));
    memcpy(
        candidate.Scope.BackendSessionId,
        backendSessionId,
        sizeof(candidate.Scope.BackendSessionId));
    memcpy(
        candidate.Scope.MatchId, matchId, sizeof(candidate.Scope.MatchId));
    memcpy(
        candidate.Scope.PlayerPseudonym,
        playerPseudonym,
        sizeof(candidate.Scope.PlayerPseudonym));
    memcpy(
        candidate.Scope.ReplaySha256,
        replaySha256,
        sizeof(candidate.Scope.ReplaySha256));
    candidate.NextSequence = 1;
    *context = candidate;
    return 1;
}

int OacGameCreateMovementEvent(
    OAC_GAME_SESSION_CONTEXT* context,
    uint64_t serverTick,
    uint64_t replayOffset,
    const int64_t positionMillimeters[3],
    const int32_t velocityMillimetersPerSecond[3],
    OAC_GAME_MOVEMENT_FLAGS movementFlags,
    OAC_GAME_MOVEMENT_EVENT* event)
{
    OAC_GAME_MOVEMENT_EVENT candidate;

    if (!OacGameSessionValid(context) || event == NULL ||
        positionMillimeters == NULL || velocityMillimetersPerSecond == NULL ||
        serverTick == 0 || replayOffset == 0 ||
        (movementFlags & ~OAC_GAME_MOVEMENT_VALID_FLAGS) != 0)
    {
        return 0;
    }

    memset(&candidate, 0, sizeof(candidate));
    candidate.Header.SchemaVersion = OAC_GAME_SCHEMA;
    candidate.Header.Size = sizeof(candidate);
    candidate.Header.EventType = OAC_GAME_EVENT_MOVEMENT;
    candidate.Header.Flags = OAC_GAME_EVENT_SERVER_AUTHORITY;
    candidate.Header.Scope = context->Scope;
    candidate.Header.Sequence = context->NextSequence;
    candidate.Header.ServerTick = serverTick;
    candidate.Header.ReplayOffset = replayOffset;
    memcpy(
        candidate.PositionMillimeters,
        positionMillimeters,
        sizeof(candidate.PositionMillimeters));
    memcpy(
        candidate.VelocityMillimetersPerSecond,
        velocityMillimetersPerSecond,
        sizeof(candidate.VelocityMillimetersPerSecond));
    candidate.MovementFlags = movementFlags;

    *event = candidate;
    ++context->NextSequence;
    return 1;
}

OAC_GAME_VALIDATION OacGameValidateMovementEvent(
    const OAC_GAME_MOVEMENT_EVENT* event,
    size_t length)
{
    const OAC_GAME_EVENT_HEADER* header;

    if (event == NULL) return OAC_GAME_INVALID_POINTER;
    if (length != sizeof(*event)) return OAC_GAME_INVALID_LENGTH;
    header = &event->Header;
    if (header->SchemaVersion != OAC_GAME_SCHEMA ||
        header->Size != sizeof(*event))
    {
        return OAC_GAME_INVALID_SCHEMA;
    }
    if (header->EventType != OAC_GAME_EVENT_MOVEMENT)
        return OAC_GAME_INVALID_EVENT_TYPE;
    if (header->Flags != OAC_GAME_EVENT_SERVER_AUTHORITY ||
        !OacGameBytesAreZero(event->Reserved, sizeof(event->Reserved)))
    {
        return OAC_GAME_INVALID_RESERVED;
    }
    if ((event->MovementFlags & ~OAC_GAME_MOVEMENT_VALID_FLAGS) != 0)
        return OAC_GAME_INVALID_MOVEMENT;
    if (OacGameBytesAreZero(
            header->Scope.GameId, sizeof(header->Scope.GameId)) ||
        OacGameBytesAreZero(
            header->Scope.BuildId, sizeof(header->Scope.BuildId)) ||
        OacGameBytesAreZero(
            header->Scope.BackendSessionId,
            sizeof(header->Scope.BackendSessionId)) ||
        OacGameBytesAreZero(
            header->Scope.MatchId, sizeof(header->Scope.MatchId)) ||
        OacGameBytesAreZero(
            header->Scope.PlayerPseudonym,
            sizeof(header->Scope.PlayerPseudonym)))
    {
        return OAC_GAME_INVALID_IDENTITY;
    }
    if (header->Sequence == 0) return OAC_GAME_INVALID_SEQUENCE;
    if (header->ServerTick == 0) return OAC_GAME_INVALID_TIME;
    if (header->ReplayOffset == 0 || OacGameBytesAreZero(
            header->Scope.ReplaySha256,
            sizeof(header->Scope.ReplaySha256)))
    {
        return OAC_GAME_INVALID_REPLAY;
    }
    return OAC_GAME_VALID;
}

int OacGameMovementRulesValid(const OAC_GAME_MOVEMENT_RULES* rules)
{
    return rules != NULL && rules->SchemaVersion == OAC_GAME_SCHEMA &&
        rules->Size == sizeof(*rules) && rules->Flags == 0 &&
        !OacGameBytesAreZero(rules->GameId, sizeof(rules->GameId)) &&
        !OacGameBytesAreZero(rules->BuildId, sizeof(rules->BuildId)) &&
        rules->ServerTicksPerSecond != 0 &&
        rules->ServerTicksPerSecond <= OAC_GAME_MAX_TICK_RATE &&
        rules->MaximumHorizontalSpeedMmPerSecond != 0 &&
        rules->MaximumHorizontalSpeedMmPerSecond <=
            OAC_GAME_MAX_SPEED_MM_PER_SECOND &&
        rules->MaximumVerticalSpeedMmPerSecond != 0 &&
        rules->MaximumVerticalSpeedMmPerSecond <=
            OAC_GAME_MAX_SPEED_MM_PER_SECOND &&
        rules->PositionToleranceMillimeters <=
            OAC_GAME_MAX_POSITION_TOLERANCE_MM &&
        rules->MaximumTickGap != 0 &&
        rules->MaximumTickGap <= OAC_GAME_MAX_TICK_GAP &&
        rules->SequenceGapRisk != 0 &&
        rules->TickGapRisk != 0 && rules->MovementRisk != 0 &&
        rules->VelocityRisk != 0 &&
        rules->SequenceGapRisk <= OAC_GAME_RISK_MAX &&
        rules->TickGapRisk <= OAC_GAME_RISK_MAX &&
        rules->MovementRisk <= OAC_GAME_RISK_MAX &&
        rules->VelocityRisk <= OAC_GAME_RISK_MAX &&
        rules->ReviewThreshold != 0 &&
        rules->ReviewThreshold < rules->RejectThreshold &&
        rules->RejectThreshold <= OAC_GAME_RISK_MAX &&
        OacGameBytesAreZero(rules->Reserved, sizeof(rules->Reserved));
}

int OacGameInitializeDetector(
    const OAC_GAME_MOVEMENT_RULES* rules,
    const OAC_GAME_SESSION_CONTEXT* context,
    OAC_GAME_DETECTOR_STATE* state)
{
    if (!OacGameMovementRulesValid(rules) ||
        !OacGameSessionValid(context) || state == NULL ||
        !OacGameSameBytes(
            rules->GameId, context->Scope.GameId, OAC_GAME_ID_SIZE) ||
        !OacGameSameBytes(
            rules->BuildId, context->Scope.BuildId, OAC_GAME_ID_SIZE))
    {
        return 0;
    }

    memset(state, 0, sizeof(*state));
    state->SchemaVersion = OAC_GAME_SCHEMA;
    state->Size = sizeof(*state);
    state->Scope = context->Scope;
    return 1;
}

OAC_GAME_DECISION OacGameEvaluateMovement(
    const OAC_GAME_MOVEMENT_RULES* rules,
    const OAC_GAME_MOVEMENT_EVENT* event,
    size_t length,
    uint32_t endpointRisk,
    OAC_GAME_DETECTOR_STATE* state,
    OAC_GAME_DETECTOR_RESULT* result)
{
    OAC_GAME_DETECTOR_STATE nextState;
    OAC_GAME_FINDINGS findings = 0;
    uint32_t riskDelta = 0;
    uint32_t combinedRisk;
    uint64_t tickDelta = 0;
    uint64_t allowedHorizontal = 0;
    uint64_t allowedVertical = 0;
    uint64_t observed[3] = { 0, 0, 0 };
    OAC_GAME_VALIDATION validation;

    if (result == NULL) return OAC_GAME_DECISION_INVALID;
    memset(result, 0, sizeof(*result));
    result->SchemaVersion = OAC_GAME_SCHEMA;
    result->Size = sizeof(*result);
    result->Decision = OAC_GAME_DECISION_INVALID;
    result->Reason = OAC_GAME_REASON_MALFORMED_EVENT;
    if (!OacGameMovementRulesValid(rules))
    {
        result->Reason = OAC_GAME_REASON_INVALID_RULES;
        return result->Decision;
    }
    if (!OacGameStateValid(state))
    {
        result->Reason = OAC_GAME_REASON_INVALID_STATE;
        return result->Decision;
    }
    if (endpointRisk > OAC_GAME_RISK_MAX)
    {
        result->Reason = OAC_GAME_REASON_INVALID_ENDPOINT_RISK;
        return result->Decision;
    }

    validation = OacGameValidateMovementEvent(event, length);
    if (validation != OAC_GAME_VALID) return result->Decision;
    result->Sequence = event->Header.Sequence;
    result->ServerTick = event->Header.ServerTick;
    result->EndpointRisk = endpointRisk;
    result->BehaviorRisk = state->BehaviorRisk;
    result->CombinedRisk = OacGameAddRisk(state->BehaviorRisk, endpointRisk);

    if (!OacGameEventMatchesState(&event->Header, state) ||
        !OacGameSameBytes(
            rules->GameId,
            event->Header.Scope.GameId,
            OAC_GAME_ID_SIZE) ||
        !OacGameSameBytes(
            rules->BuildId,
            event->Header.Scope.BuildId,
            OAC_GAME_ID_SIZE))
    {
        result->Reason = OAC_GAME_REASON_IDENTITY_MISMATCH;
        return result->Decision;
    }
    if (state->HasPosition != 0 &&
        (event->Header.Sequence <= state->LastSequence ||
         event->Header.ServerTick <= state->LastServerTick ||
         event->Header.ReplayOffset <= state->LastReplayOffset))
    {
        result->Decision = OAC_GAME_DECISION_REPLAY;
        result->Reason = OAC_GAME_REASON_REPLAY;
        return result->Decision;
    }

    nextState = *state;
    if (state->HasPosition != 0)
    {
        tickDelta = event->Header.ServerTick - state->LastServerTick;
        if (event->Header.Sequence != state->LastSequence + 1u)
        {
            findings |= OAC_GAME_FINDING_SEQUENCE_GAP;
            riskDelta = OacGameAddRisk(
                riskDelta, rules->SequenceGapRisk);
        }
        if (tickDelta > rules->MaximumTickGap)
        {
            findings |= OAC_GAME_FINDING_TICK_GAP;
            riskDelta = OacGameAddRisk(riskDelta, rules->TickGapRisk);
        }

        observed[0] = OacGameDistance64(
            event->PositionMillimeters[0], state->LastPositionMillimeters[0]);
        observed[1] = OacGameDistance64(
            event->PositionMillimeters[1], state->LastPositionMillimeters[1]);
        observed[2] = OacGameDistance64(
            event->PositionMillimeters[2], state->LastPositionMillimeters[2]);
        if (tickDelta <= rules->MaximumTickGap)
        {
            allowedHorizontal = OacGameAllowedDelta(
                rules->MaximumHorizontalSpeedMmPerSecond,
                tickDelta,
                rules->ServerTicksPerSecond,
                rules->PositionToleranceMillimeters);
            allowedVertical = OacGameAllowedDelta(
                rules->MaximumVerticalSpeedMmPerSecond,
                tickDelta,
                rules->ServerTicksPerSecond,
                rules->PositionToleranceMillimeters);
            if ((event->MovementFlags &
                    OAC_GAME_MOVEMENT_SERVER_CORRECTION) == 0 &&
                (observed[0] > allowedHorizontal ||
                 observed[1] > allowedHorizontal ||
                 observed[2] > allowedVertical))
            {
                findings |= OAC_GAME_FINDING_MOVEMENT_ENVELOPE;
                riskDelta = OacGameAddRisk(riskDelta, rules->MovementRisk);
            }
        }
    }

    if ((uint64_t)(event->VelocityMillimetersPerSecond[0] < 0
            ? -(int64_t)event->VelocityMillimetersPerSecond[0]
            : event->VelocityMillimetersPerSecond[0]) >
            rules->MaximumHorizontalSpeedMmPerSecond ||
        (uint64_t)(event->VelocityMillimetersPerSecond[1] < 0
            ? -(int64_t)event->VelocityMillimetersPerSecond[1]
            : event->VelocityMillimetersPerSecond[1]) >
            rules->MaximumHorizontalSpeedMmPerSecond ||
        (uint64_t)(event->VelocityMillimetersPerSecond[2] < 0
            ? -(int64_t)event->VelocityMillimetersPerSecond[2]
            : event->VelocityMillimetersPerSecond[2]) >
            rules->MaximumVerticalSpeedMmPerSecond)
    {
        findings |= OAC_GAME_FINDING_REPORTED_VELOCITY;
        riskDelta = OacGameAddRisk(riskDelta, rules->VelocityRisk);
    }

    nextState.HasPosition = 1;
    nextState.LastSequence = event->Header.Sequence;
    nextState.LastServerTick = event->Header.ServerTick;
    nextState.LastReplayOffset = event->Header.ReplayOffset;
    memcpy(
        nextState.LastPositionMillimeters,
        event->PositionMillimeters,
        sizeof(nextState.LastPositionMillimeters));
    nextState.BehaviorRisk = OacGameAddRisk(
        nextState.BehaviorRisk, riskDelta);
    if (nextState.EventsEvaluated != UINT32_MAX) ++nextState.EventsEvaluated;
    if (findings != 0 && nextState.AnomaliesObserved != UINT32_MAX)
        ++nextState.AnomaliesObserved;

    combinedRisk = OacGameAddRisk(nextState.BehaviorRisk, endpointRisk);
    result->Decision = OacGameRiskDecision(
        rules, nextState.BehaviorRisk, combinedRisk);
    result->Reason = OacGamePrimaryReason(findings);
    result->BehaviorRisk = nextState.BehaviorRisk;
    result->CombinedRisk = combinedRisk;
    result->RiskDelta = riskDelta;
    result->Findings = findings;
    result->AllowedHorizontalDeltaMillimeters = allowedHorizontal;
    result->AllowedVerticalDeltaMillimeters = allowedVertical;
    memcpy(
        result->ObservedDeltaMillimeters,
        observed,
        sizeof(result->ObservedDeltaMillimeters));
    *state = nextState;
    return result->Decision;
}
