namespace Oac.Backend;

internal sealed record GameDetectorState
{
    public byte[] Scope { get; init; } = [];
    public bool HasPosition { get; init; }
    public ulong LastSequence { get; init; }
    public ulong LastServerTick { get; init; }
    public ulong LastReplayOffset { get; init; }
    public long[] LastPosition { get; init; } = [0, 0, 0];
    public uint BehaviorRisk { get; init; }
    public uint EventsEvaluated { get; init; }
    public uint AnomaliesObserved { get; init; }

    public static GameDetectorState FromWire(ReadOnlySpan<byte> value)
    {
        if (value.Length != 224 || WireProtocol.ReadUInt32(value, 0) != 1 ||
            WireProtocol.ReadUInt32(value, 4) != 224 ||
            WireProtocol.ReadUInt32(value, 8) != 0 ||
            WireProtocol.ReadUInt32(value, 12) > 1 ||
            WireProtocol.IsZero(value.Slice(16, 16)) ||
            WireProtocol.IsZero(value.Slice(32, 16)) ||
            WireProtocol.IsZero(value.Slice(48, 16)) ||
            WireProtocol.IsZero(value.Slice(64, 16)) ||
            WireProtocol.IsZero(value.Slice(80, 32)) ||
            WireProtocol.IsZero(value.Slice(112, 32)) ||
            WireProtocol.ReadUInt32(value, 204) != 0 ||
            !WireProtocol.IsZero(value.Slice(208, 16)))
        {
            throw new InvalidDataException("A durable game detector state is malformed.");
        }
        long[] position = new long[3];
        for (int index = 0; index != 3; ++index)
            position[index] = WireProtocol.ReadInt64(value, 168 + index * 8);
        GameDetectorState state = new()
        {
            Scope = value.Slice(16, 128).ToArray(),
            HasPosition = WireProtocol.ReadUInt32(value, 12) != 0,
            LastSequence = WireProtocol.ReadUInt64(value, 144),
            LastServerTick = WireProtocol.ReadUInt64(value, 152),
            LastReplayOffset = WireProtocol.ReadUInt64(value, 160),
            LastPosition = position,
            BehaviorRisk = WireProtocol.ReadUInt32(value, 192),
            EventsEvaluated = WireProtocol.ReadUInt32(value, 196),
            AnomaliesObserved = WireProtocol.ReadUInt32(value, 200)
        };
        if (state.BehaviorRisk > 1000 ||
            state.AnomaliesObserved > state.EventsEvaluated ||
            (!state.HasPosition &&
             (state.LastSequence != 0 || state.LastServerTick != 0 ||
              state.LastReplayOffset != 0 || state.BehaviorRisk != 0 ||
              state.EventsEvaluated != 0 || state.AnomaliesObserved != 0 ||
              state.LastPosition.Any(static item => item != 0))) ||
            (state.HasPosition &&
             (state.LastSequence == 0 || state.LastServerTick == 0 ||
              state.LastReplayOffset == 0 || state.EventsEvaluated == 0 ||
              ((state.BehaviorRisk == 0) != (state.AnomaliesObserved == 0)))))
        {
            throw new InvalidDataException("A durable game detector state is inconsistent.");
        }
        return state;
    }

    public byte[] ToWire()
    {
        byte[] result = new byte[224];
        WireProtocol.WriteUInt32(result, 0, 1);
        WireProtocol.WriteUInt32(result, 4, 224);
        WireProtocol.WriteUInt32(result, 12, HasPosition ? 1u : 0u);
        Scope.CopyTo(result, 16);
        WireProtocol.WriteUInt64(result, 144, LastSequence);
        WireProtocol.WriteUInt64(result, 152, LastServerTick);
        WireProtocol.WriteUInt64(result, 160, LastReplayOffset);
        for (int index = 0; index != 3; ++index)
            System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(
                result.AsSpan(168 + index * 8, 8), LastPosition[index]);
        WireProtocol.WriteUInt32(result, 192, BehaviorRisk);
        WireProtocol.WriteUInt32(result, 196, EventsEvaluated);
        WireProtocol.WriteUInt32(result, 200, AnomaliesObserved);
        return result;
    }
}

internal static class GameDetector
{
    public static (GameDetectorState State, DetectorResult Result) Evaluate(
        MovementRules rules,
        MovementEvent movement,
        uint endpointRisk,
        GameDetectorState? current)
    {
        GameDetectorState state = current ?? new GameDetectorState
        {
            Scope = (byte[])movement.Scope.Clone()
        };
        if (!WireProtocol.FixedEquals(state.Scope, movement.Scope) ||
            !WireProtocol.FixedEquals(rules.GameIdBytes, movement.GameId) ||
            !WireProtocol.FixedEquals(rules.BuildIdBytes, movement.BuildId))
        {
            throw new BackendRequestException(403, "The game event scope is not authorized.");
        }
        if (state.HasPosition &&
            (movement.Sequence <= state.LastSequence ||
             movement.ServerTick <= state.LastServerTick ||
             movement.ReplayOffset <= state.LastReplayOffset))
        {
            return (state, Result(
                4, 5, movement, endpointRisk, state.BehaviorRisk,
                AddRisk(state.BehaviorRisk, endpointRisk), 0, 0, 0, 0,
                [0, 0, 0]));
        }

        uint findings = 0;
        uint riskDelta = 0;
        ulong allowedHorizontal = 0;
        ulong allowedVertical = 0;
        ulong[] observed = [0, 0, 0];
        if (state.HasPosition)
        {
            ulong tickDelta = movement.ServerTick - state.LastServerTick;
            if (movement.Sequence != state.LastSequence + 1)
            {
                findings |= 1;
                riskDelta = AddRisk(riskDelta, rules.SequenceGapRisk);
            }
            if (tickDelta > rules.MaximumTickGap)
            {
                findings |= 2;
                riskDelta = AddRisk(riskDelta, rules.TickGapRisk);
            }
            for (int index = 0; index != 3; ++index)
                observed[index] = Distance(movement.Position[index], state.LastPosition[index]);
            if (tickDelta <= rules.MaximumTickGap)
            {
                allowedHorizontal = AllowedDelta(
                    rules.MaximumHorizontalSpeedMmPerSecond,
                    tickDelta,
                    rules.ServerTicksPerSecond,
                    rules.PositionToleranceMillimeters);
                allowedVertical = AllowedDelta(
                    rules.MaximumVerticalSpeedMmPerSecond,
                    tickDelta,
                    rules.ServerTicksPerSecond,
                    rules.PositionToleranceMillimeters);
                if ((movement.Flags & 1) == 0 &&
                    (observed[0] > allowedHorizontal ||
                     observed[1] > allowedHorizontal ||
                     observed[2] > allowedVertical))
                {
                    findings |= 4;
                    riskDelta = AddRisk(riskDelta, rules.MovementRisk);
                }
            }
        }
        if (Magnitude(movement.Velocity[0]) > rules.MaximumHorizontalSpeedMmPerSecond ||
            Magnitude(movement.Velocity[1]) > rules.MaximumHorizontalSpeedMmPerSecond ||
            Magnitude(movement.Velocity[2]) > rules.MaximumVerticalSpeedMmPerSecond)
        {
            findings |= 8;
            riskDelta = AddRisk(riskDelta, rules.VelocityRisk);
        }

        uint behaviorRisk = AddRisk(state.BehaviorRisk, riskDelta);
        uint combinedRisk = AddRisk(behaviorRisk, endpointRisk);
        uint decision = behaviorRisk == 0
            ? combinedRisk == 0 ? 0u : 1u
            : combinedRisk >= rules.RejectThreshold ? 3u
            : combinedRisk >= rules.ReviewThreshold ? 2u : 1u;
        uint reason = (findings & 8) != 0 ? 4u
            : (findings & 4) != 0 ? 3u
            : (findings & 2) != 0 ? 2u
            : (findings & 1) != 0 ? 1u : 0u;
        GameDetectorState next = state with
        {
            HasPosition = true,
            LastSequence = movement.Sequence,
            LastServerTick = movement.ServerTick,
            LastReplayOffset = movement.ReplayOffset,
            LastPosition = (long[])movement.Position.Clone(),
            BehaviorRisk = behaviorRisk,
            EventsEvaluated = state.EventsEvaluated == uint.MaxValue
                ? uint.MaxValue : state.EventsEvaluated + 1,
            AnomaliesObserved = findings == 0 || state.AnomaliesObserved == uint.MaxValue
                ? state.AnomaliesObserved : state.AnomaliesObserved + 1
        };
        return (next, Result(
            decision, reason, movement, endpointRisk, behaviorRisk,
            combinedRisk, riskDelta, findings, allowedHorizontal,
            allowedVertical, observed));
    }

    private static DetectorResult Result(
        uint decision,
        uint reason,
        MovementEvent movement,
        uint endpointRisk,
        uint behaviorRisk,
        uint combinedRisk,
        uint riskDelta,
        uint findings,
        ulong allowedHorizontal,
        ulong allowedVertical,
        ulong[] observed) => new(
            decision,
            reason,
            movement.Sequence,
            movement.ServerTick,
            endpointRisk,
            behaviorRisk,
            combinedRisk,
            riskDelta,
            findings,
            allowedHorizontal,
            allowedVertical,
            observed);

    private static uint AddRisk(uint current, uint addition) =>
        current >= 1000 || addition >= 1000 - current ? 1000 : current + addition;

    private static ulong Magnitude(int value) =>
        value >= 0 ? (ulong)value : (ulong)-(long)value;

    private static ulong Magnitude(long value) =>
        value >= 0 ? (ulong)value : (ulong)(-(value + 1)) + 1;

    private static ulong Distance(long left, long right)
    {
        ulong leftMagnitude = Magnitude(left);
        ulong rightMagnitude = Magnitude(right);
        if ((left < 0) == (right < 0))
            return leftMagnitude >= rightMagnitude
                ? leftMagnitude - rightMagnitude
                : rightMagnitude - leftMagnitude;
        return ulong.MaxValue - leftMagnitude < rightMagnitude
            ? ulong.MaxValue : leftMagnitude + rightMagnitude;
    }

    private static ulong AllowedDelta(
        uint speed,
        ulong tickDelta,
        uint ticksPerSecond,
        uint tolerance)
    {
        ulong scaled = speed * tickDelta;
        return (scaled + ticksPerSecond - 1) / ticksPerSecond + tolerance;
    }
}
