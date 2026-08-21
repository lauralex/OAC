using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Oac.Backend;

internal sealed class BackendRequestException(
    int statusCode,
    string message) : Exception(message)
{
    public int StatusCode { get; } = statusCode;
}

internal readonly record struct RequestHeader(
    uint MessageType,
    ulong RequestSequence,
    byte[] SessionId,
    byte[] Nonce,
    ulong IssuedAtUnixSeconds,
    ulong ExpiresAtUnixSeconds);

internal sealed record PolicyRequest(
    RequestHeader Header,
    byte[] GameId,
    byte[] BuildId,
    byte[] ChannelId,
    ulong CurrentPolicyVersion,
    byte[] CurrentPolicySha256);

internal sealed record OpenRequest(
    RequestHeader Header,
    byte[] GameId,
    byte[] BuildId,
    byte[] PolicyId,
    byte[] PolicySha256,
    uint MaximumLeaseMilliseconds,
    uint MaximumGraceMilliseconds,
    uint RenewalMilliseconds,
    uint EvidenceAcknowledgementMilliseconds);

internal sealed record RenewalRequest(
    RequestHeader Header,
    ulong CurrentLeaseSequence);

internal sealed record EvidenceRequest(
    RequestHeader Header,
    byte[] BindingSha256,
    ulong FirstServiceSequence,
    ulong LastServiceSequence,
    IReadOnlyList<byte[]> Items);

internal sealed record MovementEvent(
    byte[] Raw,
    byte[] GameId,
    byte[] BuildId,
    byte[] BackendSessionId,
    byte[] Scope,
    ulong Sequence,
    ulong ServerTick,
    ulong ReplayOffset,
    long[] Position,
    int[] Velocity,
    uint Flags);

internal sealed record GameRequest(
    RequestHeader Header,
    MovementEvent Event,
    uint EndpointRisk,
    byte[] Raw);

internal sealed record DetectorResult(
    uint Decision,
    uint Reason,
    ulong Sequence,
    ulong ServerTick,
    uint EndpointRisk,
    uint BehaviorRisk,
    uint CombinedRisk,
    uint RiskDelta,
    uint Findings,
    ulong AllowedHorizontalDelta,
    ulong AllowedVerticalDelta,
    ulong[] ObservedDelta)
{
    public byte[] ToWire()
    {
        byte[] result = new byte[WireProtocol.DetectorResultSize];
        WireProtocol.WriteUInt32(result, 0, 1);
        WireProtocol.WriteUInt32(result, 4, WireProtocol.DetectorResultSize);
        WireProtocol.WriteUInt32(result, 8, Decision);
        WireProtocol.WriteUInt32(result, 12, Reason);
        WireProtocol.WriteUInt64(result, 16, Sequence);
        WireProtocol.WriteUInt64(result, 24, ServerTick);
        WireProtocol.WriteUInt32(result, 32, EndpointRisk);
        WireProtocol.WriteUInt32(result, 36, BehaviorRisk);
        WireProtocol.WriteUInt32(result, 40, CombinedRisk);
        WireProtocol.WriteUInt32(result, 44, RiskDelta);
        WireProtocol.WriteUInt32(result, 48, Findings);
        WireProtocol.WriteUInt64(result, 56, AllowedHorizontalDelta);
        WireProtocol.WriteUInt64(result, 64, AllowedVerticalDelta);
        for (int index = 0; index != 3; ++index)
            WireProtocol.WriteUInt64(result, 72 + index * 8, ObservedDelta[index]);
        return result;
    }
}

internal static class WireProtocol
{
    public const uint Revision = 0x00010002;
    public const uint ProductionProtocol = 0x00050007;
    public const uint ServiceProtocol = 0x00010007;
    public const int HeaderSize = 88;
    public const int ResponseHeaderSize = 80;
    public const int PolicyRequestSize = 184;
    public const int PolicyResponseSize = 10760;
    public const int OpenRequestSize = 184;
    public const int OpenResponseSize = 144;
    public const int RenewalRequestSize = 96;
    public const int RenewalResponseSize = 104;
    public const int EvidenceMetadataSize = 144;
    public const int EvidenceItemSize = 584;
    public const int UploadResponseSize = 88;
    public const int GameRequestSize = 352;
    public const int GameResponseSize = 184;
    public const int MovementEventSize = 256;
    public const int DetectorResultSize = 96;
    public const int MaximumRequestSize = EvidenceMetadataSize + 16 * EvidenceItemSize;

    public const uint OpenMessage = 1;
    public const uint RenewMessage = 2;
    public const uint EvidenceMessage = 3;
    public const uint PolicyMessage = 4;
    public const uint GameMessage = 5;

    public static PolicyRequest ParsePolicy(ReadOnlySpan<byte> body, DateTimeOffset now)
    {
        RequestHeader header = ParseHeader(body, PolicyRequestSize, PolicyMessage, false, now);
        byte[] game = Identity(body, 88, 16, "game");
        byte[] build = Identity(body, 104, 16, "build");
        byte[] channel = Identity(body, 120, 16, "channel");
        ulong version = ReadUInt64(body, 136);
        byte[] digest = body.Slice(144, 32).ToArray();
        if ((version == 0) != IsZero(digest) || !IsZero(body.Slice(176, 8)))
            throw Invalid("The policy cache identity is malformed.");
        return new(header, game, build, channel, version, digest);
    }

    public static OpenRequest ParseOpen(ReadOnlySpan<byte> body, DateTimeOffset now)
    {
        RequestHeader header = ParseHeader(body, OpenRequestSize, OpenMessage, false, now);
        byte[] game = Identity(body, 88, 16, "game");
        byte[] build = Identity(body, 104, 16, "build");
        byte[] policy = Identity(body, 120, 16, "policy");
        byte[] policyDigest = Identity(body, 136, 32, "policy digest");
        uint lease = ReadUInt32(body, 168);
        uint grace = ReadUInt32(body, 172);
        uint renewal = ReadUInt32(body, 176);
        uint acknowledgement = ReadUInt32(body, 180);
        if (!BackendPolicyValid(lease, grace, renewal, acknowledgement))
            throw Invalid("The lease policy is invalid.");
        return new(header, game, build, policy, policyDigest,
            lease, grace, renewal, acknowledgement);
    }

    public static RenewalRequest ParseRenewal(
        ReadOnlySpan<byte> body,
        DateTimeOffset now)
    {
        RequestHeader header = ParseHeader(
            body, RenewalRequestSize, RenewMessage, true, now);
        ulong lease = ReadUInt64(body, 88);
        if (lease == 0) throw Invalid("The current lease sequence is required.");
        return new(header, lease);
    }

    public static EvidenceRequest ParseEvidence(
        ReadOnlySpan<byte> body,
        DateTimeOffset now)
    {
        if (body.Length < EvidenceMetadataSize || body.Length > MaximumRequestSize)
            throw Invalid("The evidence request size is invalid.");
        RequestHeader header = ParseHeader(
            body[..EvidenceMetadataSize], EvidenceMetadataSize, EvidenceMessage, true, now);
        byte[] binding = Identity(body, 88, 32, "backend binding");
        ulong first = ReadUInt64(body, 120);
        ulong last = ReadUInt64(body, 128);
        uint count = ReadUInt32(body, 136);
        if (count is 0 or > 16 || ReadUInt32(body, 140) != 0 || first == 0 ||
            first > ulong.MaxValue - (count - 1) || last != first + count - 1 ||
            body.Length != EvidenceMetadataSize + checked((int)count * EvidenceItemSize))
        {
            throw Invalid("The evidence sequence range is invalid.");
        }
        List<byte[]> items = new(checked((int)count));
        for (int index = 0; index != count; ++index)
        {
            ReadOnlySpan<byte> item = body.Slice(
                EvidenceMetadataSize + index * EvidenceItemSize, EvidenceItemSize);
            ValidateEvidenceItem(item, first + (uint)index);
            items.Add(item.ToArray());
        }
        return new(header, binding, first, last, items);
    }

    public static GameRequest ParseGame(ReadOnlySpan<byte> body, DateTimeOffset now)
    {
        RequestHeader header = ParseHeader(body, GameRequestSize, GameMessage, true, now);
        MovementEvent movement = ParseMovement(body.Slice(88, MovementEventSize));
        uint endpointRisk = ReadUInt32(body, 344);
        if (endpointRisk > 1000 || ReadUInt32(body, 348) != 0 ||
            header.RequestSequence != movement.Sequence ||
            !FixedEquals(header.SessionId, movement.BackendSessionId))
        {
            throw Invalid("The game event correlation is invalid.");
        }
        return new(header, movement, endpointRisk, body.ToArray());
    }

    public static byte[] PolicyResponse(PolicyRequest request, PolicyBundle policy)
    {
        byte[] response = Response(PolicyResponseSize, PolicyMessage, request.Header, null);
        WriteUInt32(response, 80, PolicyBundle.PolicySize);
        WriteUInt32(response, 84, checked((uint)policy.Signature.Length));
        policy.Record.CopyTo(response, 88);
        policy.Signature.CopyTo(response, 2568);
        return response;
    }

    public static byte[] OpenResponse(
        OpenRequest request,
        byte[] sessionId,
        byte[] serverNonce,
        ulong leaseSequence,
        uint lease,
        uint grace,
        uint renewal,
        ulong acknowledgement)
    {
        byte[] response = Response(OpenResponseSize, OpenMessage, request.Header, sessionId);
        serverNonce.CopyTo(response.AsSpan(80, 32));
        WriteUInt64(response, 112, leaseSequence);
        WriteUInt32(response, 120, lease);
        WriteUInt32(response, 124, grace);
        WriteUInt32(response, 128, renewal);
        WriteUInt64(response, 136, acknowledgement);
        return response;
    }

    public static byte[] RenewalResponse(
        RenewalRequest request,
        ulong leaseSequence,
        uint lease,
        uint grace,
        uint renewal,
        bool revoked)
    {
        byte[] response = Response(
            RenewalResponseSize, RenewMessage, request.Header, request.Header.SessionId);
        WriteUInt64(response, 80, leaseSequence);
        WriteUInt32(response, 88, revoked ? 0 : lease);
        WriteUInt32(response, 92, revoked ? 0 : grace);
        WriteUInt32(response, 96, revoked ? 0 : renewal);
        WriteUInt32(response, 100, revoked ? 1u : 0u);
        return response;
    }

    public static byte[] EvidenceResponse(EvidenceRequest request, ulong acknowledged)
    {
        byte[] response = Response(
            UploadResponseSize, EvidenceMessage, request.Header, request.Header.SessionId);
        WriteUInt64(response, 80, acknowledged);
        return response;
    }

    public static byte[] GameResponse(
        GameRequest request,
        DetectorResult result,
        ulong durableSequence)
    {
        byte[] response = Response(
            GameResponseSize, GameMessage, request.Header, request.Header.SessionId);
        result.ToWire().CopyTo(response, 80);
        WriteUInt64(response, 176, durableSequence);
        return response;
    }

    public static byte[] BindingDigest(
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> requestNonce,
        ReadOnlySpan<byte> serverNonce)
    {
        Span<byte> material = stackalloc byte[80];
        sessionId.CopyTo(material[..16]);
        SHA256.HashData(requestNonce, material.Slice(16, 32));
        serverNonce.CopyTo(material.Slice(48, 32));
        byte[] digest = SHA256.HashData(material);
        CryptographicOperations.ZeroMemory(material);
        return digest;
    }

    private static RequestHeader ParseHeader(
        ReadOnlySpan<byte> body,
        int expectedSize,
        uint expectedType,
        bool requireSession,
        DateTimeOffset now)
    {
        if (body.Length != expectedSize || ReadUInt32(body, 0) != Revision ||
            ReadUInt32(body, 4) != expectedSize || ReadUInt32(body, 8) != expectedType ||
            ReadUInt32(body, 12) != 0 || ReadUInt64(body, 16) == 0)
        {
            throw Invalid("The backend request header is malformed.");
        }
        byte[] session = body.Slice(24, 16).ToArray();
        byte[] nonce = body.Slice(40, 32).ToArray();
        ulong issued = ReadUInt64(body, 72);
        ulong expires = ReadUInt64(body, 80);
        ulong current = checked((ulong)now.ToUnixTimeSeconds());
        bool sessionZero = IsZero(session);
        if (IsZero(nonce) || requireSession == sessionZero || issued == 0 ||
            expires <= issued || expires - issued > 60 ||
            (issued > current && issued - current > 30) || current > expires)
        {
            throw Invalid("The backend request identity or lifetime is invalid.");
        }
        return new(expectedType, ReadUInt64(body, 16), session, nonce, issued, expires);
    }

    private static MovementEvent ParseMovement(ReadOnlySpan<byte> value)
    {
        if (value.Length != MovementEventSize || ReadUInt32(value, 0) != 1 ||
            ReadUInt32(value, 4) != MovementEventSize || ReadUInt32(value, 8) != 1 ||
            ReadUInt32(value, 12) != 1 || IsZero(value.Slice(16, 16)) ||
            IsZero(value.Slice(32, 16)) || IsZero(value.Slice(48, 16)) ||
            IsZero(value.Slice(64, 16)) || IsZero(value.Slice(80, 32)) ||
            IsZero(value.Slice(112, 32)) || ReadUInt64(value, 144) == 0 ||
            ReadUInt64(value, 152) == 0 || ReadUInt64(value, 160) == 0 ||
            (ReadUInt32(value, 204) & ~1u) != 0 || !IsZero(value.Slice(208, 48)))
        {
            throw Invalid("The authoritative movement event is malformed.");
        }
        long[] position = new long[3];
        int[] velocity = new int[3];
        for (int index = 0; index != 3; ++index)
        {
            position[index] = ReadInt64(value, 168 + index * 8);
            velocity[index] = ReadInt32(value, 192 + index * 4);
        }
        return new(
            value.ToArray(),
            value.Slice(16, 16).ToArray(),
            value.Slice(32, 16).ToArray(),
            value.Slice(48, 16).ToArray(),
            value.Slice(16, 128).ToArray(),
            ReadUInt64(value, 144),
            ReadUInt64(value, 152),
            ReadUInt64(value, 160),
            position,
            velocity,
            ReadUInt32(value, 204));
    }

    internal static void ValidateEvidenceItem(ReadOnlySpan<byte> item, ulong sequence)
    {
        ReadOnlySpan<byte> record = item[..560];
        uint ruleId = ReadUInt32(record, 8);
        uint group = ruleId & 0xFFFF0000u;
        uint code = ruleId & 0xFFFFu;
        uint eventType = ReadUInt32(record, 12);
        uint policySeverity = ReadUInt32(record, 20);
        ulong timestamp = ReadUInt64(record, 72);
        ulong ingestion = ReadUInt64(record, 88);
        ulong serviceSequence = ReadUInt64(record, 96);
        ulong firstOccurrence = ReadUInt64(record, 112);
        ulong lastOccurrence = ReadUInt64(record, 120);
        if (ReadUInt32(record, 0) != ProductionProtocol ||
            ReadUInt32(record, 4) != 560 || code == 0 ||
            group is < 0x00010000 or > 0x000B0000 || eventType is < 1 or > 9 ||
            ReadUInt32(record, 16) > 4 || policySeverity > 5 ||
            ReadUInt32(record, 24) > 3 || ReadUInt32(record, 28) > 13 ||
            ReadUInt32(record, 36) != 0 || IsZero(record.Slice(40, 16)) ||
            ReadUInt64(record, 56) == 0 || ReadUInt64(record, 64) == 0 ||
            timestamp == 0 || serviceSequence != sequence || ingestion < timestamp ||
            ReadUInt64(record, 104) == 0 || firstOccurrence == 0 ||
            lastOccurrence == 0 || firstOccurrence > timestamp || timestamp > lastOccurrence ||
            (ReadUInt64(record, 160) & ~0xFFUL) != 0 || ReadUInt32(record, 172) != 0 ||
            (eventType == 2 && policySeverity == 0) || !PayloadValid(record))
        {
            throw Invalid("An evidence item is malformed.");
        }
        ReadOnlySpan<byte> decision = item.Slice(560, 16);
        uint source = ReadUInt32(item, 576);
        if (ReadUInt32(decision, 0) != ruleId || ReadUInt32(decision, 4) > 6 ||
            ReadUInt32(decision, 8) > 4 || ReadUInt32(decision, 12) != policySeverity ||
            source is < 1 or > 3 || ReadUInt32(item, 580) != 0)
        {
            throw Invalid("An evidence policy decision is malformed.");
        }
    }

    internal static DetectorResult ParseDetectorResult(
        ReadOnlySpan<byte> value,
        MovementEvent movement,
        uint endpointRisk)
    {
        if (value.Length != DetectorResultSize || ReadUInt32(value, 0) != 1 ||
            ReadUInt32(value, 4) != DetectorResultSize || ReadUInt32(value, 8) > 5 ||
            ReadUInt32(value, 12) > 10 || ReadUInt64(value, 16) != movement.Sequence ||
            ReadUInt64(value, 24) != movement.ServerTick ||
            ReadUInt32(value, 32) != endpointRisk ||
            ReadUInt32(value, 36) > 1000 || ReadUInt32(value, 40) > 1000 ||
            ReadUInt32(value, 44) > 1000 || (ReadUInt32(value, 48) & ~0xFu) != 0 ||
            ReadUInt32(value, 52) != 0)
        {
            throw Invalid("A durable game detector result is malformed.");
        }
        ulong[] observed = new ulong[3];
        for (int index = 0; index != observed.Length; ++index)
            observed[index] = ReadUInt64(value, 72 + index * 8);
        return new DetectorResult(
            ReadUInt32(value, 8), ReadUInt32(value, 12),
            ReadUInt64(value, 16), ReadUInt64(value, 24),
            ReadUInt32(value, 32), ReadUInt32(value, 36),
            ReadUInt32(value, 40), ReadUInt32(value, 44),
            ReadUInt32(value, 48), ReadUInt64(value, 56),
            ReadUInt64(value, 64), observed);
    }

    private static bool PayloadValid(ReadOnlySpan<byte> record)
    {
        uint type = ReadUInt32(record, 32);
        uint length = ReadUInt32(record, 168);
        if (type > 2 || length > 384) return false;
        if ((type == 0 && length != 0) || (type == 1 && length == 0) ||
            (type == 2 && (length < 2 || (length & 1) != 0))) return false;
        ReadOnlySpan<byte> payload = record.Slice(176, 384);
        if (type == 2)
        {
            if (payload[(int)length - 1] != 0 || payload[(int)length - 2] != 0)
                return false;
            try
            {
                _ = new UnicodeEncoding(false, false, true).GetString(
                    payload[..checked((int)length - 2)]);
            }
            catch (DecoderFallbackException)
            {
                return false;
            }
            for (int index = 0; index + 2 < length; index += 2)
            {
                if (payload[index] == 0 && payload[index + 1] == 0) return false;
            }
        }
        return IsZero(payload[checked((int)length)..]);
    }

    private static byte[] Response(
        int size,
        uint type,
        RequestHeader request,
        byte[]? sessionId)
    {
        byte[] response = new byte[size];
        WriteUInt32(response, 0, Revision);
        WriteUInt32(response, 4, checked((uint)size));
        WriteUInt32(response, 8, type);
        WriteUInt64(response, 16, request.RequestSequence);
        if (sessionId is not null)
            sessionId.CopyTo(response, 32);
        SHA256.HashData(request.Nonce, response.AsSpan(48, 32));
        return response;
    }

    private static bool BackendPolicyValid(uint lease, uint grace, uint renewal, uint ack) =>
        lease is >= 1000 and <= 60_000 && grace <= 60_000 &&
        renewal != 0 && renewal < lease && ack is >= 1000 and <= 60_000;

    private static byte[] Identity(
        ReadOnlySpan<byte> value,
        int offset,
        int size,
        string name)
    {
        byte[] identity = value.Slice(offset, size).ToArray();
        if (IsZero(identity)) throw Invalid($"The {name} identity is required.");
        return identity;
    }

    internal static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    internal static bool IsZero(ReadOnlySpan<byte> value)
    {
        byte combined = 0;
        foreach (byte item in value) combined |= item;
        return combined == 0;
    }

    internal static uint ReadUInt32(ReadOnlySpan<byte> value, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(value.Slice(offset, 4));
    internal static ulong ReadUInt64(ReadOnlySpan<byte> value, int offset) =>
        BinaryPrimitives.ReadUInt64LittleEndian(value.Slice(offset, 8));
    internal static int ReadInt32(ReadOnlySpan<byte> value, int offset) =>
        BinaryPrimitives.ReadInt32LittleEndian(value.Slice(offset, 4));
    internal static long ReadInt64(ReadOnlySpan<byte> value, int offset) =>
        BinaryPrimitives.ReadInt64LittleEndian(value.Slice(offset, 8));
    internal static void WriteUInt32(Span<byte> value, int offset, uint item) =>
        BinaryPrimitives.WriteUInt32LittleEndian(value.Slice(offset, 4), item);
    internal static void WriteUInt64(Span<byte> value, int offset, ulong item) =>
        BinaryPrimitives.WriteUInt64LittleEndian(value.Slice(offset, 8), item);

    private static BackendRequestException Invalid(string message) => new(400, message);
}
