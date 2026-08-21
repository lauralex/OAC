using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;

namespace Oac.Backend;

internal sealed record SessionState
{
    public byte[] SessionId { get; init; } = [];
    public byte[] ClientCertificateSha256 { get; init; } = [];
    public byte[] GameId { get; init; } = [];
    public byte[] BuildId { get; init; } = [];
    public byte[] PolicyId { get; init; } = [];
    public byte[] PolicySha256 { get; init; } = [];
    public byte[] BindingSha256 { get; init; } = [];
    public ulong LastEndpointRequestSequence { get; init; }
    public ulong LastGameRequestSequence { get; init; }
    public ulong LeaseSequence { get; init; }
    public ulong AcknowledgedSequence { get; init; }
    public long LeaseExpiresAtUnixMilliseconds { get; init; }
    public uint LeaseMilliseconds { get; init; }
    public uint GraceMilliseconds { get; init; }
    public uint RenewalMilliseconds { get; init; }
    public uint AcknowledgementMilliseconds { get; init; }
    public bool Revoked { get; init; }
}

internal sealed record StoreState
{
    public ulong Generation { get; init; }
    public ulong DurableSequence { get; init; }
    public List<string> ReplayNonceSha256 { get; init; } = [];
    public Dictionary<string, SessionState> Sessions { get; init; } =
        new(StringComparer.Ordinal);
    public Dictionary<string, GameDetectorState> GameStates { get; init; } =
        new(StringComparer.Ordinal);
    public List<RetiredSessionState> RetiredSessions { get; init; } = [];
}

internal sealed record RetiredSessionState
{
    public string SessionId { get; init; } = string.Empty;
    public long RetiredAtUnixMilliseconds { get; init; }
    public ulong AcknowledgedSequence { get; init; }
    public long EvidenceBytes { get; init; }
    public string EvidenceSha256 { get; init; } = string.Empty;
    public long GameBytes { get; init; }
    public string GameSha256 { get; init; } = string.Empty;
}

internal sealed class AdmissionStore : IDisposable
{
    private const int SessionCapacity = 64;
    private const int RetiredSessionCapacity = 1024;
    private const int GameStateCapacity = 128;
    private const int ReplayCapacity = 64;
    private const int MaximumLogRecords = 65_536;
    private const int SnapshotHeaderSize = 56;
    private const int EvidenceFrameSize = 712;
    private const int GameFrameSize = 736;
    private static readonly byte[] SnapshotMagic = "OACSTATE"u8.ToArray();
    private static readonly byte[] EvidenceMagic = "OACEVIDE"u8.ToArray();
    private static readonly byte[] GameMagic = "OACGAMEE"u8.ToArray();
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private readonly object sync_ = new();
    private readonly string root_;
    private readonly PolicyBundle policy_;
    private readonly MovementRules movementRules_;
    private readonly Func<DateTimeOffset> clock_;
    private FileStream? lockFile_;
    private StoreState state_ = new();
    private bool faulted_;

    public AdmissionStore(
        string root,
        PolicyBundle policy,
        MovementRules movementRules,
        Func<DateTimeOffset>? clock = null)
    {
        root_ = root;
        policy_ = policy;
        movementRules_ = movementRules;
        clock_ = clock ?? (() => DateTimeOffset.UtcNow);
        if (!WireProtocol.FixedEquals(policy.GameId, movementRules.GameIdBytes) ||
            !WireProtocol.FixedEquals(policy.BuildId, movementRules.BuildIdBytes))
        {
            throw new InvalidDataException("The movement rules do not match the signed policy scope.");
        }
        Directory.CreateDirectory(root_);
        FileAttributes attributes = File.GetAttributes(root_);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("The backend data directory cannot be a reparse point.");
        lockFile_ = new FileStream(Path.Combine(root_, "store.lock"),
            FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1,
            FileOptions.WriteThrough);
        state_ = LoadState();
        CleanupRetiredLogs(state_.RetiredSessions);
        bool recovered = RecoverLogs();
        if (recovered) Persist(state_ with { });
    }

    public byte[] FetchPolicy(PolicyRequest request)
    {
        lock (sync_)
        {
            EnsureReady();
            if (!WireProtocol.FixedEquals(request.GameId, policy_.GameId) ||
                !WireProtocol.FixedEquals(request.BuildId, policy_.BuildId) ||
                !WireProtocol.FixedEquals(request.ChannelId, policy_.ChannelId) ||
                request.CurrentPolicyVersion > policy_.PolicyVersion ||
                (request.CurrentPolicyVersion == policy_.PolicyVersion &&
                 !WireProtocol.FixedEquals(request.CurrentPolicySha256, policy_.Digest)))
            {
                throw new BackendRequestException(403, "The requested policy scope is not authorized.");
            }
            StoreState next = AcceptNonce(state_, request.Header.Nonce);
            Persist(next);
            return WireProtocol.PolicyResponse(request, policy_);
        }
    }

    public byte[] OpenSession(OpenRequest request, byte[] clientCertificateSha256)
    {
        lock (sync_)
        {
            EnsureReady();
            if (!WireProtocol.FixedEquals(request.GameId, policy_.GameId) ||
                !WireProtocol.FixedEquals(request.BuildId, policy_.BuildId) ||
                !WireProtocol.FixedEquals(request.PolicyId, policy_.PolicyId) ||
                !WireProtocol.FixedEquals(request.PolicySha256, policy_.Digest) ||
                request.RenewalMilliseconds != policy_.RenewalMilliseconds ||
                request.EvidenceAcknowledgementMilliseconds !=
                    policy_.EvidenceAcknowledgementMilliseconds)
            {
                throw new BackendRequestException(403, "The endpoint policy is not current.");
            }
            StoreState next = AcceptNonce(state_, request.Header.Nonce);
            Dictionary<string, SessionState> sessions = CopySessions(next);
            Dictionary<string, GameDetectorState> games = CopyGames(next);
            List<RetiredSessionState> retired = [.. next.RetiredSessions];
            List<RetiredSessionState> retiredNow = [];
            long now = clock_().ToUnixTimeMilliseconds();
            foreach ((string key, SessionState existing) in sessions.ToArray())
            {
                if (!WireProtocol.FixedEquals(
                        existing.ClientCertificateSha256,
                        clientCertificateSha256) ||
                    !WireProtocol.FixedEquals(existing.GameId, request.GameId) ||
                    !WireProtocol.FixedEquals(existing.BuildId, request.BuildId))
                {
                    continue;
                }
                if (existing.Revoked)
                    throw new BackendRequestException(
                        403, "The endpoint credential is revoked for this scope.");
                if (Admitted(existing, now))
                    throw new BackendRequestException(
                        409, "An admitted endpoint session is already active.");
                RetireSession(
                    key, existing, sessions, games, retired, retiredNow, now);
            }
            if (sessions.Count >= SessionCapacity)
            {
                string? reusable = sessions.FirstOrDefault(pair =>
                    !pair.Value.Revoked && !Alive(pair.Value, now)).Key;
                if (reusable is null)
                    throw new BackendRequestException(503, "The session capacity is exhausted.");
                RetireSession(
                    reusable,
                    sessions[reusable],
                    sessions,
                    games,
                    retired,
                    retiredNow,
                    now);
            }
            byte[] sessionId = RandomNumberGenerator.GetBytes(16);
            byte[] serverNonce = RandomNumberGenerator.GetBytes(32);
            string sessionKey = Convert.ToHexString(sessionId);
            while (sessions.ContainsKey(sessionKey))
            {
                sessionId = RandomNumberGenerator.GetBytes(16);
                sessionKey = Convert.ToHexString(sessionId);
            }
            uint lease = Math.Min(request.MaximumLeaseMilliseconds,
                policy_.LeaseMilliseconds);
            uint grace = Math.Min(request.MaximumGraceMilliseconds,
                policy_.GraceMilliseconds);
            byte[] binding = WireProtocol.BindingDigest(
                sessionId, request.Header.Nonce, serverNonce);
            SessionState session = new()
            {
                SessionId = sessionId,
                ClientCertificateSha256 = (byte[])clientCertificateSha256.Clone(),
                GameId = (byte[])request.GameId.Clone(),
                BuildId = (byte[])request.BuildId.Clone(),
                PolicyId = (byte[])request.PolicyId.Clone(),
                PolicySha256 = (byte[])request.PolicySha256.Clone(),
                BindingSha256 = binding,
                LastEndpointRequestSequence = request.Header.RequestSequence,
                LeaseSequence = 1,
                LeaseExpiresAtUnixMilliseconds = checked(now + lease),
                LeaseMilliseconds = lease,
                GraceMilliseconds = grace,
                RenewalMilliseconds = policy_.RenewalMilliseconds,
                AcknowledgementMilliseconds = policy_.EvidenceAcknowledgementMilliseconds
            };
            sessions.Add(sessionKey, session);
            next = next with
            {
                Sessions = sessions,
                GameStates = games,
                RetiredSessions = retired
            };
            Persist(next);
            CleanupRetiredLogs(retiredNow);
            return WireProtocol.OpenResponse(request, sessionId, serverNonce,
                1, lease, grace, policy_.RenewalMilliseconds, 0);
        }
    }

    public byte[] RenewSession(RenewalRequest request, byte[] clientCertificateSha256)
    {
        lock (sync_)
        {
            EnsureReady();
            string key = Convert.ToHexString(request.Header.SessionId);
            if (!state_.Sessions.TryGetValue(key, out SessionState? current))
                throw new BackendRequestException(404, "The backend session does not exist.");
            if (!WireProtocol.FixedEquals(
                    current.ClientCertificateSha256, clientCertificateSha256) ||
                request.Header.RequestSequence <= current.LastEndpointRequestSequence ||
                request.CurrentLeaseSequence != current.LeaseSequence)
            {
                throw new BackendRequestException(403, "The lease renewal is not authorized.");
            }
            long now = clock_().ToUnixTimeMilliseconds();
            bool revoked = current.Revoked ||
                !WireProtocol.FixedEquals(current.PolicySha256, policy_.Digest);
            if (!revoked && !Alive(current, now))
                throw new BackendRequestException(410, "The backend lease has expired.");
            StoreState next = AcceptNonce(state_, request.Header.Nonce);
            Dictionary<string, SessionState> sessions = CopySessions(next);
            ulong leaseSequence = checked(current.LeaseSequence + 1);
            SessionState renewed = current with
            {
                LastEndpointRequestSequence = request.Header.RequestSequence,
                LeaseSequence = leaseSequence,
                LeaseExpiresAtUnixMilliseconds = revoked
                    ? current.LeaseExpiresAtUnixMilliseconds
                    : checked(now + current.LeaseMilliseconds),
                Revoked = revoked
            };
            sessions[key] = renewed;
            Persist(next with { Sessions = sessions });
            return WireProtocol.RenewalResponse(request, leaseSequence,
                current.LeaseMilliseconds, current.GraceMilliseconds,
                current.RenewalMilliseconds, revoked);
        }
    }

    public byte[] UploadEvidence(EvidenceRequest request, byte[] clientCertificateSha256)
    {
        lock (sync_)
        {
            EnsureReady();
            string key = Convert.ToHexString(request.Header.SessionId);
            if (!state_.Sessions.TryGetValue(key, out SessionState? current))
                throw new BackendRequestException(404, "The backend session does not exist.");
            long now = clock_().ToUnixTimeMilliseconds();
            if (!WireProtocol.FixedEquals(
                    current.ClientCertificateSha256, clientCertificateSha256) ||
                !WireProtocol.FixedEquals(current.BindingSha256, request.BindingSha256) ||
                request.Header.RequestSequence <= current.LastEndpointRequestSequence)
            {
                throw new BackendRequestException(403, "The evidence upload is not authorized.");
            }
            if (!Alive(current, now))
                throw new BackendRequestException(410, "The backend lease is not active.");
            StoreState next = AcceptNonce(state_, request.Header.Nonce);
            Dictionary<string, SessionState> sessions = CopySessions(next);
            SessionState updated = current with
            {
                LastEndpointRequestSequence = request.Header.RequestSequence
            };
            if (request.LastServiceSequence > current.AcknowledgedSequence)
            {
                if (request.FirstServiceSequence <= current.AcknowledgedSequence ||
                    request.FirstServiceSequence != current.AcknowledgedSequence + 1)
                {
                    throw new BackendRequestException(409, "The evidence batch overlaps durable state.");
                }
                ulong durable = AppendEvidence(
                    current, request, next.DurableSequence);
                updated = updated with
                {
                    AcknowledgedSequence = request.LastServiceSequence
                };
                next = next with { DurableSequence = durable };
            }
            sessions[key] = updated;
            Persist(next with { Sessions = sessions });
            return WireProtocol.EvidenceResponse(request, updated.AcknowledgedSequence);
        }
    }

    public byte[] SubmitGameEvent(GameRequest request)
    {
        lock (sync_)
        {
            EnsureReady();
            string sessionKey = Convert.ToHexString(request.Header.SessionId);
            if (!state_.Sessions.TryGetValue(sessionKey, out SessionState? current))
                throw new BackendRequestException(404, "The endpoint session does not exist.");
            if (!Admitted(current, clock_().ToUnixTimeMilliseconds()) ||
                request.Header.RequestSequence <= current.LastGameRequestSequence ||
                !WireProtocol.FixedEquals(request.Event.GameId, current.GameId) ||
                !WireProtocol.FixedEquals(request.Event.BuildId, current.BuildId))
            {
                throw new BackendRequestException(403, "The game event is not authorized.");
            }
            StoreState next = AcceptNonce(state_, request.Header.Nonce);
            string scopeKey = Convert.ToHexString(request.Event.Scope);
            next.GameStates.TryGetValue(scopeKey, out GameDetectorState? detector);
            if (detector is null && request.Event.Sequence != 1)
                throw new BackendRequestException(409, "The first event sequence must be one.");
            (GameDetectorState newState, DetectorResult result) =
                GameDetector.Evaluate(movementRules_, request.Event,
                    request.EndpointRisk, detector);
            if (result.Decision == 4)
                throw new BackendRequestException(409, "The game event is a replay.");
            if (detector is null && next.GameStates.Count >= GameStateCapacity)
                throw new BackendRequestException(503, "The game-state capacity is exhausted.");
            ulong durableSequence = checked(next.DurableSequence + 1);
            AppendGame(current, request, newState, result, durableSequence);
            Dictionary<string, GameDetectorState> games = CopyGames(next);
            games[scopeKey] = newState;
            Dictionary<string, SessionState> sessions = CopySessions(next);
            sessions[sessionKey] = current with
            {
                LastGameRequestSequence = request.Header.RequestSequence
            };
            Persist(next with
            {
                DurableSequence = durableSequence,
                GameStates = games,
                Sessions = sessions
            });
            return WireProtocol.GameResponse(request, result, durableSequence);
        }
    }

    public void Revoke(ReadOnlySpan<byte> sessionId)
    {
        lock (sync_)
        {
            EnsureReady();
            if (sessionId.Length != 16 || WireProtocol.IsZero(sessionId))
                throw new ArgumentException("A nonzero session identifier is required.", nameof(sessionId));
            string key = Convert.ToHexString(sessionId);
            if (!state_.Sessions.TryGetValue(key, out SessionState? current))
                throw new KeyNotFoundException("The backend session does not exist.");
            if (current.Revoked) return;
            Dictionary<string, SessionState> sessions = CopySessions(state_);
            sessions[key] = current with { Revoked = true };
            Persist(state_ with { Sessions = sessions });
        }
    }

    public void Dispose()
    {
        lock (sync_)
        {
            lockFile_?.Dispose();
            lockFile_ = null;
            faulted_ = true;
        }
    }

    private StoreState AcceptNonce(StoreState source, byte[] nonce)
    {
        string digest = Convert.ToHexString(SHA256.HashData(nonce));
        if (source.ReplayNonceSha256.Contains(digest, StringComparer.Ordinal))
            throw new BackendRequestException(409, "The request nonce was replayed.");
        List<string> nonces = [.. source.ReplayNonceSha256, digest];
        if (nonces.Count > ReplayCapacity) nonces.RemoveAt(0);
        return source with { ReplayNonceSha256 = nonces };
    }

    private ulong AppendEvidence(
        SessionState session,
        EvidenceRequest request,
        ulong currentDurableSequence)
    {
        string path = EvidencePath(session.SessionId);
        using FileStream stream = OpenAppendLog(path, EvidenceFrameSize, MaximumLogRecords);
        ulong durable = currentDurableSequence;
        foreach (byte[] item in request.Items)
        {
            durable = checked(durable + 1);
            byte[] frame = new byte[EvidenceFrameSize];
            EvidenceMagic.CopyTo(frame, 0);
            WireProtocol.WriteUInt32(frame, 8, 1);
            WireProtocol.WriteUInt32(frame, 12, EvidenceFrameSize);
            WireProtocol.WriteUInt64(frame, 16, durable);
            WireProtocol.WriteUInt64(frame, 24, request.Header.RequestSequence);
            WireProtocol.WriteUInt64(frame, 32, WireProtocol.ReadUInt64(item, 96));
            WireProtocol.WriteUInt64(frame, 40, request.FirstServiceSequence);
            WireProtocol.WriteUInt64(frame, 48, request.LastServiceSequence);
            WireProtocol.WriteUInt32(frame, 56,
                checked((uint)(WireProtocol.ReadUInt64(item, 96) -
                    request.FirstServiceSequence)));
            WireProtocol.WriteUInt32(frame, 60, checked((uint)request.Items.Count));
            SHA256.HashData(request.Header.Nonce, frame.AsSpan(64, 32));
            item.CopyTo(frame, 96);
            SHA256.HashData(frame.AsSpan(0, EvidenceFrameSize - 32),
                frame.AsSpan(EvidenceFrameSize - 32, 32));
            stream.Write(frame);
        }
        stream.Flush(flushToDisk: true);
        return durable;
    }

    private void AppendGame(
        SessionState session,
        GameRequest request,
        GameDetectorState state,
        DetectorResult result,
        ulong durableSequence)
    {
        using FileStream stream = OpenAppendLog(
            GamePath(session.SessionId), GameFrameSize, MaximumLogRecords);
        byte[] frame = new byte[GameFrameSize];
        GameMagic.CopyTo(frame, 0);
        WireProtocol.WriteUInt32(frame, 8, 1);
        WireProtocol.WriteUInt32(frame, 12, GameFrameSize);
        WireProtocol.WriteUInt64(frame, 16, durableSequence);
        WireProtocol.WriteUInt64(frame, 24, request.Header.RequestSequence);
        request.Raw.CopyTo(frame, 32);
        state.ToWire().CopyTo(frame, 384);
        result.ToWire().CopyTo(frame, 608);
        SHA256.HashData(frame.AsSpan(0, GameFrameSize - 32),
            frame.AsSpan(GameFrameSize - 32, 32));
        stream.Write(frame);
        stream.Flush(flushToDisk: true);
    }

    private FileStream OpenAppendLog(string path, int frameSize, int capacity)
    {
        RejectReparsePointIfPresent(path);
        FileStream stream = new(path, FileMode.OpenOrCreate, FileAccess.ReadWrite,
            FileShare.Read, 4096, FileOptions.WriteThrough);
        if (stream.Length % frameSize != 0 || stream.Length / frameSize >= capacity)
        {
            stream.Dispose();
            throw new BackendRequestException(507, "A durable backend log is full or malformed.");
        }
        stream.Seek(0, SeekOrigin.End);
        return stream;
    }

    private bool RecoverLogs()
    {
        bool changed = false;
        HashSet<ulong> durableSequences = [];
        foreach ((string key, SessionState original) in state_.Sessions.ToArray())
        {
            SessionState session = original;
            changed |= RecoverEvidence(ref session, durableSequences);
            changed |= RecoverGame(ref session, durableSequences);
            if (!ReferenceEquals(session, original)) state_.Sessions[key] = session;
        }
        return changed;
    }

    private bool RecoverEvidence(
        ref SessionState session,
        HashSet<ulong> durableSequences)
    {
        string path = EvidencePath(session.SessionId);
        if (!File.Exists(path))
        {
            if (session.AcknowledgedSequence != 0)
                throw new InvalidDataException("Durable evidence acknowledgement has no log.");
            return false;
        }
        bool changed = false;
        using FileStream stream = OpenRecoveryLog(path, EvidenceFrameSize);
        ulong lastServiceSequence = 0;
        long batchOffset = -1;
        ulong batchFirst = 0;
        ulong batchLast = 0;
        ulong batchRequestSequence = 0;
        uint batchCount = 0;
        uint nextIndex = 0;
        byte[] batchNonceDigest = new byte[32];
        List<ulong> batchDurableSequences = [];
        byte[] frame = new byte[EvidenceFrameSize];
        while (stream.Position < stream.Length)
        {
            long frameOffset = stream.Position;
            stream.ReadExactly(frame);
            ValidateFrame(frame, EvidenceMagic, EvidenceFrameSize);
            ulong durable = WireProtocol.ReadUInt64(frame, 16);
            ulong requestSequence = WireProtocol.ReadUInt64(frame, 24);
            ulong service = WireProtocol.ReadUInt64(frame, 32);
            ulong first = WireProtocol.ReadUInt64(frame, 40);
            ulong last = WireProtocol.ReadUInt64(frame, 48);
            uint index = WireProtocol.ReadUInt32(frame, 56);
            uint count = WireProtocol.ReadUInt32(frame, 60);
            ReadOnlySpan<byte> nonceDigest = frame.AsSpan(64, 32);
            if (durable == 0 || requestSequence == 0 ||
                service != lastServiceSequence + 1 || first == 0 ||
                count is 0 or > 16 || first > ulong.MaxValue - (count - 1) ||
                last != first + count - 1 || index >= count ||
                service != first + index || WireProtocol.IsZero(nonceDigest))
            {
                throw new InvalidDataException("The durable evidence sequence is invalid.");
            }
            WireProtocol.ValidateEvidenceItem(
                frame.AsSpan(96, WireProtocol.EvidenceItemSize), service);

            if (index == 0)
            {
                if (nextIndex != 0)
                    throw new InvalidDataException("A durable evidence batch is incomplete.");
                batchOffset = frameOffset;
                batchFirst = first;
                batchLast = last;
                batchRequestSequence = requestSequence;
                batchCount = count;
                nonceDigest.CopyTo(batchNonceDigest);
                batchDurableSequences.Clear();
            }
            if (index != nextIndex || first != batchFirst || last != batchLast ||
                requestSequence != batchRequestSequence || count != batchCount ||
                !WireProtocol.FixedEquals(nonceDigest, batchNonceDigest))
            {
                throw new InvalidDataException("A durable evidence batch is not correlated.");
            }
            batchDurableSequences.Add(durable);
            ++nextIndex;
            lastServiceSequence = service;
            if (nextIndex != batchCount) continue;

            foreach (ulong sequence in batchDurableSequences)
            {
                if (!durableSequences.Add(sequence))
                    throw new InvalidDataException("A durable backend sequence was reused.");
                if (sequence > state_.DurableSequence)
                {
                    state_ = state_ with { DurableSequence = sequence };
                    changed = true;
                }
            }
            if (batchRequestSequence > session.LastEndpointRequestSequence)
            {
                session = session with
                {
                    LastEndpointRequestSequence = batchRequestSequence
                };
                changed = true;
            }
            changed |= RecoverNonceDigest(batchNonceDigest);
            nextIndex = 0;
            batchOffset = -1;
        }
        if (nextIndex != 0)
        {
            stream.SetLength(batchOffset);
            stream.Flush(flushToDisk: true);
            lastServiceSequence = batchFirst - 1;
            changed = true;
        }
        if (lastServiceSequence < session.AcknowledgedSequence)
            throw new InvalidDataException("The durable evidence log regressed.");
        if (lastServiceSequence > session.AcknowledgedSequence)
        {
            session = session with { AcknowledgedSequence = lastServiceSequence };
            changed = true;
        }
        return changed;
    }

    private bool RecoverGame(
        ref SessionState session,
        HashSet<ulong> durableSequences)
    {
        string path = GamePath(session.SessionId);
        if (!File.Exists(path)) return false;
        bool changed = false;
        using FileStream stream = OpenRecoveryLog(path, GameFrameSize);
        byte[] frame = new byte[GameFrameSize];
        Dictionary<string, GameDetectorState> replayStates =
            new(StringComparer.Ordinal);
        while (stream.Position < stream.Length)
        {
            stream.ReadExactly(frame);
            ValidateFrame(frame, GameMagic, GameFrameSize);
            ulong durable = WireProtocol.ReadUInt64(frame, 16);
            ulong requestSequence = WireProtocol.ReadUInt64(frame, 24);
            ReadOnlySpan<byte> rawRequest = frame.AsSpan(32, WireProtocol.GameRequestSize);
            ulong issued = WireProtocol.ReadUInt64(rawRequest, 72);
            GameRequest request = WireProtocol.ParseGame(
                rawRequest, DateTimeOffset.FromUnixTimeSeconds(checked((long)issued)));
            if (!WireProtocol.FixedEquals(request.Header.SessionId, session.SessionId) ||
                request.Header.RequestSequence != requestSequence || durable == 0 ||
                !durableSequences.Add(durable))
            {
                throw new InvalidDataException("A durable game record is not correlated.");
            }
            GameDetectorState detector = GameDetectorState.FromWire(
                frame.AsSpan(384, 224));
            string scopeKey = Convert.ToHexString(detector.Scope);
            replayStates.TryGetValue(scopeKey, out GameDetectorState? previous);
            (GameDetectorState expectedState, DetectorResult expectedResult) =
                GameDetector.Evaluate(
                    movementRules_, request.Event, request.EndpointRisk, previous);
            DetectorResult storedResult = WireProtocol.ParseDetectorResult(
                frame.AsSpan(608, WireProtocol.DetectorResultSize),
                request.Event, request.EndpointRisk);
            if (!detector.ToWire().AsSpan().SequenceEqual(expectedState.ToWire()) ||
                !storedResult.ToWire().AsSpan().SequenceEqual(expectedResult.ToWire()))
            {
                throw new InvalidDataException("A durable game decision is inconsistent.");
            }
            replayStates[scopeKey] = detector;
            if (!state_.GameStates.TryGetValue(scopeKey, out GameDetectorState? current) ||
                current.LastSequence < detector.LastSequence)
            {
                state_.GameStates[scopeKey] = detector;
                changed = true;
            }
            if (requestSequence > session.LastGameRequestSequence)
            {
                session = session with { LastGameRequestSequence = requestSequence };
                changed = true;
            }
            changed |= RecoverNonceDigest(SHA256.HashData(request.Header.Nonce));
            if (durable > state_.DurableSequence)
            {
                state_ = state_ with { DurableSequence = durable };
                changed = true;
            }
        }
        return changed;
    }

    private bool RecoverNonceDigest(ReadOnlySpan<byte> digest)
    {
        string value = Convert.ToHexString(digest);
        if (state_.ReplayNonceSha256.Contains(value, StringComparer.Ordinal))
            return false;
        List<string> nonces = [.. state_.ReplayNonceSha256, value];
        if (nonces.Count > ReplayCapacity) nonces.RemoveAt(0);
        state_ = state_ with { ReplayNonceSha256 = nonces };
        return true;
    }

    private FileStream OpenRecoveryLog(string path, int frameSize)
    {
        RejectReparsePointIfPresent(path);
        FileStream stream = new(path, FileMode.Open, FileAccess.ReadWrite,
            FileShare.Read, 4096, FileOptions.SequentialScan);
        long complete = stream.Length - stream.Length % frameSize;
        if (complete / frameSize > MaximumLogRecords)
        {
            stream.Dispose();
            throw new InvalidDataException("A durable backend log exceeds its bound.");
        }
        if (complete != stream.Length)
        {
            stream.SetLength(complete);
            stream.Flush(flushToDisk: true);
        }
        stream.Position = 0;
        return stream;
    }

    private static void ValidateFrame(byte[] frame, byte[] magic, int size)
    {
        byte[] digest = SHA256.HashData(frame.AsSpan(0, size - 32));
        if (!frame.AsSpan(0, 8).SequenceEqual(magic) ||
            WireProtocol.ReadUInt32(frame, 8) != 1 ||
            WireProtocol.ReadUInt32(frame, 12) != size ||
            !CryptographicOperations.FixedTimeEquals(
                digest, frame.AsSpan(size - 32, 32)))
        {
            throw new InvalidDataException("A durable backend log frame is malformed.");
        }
    }

    private StoreState LoadState()
    {
        (StoreState? State, bool Present, bool Valid) first =
            ReadSnapshot(Path.Combine(root_, "state-a.bin"));
        (StoreState? State, bool Present, bool Valid) second =
            ReadSnapshot(Path.Combine(root_, "state-b.bin"));
        StoreState? selected = first.Valid && second.Valid
            ? first.State!.Generation >= second.State!.Generation
                ? first.State : second.State
            : first.Valid ? first.State : second.Valid ? second.State : null;
        if (selected is null && (first.Present || second.Present))
            throw new InvalidDataException("No valid backend state snapshot remains.");
        if (selected is not null)
        {
            ValidateState(selected);
            return selected;
        }
        StoreState initial = new();
        Persist(initial);
        return state_;
    }

    private static (StoreState? State, bool Present, bool Valid) ReadSnapshot(string path)
    {
        if (!File.Exists(path)) return (null, false, false);
        try
        {
            RejectReparsePointIfPresent(path);
            byte[] bytes = File.ReadAllBytes(path);
            if (bytes.Length < SnapshotHeaderSize ||
                !bytes.AsSpan(0, 8).SequenceEqual(SnapshotMagic) ||
                WireProtocol.ReadUInt32(bytes, 8) != 1 ||
                WireProtocol.ReadUInt32(bytes, 12) != bytes.Length - SnapshotHeaderSize)
            {
                return (null, true, false);
            }
            byte[] digestInput = new byte[24 + bytes.Length - SnapshotHeaderSize];
            bytes.AsSpan(0, 24).CopyTo(digestInput);
            bytes.AsSpan(SnapshotHeaderSize).CopyTo(digestInput.AsSpan(24));
            if (!CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(digestInput), bytes.AsSpan(24, 32)))
            {
                return (null, true, false);
            }
            StoreState? state = JsonSerializer.Deserialize<StoreState>(
                bytes.AsSpan(SnapshotHeaderSize), JsonOptions);
            if (state is null || state.Generation != WireProtocol.ReadUInt64(bytes, 16))
                return (null, true, false);
            return (state, true, true);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or
            JsonException or InvalidDataException)
        {
            return (null, true, false);
        }
    }

    private void Persist(StoreState candidate)
    {
        try
        {
            ulong generation = checked(state_.Generation + 1);
            StoreState next = candidate with { Generation = generation };
            ValidateState(next);
            byte[] payload = JsonSerializer.SerializeToUtf8Bytes(next, JsonOptions);
            if (payload.Length > 2 * 1024 * 1024)
                throw new InvalidDataException("The backend state snapshot is too large.");
            byte[] bytes = new byte[SnapshotHeaderSize + payload.Length];
            SnapshotMagic.CopyTo(bytes, 0);
            WireProtocol.WriteUInt32(bytes, 8, 1);
            WireProtocol.WriteUInt32(bytes, 12, checked((uint)payload.Length));
            WireProtocol.WriteUInt64(bytes, 16, generation);
            payload.CopyTo(bytes, SnapshotHeaderSize);
            byte[] digestInput = new byte[24 + payload.Length];
            bytes.AsSpan(0, 24).CopyTo(digestInput);
            payload.CopyTo(digestInput, 24);
            SHA256.HashData(digestInput, bytes.AsSpan(24, 32));
            string target = Path.Combine(root_,
                (generation & 1) != 0 ? "state-a.bin" : "state-b.bin");
            string temporary = target + ".tmp";
            RejectReparsePointIfPresent(target);
            RejectReparsePointIfPresent(temporary);
            using (FileStream stream = new(temporary, FileMode.Create,
                FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, target, overwrite: true);
            state_ = next;
        }
        catch
        {
            faulted_ = true;
            throw;
        }
    }

    private static void ValidateState(StoreState state)
    {
        if (state.ReplayNonceSha256.Count > ReplayCapacity ||
            state.ReplayNonceSha256.Distinct(StringComparer.Ordinal).Count() !=
                state.ReplayNonceSha256.Count ||
            state.ReplayNonceSha256.Any(static value =>
                !IsSha256Hex(value)) ||
            state.Sessions.Count > SessionCapacity ||
            state.GameStates.Count > GameStateCapacity ||
            state.RetiredSessions.Count > RetiredSessionCapacity ||
            state.RetiredSessions.Select(static item => item.SessionId)
                .Distinct(StringComparer.Ordinal).Count() != state.RetiredSessions.Count)
        {
            throw new InvalidDataException("The backend state bounds are invalid.");
        }
        foreach ((string key, SessionState session) in state.Sessions)
        {
            if (key != Convert.ToHexString(session.SessionId) ||
                session.SessionId.Length != 16 ||
                session.ClientCertificateSha256.Length != 32 ||
                session.GameId.Length != 16 || session.BuildId.Length != 16 ||
                session.PolicyId.Length != 16 || session.PolicySha256.Length != 32 ||
                session.BindingSha256.Length != 32 ||
                session.LastEndpointRequestSequence == 0 ||
                session.LeaseSequence == 0 || session.LeaseExpiresAtUnixMilliseconds <= 0 ||
                session.LeaseMilliseconds is < 1000 or > 60_000 ||
                session.GraceMilliseconds > 60_000 ||
                session.RenewalMilliseconds == 0 ||
                session.RenewalMilliseconds >= session.LeaseMilliseconds ||
                session.AcknowledgementMilliseconds is < 1000 or > 60_000)
            {
                throw new InvalidDataException("A backend session state is malformed.");
            }
        }
        foreach ((string key, GameDetectorState game) in state.GameStates)
        {
            if (game.Scope.Length != 128 || key != Convert.ToHexString(game.Scope))
                throw new InvalidDataException("A backend game state is malformed.");
            _ = GameDetectorState.FromWire(game.ToWire());
        }
        foreach (RetiredSessionState retired in state.RetiredSessions)
        {
            if (!IsSessionHex(retired.SessionId) ||
                state.Sessions.ContainsKey(retired.SessionId) ||
                retired.RetiredAtUnixMilliseconds <= 0 ||
                (retired.AcknowledgedSequence == 0) != (retired.EvidenceBytes == 0) ||
                !LogReceiptValid(retired.EvidenceBytes, retired.EvidenceSha256) ||
                !LogReceiptValid(retired.GameBytes, retired.GameSha256))
            {
                throw new InvalidDataException("A retired backend session receipt is malformed.");
            }
        }
    }

    private static Dictionary<string, SessionState> CopySessions(StoreState state) =>
        new(state.Sessions, StringComparer.Ordinal);
    private static Dictionary<string, GameDetectorState> CopyGames(StoreState state) =>
        new(state.GameStates, StringComparer.Ordinal);

    private static bool Alive(SessionState session, long now)
    {
        if (session.Revoked || now <= 0) return false;
        long graceDeadline = session.LeaseExpiresAtUnixMilliseconds >
            long.MaxValue - session.GraceMilliseconds
            ? long.MaxValue
            : session.LeaseExpiresAtUnixMilliseconds + session.GraceMilliseconds;
        return now <= graceDeadline;
    }

    private bool Admitted(SessionState session, long now) =>
        Alive(session, now) &&
        WireProtocol.FixedEquals(session.PolicyId, policy_.PolicyId) &&
        WireProtocol.FixedEquals(session.PolicySha256, policy_.Digest);

    private static bool IsSha256Hex(string value)
    {
        if (value.Length != 64) return false;
        try
        {
            return Convert.FromHexString(value).Length == 32;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool IsSessionHex(string value)
    {
        if (value.Length != 32) return false;
        try
        {
            return !WireProtocol.IsZero(Convert.FromHexString(value));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool LogReceiptValid(long bytes, string digest) =>
        bytes >= 0 && (bytes == 0 ? digest.Length == 0 : IsSha256Hex(digest));

    private RetiredSessionState CreateRetiredSession(
        SessionState session,
        long now)
    {
        (long EvidenceBytes, string EvidenceSha256) evidence =
            LogReceipt(EvidencePath(session.SessionId));
        (long GameBytes, string GameSha256) game =
            LogReceipt(GamePath(session.SessionId));
        return new RetiredSessionState
        {
            SessionId = Convert.ToHexString(session.SessionId),
            RetiredAtUnixMilliseconds = now,
            AcknowledgedSequence = session.AcknowledgedSequence,
            EvidenceBytes = evidence.EvidenceBytes,
            EvidenceSha256 = evidence.EvidenceSha256,
            GameBytes = game.GameBytes,
            GameSha256 = game.GameSha256
        };
    }

    private void RetireSession(
        string sessionKey,
        SessionState session,
        Dictionary<string, SessionState> sessions,
        Dictionary<string, GameDetectorState> games,
        List<RetiredSessionState> retired,
        List<RetiredSessionState> retiredNow,
        long now)
    {
        if (retired.Count >= RetiredSessionCapacity)
            throw new BackendRequestException(507,
                "The retired-session receipt capacity is exhausted.");
        RetiredSessionState receipt = CreateRetiredSession(session, now);
        retired.Add(receipt);
        retiredNow.Add(receipt);
        sessions.Remove(sessionKey);
        foreach (string key in games.Where(pair =>
            Convert.ToHexString(pair.Value.Scope.AsSpan(32, 16)) == sessionKey)
            .Select(static pair => pair.Key).ToArray())
        {
            games.Remove(key);
        }
    }

    private static (long Bytes, string Sha256) LogReceipt(string path)
    {
        if (!File.Exists(path)) return (0, string.Empty);
        RejectReparsePointIfPresent(path);
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read,
            FileShare.Read, 4096, FileOptions.SequentialScan);
        if (stream.Length == 0) return (0, string.Empty);
        return (stream.Length, Convert.ToHexString(SHA256.HashData(stream)));
    }

    private void CleanupRetiredLogs(IEnumerable<RetiredSessionState> retired)
    {
        foreach (RetiredSessionState receipt in retired)
        {
            byte[] sessionId = Convert.FromHexString(receipt.SessionId);
            DeleteRetiredLog(
                EvidencePath(sessionId), receipt.EvidenceBytes, receipt.EvidenceSha256);
            DeleteRetiredLog(GamePath(sessionId), receipt.GameBytes, receipt.GameSha256);
        }
    }

    private static void DeleteRetiredLog(string path, long expectedBytes, string expectedSha256)
    {
        if (!File.Exists(path)) return;
        (long Bytes, string Sha256) observed = LogReceipt(path);
        if (observed.Bytes != expectedBytes ||
            !string.Equals(observed.Sha256, expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("A retired backend log changed before cleanup.");
        }
        File.Delete(path);
    }

    private string EvidencePath(byte[] sessionId) => Path.Combine(
        root_, $"evidence-{Convert.ToHexString(sessionId)}.bin");
    private string GamePath(byte[] sessionId) => Path.Combine(
        root_, $"game-{Convert.ToHexString(sessionId)}.bin");

    private static void RejectReparsePointIfPresent(string path)
    {
        if (File.Exists(path) &&
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"{path} cannot be a reparse point.");
        }
    }

    private void EnsureReady()
    {
        if (faulted_ || lockFile_ is null)
            throw new InvalidOperationException("The backend store is not writable.");
    }
}
