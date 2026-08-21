using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Oac.GameAdapter;

public sealed class GameServerClientOptions
{
    public required Uri BackendOrigin { get; init; }
    public required X509Certificate2 ClientCertificate { get; init; }
    public required IReadOnlyList<string> ServerCertificateSha256 { get; init; }
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);
}

public sealed record AuthoritativeMovement(
    ulong ServerTick,
    ulong ReplayOffset,
    long PositionXMillimeters,
    long PositionYMillimeters,
    long PositionZMillimeters,
    int VelocityXMillimetersPerSecond,
    int VelocityYMillimetersPerSecond,
    int VelocityZMillimetersPerSecond,
    bool TeleportAuthorized,
    uint EndpointRisk);

public sealed record GameDecision(
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
    ulong ObservedXDelta,
    ulong ObservedYDelta,
    ulong ObservedZDelta,
    ulong DurableSequence);

public sealed class GameAdmissionSession
{
    private readonly byte[] gameId_;
    private readonly byte[] buildId_;
    private readonly byte[] backendSessionId_;
    private readonly byte[] matchId_;
    private readonly byte[] playerPseudonym_;
    private readonly byte[] replaySha256_;

    public GameAdmissionSession(
        ReadOnlySpan<byte> gameId,
        ReadOnlySpan<byte> buildId,
        ReadOnlySpan<byte> backendSessionId,
        ReadOnlySpan<byte> matchId,
        ReadOnlySpan<byte> playerPseudonym,
        ReadOnlySpan<byte> replaySha256,
        ulong nextSequence = 1)
    {
        gameId_ = RequiredIdentity(gameId, 16, nameof(gameId));
        buildId_ = RequiredIdentity(buildId, 16, nameof(buildId));
        backendSessionId_ = RequiredIdentity(
            backendSessionId, 16, nameof(backendSessionId));
        matchId_ = RequiredIdentity(matchId, 16, nameof(matchId));
        playerPseudonym_ = RequiredIdentity(
            playerPseudonym, 32, nameof(playerPseudonym));
        replaySha256_ = RequiredIdentity(
            replaySha256, 32, nameof(replaySha256));
        if (nextSequence == 0)
            throw new ArgumentOutOfRangeException(nameof(nextSequence));
        NextSequence = nextSequence;
    }

    public ulong NextSequence { get; internal set; }
    public bool RequiresReadmission { get; internal set; }

    internal ReadOnlySpan<byte> GameId => gameId_;
    internal ReadOnlySpan<byte> BuildId => buildId_;
    internal ReadOnlySpan<byte> BackendSessionId => backendSessionId_;
    internal ReadOnlySpan<byte> MatchId => matchId_;
    internal ReadOnlySpan<byte> PlayerPseudonym => playerPseudonym_;
    internal ReadOnlySpan<byte> ReplaySha256 => replaySha256_;

    private static byte[] RequiredIdentity(
        ReadOnlySpan<byte> value,
        int size,
        string name)
    {
        if (value.Length != size || IsZero(value))
            throw new ArgumentException(
                $"{name} must be a nonzero {size}-byte identity.", name);
        return value.ToArray();
    }

    private static bool IsZero(ReadOnlySpan<byte> value)
    {
        byte combined = 0;
        foreach (byte item in value) combined |= item;
        return combined == 0;
    }
}

public sealed class GameServerClient : IDisposable
{
    private const string BinaryContentType = "application/octet-stream";
    private const uint BackendRevision = 0x00010002;
    private const uint GameMessage = 5;
    private const int RequestSize = 352;
    private const int ResponseSize = 184;
    private const int MovementSize = 256;
    private readonly HttpClient client_;
    private readonly Uri gameEndpoint_;
    private readonly SemaphoreSlim transaction_ = new(1, 1);
    private readonly bool ownsClient_;
    private bool disposed_;

    public GameServerClient(GameServerClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Uri origin = ValidateOrigin(options.BackendOrigin);
        ArgumentNullException.ThrowIfNull(options.ClientCertificate);
        if (!ClientCertificateValid(options.ClientCertificate))
            throw new ArgumentException(
                "The game-server client certificate is not a current, strong client-authentication identity.",
                nameof(options));
        IReadOnlyList<byte[]> serverPins = ParsePins(
            options.ServerCertificateSha256);
        if (options.Timeout <= TimeSpan.Zero ||
            options.Timeout > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(
                nameof(options), "The network timeout must be at most 30 seconds.");
        }

        HttpClientHandler handler = new()
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ClientCertificateOptions = ClientCertificateOption.Manual,
            ServerCertificateCustomValidationCallback =
                (_, certificate, _, errors) =>
                    errors == SslPolicyErrors.None &&
                    certificate is not null &&
                    PinsContain(serverPins,
                        certificate.GetCertHash(HashAlgorithmName.SHA256))
        };
        handler.ClientCertificates.Add(options.ClientCertificate);
        client_ = new HttpClient(handler) { Timeout = options.Timeout };
        gameEndpoint_ = new Uri(origin, "/game");
        ownsClient_ = true;
    }

    internal GameServerClient(Uri backendOrigin, HttpClient client)
    {
        gameEndpoint_ = new Uri(ValidateOrigin(backendOrigin), "/game");
        client_ = client ?? throw new ArgumentNullException(nameof(client));
    }

    public async Task<GameDecision> SubmitMovementAsync(
        GameAdmissionSession session,
        AuthoritativeMovement movement,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed_, this);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(movement);
        if (movement.ServerTick == 0 || movement.ReplayOffset == 0 ||
            movement.EndpointRisk > 1000)
        {
            throw new ArgumentOutOfRangeException(
                nameof(movement), "Movement correlation and risk must be canonical.");
        }

        await transaction_.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (session.RequiresReadmission)
                throw new InvalidOperationException(
                    "The game session requires fresh backend admission.");
            byte[] request = CreateRequest(session, movement);
            byte[] nonce = request.AsSpan(40, 32).ToArray();
            ulong sequence = session.NextSequence;
            using ByteArrayContent content = new(request);
            content.Headers.ContentType = new MediaTypeHeaderValue(BinaryContentType);
            using HttpRequestMessage message = new(HttpMethod.Post, gameEndpoint_)
            {
                Content = content,
                Version = HttpVersion.Version20,
                VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
            };
            try
            {
                using HttpResponseMessage response = await client_.SendAsync(
                    message,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken).ConfigureAwait(false);
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new HttpRequestException(
                        $"Backend game admission failed with HTTP {(int)response.StatusCode}.",
                        null,
                        response.StatusCode);
                if (response.Content.Headers.ContentType?.MediaType !=
                        BinaryContentType ||
                    response.Content.Headers.ContentLength != ResponseSize)
                {
                    throw new InvalidDataException(
                        "The backend game response metadata is invalid.");
                }
                byte[] body = await response.Content.ReadAsByteArrayAsync(
                    cancellationToken).ConfigureAwait(false);
                GameDecision decision = ParseResponse(
                    body, session.BackendSessionId, sequence,
                    movement.ServerTick, movement.EndpointRisk, nonce);
                if (sequence == ulong.MaxValue)
                    session.RequiresReadmission = true;
                else
                    session.NextSequence = sequence + 1;
                return decision;
            }
            catch
            {
                // A request may have reached durable storage even if its response
                // was lost. Reusing its sequence or nonce would be ambiguous.
                session.RequiresReadmission = true;
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(nonce);
                CryptographicOperations.ZeroMemory(request);
            }
        }
        finally
        {
            transaction_.Release();
        }
    }

    public void Dispose()
    {
        if (disposed_) return;
        disposed_ = true;
        transaction_.Dispose();
        if (ownsClient_) client_.Dispose();
    }

    private static byte[] CreateRequest(
        GameAdmissionSession session,
        AuthoritativeMovement movement)
    {
        byte[] request = new byte[RequestSize];
        WriteUInt32(request, 0, BackendRevision);
        WriteUInt32(request, 4, RequestSize);
        WriteUInt32(request, 8, GameMessage);
        WriteUInt64(request, 16, session.NextSequence);
        session.BackendSessionId.CopyTo(request.AsSpan(24, 16));
        RandomNumberGenerator.Fill(request.AsSpan(40, 32));
        ulong now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        WriteUInt64(request, 72, now);
        WriteUInt64(request, 80, checked(now + 60));

        Span<byte> record = request.AsSpan(88, MovementSize);
        WriteUInt32(record, 0, 1);
        WriteUInt32(record, 4, MovementSize);
        WriteUInt32(record, 8, 1);
        WriteUInt32(record, 12, 1);
        session.GameId.CopyTo(record.Slice(16, 16));
        session.BuildId.CopyTo(record.Slice(32, 16));
        session.BackendSessionId.CopyTo(record.Slice(48, 16));
        session.MatchId.CopyTo(record.Slice(64, 16));
        session.PlayerPseudonym.CopyTo(record.Slice(80, 32));
        session.ReplaySha256.CopyTo(record.Slice(112, 32));
        WriteUInt64(record, 144, session.NextSequence);
        WriteUInt64(record, 152, movement.ServerTick);
        WriteUInt64(record, 160, movement.ReplayOffset);
        WriteInt64(record, 168, movement.PositionXMillimeters);
        WriteInt64(record, 176, movement.PositionYMillimeters);
        WriteInt64(record, 184, movement.PositionZMillimeters);
        WriteInt32(record, 192, movement.VelocityXMillimetersPerSecond);
        WriteInt32(record, 196, movement.VelocityYMillimetersPerSecond);
        WriteInt32(record, 200, movement.VelocityZMillimetersPerSecond);
        WriteUInt32(record, 204, movement.TeleportAuthorized ? 1u : 0u);
        WriteUInt32(request, 344, movement.EndpointRisk);
        return request;
    }

    private static GameDecision ParseResponse(
        ReadOnlySpan<byte> response,
        ReadOnlySpan<byte> sessionId,
        ulong sequence,
        ulong serverTick,
        uint endpointRisk,
        ReadOnlySpan<byte> nonce)
    {
        Span<byte> nonceDigest = stackalloc byte[32];
        SHA256.HashData(nonce, nonceDigest);
        if (response.Length != ResponseSize ||
            ReadUInt32(response, 0) != BackendRevision ||
            ReadUInt32(response, 4) != ResponseSize ||
            ReadUInt32(response, 8) != GameMessage ||
            ReadUInt32(response, 12) != 0 ||
            ReadUInt64(response, 16) != sequence ||
            ReadUInt32(response, 24) != 0 ||
            ReadUInt32(response, 28) != 0 ||
            !FixedEquals(response.Slice(32, 16), sessionId) ||
            !FixedEquals(response.Slice(48, 32), nonceDigest) ||
            ReadUInt32(response, 80) != 1 ||
            ReadUInt32(response, 84) != 96 ||
            ReadUInt32(response, 88) > 5 ||
            ReadUInt32(response, 92) > 10 ||
            ReadUInt64(response, 96) != sequence ||
            ReadUInt64(response, 104) != serverTick ||
            ReadUInt32(response, 112) != endpointRisk ||
            ReadUInt32(response, 116) > 1000 ||
            ReadUInt32(response, 120) > 1000 ||
            ReadUInt32(response, 124) > 1000 ||
            (ReadUInt32(response, 128) & ~0xFu) != 0 ||
            ReadUInt32(response, 132) != 0 ||
            ReadUInt64(response, 176) == 0)
        {
            throw new InvalidDataException(
                "The backend game response is malformed or uncorrelated.");
        }
        return new GameDecision(
            ReadUInt32(response, 88),
            ReadUInt32(response, 92),
            ReadUInt64(response, 96),
            ReadUInt64(response, 104),
            ReadUInt32(response, 112),
            ReadUInt32(response, 116),
            ReadUInt32(response, 120),
            ReadUInt32(response, 124),
            ReadUInt32(response, 128),
            ReadUInt64(response, 136),
            ReadUInt64(response, 144),
            ReadUInt64(response, 152),
            ReadUInt64(response, 160),
            ReadUInt64(response, 168),
            ReadUInt64(response, 176));
    }

    private static Uri ValidateOrigin(Uri? origin)
    {
        ArgumentNullException.ThrowIfNull(origin);
        if (!origin.IsAbsoluteUri || origin.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(origin.UserInfo) ||
            origin.AbsolutePath != "/" || !string.IsNullOrEmpty(origin.Query) ||
            !string.IsNullOrEmpty(origin.Fragment))
        {
            throw new ArgumentException(
                "BackendOrigin must be an HTTPS origin without credentials or a path.",
                nameof(origin));
        }
        return origin;
    }

    private static IReadOnlyList<byte[]> ParsePins(IReadOnlyList<string>? values)
    {
        if (values is null || values.Count is < 1 or > 2)
            throw new ArgumentException(
                "Configure one server certificate pin and at most one rotation pin.",
                nameof(values));
        List<byte[]> pins = [];
        foreach (string value in values)
        {
            if (value.Length != 64)
                throw new ArgumentException("A server certificate pin is malformed.",
                    nameof(values));
            byte[] pin;
            try
            {
                pin = Convert.FromHexString(value);
            }
            catch (FormatException exception)
            {
                throw new ArgumentException(
                    "A server certificate pin is malformed.", nameof(values), exception);
            }
            if (pin.All(static item => item == 0) ||
                pins.Any(existing => FixedEquals(existing, pin)))
            {
                throw new ArgumentException(
                    "Server certificate pins must be nonzero and distinct.",
                    nameof(values));
            }
            pins.Add(pin);
        }
        return pins;
    }

    private static bool ClientCertificateValid(X509Certificate2 certificate)
    {
        DateTime now = DateTime.UtcNow;
        if (!certificate.HasPrivateKey || now < certificate.NotBefore.ToUniversalTime() ||
            now > certificate.NotAfter.ToUniversalTime())
        {
            return false;
        }
        bool endEntity = false;
        bool clientAuthentication = false;
        bool digitalSignature = false;
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension is X509BasicConstraintsExtension constraints)
            {
                if (constraints.CertificateAuthority) return false;
                endEntity = true;
            }
            else if (extension is X509EnhancedKeyUsageExtension usages)
            {
                clientAuthentication = usages.EnhancedKeyUsages
                    .Cast<Oid>()
                    .Any(static oid => oid.Value == "1.3.6.1.5.5.7.3.2");
            }
            else if (extension is X509KeyUsageExtension usage)
            {
                digitalSignature =
                    (usage.KeyUsages & X509KeyUsageFlags.DigitalSignature) != 0 &&
                    (usage.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0;
            }
        }
        using RSA? rsa = certificate.GetRSAPublicKey();
        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        return endEntity && clientAuthentication && digitalSignature &&
            ((rsa is not null && rsa.KeySize >= 3072) ||
             (ecdsa is not null && ecdsa.KeySize >= 256));
    }

    private static bool PinsContain(
        IReadOnlyList<byte[]> pins,
        ReadOnlySpan<byte> digest)
    {
        bool matched = false;
        foreach (byte[] pin in pins) matched |= FixedEquals(pin, digest);
        return matched;
    }

    private static bool FixedEquals(
        ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static uint ReadUInt32(ReadOnlySpan<byte> value, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(value.Slice(offset, 4));
    private static ulong ReadUInt64(ReadOnlySpan<byte> value, int offset) =>
        BinaryPrimitives.ReadUInt64LittleEndian(value.Slice(offset, 8));
    private static void WriteUInt32(Span<byte> value, int offset, uint item) =>
        BinaryPrimitives.WriteUInt32LittleEndian(value.Slice(offset, 4), item);
    private static void WriteUInt64(Span<byte> value, int offset, ulong item) =>
        BinaryPrimitives.WriteUInt64LittleEndian(value.Slice(offset, 8), item);
    private static void WriteInt32(Span<byte> value, int offset, int item) =>
        BinaryPrimitives.WriteInt32LittleEndian(value.Slice(offset, 4), item);
    private static void WriteInt64(Span<byte> value, int offset, long item) =>
        BinaryPrimitives.WriteInt64LittleEndian(value.Slice(offset, 8), item);
}
