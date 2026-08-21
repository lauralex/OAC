using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Oac.Backend;
using Oac.GameAdapter;

return await BackendTests.Run();

internal static class BackendTests
{
    private const string BinaryContentType = "application/octet-stream";
    private static int passed_;

    public static async Task<int> Run()
    {
        string root = Path.Combine(
            Path.GetTempPath(), "oac-backend-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using X509Certificate2 policySigner = Certificate(
                "OAC backend policy test", "1.3.6.1.5.5.7.3.3");
            using X509Certificate2 endpoint = Certificate(
                "OAC endpoint test", "1.3.6.1.5.5.7.3.2");
            using X509Certificate2 endpointRotation = Certificate(
                "OAC endpoint rotation test", "1.3.6.1.5.5.7.3.2");
            using X509Certificate2 gameServer = Certificate(
                "OAC game server test", "1.3.6.1.5.5.7.3.2");
            using X509Certificate2 untrustedClient = Certificate(
                "OAC untrusted client test", "1.3.6.1.5.5.7.3.2");
            using X509Certificate2 server = ServerCertificate();

            DateTimeOffset now = DateTimeOffset.UtcNow;
            Fixture fixture = Fixture.Create(policySigner, now);
            TestConfigurationBoundaries(endpoint, gameServer);
            TestPolicySignerAlgorithm(now);
            TestWireAndStore(Path.Combine(root, "store"), fixture, endpoint, now);
            TestExpiration(Path.Combine(root, "expiration"), policySigner, endpoint, now);
            await TestGameAdapterFailure(fixture);
            await TestMutualTls(Path.Combine(root, "http"), fixture, policySigner,
                endpoint, endpointRotation, gameServer, untrustedClient, server, now);

            Console.WriteLine($"SUMMARY passed={passed_} total={passed_}");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 1;
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static void TestConfigurationBoundaries(
        X509Certificate2 endpoint,
        X509Certificate2 gameServer)
    {
        BackendOptions options = new()
        {
            DataDirectory = "relative-data",
            PolicyPath = Path.GetFullPath("policy.dat"),
            PolicySignaturePath = Path.GetFullPath("policy.p7s"),
            MovementRulesPath = Path.GetFullPath("movement.json"),
            PolicySignerSha256 = Convert.ToHexString(
                SHA256.HashData(new byte[] { 1 })),
            EndpointClientCertificateSha256 =
                [endpoint.GetCertHashString(HashAlgorithmName.SHA256)],
            GameServerCertificateSha256 =
                [gameServer.GetCertHashString(HashAlgorithmName.SHA256)]
        };
        bool rejected = false;
        try
        {
            _ = options.Validate();
        }
        catch (InvalidOperationException)
        {
            rejected = true;
        }
        Check(rejected, "backend storage paths must be absolute");
    }

    private static void TestPolicySignerAlgorithm(DateTimeOffset now)
    {
        using X509Certificate2 signer = Certificate(
            "OAC weak policy signer test",
            "1.3.6.1.5.5.7.3.3",
            HashAlgorithmName.SHA384);
        bool rejected = false;
        try
        {
            _ = Fixture.Create(signer, now);
        }
        catch (InvalidDataException)
        {
            rejected = true;
        }
        Check(rejected, "policy signer certificates require SHA-256");
    }

    private static async Task TestGameAdapterFailure(Fixture fixture)
    {
        using HttpClient client = new(new StaticResponseHandler(
            HttpStatusCode.OK, new byte[WireProtocol.GameResponseSize]));
        using GameServerClient adapter = new(new Uri("https://backend.invalid"), client);
        GameAdmissionSession session = fixture.GameSession(
            fixture.Nonce(40).AsSpan(0, 16).ToArray());
        bool rejected = false;
        try
        {
            _ = await adapter.SubmitMovementAsync(
                session,
                new AuthoritativeMovement(
                    1, 1, 0, 0, 0, 0, 0, 0, false, 0));
        }
        catch (InvalidDataException)
        {
            rejected = true;
        }
        Check(rejected && session.RequiresReadmission && session.NextSequence == 1,
            "game adapter fails closed after an uncorrelated response");

        bool blocked = false;
        try
        {
            _ = await adapter.SubmitMovementAsync(
                session,
                new AuthoritativeMovement(
                    2, 2, 0, 0, 0, 0, 0, 0, false, 0));
        }
        catch (InvalidOperationException)
        {
            blocked = true;
        }
        Check(blocked,
            "game adapter requires fresh admission after an ambiguous transaction");
    }

    private static void TestWireAndStore(
        string root,
        Fixture fixture,
        X509Certificate2 endpoint,
        DateTimeOffset initialNow)
    {
        DateTimeOffset now = initialNow;
        Func<DateTimeOffset> clock = () => now;
        byte[] certificateDigest = endpoint.GetCertHash(HashAlgorithmName.SHA256);
        byte[] policyRequestBytes = fixture.PolicyRequest(1, fixture.Nonce(1), now);
        PolicyRequest policyRequest = WireProtocol.ParsePolicy(policyRequestBytes, now);
        byte[] openBytes = fixture.OpenRequest(1, fixture.Nonce(2), now);
        OpenRequest openRequest = WireProtocol.ParseOpen(openBytes, now);

        byte[] sessionId;
        byte[] binding;
        byte[] evidenceBytes;
        byte[] gameBytes;
        Dictionary<string, byte[]?> snapshotBackup;
        using (AdmissionStore store = new(root, fixture.Policy, fixture.Rules, clock))
        {
            byte[] policyResponse = store.FetchPolicy(policyRequest);
            Check(policyResponse.Length == WireProtocol.PolicyResponseSize &&
                policyResponse.AsSpan(88, PolicyBundle.PolicySize)
                    .SequenceEqual(fixture.Policy.Record),
                "policy delivery preserves the signed record");
            ExpectBackend(409, () => store.FetchPolicy(policyRequest),
                "policy nonce replay is rejected");

            byte[] openResponse = store.OpenSession(openRequest, certificateDigest);
            sessionId = openResponse.AsSpan(32, 16).ToArray();
            binding = WireProtocol.BindingDigest(
                sessionId, openRequest.Header.Nonce, openResponse.AsSpan(80, 32));
            Check(!WireProtocol.IsZero(sessionId) && !WireProtocol.IsZero(binding),
                "session open returns a bound nonzero identity");

            evidenceBytes = fixture.EvidenceRequest(
                sessionId, binding, 2, fixture.Nonce(3), 1, 2, now);
            EvidenceRequest evidence = WireProtocol.ParseEvidence(evidenceBytes, now);
            snapshotBackup = SnapshotFiles(root);
            byte[] upload = store.UploadEvidence(evidence, certificateDigest);
            Check(WireProtocol.ReadUInt64(upload, 80) == 2,
                "evidence acknowledgement advances only after durable append");

            gameBytes = fixture.GameRequest(
                sessionId, 1, fixture.Nonce(4), now, positionX: 0);
            GameRequest game = WireProtocol.ParseGame(gameBytes, now);
            byte[] gameResponse = store.SubmitGameEvent(game);
            Check(WireProtocol.ReadUInt32(gameResponse, 88) == 0 &&
                WireProtocol.ReadUInt64(gameResponse, 176) != 0,
                "authoritative game event is durably accepted");
        }

        // Restore the pre-upload snapshot and leave one valid frame from a
        // two-record batch. Startup must discard the uncommitted batch.
        RestoreSnapshots(root, snapshotBackup);
        string evidencePath = Path.Combine(
            root, $"evidence-{Convert.ToHexString(sessionId)}.bin");
        using (FileStream evidence = new(evidencePath, FileMode.Open, FileAccess.Write,
            FileShare.None))
        {
            evidence.SetLength(712);
            evidence.Flush(flushToDisk: true);
        }
        string gamePath = Path.Combine(
            root, $"game-{Convert.ToHexString(sessionId)}.bin");
        if (File.Exists(gamePath)) File.Delete(gamePath);

        using (AdmissionStore recovered = new(root, fixture.Policy, fixture.Rules, clock))
        {
            Check(new FileInfo(evidencePath).Length == 0,
                "restart discards an incomplete evidence batch");
            EvidenceRequest evidence = WireProtocol.ParseEvidence(evidenceBytes, now);
            byte[] upload = recovered.UploadEvidence(evidence, certificateDigest);
            Check(WireProtocol.ReadUInt64(upload, 80) == 2,
                "discarded evidence can be resubmitted as one complete batch");

            GameRequest game = WireProtocol.ParseGame(gameBytes, now);
            _ = recovered.SubmitGameEvent(game);
        }

        using (AdmissionStore restarted = new(root, fixture.Policy, fixture.Rules, clock))
        {
            EvidenceRequest evidence = WireProtocol.ParseEvidence(evidenceBytes, now);
            ExpectBackend(403, () => restarted.UploadEvidence(evidence, certificateDigest),
                "evidence request replay is rejected after restart");
            GameRequest game = WireProtocol.ParseGame(gameBytes, now);
            ExpectBackend(403, () => restarted.SubmitGameEvent(game),
                "game request replay is rejected after restart");

            OpenRequest duplicateAdmission = WireProtocol.ParseOpen(
                fixture.OpenRequest(9, fixture.Nonce(30), now), now);
            ExpectBackend(409,
                () => restarted.OpenSession(duplicateAdmission, certificateDigest),
                "an active endpoint admission remains exclusive after restart");

            restarted.Revoke(sessionId);
        }

        using (AdmissionStore revoked = new(root, fixture.Policy, fixture.Rules, clock))
        {
            byte[] renewalBytes = fixture.RenewalRequest(
                sessionId, 3, fixture.Nonce(5), 1, now);
            RenewalRequest renewal = WireProtocol.ParseRenewal(renewalBytes, now);
            byte[] response = revoked.RenewSession(renewal, certificateDigest);
            Check(WireProtocol.ReadUInt32(response, 100) == 1 &&
                WireProtocol.ReadUInt32(response, 88) == 0,
                "revocation survives backend restart and returns a terminal lease");
            OpenRequest readmission = WireProtocol.ParseOpen(
                fixture.OpenRequest(10, fixture.Nonce(31), now), now);
            ExpectBackend(403,
                () => revoked.OpenSession(readmission, certificateDigest),
                "a revoked endpoint credential cannot bypass revocation by reopening");
        }
    }

    private static void TestExpiration(
        string root,
        X509Certificate2 policySigner,
        X509Certificate2 endpoint,
        DateTimeOffset initialNow)
    {
        DateTimeOffset now = initialNow;
        Fixture fixture = Fixture.Create(
            policySigner, initialNow, lease: 1000, grace: 0, renewal: 500);
        byte[] certificateDigest = endpoint.GetCertHash(HashAlgorithmName.SHA256);
        byte[] session;
        using (AdmissionStore store = new(root, fixture.Policy, fixture.Rules, () => now))
        {
            OpenRequest open = WireProtocol.ParseOpen(
                fixture.OpenRequest(1, fixture.Nonce(10), now), now);
            session = store.OpenSession(open, certificateDigest).AsSpan(32, 16).ToArray();
        }
        now = now.AddMilliseconds(1001);
        using (AdmissionStore store = new(root, fixture.Policy, fixture.Rules, () => now))
        {
            RenewalRequest renewal = WireProtocol.ParseRenewal(
                fixture.RenewalRequest(session, 2, fixture.Nonce(11), 1, now), now);
            ExpectBackend(410, () => store.RenewSession(renewal, certificateDigest),
                "expired lease remains expired after backend restart");
            OpenRequest readmission = WireProtocol.ParseOpen(
                fixture.OpenRequest(3, fixture.Nonce(12), now), now);
            byte[] replacement = store.OpenSession(
                readmission, certificateDigest).AsSpan(32, 16).ToArray();
            Check(!replacement.AsSpan().SequenceEqual(session),
                "an expired endpoint session is retired before fresh admission");
        }
    }

    private static async Task TestMutualTls(
        string root,
        Fixture fixture,
        X509Certificate2 policySigner,
        X509Certificate2 endpoint,
        X509Certificate2 endpointRotation,
        X509Certificate2 gameServer,
        X509Certificate2 untrustedClient,
        X509Certificate2 server,
        DateTimeOffset now)
    {
        Directory.CreateDirectory(root);
        string data = Path.Combine(root, "data");
        string policyPath = Path.Combine(root, "policy.dat");
        string signaturePath = Path.Combine(root, "policy.p7s");
        string rulesPath = Path.Combine(root, "movement.json");
        string serverPath = Path.Combine(root, "server.pfx");
        File.WriteAllBytes(policyPath, fixture.Policy.Record);
        File.WriteAllBytes(signaturePath, fixture.Policy.Signature);
        File.WriteAllText(rulesPath, JsonSerializer.Serialize(new
        {
            gameId = Convert.ToHexString(fixture.GameId),
            buildId = Convert.ToHexString(fixture.BuildId),
            serverTicksPerSecond = fixture.Rules.ServerTicksPerSecond,
            maximumHorizontalSpeedMmPerSecond =
                fixture.Rules.MaximumHorizontalSpeedMmPerSecond,
            maximumVerticalSpeedMmPerSecond =
                fixture.Rules.MaximumVerticalSpeedMmPerSecond,
            positionToleranceMillimeters = fixture.Rules.PositionToleranceMillimeters,
            maximumTickGap = fixture.Rules.MaximumTickGap,
            sequenceGapRisk = fixture.Rules.SequenceGapRisk,
            tickGapRisk = fixture.Rules.TickGapRisk,
            movementRisk = fixture.Rules.MovementRisk,
            velocityRisk = fixture.Rules.VelocityRisk,
            reviewThreshold = fixture.Rules.ReviewThreshold,
            rejectThreshold = fixture.Rules.RejectThreshold
        }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
        const string password = "oac-backend-test";
        File.WriteAllBytes(serverPath, server.Export(X509ContentType.Pfx, password));

        int port = AvailablePort();
        string origin = $"https://127.0.0.1:{port}";
        string[] arguments =
        [
            $"--urls={origin}",
            $"--Kestrel:Certificates:Default:Path={serverPath}",
            $"--Kestrel:Certificates:Default:Password={password}",
            $"--Backend:DataDirectory={data}",
            $"--Backend:PolicyPath={policyPath}",
            $"--Backend:PolicySignaturePath={signaturePath}",
            $"--Backend:MovementRulesPath={rulesPath}",
            $"--Backend:PolicySignerSha256={policySigner.GetCertHashString(HashAlgorithmName.SHA256)}",
            $"--Backend:EndpointClientCertificateSha256:0={endpoint.GetCertHashString(HashAlgorithmName.SHA256)}",
            $"--Backend:EndpointClientCertificateSha256:1={endpointRotation.GetCertHashString(HashAlgorithmName.SHA256)}",
            $"--Backend:GameServerCertificateSha256:0={gameServer.GetCertHashString(HashAlgorithmName.SHA256)}"
        ];

        await using WebApplication application = BackendApplication.Build(arguments);
        await application.StartAsync();
        try
        {
            byte[] serverDigest = server.GetCertHash(HashAlgorithmName.SHA256);
            using X509Certificate2 endpointForTls = SchannelCertificate(endpoint);
            using X509Certificate2 rotationForTls = SchannelCertificate(endpointRotation);
            using X509Certificate2 gameForTls = SchannelCertificate(gameServer);
            using X509Certificate2 deniedForTls = SchannelCertificate(untrustedClient);
            using HttpClient endpointClient = Client(endpointForTls, serverDigest);
            using HttpClient rotatedClient = Client(rotationForTls, serverDigest);
            using HttpClient gameClient = Client(gameForTls, serverDigest);
            using HttpClient deniedClient = Client(deniedForTls, serverDigest);

            Check((await endpointClient.GetAsync(origin + "/health")).StatusCode ==
                HttpStatusCode.NoContent, "mTLS health endpoint is available");
            Check((await Send(endpointClient, origin + "/policy",
                    fixture.PolicyRequest(1, fixture.Nonce(20), now))).StatusCode ==
                HttpStatusCode.OK, "endpoint certificate can fetch signed policy");
            Check((await Send(rotatedClient, origin + "/policy",
                    fixture.PolicyRequest(2, fixture.Nonce(21), now))).StatusCode ==
                HttpStatusCode.OK, "bounded endpoint certificate rotation is accepted");
            Check((await Send(gameClient, origin + "/policy",
                    fixture.PolicyRequest(3, fixture.Nonce(22), now))).StatusCode ==
                HttpStatusCode.Forbidden, "game-server certificate cannot use endpoint routes");

            using HttpResponseMessage openResponse = await Send(endpointClient,
                origin + "/session", fixture.OpenRequest(3, fixture.Nonce(23), now));
            Check(openResponse.StatusCode == HttpStatusCode.OK,
                "endpoint session opens over mutual TLS");
            byte[] open = await openResponse.Content.ReadAsByteArrayAsync();
            byte[] session = open.AsSpan(32, 16).ToArray();
            using GameServerClient gameAdapter = new(new Uri(origin), gameClient);
            GameAdmissionSession gameSession = fixture.GameSession(session);
            GameDecision gameDecision = await gameAdapter.SubmitMovementAsync(
                gameSession,
                new AuthoritativeMovement(
                    1, 1, 0, 0, 0, 0, 0, 0, false, 0));
            Check(gameDecision.DurableSequence != 0 &&
                gameDecision.Sequence == 1 && gameSession.NextSequence == 2 &&
                !gameSession.RequiresReadmission,
                "game adapter submits and correlates a durable canonical event");
            Check((await Send(endpointClient, origin + "/game",
                    fixture.GameRequest(session, 2, fixture.Nonce(25), now, 0))).StatusCode ==
                HttpStatusCode.Forbidden, "endpoint certificate cannot impersonate a game server");

            bool handshakeRejected = false;
            try
            {
                using HttpResponseMessage denied = await deniedClient.GetAsync(origin + "/health");
                handshakeRejected = denied.StatusCode is HttpStatusCode.Unauthorized or
                    HttpStatusCode.Forbidden;
            }
            catch (HttpRequestException)
            {
                handshakeRejected = true;
            }
            Check(handshakeRejected, "untrusted client certificate is rejected during admission");
        }
        finally
        {
            await application.StopAsync();
        }
    }

    private static HttpClient Client(X509Certificate2 certificate, byte[] serverDigest)
    {
        HttpClientHandler handler = new();
        handler.ClientCertificates.Add(certificate);
        handler.ServerCertificateCustomValidationCallback = (_, observed, _, _) =>
            observed is not null && CryptographicOperations.FixedTimeEquals(
                observed.GetCertHash(HashAlgorithmName.SHA256), serverDigest);
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
    }

    private static X509Certificate2 SchannelCertificate(X509Certificate2 certificate)
    {
        X509Certificate2Collection imported = [];
        imported.Import(certificate.Export(X509ContentType.Pfx), string.Empty,
            X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
        return imported.Single(static item => item.HasPrivateKey);
    }

    private static async Task<HttpResponseMessage> Send(
        HttpClient client,
        string url,
        byte[] body)
    {
        using ByteArrayContent content = new(body);
        content.Headers.ContentType = new MediaTypeHeaderValue(BinaryContentType);
        return await client.PostAsync(url, content);
    }

    private static int AvailablePort()
    {
        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static Dictionary<string, byte[]?> SnapshotFiles(string root) =>
        new(StringComparer.Ordinal)
        {
            ["state-a.bin"] = ReadOptional(Path.Combine(root, "state-a.bin")),
            ["state-b.bin"] = ReadOptional(Path.Combine(root, "state-b.bin"))
        };

    private static byte[]? ReadOptional(string path) =>
        File.Exists(path) ? File.ReadAllBytes(path) : null;

    private static void RestoreSnapshots(
        string root,
        IReadOnlyDictionary<string, byte[]?> snapshots)
    {
        foreach ((string name, byte[]? bytes) in snapshots)
        {
            string path = Path.Combine(root, name);
            if (bytes is null)
            {
                if (File.Exists(path)) File.Delete(path);
            }
            else
            {
                File.WriteAllBytes(path, bytes);
            }
        }
    }

    private static X509Certificate2 Certificate(
        string name,
        string eku,
        HashAlgorithmName? signatureAlgorithm = null)
    {
        RSA key = RSA.Create(3072);
        CertificateRequest request = new($"CN={name}", key,
            signatureAlgorithm ?? HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature, true));
        OidCollection usages = new() { new Oid(eku) };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(1));
    }

    private static X509Certificate2 ServerCertificate()
    {
        RSA key = RSA.Create(3072);
        CertificateRequest request = new("CN=localhost", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        SubjectAlternativeNameBuilder names = new();
        names.AddDnsName("localhost");
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(1));
    }

    private static void ExpectBackend(int status, Action action, string name)
    {
        try
        {
            action();
            throw new InvalidOperationException($"FAIL: {name} was accepted.");
        }
        catch (BackendRequestException exception) when (exception.StatusCode == status)
        {
            Check(true, name);
        }
    }

    private static void Check(bool condition, string name)
    {
        if (!condition) throw new InvalidOperationException($"FAIL: {name}");
        ++passed_;
        Console.WriteLine($"PASS: {name}");
    }
}

internal sealed record Fixture(
    PolicyBundle Policy,
    MovementRules Rules,
    byte[] GameId,
    byte[] BuildId,
    byte[] PolicyId,
    byte[] ChannelId,
    DateTimeOffset CreatedAt)
{
    public GameAdmissionSession GameSession(byte[] backendSessionId) => new(
        GameId,
        BuildId,
        backendSessionId,
        Identity(5),
        Identity(6, 32),
        Identity(7, 32));

    public static Fixture Create(
        X509Certificate2 signer,
        DateTimeOffset now,
        uint lease = 20_000,
        uint grace = 5_000,
        uint renewal = 5_000)
    {
        byte[] game = Identity(1);
        byte[] build = Identity(2);
        byte[] policyId = Identity(3);
        byte[] channel = Identity(4);
        byte[] record = new byte[PolicyBundle.PolicySize];
        "OACPOLCY"u8.CopyTo(record);
        Write32(record, 8, 3);
        Write32(record, 12, PolicyBundle.PolicySize);
        Write32(record, 20, 2);
        policyId.CopyTo(record, 24);
        game.CopyTo(record, 40);
        build.CopyTo(record, 56);
        channel.CopyTo(record, 72);
        Write64(record, 88, 1);
        Write64(record, 96, 1);
        Write64(record, 104, checked((ulong)now.AddMinutes(-1).ToUnixTimeSeconds()));
        Write64(record, 112, checked((ulong)now.AddHours(1).ToUnixTimeSeconds()));
        Write32(record, 120, WireProtocol.ProductionProtocol);
        Write32(record, 124, WireProtocol.ServiceProtocol);
        Write32(record, 128, WireProtocol.ServiceProtocol);
        Write32(record, 132, 3);
        Write32(record, 136, 37);
        signer.GetCertHash(HashAlgorithmName.SHA256).CopyTo(record, 144);
        for (int index = 0; index != 37; ++index)
        {
            int offset = 216 + index * 56;
            Write32(record, offset, 0x00010001u + checked((uint)index));
            Write32(record, offset + 4, 1);
            Write32(record, offset + 8, 1);
            Write32(record, offset + 16, 4);
            Write32(record, offset + 20, 2);
            Write32(record, offset + 24, 1);
            Write32(record, offset + 28, 3);
            Write32(record, offset + 32, 4);
        }
        Write32(record, 2456, lease);
        Write32(record, 2460, grace);
        Write32(record, 2464, renewal);
        Write32(record, 2468, 10_000);
        byte[] signature = Sign(record, signer);
        PolicyBundle policy = PolicyBundle.LoadForTest(
            record, signature, signer.GetCertHash(HashAlgorithmName.SHA256), now);
        MovementRules rules = new()
        {
            GameId = Convert.ToHexString(game),
            BuildId = Convert.ToHexString(build),
            ServerTicksPerSecond = 60,
            MaximumHorizontalSpeedMmPerSecond = 10_000,
            MaximumVerticalSpeedMmPerSecond = 5_000,
            PositionToleranceMillimeters = 100,
            MaximumTickGap = 300,
            SequenceGapRisk = 100,
            TickGapRisk = 100,
            MovementRisk = 400,
            VelocityRisk = 400,
            ReviewThreshold = 300,
            RejectThreshold = 700
        };
        rules.Validate();
        return new(policy, rules, game, build, policyId, channel, now);
    }

    public byte[] Nonce(byte value)
    {
        byte[] nonce = new byte[32];
        nonce[0] = value;
        nonce[31] = checked((byte)(value ^ 0xA5));
        return nonce;
    }

    public byte[] PolicyRequest(
        ulong sequence,
        byte[] nonce,
        DateTimeOffset now)
    {
        byte[] request = Header(WireProtocol.PolicyRequestSize,
            WireProtocol.PolicyMessage, sequence, null, nonce, now);
        GameId.CopyTo(request, 88);
        BuildId.CopyTo(request, 104);
        ChannelId.CopyTo(request, 120);
        return request;
    }

    public byte[] OpenRequest(
        ulong sequence,
        byte[] nonce,
        DateTimeOffset now)
    {
        byte[] request = Header(WireProtocol.OpenRequestSize,
            WireProtocol.OpenMessage, sequence, null, nonce, now);
        GameId.CopyTo(request, 88);
        BuildId.CopyTo(request, 104);
        PolicyId.CopyTo(request, 120);
        Policy.Digest.CopyTo(request, 136);
        Write32(request, 168, Policy.LeaseMilliseconds);
        Write32(request, 172, Policy.GraceMilliseconds);
        Write32(request, 176, Policy.RenewalMilliseconds);
        Write32(request, 180, Policy.EvidenceAcknowledgementMilliseconds);
        return request;
    }

    public byte[] RenewalRequest(
        byte[] session,
        ulong sequence,
        byte[] nonce,
        ulong leaseSequence,
        DateTimeOffset now)
    {
        byte[] request = Header(WireProtocol.RenewalRequestSize,
            WireProtocol.RenewMessage, sequence, session, nonce, now);
        Write64(request, 88, leaseSequence);
        return request;
    }

    public byte[] EvidenceRequest(
        byte[] session,
        byte[] binding,
        ulong requestSequence,
        byte[] nonce,
        ulong first,
        uint count,
        DateTimeOffset now)
    {
        byte[] request = Header(
            WireProtocol.EvidenceMetadataSize + checked((int)count * WireProtocol.EvidenceItemSize),
            WireProtocol.EvidenceMessage, requestSequence, session, nonce, now,
            WireProtocol.EvidenceMetadataSize);
        binding.CopyTo(request, 88);
        Write64(request, 120, first);
        Write64(request, 128, checked(first + count - 1));
        Write32(request, 136, count);
        for (uint index = 0; index != count; ++index)
            EvidenceItem(first + index).CopyTo(request,
                WireProtocol.EvidenceMetadataSize + checked((int)index) * WireProtocol.EvidenceItemSize);
        return request;
    }

    public byte[] GameRequest(
        byte[] session,
        ulong sequence,
        byte[] nonce,
        DateTimeOffset now,
        long positionX)
    {
        byte[] request = Header(WireProtocol.GameRequestSize,
            WireProtocol.GameMessage, sequence, session, nonce, now);
        Span<byte> movement = request.AsSpan(88, WireProtocol.MovementEventSize);
        Write32(movement, 0, 1);
        Write32(movement, 4, WireProtocol.MovementEventSize);
        Write32(movement, 8, 1);
        Write32(movement, 12, 1);
        GameId.CopyTo(movement.Slice(16, 16));
        BuildId.CopyTo(movement.Slice(32, 16));
        session.CopyTo(movement.Slice(48, 16));
        Identity(5).CopyTo(movement.Slice(64, 16));
        Identity(6, 32).CopyTo(movement.Slice(80, 32));
        Identity(7, 32).CopyTo(movement.Slice(112, 32));
        Write64(movement, 144, sequence);
        Write64(movement, 152, sequence);
        Write64(movement, 160, sequence);
        BinaryPrimitives.WriteInt64LittleEndian(movement.Slice(168, 8), positionX);
        return request;
    }

    private byte[] EvidenceItem(ulong serviceSequence)
    {
        byte[] item = new byte[WireProtocol.EvidenceItemSize];
        Write32(item, 0, WireProtocol.ProductionProtocol);
        Write32(item, 4, 560);
        Write32(item, 8, 0x00010001);
        Write32(item, 12, 1);
        Write32(item, 16, 1);
        Write32(item, 20, 1);
        Write32(item, 24, 1);
        Write32(item, 28, 1);
        Write32(item, 32, 2);
        Identity(8).CopyTo(item, 40);
        Write64(item, 56, 1);
        Write64(item, 64, 1);
        Write64(item, 72, 1);
        Write64(item, 80, 1);
        Write64(item, 88, 1);
        Write64(item, 96, serviceSequence);
        Write64(item, 104, 1);
        Write64(item, 112, 1);
        Write64(item, 120, 1);
        Write64(item, 160, 1);
        Write32(item, 168, 6);
        item[176] = (byte)'o';
        item[178] = (byte)'k';
        Write32(item, 560, 0x00010001);
        Write32(item, 564, 1);
        Write32(item, 568, 1);
        Write32(item, 572, 1);
        Write32(item, 576, 3);
        return item;
    }

    private static byte[] Header(
        int totalSize,
        uint type,
        ulong sequence,
        byte[]? session,
        byte[] nonce,
        DateTimeOffset now,
        int? declaredSize = null)
    {
        byte[] request = new byte[totalSize];
        Write32(request, 0, WireProtocol.Revision);
        Write32(request, 4, checked((uint)(declaredSize ?? totalSize)));
        Write32(request, 8, type);
        Write64(request, 16, sequence);
        session?.CopyTo(request, 24);
        nonce.CopyTo(request, 40);
        ulong issued = checked((ulong)now.ToUnixTimeSeconds());
        Write64(request, 72, issued);
        Write64(request, 80, issued + 30);
        return request;
    }

    private static byte[] Sign(byte[] record, X509Certificate2 signer)
    {
        SignedCms message = new(new ContentInfo(record), detached: true);
        CmsSigner cmsSigner = new(SubjectIdentifierType.IssuerAndSerialNumber, signer)
        {
            DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"),
            IncludeOption = X509IncludeOption.EndCertOnly
        };
        message.ComputeSignature(cmsSigner);
        return message.Encode();
    }

    private static byte[] Identity(byte value, int size = 16)
    {
        byte[] identity = new byte[size];
        for (int index = 0; index != size; ++index)
            identity[index] = checked((byte)(value + index));
        return identity;
    }

    private static void Write32(Span<byte> value, int offset, int item) =>
        Write32(value, offset, checked((uint)item));
    private static void Write32(Span<byte> value, int offset, uint item) =>
        BinaryPrimitives.WriteUInt32LittleEndian(value.Slice(offset, 4), item);
    private static void Write64(Span<byte> value, int offset, ulong item) =>
        BinaryPrimitives.WriteUInt64LittleEndian(value.Slice(offset, 8), item);
}

internal sealed class StaticResponseHandler(
    HttpStatusCode status,
    byte[] body) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        HttpResponseMessage response = new(status)
        {
            Content = new ByteArrayContent(body)
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue(
            "application/octet-stream");
        return Task.FromResult(response);
    }
}
