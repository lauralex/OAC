using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace Oac.Backend;

internal static class BackendApplication
{
    private const string BinaryContentType = "application/octet-stream";

    public static async Task<int> RunAsync(string[] args)
    {
        try
        {
            if (args.Length != 0 && string.Equals(
                    args[0], "revoke", StringComparison.OrdinalIgnoreCase))
            {
                return Revoke(args);
            }
            if (args.Length != 0 && string.Equals(
                    args[0], "validate", StringComparison.OrdinalIgnoreCase))
            {
                return Validate(args[1..]);
            }

            WebApplication application = Build(args);
            await application.RunAsync().ConfigureAwait(false);
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"OAC backend failed: {exception.Message}");
            return 1;
        }
    }

    internal static WebApplication Build(string[] args)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
        ValidatedBackendOptions options = BackendOptions
            .FromConfiguration(builder.Configuration).Validate();
        PolicyBundle policy = PolicyBundle.Load(options);
        MovementRules movementRules = MovementRules.Load(options.MovementRulesPath);
        IReadOnlyList<byte[]> allClientPins = options.EndpointClientCertificateSha256
            .Concat(options.GameServerCertificateSha256)
            .Select(static pin => (byte[])pin.Clone()).ToArray();

        builder.WebHost.ConfigureKestrel(server =>
        {
            server.AddServerHeader = false;
            server.Limits.MaxRequestBodySize = WireProtocol.MaximumRequestSize;
            server.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
            server.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(30);
            server.ConfigureHttpsDefaults(https =>
            {
                https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                https.CheckCertificateRevocation = false;
                https.ClientCertificateValidation = (certificate, _, _) =>
                    ClientCertificatePolicy.IsAllowed(
                        certificate, allClientPins, DateTimeOffset.UtcNow);
            });
        });

        AdmissionStore store = new(options.DataDirectory, policy, movementRules);
        builder.Services.AddSingleton(store);
        WebApplication application = builder.Build();
        application.Lifetime.ApplicationStopped.Register(store.Dispose);

        application.Use(async (context, next) =>
        {
            if (!context.Request.IsHttps || context.Request.QueryString.HasValue)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.XContentTypeOptions = "nosniff";
            await next(context).ConfigureAwait(false);
        });

        application.MapGet("/health", static () => Results.NoContent());
        MapEndpoint(application, "/policy", WireProtocol.PolicyRequestSize,
            options.EndpointClientCertificateSha256,
            static (store, body, certificate) => store.FetchPolicy(
                WireProtocol.ParsePolicy(body, DateTimeOffset.UtcNow)));
        MapEndpoint(application, "/session", WireProtocol.OpenRequestSize,
            options.EndpointClientCertificateSha256,
            static (store, body, certificate) => store.OpenSession(
                WireProtocol.ParseOpen(body, DateTimeOffset.UtcNow), certificate));
        MapEndpoint(application, "/renew", WireProtocol.RenewalRequestSize,
            options.EndpointClientCertificateSha256,
            static (store, body, certificate) => store.RenewSession(
                WireProtocol.ParseRenewal(body, DateTimeOffset.UtcNow), certificate));
        MapEndpoint(application, "/evidence", WireProtocol.MaximumRequestSize,
            options.EndpointClientCertificateSha256,
            static (store, body, certificate) => store.UploadEvidence(
                WireProtocol.ParseEvidence(body, DateTimeOffset.UtcNow), certificate),
            WireProtocol.EvidenceMetadataSize + WireProtocol.EvidenceItemSize);
        MapEndpoint(application, "/game", WireProtocol.GameRequestSize,
            options.GameServerCertificateSha256,
            static (store, body, _) => store.SubmitGameEvent(
                WireProtocol.ParseGame(body, DateTimeOffset.UtcNow)));

        return application;
    }

    private static void MapEndpoint(
        WebApplication application,
        string path,
        int maximumBodySize,
        IReadOnlyList<byte[]> pins,
        Func<AdmissionStore, byte[], byte[], byte[]> handler,
        int? minimumBodySize = null)
    {
        application.MapPost(path, async (HttpContext context, AdmissionStore store) =>
        {
            try
            {
                byte[] certificate = await ClientCertificateDigest(
                    context, pins).ConfigureAwait(false);
                byte[] body = await ReadBody(
                    context.Request,
                    minimumBodySize ?? maximumBodySize,
                    maximumBodySize,
                    context.RequestAborted).ConfigureAwait(false);
                byte[] response = handler(store, body, certificate);
                context.Response.ContentType = BinaryContentType;
                context.Response.ContentLength = response.Length;
                await context.Response.Body.WriteAsync(
                    response, context.RequestAborted).ConfigureAwait(false);
            }
            catch (BackendRequestException exception)
            {
                context.Response.StatusCode = exception.StatusCode;
            }
            catch (BadHttpRequestException)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
            }
            catch (InvalidDataException)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
            }
        }).Accepts<byte[]>(BinaryContentType).Produces(StatusCodes.Status200OK,
            contentType: BinaryContentType);
    }

    private static async Task<byte[]> ClientCertificateDigest(
        HttpContext context,
        IReadOnlyList<byte[]> pins)
    {
        X509Certificate2 certificate = await context.Connection
            .GetClientCertificateAsync(context.RequestAborted).ConfigureAwait(false) ??
            throw new BackendRequestException(401, "A client certificate is required.");
        if (!ClientCertificatePolicy.IsAllowed(certificate, pins, DateTimeOffset.UtcNow))
            throw new BackendRequestException(403, "The client certificate role is not authorized.");
        return certificate.GetCertHash(HashAlgorithmName.SHA256);
    }

    private static async Task<byte[]> ReadBody(
        HttpRequest request,
        int minimumSize,
        int maximumSize,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(request.ContentType, BinaryContentType,
                StringComparison.OrdinalIgnoreCase) ||
            request.ContentLength is null ||
            request.ContentLength < minimumSize ||
            request.ContentLength > maximumSize)
        {
            throw new BadHttpRequestException("The request body has an invalid type or size.");
        }
        byte[] body = new byte[checked((int)request.ContentLength.Value)];
        try
        {
            await request.Body.ReadExactlyAsync(body, cancellationToken).ConfigureAwait(false);
        }
        catch (EndOfStreamException exception)
        {
            throw new BadHttpRequestException(
                "The request body is shorter than its declared size.", exception);
        }
        if (await request.Body.ReadAsync(new byte[1], cancellationToken).ConfigureAwait(false) != 0)
            throw new BadHttpRequestException("The request body exceeds its declared size.");
        return body;
    }

    private static int Validate(string[] args)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
        ValidatedBackendOptions options = BackendOptions
            .FromConfiguration(builder.Configuration).Validate();
        PolicyBundle policy = PolicyBundle.Load(options);
        MovementRules rules = MovementRules.Load(options.MovementRulesPath);
        using AdmissionStore store = new(options.DataDirectory, policy, rules);
        Console.WriteLine("OAC backend configuration and durable state are valid.");
        return 0;
    }

    private static int Revoke(string[] args)
    {
        if (args.Length < 2)
            throw new ArgumentException("Usage: OAC.Backend revoke <session-id-hex> [configuration options]");
        byte[] sessionId;
        try
        {
            sessionId = Convert.FromHexString(args[1]);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("The session identifier is malformed.", exception);
        }
        WebApplicationBuilder builder = WebApplication.CreateBuilder(args[2..]);
        ValidatedBackendOptions options = BackendOptions
            .FromConfiguration(builder.Configuration).Validate();
        PolicyBundle policy = PolicyBundle.Load(options);
        MovementRules rules = MovementRules.Load(options.MovementRulesPath);
        using AdmissionStore store = new(options.DataDirectory, policy, rules);
        store.Revoke(sessionId);
        Console.WriteLine($"Backend session {Convert.ToHexString(sessionId)} is revoked.");
        return 0;
    }
}
