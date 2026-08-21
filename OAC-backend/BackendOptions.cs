using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Oac.Backend;

internal sealed class BackendOptions
{
    public string DataDirectory { get; init; } = string.Empty;
    public string PolicyPath { get; init; } = string.Empty;
    public string PolicySignaturePath { get; init; } = string.Empty;
    public string MovementRulesPath { get; init; } = string.Empty;
    public string PolicySignerSha256 { get; init; } = string.Empty;
    public string[] EndpointClientCertificateSha256 { get; init; } = [];
    public string[] GameServerCertificateSha256 { get; init; } = [];

    public static BackendOptions FromConfiguration(IConfiguration configuration)
    {
        IConfigurationSection backend = configuration.GetSection("Backend");
        return new BackendOptions
        {
            DataDirectory = backend[nameof(DataDirectory)] ?? string.Empty,
            PolicyPath = backend[nameof(PolicyPath)] ?? string.Empty,
            PolicySignaturePath = backend[nameof(PolicySignaturePath)] ?? string.Empty,
            MovementRulesPath = backend[nameof(MovementRulesPath)] ?? string.Empty,
            PolicySignerSha256 = backend[nameof(PolicySignerSha256)] ?? string.Empty,
            EndpointClientCertificateSha256 = backend
                .GetSection(nameof(EndpointClientCertificateSha256))
                .GetChildren().Select(static item => item.Value ?? string.Empty).ToArray(),
            GameServerCertificateSha256 = backend
                .GetSection(nameof(GameServerCertificateSha256))
                .GetChildren().Select(static item => item.Value ?? string.Empty).ToArray()
        };
    }

    public ValidatedBackendOptions Validate()
    {
        static string FullPath(string value, string name)
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new InvalidOperationException($"Backend:{name} is required.");
            if (!Path.IsPathFullyQualified(value))
                throw new InvalidOperationException(
                    $"Backend:{name} must be an absolute path.");
            return Path.GetFullPath(value);
        }

        IReadOnlyList<byte[]> endpointPins = CertificatePin.ParseSet(
            EndpointClientCertificateSha256, "endpoint client");
        IReadOnlyList<byte[]> gamePins = CertificatePin.ParseSet(
            GameServerCertificateSha256, "game server");
        if (endpointPins.Any(endpoint => gamePins.Any(game =>
                CryptographicOperations.FixedTimeEquals(endpoint, game))))
        {
            throw new InvalidOperationException(
                "Endpoint and game-server certificate roles must use distinct identities.");
        }
        return new ValidatedBackendOptions(
            FullPath(DataDirectory, nameof(DataDirectory)),
            FullPath(PolicyPath, nameof(PolicyPath)),
            FullPath(PolicySignaturePath, nameof(PolicySignaturePath)),
            FullPath(MovementRulesPath, nameof(MovementRulesPath)),
            CertificatePin.Parse(PolicySignerSha256, "policy signer"),
            endpointPins,
            gamePins);
    }
}

internal static class ClientCertificatePolicy
{
    private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";

    public static bool IsAllowed(
        X509Certificate2 certificate,
        IReadOnlyList<byte[]> pins,
        DateTimeOffset now)
    {
        if (now < certificate.NotBefore.ToUniversalTime() ||
            now > certificate.NotAfter.ToUniversalTime())
        {
            return false;
        }

        bool clientAuthentication = false;
        bool endEntity = false;
        bool digitalSignature = false;
        foreach (System.Security.Cryptography.X509Certificates.X509Extension extension
                 in certificate.Extensions)
        {
            if (extension is X509BasicConstraintsExtension
                    basicConstraints && basicConstraints.CertificateAuthority)
            {
                return false;
            }
            if (extension is X509BasicConstraintsExtension)
                endEntity = true;
            if (extension is X509EnhancedKeyUsageExtension
                    enhancedKeyUsage)
            {
                clientAuthentication = enhancedKeyUsage.EnhancedKeyUsages
                    .Cast<System.Security.Cryptography.Oid>()
                    .Any(static oid => oid.Value == ClientAuthenticationOid);
            }
            if (extension is X509KeyUsageExtension keyUsage)
            {
                digitalSignature =
                    (keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) != 0 &&
                    (keyUsage.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0;
            }
        }
        if (!endEntity || !clientAuthentication || !digitalSignature) return false;

        using RSA? rsa = certificate.GetRSAPublicKey();
        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        if ((rsa is null || rsa.KeySize < 3072) &&
            (ecdsa is null || ecdsa.KeySize < 256))
        {
            return false;
        }
        return CertificatePin.Matches(
            pins, certificate.GetCertHash(HashAlgorithmName.SHA256));
    }
}

internal sealed record ValidatedBackendOptions(
    string DataDirectory,
    string PolicyPath,
    string PolicySignaturePath,
    string MovementRulesPath,
    byte[] PolicySignerSha256,
    IReadOnlyList<byte[]> EndpointClientCertificateSha256,
    IReadOnlyList<byte[]> GameServerCertificateSha256);

internal static class CertificatePin
{
    public static byte[] Parse(string text, string role)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length != 64)
            throw new InvalidOperationException(
                $"The {role} SHA-256 pin must contain exactly 64 hex characters.");
        try
        {
            byte[] value = Convert.FromHexString(text);
            if (value.Length != 32 || value.All(static item => item == 0))
                throw new FormatException();
            return value;
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException(
                $"The {role} SHA-256 pin is malformed.", exception);
        }
    }

    public static IReadOnlyList<byte[]> ParseSet(
        IReadOnlyList<string>? values,
        string role)
    {
        if (values is null || values.Count is < 1 or > 2)
            throw new InvalidOperationException(
                $"Configure one active {role} certificate pin and at most one rotation pin.");
        List<byte[]> parsed = values.Select(value => Parse(value, role)).ToList();
        if (parsed.Count == 2 && CryptographicOperations.FixedTimeEquals(
                parsed[0], parsed[1]))
        {
            throw new InvalidOperationException(
                $"The {role} certificate pins must be distinct.");
        }
        return parsed;
    }

    public static bool Matches(IReadOnlyList<byte[]> pins, ReadOnlySpan<byte> digest)
    {
        bool matched = false;
        foreach (byte[] pin in pins)
            matched |= CryptographicOperations.FixedTimeEquals(pin, digest);
        return matched;
    }
}
