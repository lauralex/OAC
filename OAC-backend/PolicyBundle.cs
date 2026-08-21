using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Oac.Backend;

internal sealed class PolicyBundle
{
    public const int PolicySize = 2480;
    public const int SignatureCapacity = 8192;

    private PolicyBundle(byte[] record, byte[] signature, byte[] digest)
    {
        Record = record;
        Signature = signature;
        Digest = digest;
        PolicyId = record[24..40];
        GameId = record[40..56];
        BuildId = record[56..72];
        ChannelId = record[72..88];
        PolicyVersion = ReadUInt64(record, 88);
        LeaseMilliseconds = ReadUInt32(record, 2456);
        GraceMilliseconds = ReadUInt32(record, 2460);
        RenewalMilliseconds = ReadUInt32(record, 2464);
        EvidenceAcknowledgementMilliseconds = ReadUInt32(record, 2468);
    }

    public byte[] Record { get; }
    public byte[] Signature { get; }
    public byte[] Digest { get; }
    public byte[] PolicyId { get; }
    public byte[] GameId { get; }
    public byte[] BuildId { get; }
    public byte[] ChannelId { get; }
    public ulong PolicyVersion { get; }
    public uint LeaseMilliseconds { get; }
    public uint GraceMilliseconds { get; }
    public uint RenewalMilliseconds { get; }
    public uint EvidenceAcknowledgementMilliseconds { get; }

    public static PolicyBundle Load(ValidatedBackendOptions options)
    {
        byte[] record = ReadRegularFile(options.PolicyPath, PolicySize, PolicySize);
        byte[] signature = ReadRegularFile(
            options.PolicySignaturePath, 1, SignatureCapacity);
        ValidateRecord(record, DateTimeOffset.UtcNow);
        ValidateSignature(record, signature, options.PolicySignerSha256);
        return new PolicyBundle(record, signature, SHA256.HashData(record));
    }

    internal static PolicyBundle LoadForTest(
        byte[] record,
        byte[] signature,
        byte[] signerPin,
        DateTimeOffset now)
    {
        ValidateRecord(record, now);
        ValidateSignature(record, signature, signerPin);
        return new PolicyBundle((byte[])record.Clone(), (byte[])signature.Clone(),
            SHA256.HashData(record));
    }

    private static byte[] ReadRegularFile(string path, int minimum, int maximum)
    {
        FileAttributes attributes = File.GetAttributes(path);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new InvalidDataException($"{path} is not a regular file.");
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read,
            FileShare.Read, 4096, FileOptions.SequentialScan);
        if (stream.Length < minimum || stream.Length > maximum)
            throw new InvalidDataException($"{path} has an invalid size.");
        byte[] bytes = new byte[stream.Length];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private static void ValidateSignature(
        byte[] record,
        byte[] signature,
        byte[] expectedSignerSha256)
    {
        SignedCms cms = new(new ContentInfo(record), detached: true);
        try
        {
            cms.Decode(signature);
            cms.CheckSignature(verifySignatureOnly: true);
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException("The policy signature is invalid.", exception);
        }
        if (cms.SignerInfos.Count != 1 || cms.Certificates.Count == 0)
            throw new InvalidDataException("The policy must have exactly one signer.");
        SignerInfo signer = cms.SignerInfos[0];
        if (!string.Equals(
                signer.DigestAlgorithm.Value,
                "2.16.840.1.101.3.4.2.1",
                StringComparison.Ordinal) || signer.UnsignedAttributes.Count != 0 ||
            signer.Certificate is null)
        {
            throw new InvalidDataException(
                "The policy signer must use SHA-256 without unsigned attributes.");
        }
        using RSA? rsa = signer.Certificate.GetRSAPublicKey();
        byte[] certificateDigest = SHA256.HashData(signer.Certificate.RawData);
        if (rsa is null || rsa.KeySize < 3072 ||
            !string.Equals(
                signer.Certificate.SignatureAlgorithm.Value,
                "1.2.840.113549.1.1.11",
                StringComparison.Ordinal) ||
            !CryptographicOperations.FixedTimeEquals(
                certificateDigest, expectedSignerSha256) ||
            !CryptographicOperations.FixedTimeEquals(
                certificateDigest, record.AsSpan(144, 32)))
        {
            throw new InvalidDataException("The policy signer does not match the configured key.");
        }
    }

    private static void ValidateRecord(byte[] record, DateTimeOffset now)
    {
        ReadOnlySpan<byte> value = record;
        ReadOnlySpan<byte> magic = "OACPOLCY"u8;
        ulong issued = ReadUInt64(value, 104);
        ulong expires = ReadUInt64(value, 112);
        ulong nowSeconds = checked((ulong)now.ToUnixTimeSeconds());
        uint flags = ReadUInt32(value, 16);
        uint mode = ReadUInt32(value, 20);
        if (value.Length != PolicySize || !value[..8].SequenceEqual(magic) ||
            ReadUInt32(value, 8) != 3 || ReadUInt32(value, 12) != PolicySize ||
            (flags & ~3u) != 0 || mode is < 1 or > 3 ||
            IsZero(value.Slice(24, 16)) || IsZero(value.Slice(40, 16)) ||
            IsZero(value.Slice(56, 16)) || IsZero(value.Slice(72, 16)) ||
            ReadUInt64(value, 88) == 0 || ReadUInt64(value, 96) == 0 ||
            issued == 0 || expires <= issued || expires - issued > 2_678_400 ||
            (issued > nowSeconds && issued - nowSeconds > 300) ||
            (nowSeconds > expires && nowSeconds - expires > 300) ||
            ReadUInt32(value, 120) != WireProtocol.ProductionProtocol ||
            ReadUInt32(value, 124) != WireProtocol.ServiceProtocol ||
            ReadUInt32(value, 128) != WireProtocol.ServiceProtocol ||
            ReadUInt32(value, 132) != 3 || ReadUInt32(value, 136) != 37 ||
            IsZero(value.Slice(144, 32)) || !IsZero(value.Slice(2472, 8)) ||
            !BackendPolicyValid(
                ReadUInt32(value, 2456),
                ReadUInt32(value, 2460),
                ReadUInt32(value, 2464),
                ReadUInt32(value, 2468)) ||
            !EmergencyFieldsValid(value, flags) || !RulesValid(value))
        {
            throw new InvalidDataException("The signed policy record is malformed or incompatible.");
        }
    }

    private static bool EmergencyFieldsValid(ReadOnlySpan<byte> value, uint flags)
    {
        uint reason = ReadUInt32(value, 140);
        ulong rollbackVersion = ReadUInt64(value, 176);
        bool rollbackDigestZero = IsZero(value.Slice(184, 32));
        bool emergency = (flags & 1) != 0;
        bool rollback = (flags & 2) != 0;
        return (emergency ? reason is >= 1 and <= 3 : reason == 0) &&
            (rollback
                ? rollbackVersion != 0 && !rollbackDigestZero
                : rollbackVersion == 0 && rollbackDigestZero);
    }

    private static bool RulesValid(ReadOnlySpan<byte> value)
    {
        uint previous = 0;
        for (int index = 0; index != 40; ++index)
        {
            ReadOnlySpan<byte> rule = value.Slice(216 + index * 56, 56);
            if (index >= 37)
            {
                if (!IsZero(rule)) return false;
                continue;
            }
            uint ruleId = ReadUInt32(rule, 0);
            uint eventType = ReadUInt32(rule, 4);
            uint category = ReadUInt32(rule, 8);
            uint minimum = ReadUInt32(rule, 12);
            uint maximum = ReadUInt32(rule, 16);
            uint confidence = ReadUInt32(rule, 20);
            if (ruleId == 0 || ruleId <= previous || eventType is < 1 or > 9 ||
                category > 13 || minimum > 4 || maximum > 4 || minimum > maximum ||
                confidence > 4 || ReadUInt32(rule, 24) > 6 ||
                ReadUInt32(rule, 28) > 6 || ReadUInt32(rule, 32) > 6 ||
                !IsZero(rule.Slice(36, 4)) ||
                (ReadUInt64(rule, 40) & ~0xFFUL) != 0 ||
                (ReadUInt32(rule, 48) & ~1u) != 0 ||
                ReadUInt32(rule, 52) != 0)
            {
                return false;
            }
            previous = ruleId;
        }
        return true;
    }

    private static bool BackendPolicyValid(
        uint lease,
        uint grace,
        uint renewal,
        uint acknowledgement) =>
        lease is >= 1000 and <= 60_000 && grace <= 60_000 &&
        renewal != 0 && renewal < lease &&
        acknowledgement is >= 1000 and <= 60_000;

    private static bool IsZero(ReadOnlySpan<byte> value)
    {
        byte combined = 0;
        foreach (byte item in value) combined |= item;
        return combined == 0;
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> value, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(value.Slice(offset, 4));

    private static ulong ReadUInt64(ReadOnlySpan<byte> value, int offset) =>
        BinaryPrimitives.ReadUInt64LittleEndian(value.Slice(offset, 8));
}
