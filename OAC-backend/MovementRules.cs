using System.Text.Json;
using System.Text.Json.Serialization;

namespace Oac.Backend;

internal sealed record MovementRules
{
    public string GameId { get; init; } = string.Empty;
    public string BuildId { get; init; } = string.Empty;
    public uint ServerTicksPerSecond { get; init; }
    public uint MaximumHorizontalSpeedMmPerSecond { get; init; }
    public uint MaximumVerticalSpeedMmPerSecond { get; init; }
    public uint PositionToleranceMillimeters { get; init; }
    public uint MaximumTickGap { get; init; }
    public uint SequenceGapRisk { get; init; }
    public uint TickGapRisk { get; init; }
    public uint MovementRisk { get; init; }
    public uint VelocityRisk { get; init; }
    public uint ReviewThreshold { get; init; }
    public uint RejectThreshold { get; init; }

    public byte[] GameIdBytes { get; private set; } = [];
    public byte[] BuildIdBytes { get; private set; } = [];

    public static MovementRules Load(string path)
    {
        if ((File.GetAttributes(path) &
                (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new InvalidDataException("The movement-rules path is not a regular file.");
        byte[] bytes = File.ReadAllBytes(path);
        if (bytes.Length is < 2 or > 64 * 1024)
            throw new InvalidDataException("The movement-rules file has an invalid size.");
        MovementRules rules = JsonSerializer.Deserialize<MovementRules>(bytes,
            new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = false,
                UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
            }) ??
            throw new InvalidDataException("The movement-rules file is empty.");
        rules.Validate();
        return rules;
    }

    public void Validate()
    {
        GameIdBytes = ParseIdentity(GameId, nameof(GameId));
        BuildIdBytes = ParseIdentity(BuildId, nameof(BuildId));
        if (ServerTicksPerSecond is 0 or > 1000 ||
            MaximumHorizontalSpeedMmPerSecond is 0 or > 1_000_000 ||
            MaximumVerticalSpeedMmPerSecond is 0 or > 1_000_000 ||
            PositionToleranceMillimeters > 1_000_000 ||
            MaximumTickGap is 0 or > 60_000 ||
            SequenceGapRisk is 0 or > 1000 || TickGapRisk is 0 or > 1000 ||
            MovementRisk is 0 or > 1000 || VelocityRisk is 0 or > 1000 ||
            ReviewThreshold is 0 or > 1000 ||
            RejectThreshold is 0 or > 1000 || ReviewThreshold >= RejectThreshold)
        {
            throw new InvalidDataException("The movement rules are outside their supported bounds.");
        }
    }

    private static byte[] ParseIdentity(string value, string name)
    {
        try
        {
            byte[] bytes = Convert.FromHexString(value);
            if (bytes.Length != 16 || bytes.All(static item => item == 0))
                throw new FormatException();
            return bytes;
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                $"{name} must be a nonzero 16-byte hexadecimal identity.", exception);
        }
    }
}
