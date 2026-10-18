using System.Text;
using System.Text.Json;
using Heimdall.Domain.Common;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Heimdall.Infrastructure.Persistence;

internal static class Converters
{
    /// <summary>Stores a duration as whole seconds (the <c>*_seconds</c> columns).</summary>
    public static readonly ValueConverter<TimeSpan, int> Seconds =
        new(v => (int)v.TotalSeconds, v => TimeSpan.FromSeconds(v));

    public static readonly ValueConverter<TokenHash, byte[]> Hash =
        new(v => v.ToArray(), v => HashFromArray(v));

    public static readonly ValueConverter<IReadOnlyDictionary<string, string>, string> JsonMap =
        new(v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null), v => MapFromJson(v));

    // Audit data never changes after insert, so reference comparison is enough for change tracking.
    public static readonly ValueComparer<IReadOnlyDictionary<string, string>> JsonMapComparer =
        new((a, b) => ReferenceEquals(a, b), v => v.Count, v => v);

    private static TokenHash HashFromArray(byte[] bytes) => TokenHash.FromBytes(bytes);

    private static Dictionary<string, string> MapFromJson(string json) =>
        JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? new Dictionary<string, string>();
}

/// <summary>Stores an enum as snake_case text, for example <c>ClientCredentials</c> as <c>client_credentials</c>.</summary>
internal sealed class SnakeCaseEnumConverter<TEnum> : ValueConverter<TEnum, string>
    where TEnum : struct, Enum
{
    private static readonly Dictionary<TEnum, string> ToText =
        Enum.GetValues<TEnum>().ToDictionary(v => v, v => ToSnakeCase(v.ToString()));

    private static readonly Dictionary<string, TEnum> FromText =
        ToText.ToDictionary(p => p.Value, p => p.Key, StringComparer.Ordinal);

    public SnakeCaseEnumConverter()
        : base(v => Write(v), v => Read(v))
    {
    }

    public static string Write(TEnum value) => ToText[value];

    public static TEnum Read(string value) =>
        FromText.TryGetValue(value, out var result)
            ? result
            : throw new InvalidOperationException($"'{value}' is not a valid {typeof(TEnum).Name} value.");

    private static string ToSnakeCase(string name)
    {
        var builder = new StringBuilder(name.Length + 4);
        for (var i = 0; i < name.Length; i++)
        {
            if (char.IsUpper(name[i]) && i > 0)
            {
                builder.Append('_');
            }

            builder.Append(char.ToLowerInvariant(name[i]));
        }

        return builder.ToString();
    }
}
