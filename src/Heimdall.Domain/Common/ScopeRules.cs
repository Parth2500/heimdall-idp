namespace Heimdall.Domain.Common;

internal static class ScopeRules
{
    /// <summary>Trims, removes duplicates, and rejects white space inside a scope value.</summary>
    public static List<string> Normalize(IEnumerable<string> scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);

        var result = scopes.Select(s => Guard.NotBlank(s, "scope")).Distinct(StringComparer.Ordinal).ToList();
        if (result.Any(s => s.Any(char.IsWhiteSpace)))
        {
            // A scope value is one token in a space-separated list.
            throw new DomainException("A scope must not contain white space.");
        }

        return result;
    }
}
