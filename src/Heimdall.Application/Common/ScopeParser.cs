namespace Heimdall.Application.Common;

public static class ScopeParser
{
    /// <summary>
    /// Splits a <c>scope</c> parameter into values. Returns null when a value has a character outside the
    /// scope-token set of RFC 6749, section 3.3 (printable ASCII except space, double quote, and backslash).
    /// </summary>
    public static IReadOnlyList<string>? Parse(string? scope)
    {
        if (string.IsNullOrEmpty(scope))
        {
            return [];
        }

        var values = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (var value in values)
        {
            foreach (var c in value)
            {
                var allowed = c is >= '!' and <= '~' && c is not '"' and not '\\';
                if (!allowed)
                {
                    return null;
                }
            }
        }

        return values.Distinct(StringComparer.Ordinal).ToList();
    }
}
