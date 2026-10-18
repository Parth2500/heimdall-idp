namespace Heimdall.Domain.Common;

internal static class Guard
{
    public static string NotBlank(string? value, string name)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new DomainException($"{name} must not be empty.");
        }

        return value.Trim();
    }

    public static TimeSpan Positive(TimeSpan value, string name)
    {
        if (value <= TimeSpan.Zero)
        {
            throw new DomainException($"{name} must be greater than zero.");
        }

        return value;
    }

    public static Guid NotEmpty(Guid value, string name)
    {
        if (value == Guid.Empty)
        {
            throw new DomainException($"{name} must not be empty.");
        }

        return value;
    }
}
