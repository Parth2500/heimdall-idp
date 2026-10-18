using System.Diagnostics.CodeAnalysis;

namespace Heimdall.Application.Common;

/// <summary>The outcome of a use case: a value or an OAuth error. Expected failures do not throw.</summary>
public sealed class Result<T>
{
    private readonly T? _value;

    internal Result(T? value, OAuthError? error)
    {
        _value = value;
        Error = error;
    }

    public OAuthError? Error { get; }

    [MemberNotNullWhen(false, nameof(Error))]
    public bool IsSuccess => Error is null;

    public T Value => IsSuccess
        ? _value!
        : throw new InvalidOperationException($"The result is a failure ({Error.Code}). Check IsSuccess first.");
}

public static class Result
{
    public static Result<T> Success<T>(T value) => new(value, null);

    public static Result<T> Failure<T>(OAuthError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return new Result<T>(default, error);
    }
}
