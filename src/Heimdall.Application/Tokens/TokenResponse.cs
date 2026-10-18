namespace Heimdall.Application.Tokens;

/// <summary>A successful token response (RFC 6749, section 5.1).</summary>
public sealed record TokenResponse(string AccessToken, string TokenType, int ExpiresIn, string Scope)
{
    public const string BearerType = "Bearer";
}
