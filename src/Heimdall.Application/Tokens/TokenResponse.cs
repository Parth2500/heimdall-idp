namespace Heimdall.Application.Tokens;

/// <summary>A successful token response (RFC 6749, section 5.1).</summary>
/// <param name="RefreshToken">Only when the client may refresh and asked for <c>offline_access</c>.</param>
/// <param name="IdToken">Only when the scope has <c>openid</c>.</param>
public sealed record TokenResponse(
    string AccessToken,
    string TokenType,
    int ExpiresIn,
    string Scope,
    string? RefreshToken = null,
    string? IdToken = null)
{
    public const string BearerType = "Bearer";
}
