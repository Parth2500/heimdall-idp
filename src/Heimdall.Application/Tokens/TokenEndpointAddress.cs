namespace Heimdall.Application.Tokens;

/// <summary>The token endpoint's path. A DPoP proof for /token names its URL in <c>htu</c>.</summary>
public static class TokenEndpointAddress
{
    public const string Path = "/oauth/v1/token";

    /// <summary>The token endpoint's URL in the tenant.</summary>
    public static Uri For(string issuer) => new(issuer + Path);
}
