using Heimdall.Domain.Common;

namespace Heimdall.Domain.Clients;

internal static class RedirectUriRules
{
    /// <summary>
    /// Checks a redirect URI at registration time (RFC 9700, OAuth 2.1). Returns the URI unchanged,
    /// because later matching is by exact string.
    /// </summary>
    public static string Validate(string redirectUri)
    {
        var value = Guard.NotBlank(redirectUri, "redirect URI");

        if (value.Contains('*', StringComparison.Ordinal))
        {
            throw new DomainException("A redirect URI must not contain a wildcard.");
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            throw new DomainException("A redirect URI must be an absolute URI.");
        }

        if (uri.Fragment.Length > 0)
        {
            throw new DomainException("A redirect URI must not contain a fragment.");
        }

        if (uri.UserInfo.Length > 0)
        {
            throw new DomainException("A redirect URI must not contain user information.");
        }

        var isHttps = uri.Scheme == Uri.UriSchemeHttps;
        var isLoopbackHttp = uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback;
        if (!isHttps && !isLoopbackHttp)
        {
            throw new DomainException("A redirect URI must use https. Plain http is allowed only for a loopback address.");
        }

        return value;
    }
}
