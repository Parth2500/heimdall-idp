using Heimdall.Domain.Common;

namespace Heimdall.Domain.Clients;

internal static class AudienceRules
{
    /// <summary>
    /// Checks an audience at registration time. An audience is the URI of one resource server (RFC 8707):
    /// absolute, without a fragment or query, and https except for loopback.
    /// </summary>
    public static string Validate(string audience)
    {
        var value = Guard.NotBlank(audience, "audience");

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            throw new DomainException("An audience must be an absolute URI.");
        }

        if (uri.Fragment.Length > 0 || uri.Query.Length > 0)
        {
            throw new DomainException("An audience must not contain a fragment or a query.");
        }

        if (uri.UserInfo.Length > 0)
        {
            throw new DomainException("An audience must not contain user information.");
        }

        var isHttps = uri.Scheme == Uri.UriSchemeHttps;
        var isLoopbackHttp = uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback;
        if (!isHttps && !isLoopbackHttp)
        {
            throw new DomainException("An audience must use https. Plain http is allowed only for a loopback address.");
        }

        return value;
    }
}
