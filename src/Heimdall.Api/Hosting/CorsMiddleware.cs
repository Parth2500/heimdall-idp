using System.Collections.Frozen;
using System.Globalization;
using Heimdall.Api.Endpoints;
using Heimdall.Application.Clients;
using Heimdall.Application.UserInfo;
using Heimdall.Infrastructure.Persistence;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace Heimdall.Api.Hosting;

/// <summary>
/// Cross-origin reads (D23). A browser page on a client origin may read the responses of <c>/token</c>, <c>/revoke</c>,
/// and <c>/userinfo</c>. Discovery and JWKS are public, so any origin may read them. Every other path, the session
/// API included, gets no CORS header, so the browser blocks a cross-origin read.
/// </summary>
/// <remarks>
/// CORS controls only which pages may read a response. It does not authenticate anything: each endpoint still
/// checks its code, verifier, token, or secret. Heimdall never sends <c>Access-Control-Allow-Credentials</c>, so a
/// cross-origin request never carries the session cookie.
/// </remarks>
internal sealed class CorsMiddleware
{
    /// <summary>The browser may keep a preflight answer this long. A removed origin still fails at once, because each
    /// response is checked again.</summary>
    private static readonly string PreflightMaxAge = ((int)TimeSpan.FromMinutes(10).TotalSeconds).ToString(CultureInfo.InvariantCulture);

    private static readonly FrozenDictionary<string, Rule> ClientRules = new Dictionary<string, Rule>(StringComparer.OrdinalIgnoreCase)
    {
        // A form POST is a simple request. With a DPoP header (RFC 9449) the browser sends a preflight first.
        [TokenEndpoint.Path] = new([HttpMethods.Post], [TokenEndpoint.DpopHeader], []),
        [RevokeEndpoint.Path] = new([HttpMethods.Post], [], []),

        // RFC 9126: a browser app pushes its request with a form POST, and a DPoP proof binds the code (RFC 9449, 10.1).
        [PushedAuthorizationEndpoint.Path] = new([HttpMethods.Post], [TokenEndpoint.DpopHeader], []),

        // The access token goes in the Authorization header, and a bound token's proof in the DPoP header (D28), so the
        // browser sends a preflight. The client may read WWW-Authenticate, which names the error (RFC 6750, section 3).
        [UserInfoEndpoint.Path] = new(
            [HttpMethods.Get, HttpMethods.Post],
            [HeaderNames.Authorization, TokenEndpoint.DpopHeader],
            [HeaderNames.WWWAuthenticate]),
    }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    private readonly RequestDelegate _next;

    public CorsMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, IClientStore clients, TenantScope scope)
    {
        var path = context.Request.Path.Value ?? string.Empty;
        var headers = context.Response.Headers;

        if (IsPublicMetadata(path))
        {
            // No credentials and the same body for every caller, so "*" leaks nothing.
            headers.AccessControlAllowOrigin = "*";
            await _next(context).ConfigureAwait(false);
            return;
        }

        if (!ClientRules.TryGetValue(path, out var rule))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // The answer depends on Origin, so no cache may give one origin's answer to another.
        headers.Append(HeaderNames.Vary, HeaderNames.Origin);

        var origin = await AllowedOriginAsync(context, clients, scope).ConfigureAwait(false);
        if (IsPreflight(context.Request))
        {
            // The endpoints do not handle OPTIONS. Heimdall answers every preflight here, with headers only when it
            // allows the request.
            if (origin is not null && Allows(rule, context.Request))
            {
                headers.AccessControlAllowOrigin = origin;
                headers.AccessControlAllowMethods = string.Join(", ", rule.Methods);
                if (rule.RequestHeaders.Length > 0)
                {
                    headers.AccessControlAllowHeaders = string.Join(", ", rule.RequestHeaders);
                }

                headers.AccessControlMaxAge = PreflightMaxAge;
            }

            context.Response.StatusCode = StatusCodes.Status204NoContent;
            return;
        }

        if (origin is not null)
        {
            headers.AccessControlAllowOrigin = origin;
            if (rule.ExposedHeaders.Length > 0)
            {
                headers.AccessControlExposeHeaders = string.Join(", ", rule.ExposedHeaders);
            }
        }

        await _next(context).ConfigureAwait(false);
    }

    private static bool IsPublicMetadata(string path) =>
        string.Equals(path, WellKnownEndpoints.DiscoveryPath, StringComparison.OrdinalIgnoreCase)
        || string.Equals(path, WellKnownEndpoints.JwksPath, StringComparison.OrdinalIgnoreCase);

    private static bool IsPreflight(HttpRequest request) =>
        HttpMethods.IsOptions(request.Method) && request.Headers.ContainsKey(HeaderNames.AccessControlRequestMethod);

    /// <summary>The request's single Origin header when it names a client origin of this tenant, else null.</summary>
    private static async Task<string?> AllowedOriginAsync(HttpContext context, IClientStore clients, TenantScope scope)
    {
        // Two Origin headers, an empty one, or "null" (a sandboxed or opaque origin) never match.
        if (context.Request.Headers.Origin is not [{ Length: > 0 } origin] || origin == "null" || scope.TenantId is not { } tenantId)
        {
            return null;
        }

        return await clients.IsBrowserOriginAllowedAsync(tenantId, origin, context.RequestAborted).ConfigureAwait(false)
            ? origin
            : null;
    }

    private static bool Allows(Rule rule, HttpRequest request)
    {
        var method = request.Headers.AccessControlRequestMethod.ToString();
        if (!rule.Methods.Contains(method, StringComparer.Ordinal))
        {
            return false;
        }

        // Browsers send the names in lowercase, separated by commas.
        foreach (var name in SplitList(request.Headers.AccessControlRequestHeaders))
        {
            if (!rule.RequestHeaders.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    private static IEnumerable<string> SplitList(StringValues values) =>
        values.SelectMany(v => (v ?? string.Empty).Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));

    private sealed record Rule(string[] Methods, string[] RequestHeaders, string[] ExposedHeaders);
}
