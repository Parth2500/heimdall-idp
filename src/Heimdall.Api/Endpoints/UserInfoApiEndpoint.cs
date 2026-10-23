using System.Text.Json.Serialization;
using Heimdall.Api.Hosting;
using Heimdall.Application.Common;
using Heimdall.Application.Dpop;
using Heimdall.Application.UserInfo;
using Microsoft.Extensions.Primitives;

namespace Heimdall.Api.Endpoints;

/// <summary>
/// <c>GET</c> and <c>POST /oauth/v1/userinfo</c> (OpenID Connect Core, section 5.3; POST is required there). The
/// access token comes in the <c>Authorization</c> header only, with the <c>Bearer</c> or the <c>DPoP</c> scheme. Errors
/// follow RFC 6750, section 3, and RFC 9449, section 7.1.
/// </summary>
/// <remarks>
/// No CORS headers yet, so a browser blocks cross-origin reads. Registered client origins come with the Angular SPA
/// (threat model, /userinfo, Information disclosure). No log line contains the token (D7).
/// </remarks>
internal static partial class UserInfoApiEndpoint
{
    public static void Map(IEndpointRouteBuilder app) =>
        app.MapMethods(UserInfoEndpoint.Path, [HttpMethods.Get, HttpMethods.Post], HandleAsync);

    /// <summary>The algorithms that a DPoP proof may use (D25). The DPoP challenge names them.</summary>
    private static readonly string DpopChallenge = $"DPoP algs=\"{string.Join(' ', DpopAlgorithms.Supported)}\"";

    private static async Task HandleAsync(HttpContext context, UserInfoService userInfo, ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(typeof(UserInfoApiEndpoint));
        OAuthResponses.NoStore(context.Response);

        // RFC 6750, section 2.3: a token in the URL ends up in logs and caches. Refuse it loudly, never use it.
        if (context.Request.Query.ContainsKey("access_token"))
        {
            LogRejected(logger, "invalid_request", "access_token in the query string");
            await WriteErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request").ConfigureAwait(false);
            return;
        }

        if (ReadToken(context.Request.Headers.Authorization) is not { } credentials)
        {
            // RFC 6750, section 3.1: a request with no credentials gets a challenge with no error code. RFC 9449,
            // section 7.1: the DPoP challenge goes with it, so a client knows that both schemes work here.
            LogRejected(logger, "none", "no access token");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.WWWAuthenticate = new StringValues(["Bearer", DpopChallenge]);
            return;
        }

        // RFC 9449, section 4.3: at most one DPoP header, as at /token.
        var proofs = context.Request.Headers[TokenEndpoint.DpopHeader];
        if (proofs.Count > 1)
        {
            LogRejected(logger, OAuthError.InvalidDpopProofCode, "repeated DPoP header");
            await WriteErrorAsync(context, StatusCodes.Status401Unauthorized, OAuthError.InvalidDpopProofCode, credentials.Scheme)
                .ConfigureAwait(false);
            return;
        }

        var request = new UserInfoRequest(credentials.Token, credentials.Scheme, context.Request.Method, proofs.Count == 1 ? proofs[0] ?? string.Empty : null);
        var result = await userInfo.GetAsync(TenantResolutionMiddleware.GetRequestContext(context), request, context.RequestAborted)
            .ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            LogRejected(logger, result.Error.Code, result.Error.AuditDetail ?? string.Empty);
            var status = result.Error.Code == UserInfoService.InsufficientScopeCode
                ? StatusCodes.Status403Forbidden
                : StatusCodes.Status401Unauthorized;
            await WriteErrorAsync(context, status, result.Error.Code, credentials.Scheme).ConfigureAwait(false);
            return;
        }

        var claims = result.Value;
        context.Response.StatusCode = StatusCodes.Status200OK;
        await context.Response.WriteAsJsonAsync(
            new ClaimsBody(claims.Subject, claims.Email, claims.EmailVerified),
            context.RequestAborted).ConfigureAwait(false);
    }

    /// <summary>
    /// One Authorization header with the Bearer or the DPoP scheme and a non-empty token. Anything else is no token.
    /// Scheme names compare without case (RFC 9110, section 11.1).
    /// </summary>
    private static (string Token, TokenScheme Scheme)? ReadToken(StringValues header)
    {
        if (header.Count != 1 || header[0] is not { } value)
        {
            return null;
        }

        var (scheme, rest) = value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? (TokenScheme.Bearer, value["Bearer ".Length..])
            : value.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase) ? (TokenScheme.Dpop, value["DPoP ".Length..])
            : (TokenScheme.Bearer, string.Empty);
        var token = rest.Trim();
        return token.Length == 0 ? null : (token, scheme);
    }

    // The error code is in the challenge and the body. The reason is never in the response (D5). The challenge uses
    // the scheme that the request used.
    private static Task WriteErrorAsync(HttpContext context, int status, string error, TokenScheme scheme = TokenScheme.Bearer)
    {
        context.Response.StatusCode = status;
        if (status != StatusCodes.Status400BadRequest)
        {
            context.Response.Headers.WWWAuthenticate = scheme == TokenScheme.Dpop
                ? $"{DpopChallenge}, error=\"{error}\""
                : $"Bearer error=\"{error}\"";
        }

        return context.Response.WriteAsJsonAsync(new ErrorBody(error), context.RequestAborted);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Userinfo request refused: {Error} ({Reason}).")]
    private static partial void LogRejected(ILogger logger, string error, string reason);

    private sealed record ErrorBody([property: JsonPropertyName("error")] string Error);

    private sealed record ClaimsBody(
        [property: JsonPropertyName("sub")] string Subject,
        [property: JsonPropertyName("email"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Email,
        [property: JsonPropertyName("email_verified"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? EmailVerified);
}
