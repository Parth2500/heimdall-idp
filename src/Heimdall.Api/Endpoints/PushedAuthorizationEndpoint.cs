using System.Text.Json.Serialization;
using Heimdall.Api.Hosting;
using Heimdall.Application.Authorization;
using Heimdall.Application.Common;

namespace Heimdall.Api.Endpoints;

/// <summary>
/// <c>POST /oauth/v1/par</c> (RFC 9126, D40 to D43). The form and client rules are the same as at <c>/token</c>
/// (<see cref="OAuthFormReader"/>). The logic is in <see cref="PushedAuthorization"/>.
/// </summary>
internal static partial class PushedAuthorizationEndpoint
{
    public const string Path = PushedAuthorization.Path;

    public static async Task HandleAsync(HttpContext context, PushedAuthorization pushed, ClientRateLimiter limiter, ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(typeof(PushedAuthorizationEndpoint));

        // The failure budget of /token: /par authenticates clients too.
        if (limiter.IsIpBlocked(context))
        {
            await RateLimits.WriteRejectedAsync(context, limiter.FailureWindow).ConfigureAwait(false);
            return;
        }

        var parsed = await OAuthFormReader.ReadAsync(context).ConfigureAwait(false);

        // RFC 9449, section 4.3: at most one DPoP header.
        var dpopHeaders = context.Request.Headers[TokenEndpoint.DpopHeader];
        if (parsed.Error is null && dpopHeaders.Count > 1)
        {
            parsed = OAuthForm.Fail(OAuthError.InvalidDpopProof("repeated DPoP header"));
        }

        if (parsed.Error is { } error)
        {
            await RefuseAsync(context, limiter, logger, error).ConfigureAwait(false);
            return;
        }

        // Each push stores a row, so it counts against the client's issuance budget, like a token.
        var requestContext = TenantResolutionMiddleware.GetRequestContext(context);
        if (limiter.IsClientBlocked(requestContext.Tenant.Id, parsed.ClientId))
        {
            await RateLimits.WriteRejectedAsync(context, limiter.IssuanceWindow).ConfigureAwait(false);
            return;
        }

        // The client credentials are not authorization parameters, so they are not stored with the request.
        var parameters = parsed.Form!
            .Where(p => p.Key is not ("client_assertion" or "client_assertion_type"))
            .ToDictionary(p => p.Key, p => p.Value.ToString(), StringComparer.Ordinal);
        var result = await pushed.PushAsync(
            requestContext,
            new PushRequest(
                parsed.ClientId,
                parsed.ClientSecret,
                parameters,
                dpopHeaders.Count == 1 ? dpopHeaders[0] ?? string.Empty : null,
                parsed.ClientAssertion),
            context.RequestAborted).ConfigureAwait(false);

        if (!result.IsSuccess)
        {
            await RefuseAsync(context, limiter, logger, result.Error).ConfigureAwait(false);
            return;
        }

        limiter.RecordIssued(requestContext.Tenant.Id, parsed.ClientId!);

        // RFC 9126, section 2.2: 201 with the reference and its lifetime. A cache must not keep a request_uri.
        OAuthResponses.NoStore(context.Response);
        context.Response.StatusCode = StatusCodes.Status201Created;
        await context.Response.WriteAsJsonAsync(new Body(result.Value.RequestUri, result.Value.ExpiresIn), context.RequestAborted).ConfigureAwait(false);
    }

    private static Task RefuseAsync(HttpContext context, ClientRateLimiter limiter, ILogger logger, OAuthError error)
    {
        limiter.RecordFailure(context);
        LogRejected(logger, error.Code, error.AuditDetail);
        return OAuthResponses.WriteErrorAsync(context, error);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Pushed authorization request refused: {Error} ({Reason}).")]
    private static partial void LogRejected(ILogger logger, string error, string reason);

    private sealed record Body(
        [property: JsonPropertyName("request_uri")] string RequestUri,
        [property: JsonPropertyName("expires_in")] int ExpiresIn);
}
