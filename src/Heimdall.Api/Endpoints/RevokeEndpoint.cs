using Heimdall.Api.Hosting;
using Heimdall.Application.Tokens;

namespace Heimdall.Api.Endpoints;

/// <summary>
/// <c>POST /oauth/v1/revoke</c> (RFC 7009). The form and client rules are the same as at <c>/token</c>
/// (<see cref="OAuthFormReader"/>). A success has an empty body.
/// </summary>
internal static partial class RevokeEndpoint
{
    public const string Path = "/oauth/v1/revoke";

    public static async Task HandleAsync(HttpContext context, TokenRevocation revocation, ClientRateLimiter limiter, ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(typeof(RevokeEndpoint));

        // The same failure budget as /token: /revoke authenticates clients too, so it must not be a second guessing door.
        if (limiter.IsIpBlocked(context))
        {
            await RateLimits.WriteRejectedAsync(context, limiter.FailureWindow).ConfigureAwait(false);
            return;
        }

        var parsed = await OAuthFormReader.ReadAsync(context).ConfigureAwait(false);
        if (parsed.Error is { } error)
        {
            limiter.RecordFailure(context);
            LogRejected(logger, error.Code, error.AuditDetail ?? string.Empty);
            await OAuthResponses.WriteErrorAsync(context, error).ConfigureAwait(false);
            return;
        }

        var result = await revocation.RevokeAsync(
            TenantResolutionMiddleware.GetRequestContext(context),
            new RevocationRequest(parsed.ClientId, parsed.ClientSecret, OAuthFormReader.NullIfEmpty(parsed.Form!["token"]), parsed.ClientAssertion),
            context.RequestAborted).ConfigureAwait(false);

        if (!result.IsSuccess)
        {
            limiter.RecordFailure(context);
            await OAuthResponses.WriteErrorAsync(context, result.Error).ConfigureAwait(false);
            return;
        }

        // The outcome goes to the log, never to the response (RFC 7009, section 2.2).
        LogRevoked(logger, result.Value);
        OAuthResponses.NoStore(context.Response);
        context.Response.StatusCode = StatusCodes.Status200OK;
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Revocation request refused: {Error} ({Reason}).")]
    private static partial void LogRejected(ILogger logger, string error, string reason);

    [LoggerMessage(Level = LogLevel.Information, Message = "Revocation request handled: {Outcome}.")]
    private static partial void LogRevoked(ILogger logger, RevocationOutcome outcome);
}
