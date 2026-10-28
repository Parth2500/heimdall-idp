using System.Text.Json;
using System.Text.Json.Serialization;
using Heimdall.Api.Hosting;
using Heimdall.Application.Tokens;

namespace Heimdall.Api.Endpoints;

/// <summary>
/// <c>POST /oauth/v1/introspect</c> (RFC 7662, D36 to D39). The form and client rules are the same as at <c>/token</c>
/// and <c>/revoke</c> (<see cref="OAuthFormReader"/>). The logic is in <see cref="TokenIntrospection"/>.
/// </summary>
internal static partial class IntrospectionEndpoint
{
    public const string Path = "/oauth/v1/introspect";

    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public static async Task HandleAsync(HttpContext context, TokenIntrospection introspection, ClientRateLimiter limiter, ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(typeof(IntrospectionEndpoint));

        // The failure budget of /token and /revoke: /introspect authenticates clients too.
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

        var result = await introspection.IntrospectAsync(
            TenantResolutionMiddleware.GetRequestContext(context),
            new IntrospectionRequest(parsed.ClientId, parsed.ClientSecret, OAuthFormReader.NullIfEmpty(parsed.Form!["token"]), parsed.ClientAssertion),
            context.RequestAborted).ConfigureAwait(false);

        if (!result.IsSuccess)
        {
            limiter.RecordFailure(context);
            LogRejected(logger, result.Error.Code, result.Error.AuditDetail ?? string.Empty);
            await OAuthResponses.WriteErrorAsync(context, result.Error).ConfigureAwait(false);
            return;
        }

        // D39: a resource server must not keep an old answer.
        OAuthResponses.NoStore(context.Response);
        await context.Response.WriteAsJsonAsync(Body.From(result.Value), Json, context.RequestAborted).ConfigureAwait(false);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Introspection request refused: {Error} ({Reason}).")]
    private static partial void LogRejected(ILogger logger, string error, string reason);

    /// <summary>RFC 7662, section 2.2. Times are NumericDate seconds. An inactive answer is <c>{"active":false}</c>.</summary>
    private sealed record Body(
        [property: JsonPropertyName("active")] bool Active,
        [property: JsonPropertyName("scope")] string? Scope,
        [property: JsonPropertyName("client_id")] string? ClientId,
        [property: JsonPropertyName("sub")] string? Subject,
        [property: JsonPropertyName("aud")] string? Audience,
        [property: JsonPropertyName("iss")] string? Issuer,
        [property: JsonPropertyName("exp")] long? ExpiresAt,
        [property: JsonPropertyName("iat")] long? IssuedAt,
        [property: JsonPropertyName("token_type")] string? TokenType,
        [property: JsonPropertyName("cnf")] Confirmation? Cnf)
    {
        public static Body From(IntrospectionResult result) => new(
            result.Active,
            result.Scope,
            result.ClientId,
            result.Subject,
            result.Audience,
            result.Issuer,
            result.ExpiresAt?.ToUnixTimeSeconds(),
            result.IssuedAt?.ToUnixTimeSeconds(),
            result.TokenType,
            result.KeyThumbprint is { } jkt ? new Confirmation(jkt) : null);
    }

    private sealed record Confirmation([property: JsonPropertyName("jkt")] string Jkt);
}
