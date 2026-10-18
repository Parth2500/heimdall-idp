using System.Text.Json.Serialization;
using Heimdall.Api.Hosting;
using Heimdall.Application.UserInfo;
using Microsoft.Extensions.Primitives;

namespace Heimdall.Api.Endpoints;

/// <summary>
/// <c>GET</c> and <c>POST /oauth/v1/userinfo</c> (OpenID Connect Core, section 5.3; POST is required there). The
/// access token comes in the <c>Authorization: Bearer</c> header only. Errors follow RFC 6750, section 3.
/// </summary>
/// <remarks>
/// No CORS headers yet, so a browser blocks cross-origin reads. Registered client origins come with the Angular SPA
/// (threat model, /userinfo, Information disclosure). No log line contains the token (D7).
/// </remarks>
internal static partial class UserInfoApiEndpoint
{
    public static void Map(IEndpointRouteBuilder app) =>
        app.MapMethods(UserInfoEndpoint.Path, [HttpMethods.Get, HttpMethods.Post], HandleAsync);

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

        var token = ReadBearer(context.Request.Headers.Authorization);
        if (token is null)
        {
            // RFC 6750, section 3.1: a request with no credentials gets a challenge with no error code.
            LogRejected(logger, "none", "no bearer token");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.WWWAuthenticate = "Bearer";
            return;
        }

        var result = await userInfo.GetAsync(TenantResolutionMiddleware.GetRequestContext(context), token, context.RequestAborted)
            .ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            LogRejected(logger, result.Error.Code, result.Error.AuditDetail ?? string.Empty);
            var status = result.Error.Code == UserInfoService.InsufficientScopeCode
                ? StatusCodes.Status403Forbidden
                : StatusCodes.Status401Unauthorized;
            await WriteErrorAsync(context, status, result.Error.Code).ConfigureAwait(false);
            return;
        }

        var claims = result.Value;
        context.Response.StatusCode = StatusCodes.Status200OK;
        await context.Response.WriteAsJsonAsync(
            new ClaimsBody(claims.Subject, claims.Email, claims.EmailVerified),
            context.RequestAborted).ConfigureAwait(false);
    }

    /// <summary>One Authorization header with the Bearer scheme and a non-empty token. Anything else is no token.</summary>
    private static string? ReadBearer(StringValues header)
    {
        if (header.Count != 1 || header[0] is not { } value)
        {
            return null;
        }

        const string Scheme = "Bearer ";
        if (!value.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var token = value[Scheme.Length..].Trim();
        return token.Length == 0 ? null : token;
    }

    // The error code is in the challenge and the body. The reason is never in the response (D5).
    private static Task WriteErrorAsync(HttpContext context, int status, string error)
    {
        context.Response.StatusCode = status;
        if (status != StatusCodes.Status400BadRequest)
        {
            context.Response.Headers.WWWAuthenticate = $"Bearer error=\"{error}\"";
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
