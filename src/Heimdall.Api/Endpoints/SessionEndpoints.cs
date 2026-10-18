using System.Text.Json;
using System.Text.Json.Serialization;
using Heimdall.Api.Hosting;
using Heimdall.Application.Common;
using Heimdall.Application.Sessions;
using Heimdall.Application.Users;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http.Features;

namespace Heimdall.Api.Endpoints;

/// <summary>
/// The login API for the Angular login page, on the tenant origin (D21). It sets the session cookie (D11 to D13).
/// </summary>
/// <remarks>
/// CSRF defense has three layers. (1) An antiforgery double-submit token: the page reads <see cref="XsrfCookie"/>
/// and sends it in <see cref="XsrfHeader"/>, as Angular's HttpClient does. (2) JSON bodies only: a cross-site HTML form
/// cannot send JSON, and a cross-site script that sends JSON needs a CORS preflight, which Heimdall never allows.
/// (3) The Origin header, when the browser sends one, must be the tenant's own origin.
/// </remarks>
internal static partial class SessionEndpoints
{
    public const string Prefix = "/session/v1";

    /// <summary>D11: <c>__Host-</c> means Secure, Path=/, and no Domain, so no subdomain can set or read it.</summary>
    public const string SessionCookie = "__Host-Heimdall.Session";

    /// <summary>The antiforgery request token. Readable by the page script, by design of the double-submit pattern.</summary>
    public const string XsrfCookie = "__Host-XSRF-TOKEN";

    public const string XsrfHeader = "X-XSRF-TOKEN";

    /// <summary>The antiforgery cookie token. HttpOnly. The framework compares it with the request token.</summary>
    public const string AntiforgeryCookie = "__Host-Heimdall.Antiforgery";

    private const long MaxBodyBytes = 4 * 1024;

    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public static void Map(WebApplication app)
    {
        var group = app.MapGroup(Prefix);
        group.MapGet("/csrf", Csrf);
        group.MapPost("/login", LoginAsync);
        group.MapPost("/logout", LogoutAsync);
        group.MapGet("/me", MeAsync);
    }

    /// <summary>Issues the antiforgery tokens. The page calls it before the login form.</summary>
    private static IResult Csrf(HttpContext context, IAntiforgery antiforgery)
    {
        OAuthResponses.NoStore(context.Response);
        var tokens = antiforgery.GetAndStoreTokens(context);
        context.Response.Cookies.Append(XsrfCookie, tokens.RequestToken!, new CookieOptions
        {
            HttpOnly = false,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/",
        });
        return Results.NoContent();
    }

    private static async Task<IResult> LoginAsync(HttpContext context, IAntiforgery antiforgery, SessionService sessions, ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(typeof(SessionEndpoints));
        OAuthResponses.NoStore(context.Response);

        if (await RefuseBrowserRequestAsync(context, antiforgery, logger).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        LoginBody? body;
        try
        {
            body = await context.Request.ReadFromJsonAsync<LoginBody>(Json, context.RequestAborted).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is JsonException or BadHttpRequestException)
        {
            LogRefused(logger, "malformed or oversized body");
            return Error(StatusCodes.Status400BadRequest, "invalid_request");
        }

        SignInResult result;
        try
        {
            result = await sessions.SignInAsync(
                TenantResolutionMiddleware.GetRequestContext(context),
                body?.Email,
                body?.Password,
                context.Request.Cookies[SessionCookie],
                context.RequestAborted).ConfigureAwait(false);
        }
        catch (PasswordHasherBusyException)
        {
            context.Response.Headers.RetryAfter = "5";
            return Error(StatusCodes.Status503ServiceUnavailable, "temporarily_unavailable");
        }

        if (!result.Succeeded)
        {
            // One answer for an unknown email, a wrong password, and a disabled account.
            return Error(StatusCodes.Status401Unauthorized, "invalid_credentials");
        }

        context.Response.Cookies.Append(SessionCookie, result.SessionId!, SessionCookieOptions());
        return Results.NoContent();
    }

    private static async Task<IResult> LogoutAsync(HttpContext context, IAntiforgery antiforgery, SessionService sessions, ILoggerFactory loggers)
    {
        OAuthResponses.NoStore(context.Response);

        // Logout needs the same CSRF checks: a cross-site page must not be able to sign the user out.
        if (await RefuseBrowserRequestAsync(context, antiforgery, loggers.CreateLogger(typeof(SessionEndpoints)), requireJson: false)
            .ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        await sessions.SignOutAsync(
            TenantResolutionMiddleware.GetRequestContext(context),
            context.Request.Cookies[SessionCookie],
            context.RequestAborted).ConfigureAwait(false);

        context.Response.Cookies.Delete(SessionCookie, SessionCookieOptions());
        return Results.NoContent();
    }

    /// <summary>Who is signed in, for the page. Same origin only: Heimdall sends no CORS headers.</summary>
    private static async Task<IResult> MeAsync(HttpContext context, SessionService sessions)
    {
        OAuthResponses.NoStore(context.Response);
        var valid = await sessions.ValidateAsync(
            TenantResolutionMiddleware.GetRequestContext(context),
            context.Request.Cookies[SessionCookie],
            context.RequestAborted).ConfigureAwait(false);

        return valid is null
            ? Error(StatusCodes.Status401Unauthorized, "no_session")
            : Results.Json(
                new MeBody(valid.User.Id.ToString(), valid.User.Email, valid.Session.AuthTime.ToUnixTimeSeconds()),
                Json);
    }

    private static CookieOptions SessionCookieOptions() => new()
    {
        HttpOnly = true,
        Secure = true,

        // Lax, not Strict: a client sends the user to /authorize by a cross-site top-level navigation (D11).
        SameSite = SameSiteMode.Lax,
        Path = "/",

        // No Expires: the cookie ends with the browser. The server enforces the idle and absolute limits.
    };

    /// <summary>The CSRF checks for a state-changing browser request. Returns the refusal, or null to continue.</summary>
    private static async Task<IResult?> RefuseBrowserRequestAsync(
        HttpContext context,
        IAntiforgery antiforgery,
        ILogger logger,
        bool requireJson = true)
    {
        var request = context.Request;
        var expectedOrigin = TenantResolutionMiddleware.GetRequestContext(context).Issuer;
        var origin = request.Headers.Origin.ToString();
        if (origin.Length > 0 && !string.Equals(origin, expectedOrigin, StringComparison.Ordinal))
        {
            LogRefused(logger, "foreign Origin");
            return Error(StatusCodes.Status403Forbidden, "invalid_request");
        }

        if (requireJson && !request.HasJsonContentType())
        {
            LogRefused(logger, "not JSON");
            return Error(StatusCodes.Status415UnsupportedMediaType, "invalid_request");
        }

        if (request.ContentLength is > MaxBodyBytes)
        {
            LogRefused(logger, "body too large");
            return Error(StatusCodes.Status400BadRequest, "invalid_request");
        }

        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } sizeFeature)
        {
            sizeFeature.MaxRequestBodySize = MaxBodyBytes;
        }

        try
        {
            await antiforgery.ValidateRequestAsync(context).ConfigureAwait(false);
        }
        catch (AntiforgeryValidationException)
        {
            LogRefused(logger, "antiforgery token missing or wrong");
            return Error(StatusCodes.Status403Forbidden, "invalid_request");
        }

        return null;
    }

    private static IResult Error(int status, string code) => Results.Json(new ErrorBody(code), Json, statusCode: status);

    [LoggerMessage(Level = LogLevel.Information, Message = "Session request refused: {Reason}.")]
    private static partial void LogRefused(ILogger logger, string reason);

    private sealed record LoginBody(
        [property: JsonPropertyName("email")] string? Email,
        [property: JsonPropertyName("password")] string? Password);

    private sealed record MeBody(
        [property: JsonPropertyName("sub")] string Sub,
        [property: JsonPropertyName("email")] string Email,
        [property: JsonPropertyName("auth_time")] long AuthTime);

    private sealed record ErrorBody([property: JsonPropertyName("error")] string Error);
}
