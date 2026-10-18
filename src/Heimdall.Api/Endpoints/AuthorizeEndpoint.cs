using System.Text;
using Heimdall.Api.Hosting;
using Heimdall.Application.Authorization;
using Heimdall.Application.Common;
using Microsoft.Extensions.Options;

namespace Heimdall.Api.Endpoints;

/// <summary>Where the browser goes for the Angular pages. The pages get the stored request ID only.</summary>
public sealed class UiOptions
{
    public const string SectionName = "Heimdall:Ui";

    public string LoginPath { get; set; } = "/login";

    public string ConsentPath { get; set; } = "/consent";
}

/// <summary>
/// <c>GET /oauth/v1/authorize</c> and <c>GET /oauth/v1/authorize/resume</c>. The logic is in
/// <see cref="AuthorizationService"/>. This class turns its outcome into a browser response.
/// </summary>
internal static partial class AuthorizeEndpoint
{
    public const string Path = "/oauth/v1/authorize";
    public const string ResumePath = "/oauth/v1/authorize/resume";

    public static void Map(WebApplication app)
    {
        app.MapGet(Path, AuthorizeAsync);
        app.MapGet(ResumePath, ResumeAsync);
    }

    private static async Task AuthorizeAsync(HttpContext context, AuthorizationService authorization, IOptions<UiOptions> ui, ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(typeof(AuthorizeEndpoint));

        // A repeated parameter makes the request ambiguous (RFC 6749, section 3.1). It could be client_id or
        // redirect_uri, so the error is never redirected.
        if (context.Request.Query.Any(p => p.Value.Count > 1))
        {
            await WriteAsync(context, new AuthorizeErrorPage(OAuthError.InvalidRequestCode, "repeated parameter"), ui.Value, logger).ConfigureAwait(false);
            return;
        }

        var parameters = context.Request.Query.ToDictionary(p => p.Key, p => p.Value.ToString(), StringComparer.Ordinal);
        var outcome = await authorization.AuthorizeAsync(
            TenantResolutionMiddleware.GetRequestContext(context),
            parameters,
            context.Request.Cookies[SessionEndpoints.SessionCookie],
            context.RequestAborted).ConfigureAwait(false);

        await WriteAsync(context, outcome, ui.Value, logger).ConfigureAwait(false);
    }

    /// <summary>The login page sends the browser here after sign-in, with the stored request ID and nothing else.</summary>
    private static async Task ResumeAsync(HttpContext context, AuthorizationService authorization, IOptions<UiOptions> ui, ILoggerFactory loggers)
    {
        var outcome = await authorization.ResumeAsync(
            TenantResolutionMiddleware.GetRequestContext(context),
            context.Request.Query["request_id"].Count == 1 ? context.Request.Query["request_id"].ToString() : null,
            context.Request.Cookies[SessionEndpoints.SessionCookie],
            context.RequestAborted).ConfigureAwait(false);

        await WriteAsync(context, outcome, ui.Value, loggers.CreateLogger(typeof(AuthorizeEndpoint))).ConfigureAwait(false);
    }

    private static Task WriteAsync(HttpContext context, AuthorizeOutcome outcome, UiOptions ui, ILogger logger)
    {
        // A redirect can carry a code. No browser or proxy may keep it (D6).
        OAuthResponses.NoStore(context.Response);

        switch (outcome)
        {
            case AuthorizeErrorPage page:
                // The Angular error page comes later. Until then, a JSON body with the code only (D5).
                LogRefused(logger, page.Error, page.Reason);
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return context.Response.WriteAsJsonAsync(new { error = page.Error }, context.RequestAborted);

            case AuthorizeRedirect redirect:
                if (redirect.Reason is { } reason)
                {
                    LogRefused(logger, redirect.Parameters[0].Value, reason);
                }

                return Redirect(context, AppendQuery(redirect.RedirectUri, redirect.Parameters));

            case AuthorizeLogin login:
                return Redirect(context, AppendQuery(ui.LoginPath, [new("request_id", login.RequestId.ToString())]));

            case AuthorizeConsent consent:
                return Redirect(context, AppendQuery(ui.ConsentPath, [new("request_id", consent.RequestId.ToString())]));

            default:
                throw new InvalidOperationException($"Unknown outcome {outcome.GetType().Name}.");
        }
    }

    private static Task Redirect(HttpContext context, string location)
    {
        context.Response.StatusCode = StatusCodes.Status302Found;
        context.Response.Headers.Location = location;
        return Task.CompletedTask;
    }

    /// <summary>Adds parameters to a URI that may already have a query. A registered URI has no fragment.</summary>
    private static string AppendQuery(string uri, IEnumerable<KeyValuePair<string, string>> parameters)
    {
        var builder = new StringBuilder(uri);
        var separator = uri.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        foreach (var (name, value) in parameters)
        {
            builder.Append(separator).Append(Uri.EscapeDataString(name)).Append('=').Append(Uri.EscapeDataString(value));
            separator = '&';
        }

        return builder.ToString();
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Authorization request refused: {Error} ({Reason}).")]
    private static partial void LogRefused(ILogger logger, string error, string reason);
}
