using Heimdall.Api.Hosting;
using Heimdall.Application.Common;
using Heimdall.Application.Tokens;
using Heimdall.Infrastructure.Telemetry;

namespace Heimdall.Api.Endpoints;

/// <summary>
/// <c>POST /oauth/v1/token</c>: the <c>client_credentials</c>, <c>authorization_code</c>, and <c>refresh_token</c> grants.
/// Every check before the grant runs needs no database, so a malformed request is cheap to reject.
/// </summary>
/// <remarks>
/// These protocol checks are logged, not audited: an audit row is a database write. The grant audits every
/// rejection after it (threat model, /token, Repudiation). No log line here contains a parameter value (D7).
/// </remarks>
internal static partial class TokenEndpoint
{
    public const string Path = "/oauth/v1/token";

    public static async Task HandleAsync(
        HttpContext context,
        ClientCredentialsGrant clientCredentials,
        AuthorizationCodeGrant authorizationCode,
        RefreshTokenGrant refreshToken,
        HeimdallMetrics metrics,
        ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(typeof(TokenEndpoint));
        var parsed = await OAuthFormReader.ReadAsync(context).ConfigureAwait(false);
        if (parsed.Error is null && string.IsNullOrEmpty(parsed.Form!["grant_type"]))
        {
            parsed = OAuthForm.Fail(OAuthError.InvalidRequest("grant_type missing"));
        }

        if (parsed.Error is { } error)
        {
            metrics.TokenRequest(parsed.Form?["grant_type"].ToString(), error.Code);
            LogRejected(logger, error.Code, error.AuditDetail ?? string.Empty);
            await OAuthResponses.WriteErrorAsync(context, error).ConfigureAwait(false);
            return;
        }

        var form = parsed.Form!;
        var requestContext = TenantResolutionMiddleware.GetRequestContext(context);
        Result<TokenResponse> result;
        switch (form["grant_type"].ToString())
        {
            case "client_credentials":
                result = await clientCredentials.HandleAsync(
                    requestContext,
                    new ClientCredentialsRequest(parsed.ClientId, parsed.ClientSecret, OAuthFormReader.NullIfEmpty(form["scope"]), OAuthFormReader.NullIfEmpty(form["resource"])),
                    context.RequestAborted).ConfigureAwait(false);
                break;

            case "authorization_code":
                result = await authorizationCode.HandleAsync(
                    requestContext,
                    new AuthorizationCodeRequest(
                        parsed.ClientId,
                        parsed.ClientSecret,
                        OAuthFormReader.NullIfEmpty(form["code"]),
                        OAuthFormReader.NullIfEmpty(form["code_verifier"]),
                        OAuthFormReader.NullIfEmpty(form["redirect_uri"]),
                        OAuthFormReader.NullIfEmpty(form["resource"])),
                    context.RequestAborted).ConfigureAwait(false);
                break;

            case "refresh_token":
                result = await refreshToken.HandleAsync(
                    requestContext,
                    new RefreshTokenRequest(
                        parsed.ClientId,
                        parsed.ClientSecret,
                        OAuthFormReader.NullIfEmpty(form["refresh_token"]),
                        OAuthFormReader.NullIfEmpty(form["scope"]),
                        OAuthFormReader.NullIfEmpty(form["resource"])),
                    context.RequestAborted).ConfigureAwait(false);
                break;

            default:
                var unsupported = OAuthError.UnsupportedGrantType("grant type not supported");
                metrics.TokenRequest(null, unsupported.Code);
                LogRejected(logger, unsupported.Code, unsupported.AuditDetail!);
                await OAuthResponses.WriteErrorAsync(context, unsupported).ConfigureAwait(false);
                return;
        }

        metrics.TokenRequest(form["grant_type"].ToString(), result.IsSuccess ? "success" : result.Error.Code);
        if (result.IsSuccess)
        {
            await OAuthResponses.WriteTokenAsync(context, result.Value).ConfigureAwait(false);
        }
        else
        {
            await OAuthResponses.WriteErrorAsync(context, result.Error).ConfigureAwait(false);
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Token request refused: {Error} ({Reason}).")]
    private static partial void LogRejected(ILogger logger, string error, string reason);
}
