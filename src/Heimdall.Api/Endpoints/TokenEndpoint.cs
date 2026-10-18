using System.Net.Http.Headers;
using System.Text;
using Heimdall.Api.Hosting;
using Heimdall.Application.Common;
using Heimdall.Application.Tokens;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Primitives;

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

    // A token request is a few short parameters. These limits stop a large body before it is parsed.
    private const long MaxBodyBytes = 16 * 1024;

    private static readonly FormOptions FormLimits = new()
    {
        ValueCountLimit = 16,
        KeyLengthLimit = 64,
        ValueLengthLimit = 4096,
        MultipartBodyLengthLimit = 0,
    };

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static async Task HandleAsync(
        HttpContext context,
        ClientCredentialsGrant clientCredentials,
        AuthorizationCodeGrant authorizationCode,
        RefreshTokenGrant refreshToken,
        ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(typeof(TokenEndpoint));
        var parsed = await ParseAsync(context).ConfigureAwait(false);
        if (parsed.Error is { } error)
        {
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
                    new ClientCredentialsRequest(parsed.ClientId, parsed.ClientSecret, NullIfEmpty(form["scope"]), NullIfEmpty(form["resource"])),
                    context.RequestAborted).ConfigureAwait(false);
                break;

            case "authorization_code":
                result = await authorizationCode.HandleAsync(
                    requestContext,
                    new AuthorizationCodeRequest(
                        parsed.ClientId,
                        parsed.ClientSecret,
                        NullIfEmpty(form["code"]),
                        NullIfEmpty(form["code_verifier"]),
                        NullIfEmpty(form["redirect_uri"]),
                        NullIfEmpty(form["resource"])),
                    context.RequestAborted).ConfigureAwait(false);
                break;

            case "refresh_token":
                result = await refreshToken.HandleAsync(
                    requestContext,
                    new RefreshTokenRequest(
                        parsed.ClientId,
                        parsed.ClientSecret,
                        NullIfEmpty(form["refresh_token"]),
                        NullIfEmpty(form["scope"]),
                        NullIfEmpty(form["resource"])),
                    context.RequestAborted).ConfigureAwait(false);
                break;

            default:
                var unsupported = OAuthError.UnsupportedGrantType("grant type not supported");
                LogRejected(logger, unsupported.Code, unsupported.AuditDetail!);
                await OAuthResponses.WriteErrorAsync(context, unsupported).ConfigureAwait(false);
                return;
        }

        if (result.IsSuccess)
        {
            await OAuthResponses.WriteTokenAsync(context, result.Value).ConfigureAwait(false);
        }
        else
        {
            await OAuthResponses.WriteErrorAsync(context, result.Error).ConfigureAwait(false);
        }
    }

    private static async Task<ParsedRequest> ParseAsync(HttpContext context)
    {
        var request = context.Request;

        // Proxies and access logs keep query strings. Credentials must never travel there.
        if (request.QueryString.HasValue)
        {
            return ParsedRequest.Fail(OAuthError.InvalidRequest("query string present"));
        }

        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var mediaType)
            || !string.Equals(mediaType.MediaType, "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            return ParsedRequest.Fail(OAuthError.InvalidRequest("content type is not form-urlencoded"));
        }

        if (request.ContentLength is > MaxBodyBytes)
        {
            return ParsedRequest.Fail(OAuthError.InvalidRequest("body too large"));
        }

        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } sizeFeature)
        {
            sizeFeature.MaxRequestBodySize = MaxBodyBytes;
        }

        IFormCollection form;
        try
        {
            context.Features.Set<IFormFeature>(new FormFeature(request, FormLimits));
            form = await request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
        }
        catch (InvalidDataException)
        {
            return ParsedRequest.Fail(OAuthError.InvalidRequest("form over limits"));
        }
        catch (BadHttpRequestException)
        {
            return ParsedRequest.Fail(OAuthError.InvalidRequest("body over limits"));
        }

        // A repeated parameter makes the request ambiguous (RFC 6749, section 3.2).
        if (form.Any(p => p.Value.Count > 1))
        {
            return ParsedRequest.Fail(OAuthError.InvalidRequest("repeated parameter"));
        }

        if (string.IsNullOrEmpty(form["grant_type"]))
        {
            return ParsedRequest.Fail(OAuthError.InvalidRequest("grant_type missing"));
        }

        // D10: confidential clients use client_secret_basic only. A secret in the body is another method.
        if (form.ContainsKey("client_secret"))
        {
            return ParsedRequest.Fail(OAuthError.InvalidRequest("client_secret_post not supported"));
        }

        var basic = ParseBasic(request.Headers.Authorization);
        if (basic.Error is { } basicError)
        {
            return ParsedRequest.Fail(basicError);
        }

        var bodyClientId = NullIfEmpty(form["client_id"]);
        if (basic.ClientId is not null && bodyClientId is not null && !string.Equals(basic.ClientId, bodyClientId, StringComparison.Ordinal))
        {
            return ParsedRequest.Fail(OAuthError.InvalidRequest("client_id in body differs from the header"));
        }

        return new ParsedRequest(form, basic.ClientId ?? bodyClientId, basic.ClientSecret, null);
    }

    /// <summary>
    /// RFC 6749, section 2.3.1: the client ID and secret are form-urlencoded, then joined with a colon, then
    /// base64-encoded (RFC 7617). A client ID or secret can therefore contain a colon.
    /// </summary>
    private static BasicCredentials ParseBasic(StringValues header)
    {
        if (header.Count == 0)
        {
            return new BasicCredentials(null, null, null);
        }

        if (header.Count > 1)
        {
            return BasicCredentials.Fail(OAuthError.InvalidRequest("repeated Authorization header"));
        }

        var value = header[0]!;
        const string Scheme = "Basic ";
        if (!value.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
        {
            return BasicCredentials.Fail(OAuthError.InvalidClient("authorization scheme is not Basic"));
        }

        string decoded;
        try
        {
            decoded = StrictUtf8.GetString(Convert.FromBase64String(value[Scheme.Length..].Trim()));
        }
        catch (FormatException)
        {
            return BasicCredentials.Fail(OAuthError.InvalidClient("Basic credentials are not base64"));
        }
        catch (ArgumentException)
        {
            return BasicCredentials.Fail(OAuthError.InvalidClient("Basic credentials are not UTF-8"));
        }

        var colon = decoded.IndexOf(':', StringComparison.Ordinal);
        if (colon <= 0)
        {
            return BasicCredentials.Fail(OAuthError.InvalidClient("Basic credentials have no client ID"));
        }

        return new BasicCredentials(FormDecode(decoded[..colon]), FormDecode(decoded[(colon + 1)..]), null);
    }

    // application/x-www-form-urlencoded: '+' is a space, then percent-decoding.
    private static string FormDecode(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));

    private static string? NullIfEmpty(StringValues value) => StringValues.IsNullOrEmpty(value) ? null : value.ToString();

    [LoggerMessage(Level = LogLevel.Information, Message = "Token request refused: {Error} ({Reason}).")]
    private static partial void LogRejected(ILogger logger, string error, string reason);

    private sealed record ParsedRequest(IFormCollection? Form, string? ClientId, string? ClientSecret, OAuthError? Error)
    {
        public static ParsedRequest Fail(OAuthError error) => new(null, null, null, error);
    }

    private sealed record BasicCredentials(string? ClientId, string? ClientSecret, OAuthError? Error)
    {
        public static BasicCredentials Fail(OAuthError error) => new(null, null, error);
    }
}
