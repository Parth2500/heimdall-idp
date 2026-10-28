using System.Net.Http.Headers;
using System.Text;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Primitives;

namespace Heimdall.Api.Endpoints;

/// <summary>
/// Reads the form body and the client credentials of a client request to <c>/token</c> or <c>/revoke</c>. Both endpoints
/// use the same rules, so a request that one endpoint refuses, the other endpoint refuses too. No check needs the
/// database, so a malformed request is cheap to reject.
/// </summary>
internal static class OAuthFormReader
{
    // A client request is a few short parameters. These limits stop a large body before it is parsed.
    private const long MaxBodyBytes = 16 * 1024;

    private static readonly FormOptions FormLimits = new()
    {
        ValueCountLimit = 16,
        KeyLengthLimit = 64,
        ValueLengthLimit = 4096,
        MultipartBodyLengthLimit = 0,
    };

    // Stryker disable once Boolean : the identifier applies to encoding only, and this reader only decodes.
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static async Task<OAuthForm> ReadAsync(HttpContext context)
    {
        var request = context.Request;

        // Proxies and access logs keep query strings. Credentials and tokens must never travel there.
        if (request.QueryString.HasValue)
        {
            return OAuthForm.Fail(OAuthError.InvalidRequest("query string present"));
        }

        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var mediaType)
            || !string.Equals(mediaType.MediaType, "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            return OAuthForm.Fail(OAuthError.InvalidRequest("content type is not form-urlencoded"));
        }

        // RFC 6749, appendix B: the form is UTF-8. The form reader decodes with the charset that the client names, and
        // some charsets (UTF-7) make it throw. Any other charset is refused before the body is read.
        if (mediaType.CharSet is { } charset && !string.Equals(charset.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase))
        {
            return OAuthForm.Fail(OAuthError.InvalidRequest("charset is not UTF-8"));
        }

        if (request.ContentLength is > MaxBodyBytes)
        {
            return OAuthForm.Fail(OAuthError.InvalidRequest("body too large"));
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
            // Over a limit, or a NUL character in a key or value, which ASP.NET Core refuses.
            return OAuthForm.Fail(OAuthError.InvalidRequest("form malformed or over limits"));
        }
        catch (BadHttpRequestException)
        {
            return OAuthForm.Fail(OAuthError.InvalidRequest("body over limits"));
        }

        // A repeated parameter makes the request ambiguous (RFC 6749, section 3.2; RFC 7009, section 2.1).
        if (form.Any(p => p.Value.Count > 1))
        {
            return OAuthForm.Fail(OAuthError.InvalidRequest("repeated parameter"));
        }

        // D10: confidential clients use client_secret_basic only. A secret in the body is another method.
        if (form.ContainsKey("client_secret"))
        {
            return OAuthForm.Fail(OAuthError.InvalidRequest("client_secret_post not supported"));
        }

        var basic = ParseBasic(request.Headers.Authorization);
        if (basic.Error is { } basicError)
        {
            return OAuthForm.Fail(basicError);
        }

        var bodyClientId = NullIfEmpty(form["client_id"]);
        var assertionType = NullIfEmpty(form["client_assertion_type"]);
        var assertion = NullIfEmpty(form["client_assertion"]);
        if (assertionType is not null || assertion is not null)
        {
            return ReadAssertion(context, form, basic, bodyClientId, assertionType, assertion);
        }

        // A public client sends client_id in the body only.
        if (basic.ClientId is null)
        {
            return new OAuthForm(form, bodyClientId, null, null);
        }

        // A confidential client may repeat its client_id in the body, but only the same value.
        if (bodyClientId is not null && !string.Equals(basic.ClientId, bodyClientId, StringComparison.Ordinal))
        {
            return OAuthForm.Fail(OAuthError.InvalidRequest("client_id in body differs from the header"));
        }

        return new OAuthForm(form, basic.ClientId, basic.ClientSecret, null);
    }

    /// <summary>
    /// D45: <c>private_key_jwt</c> (RFC 7523, section 2.2). The client ID comes from the body, or else from the
    /// assertion's <c>sub</c>. That value is not verified yet: it only names the client for the rate limit check, which
    /// takes a permit only after a success. <see cref="Heimdall.Application.Clients.ClientAuthenticator"/> verifies it.
    /// </summary>
    private static OAuthForm ReadAssertion(
        HttpContext context,
        IFormCollection form,
        BasicCredentials basic,
        string? bodyClientId,
        string? assertionType,
        string? assertion)
    {
        if (assertionType is null || assertion is null)
        {
            return OAuthForm.Fail(OAuthError.InvalidRequest("client_assertion without client_assertion_type, or the reverse"));
        }

        if (!string.Equals(assertionType, ClientAssertionTypes.JwtBearer, StringComparison.Ordinal))
        {
            return OAuthForm.Fail(OAuthError.InvalidClient("client_assertion_type not supported"));
        }

        // RFC 6749, section 2.3: one authentication method in a request.
        if (basic.ClientId is not null)
        {
            return OAuthForm.Fail(OAuthError.InvalidRequest("Basic header and client_assertion in one request"));
        }

        var assertedId = context.RequestServices.GetRequiredService<IClientAssertionValidator>().ReadClientId(assertion);
        if (assertedId is null)
        {
            return OAuthForm.Fail(OAuthError.InvalidClient("client_assertion unreadable"));
        }

        return new OAuthForm(form, bodyClientId ?? assertedId, null, null, assertion);
    }

    public static string? NullIfEmpty(StringValues value) => StringValues.IsNullOrEmpty(value) ? null : value.ToString();

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

    private sealed record BasicCredentials(string? ClientId, string? ClientSecret, OAuthError? Error)
    {
        public static BasicCredentials Fail(OAuthError error) => new(null, null, error);
    }
}

/// <summary>
/// A parsed client request: the form, the client ID, and the secret from the Basic header or the client assertion. Or
/// an error.
/// </summary>
internal sealed record OAuthForm(IFormCollection? Form, string? ClientId, string? ClientSecret, OAuthError? Error, string? ClientAssertion = null)
{
    public static OAuthForm Fail(OAuthError error) => new(null, null, null, error);
}
