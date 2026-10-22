using System.Net.Http.Headers;
using System.Text;
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

        // A public client sends client_id in the body only.
        var bodyClientId = NullIfEmpty(form["client_id"]);
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

/// <summary>A parsed client request: the form, the client ID, and the secret from the Basic header. Or an error.</summary>
internal sealed record OAuthForm(IFormCollection? Form, string? ClientId, string? ClientSecret, OAuthError? Error)
{
    public static OAuthForm Fail(OAuthError error) => new(null, null, null, error);
}
