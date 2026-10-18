using System.Text.Json;
using System.Text.Json.Serialization;
using Heimdall.Application.Common;
using Heimdall.Application.Tokens;

namespace Heimdall.Api.Endpoints;

/// <summary>Writes OAuth responses (RFC 6749, sections 5.1 and 5.2).</summary>
internal static class OAuthResponses
{
    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    /// <summary>
    /// D6: a token response and its errors must never be cached by a browser or proxy. Call it before the body.
    /// </summary>
    public static void NoStore(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";
    }

    /// <summary>
    /// Writes <c>{"error": "..."}</c> only. The reason is never in the response (D5). It goes to the audit log.
    /// <c>invalid_client</c> returns 401 with a Basic challenge (RFC 6749, section 5.2). Other errors return 400.
    /// </summary>
    public static Task WriteErrorAsync(HttpContext context, OAuthError error)
    {
        NoStore(context.Response);
        if (error.Code == OAuthError.InvalidClientCode)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.WWWAuthenticate = "Basic";
        }
        else
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
        }

        return context.Response.WriteAsJsonAsync(new ErrorBody(error.Code), Json, context.RequestAborted);
    }

    public static Task WriteTokenAsync(HttpContext context, TokenResponse token)
    {
        NoStore(context.Response);
        context.Response.StatusCode = StatusCodes.Status200OK;
        return context.Response.WriteAsJsonAsync(
            new TokenBody(
                token.AccessToken,
                token.TokenType,
                token.ExpiresIn,
                string.IsNullOrEmpty(token.Scope) ? null : token.Scope,
                token.RefreshToken,
                token.IdToken),
            Json,
            context.RequestAborted);
    }

    private sealed record ErrorBody([property: JsonPropertyName("error")] string Error);

    private sealed record TokenBody(
        [property: JsonPropertyName("access_token")] string AccessToken,
        [property: JsonPropertyName("token_type")] string TokenType,
        [property: JsonPropertyName("expires_in")] int ExpiresIn,
        [property: JsonPropertyName("scope")] string? Scope,
        [property: JsonPropertyName("refresh_token")] string? RefreshToken,
        [property: JsonPropertyName("id_token")] string? IdToken);
}
