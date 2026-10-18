using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Heimdall.Api.Hosting;
using Heimdall.Application.Keys;
using Microsoft.Net.Http.Headers;

namespace Heimdall.Api.Endpoints;

/// <summary>
/// Discovery and JWKS. Resource servers read these often, so both come from memory, never from one database read
/// for each request. A CDN or proxy in front can cache them for <c>max-age</c>.
/// </summary>
internal static class WellKnownEndpoints
{
    public const string DiscoveryPath = "/.well-known/openid-configuration";
    public const string JwksPath = "/.well-known/jwks.json";

    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    /// <summary>
    /// Lists only what Heimdall supports today, so a client never relies on a capability that does not exist.
    /// <c>userinfo_endpoint</c> and the <c>refresh_token</c> grant come with those features.
    /// </summary>
    public static Task DiscoveryAsync(HttpContext context, SigningKeyOptions keyOptions)
    {
        var issuer = TenantResolutionMiddleware.GetRequestContext(context).Issuer;
        var document = new DiscoveryDocument(
            issuer,
            issuer + AuthorizeEndpoint.Path,
            issuer + TokenEndpoint.Path,
            issuer + JwksPath,
            ["code"],
            ["query"],
            ["authorization_code", "client_credentials"],
            ["client_secret_basic", "none"],
            ["S256"],
            ["public"],
            ["RS256"],
            AuthorizationResponseIssParameterSupported: true);

        return WriteCacheableAsync(context, JsonSerializer.SerializeToUtf8Bytes(document, Json), keyOptions.JwksCacheLifetime);
    }

    /// <summary>
    /// The tenant's published keys: pending, active, and retired before removal. Each entry has only public members
    /// (<see cref="RsaPublicJwk"/>).
    /// </summary>
    public static async Task JwksAsync(HttpContext context, ISigningKeyCache keys, SigningKeyOptions keyOptions)
    {
        var tenantId = TenantResolutionMiddleware.GetRequestContext(context).Tenant.Id;
        var published = await keys.GetPublishedKeysAsync(tenantId, context.RequestAborted).ConfigureAwait(false);
        var body = JsonSerializer.SerializeToUtf8Bytes(new JwkSet(published), Json);
        await WriteCacheableAsync(context, body, keyOptions.JwksCacheLifetime).ConfigureAwait(false);
    }

    private static async Task WriteCacheableAsync(HttpContext context, byte[] body, TimeSpan maxAge)
    {
        // A strong ETag from the body. A resource server that sends it back gets 304 and no body.
        var etag = "\"" + Base64Url.EncodeToString(SHA256.HashData(body).AsSpan(0, 16)) + "\"";
        var headers = context.Response.Headers;
        headers.CacheControl = "public, max-age=" + ((long)maxAge.TotalSeconds).ToString(CultureInfo.InvariantCulture);
        headers.ETag = etag;

        if (context.Request.Headers.IfNoneMatch.Any(value => value is not null && value.Split(',').Any(tag => tag.Trim() == etag)))
        {
            context.Response.StatusCode = StatusCodes.Status304NotModified;
            return;
        }

        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "application/json";
        context.Response.ContentLength = body.Length;
        await context.Response.Body.WriteAsync(body, context.RequestAborted).ConfigureAwait(false);
    }

    private sealed record DiscoveryDocument(
        [property: JsonPropertyName("issuer")] string Issuer,
        [property: JsonPropertyName("authorization_endpoint")] string AuthorizationEndpoint,
        [property: JsonPropertyName("token_endpoint")] string TokenEndpoint,
        [property: JsonPropertyName("jwks_uri")] string JwksUri,
        [property: JsonPropertyName("response_types_supported")] string[] ResponseTypesSupported,
        [property: JsonPropertyName("response_modes_supported")] string[] ResponseModesSupported,
        [property: JsonPropertyName("grant_types_supported")] string[] GrantTypesSupported,
        [property: JsonPropertyName("token_endpoint_auth_methods_supported")] string[] TokenEndpointAuthMethodsSupported,
        [property: JsonPropertyName("code_challenge_methods_supported")] string[] CodeChallengeMethodsSupported,
        [property: JsonPropertyName("subject_types_supported")] string[] SubjectTypesSupported,
        [property: JsonPropertyName("id_token_signing_alg_values_supported")] string[] IdTokenSigningAlgValuesSupported,
        [property: JsonPropertyName("authorization_response_iss_parameter_supported")] bool AuthorizationResponseIssParameterSupported);

    private sealed record JwkSet([property: JsonPropertyName("keys")] IReadOnlyList<RsaPublicJwk> Keys);
}
