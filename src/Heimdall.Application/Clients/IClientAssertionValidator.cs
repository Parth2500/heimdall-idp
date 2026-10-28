using Heimdall.Application.Common;
using Heimdall.Domain.Clients;

namespace Heimdall.Application.Clients;

/// <summary>The <c>client_assertion_type</c> of a JWT client assertion (RFC 7523, section 2.2).</summary>
public static class ClientAssertionTypes
{
    public const string JwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /// <summary>D48: the signature algorithms of a client assertion. Discovery lists the same values.</summary>
    public static readonly IReadOnlyList<string> SupportedAlgorithms = ["RS256", "PS256", "ES256"];

    /// <summary>D48: the longest time from now to <c>exp</c>. A short life keeps the replay store small.</summary>
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromMinutes(5);

    /// <summary>D48: the clock difference allowed for <c>iat</c> and <c>nbf</c> in the future, and for <c>exp</c>.</summary>
    public static readonly TimeSpan MaxClockDifference = TimeSpan.FromSeconds(60);
}

/// <summary>A client assertion whose signature, claims, and lifetime are valid (D48).</summary>
/// <param name="Jti">The assertion's ID. It works once for the client (D49).</param>
/// <param name="ExpiresAt">The <c>exp</c> claim. The replay record must live until then.</param>
public sealed record ClientAssertion(string Jti, DateTimeOffset ExpiresAt);

/// <summary>Checks a <c>private_key_jwt</c> client assertion. It reads no database.</summary>
public interface IClientAssertionValidator
{
    /// <summary>
    /// The <c>sub</c> claim, read without a signature check, so the authenticator can find the client when the body
    /// has no <c>client_id</c>. <see cref="Validate"/> checks the signature and the claims later. Null when unreadable.
    /// </summary>
    string? ReadClientId(string assertion);

    /// <summary>
    /// Checks the assertion against the client's registered keys (D46) and the claim rules of D48: <c>iss</c> and
    /// <c>sub</c> are the client ID, <c>aud</c> is exactly the issuer, <c>exp</c> is in the future and at most
    /// <see cref="ClientAssertionTypes.MaxLifetime"/> away, and <c>jti</c> is present.
    /// </summary>
    Result<ClientAssertion> Validate(string assertion, Client client, string issuer);
}

/// <summary>Remembers each client assertion until its <c>exp</c> (D49).</summary>
public interface IClientAssertionReplayStore
{
    /// <summary>
    /// One atomic statement. True when the assertion is new. False when this client already used the <c>jti</c>: a
    /// replay. Two servers that see one assertion at the same time get one true and one false.
    /// </summary>
    Task<bool> TryUseAsync(Guid tenantId, Guid clientPk, ClientAssertion assertion, CancellationToken cancellationToken);
}
