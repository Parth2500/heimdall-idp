using System.Security.Cryptography;
using Heimdall.Application.Common;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;

namespace Heimdall.Application.Clients;

/// <summary>
/// Authenticates a client at /token, /revoke, /introspect, and /par (D10, D45). Every failure returns the same
/// <c>invalid_client</c> error (D5). The reason goes to <see cref="OAuthError.AuditDetail"/> only.
/// </summary>
/// <remarks>
/// Each client has exactly one method (D47): <c>none</c> for a public client, <c>client_secret_basic</c> or
/// <c>private_key_jwt</c> for a confidential one. A request with another method fails, also when its credential would be
/// valid for that other method.
/// </remarks>
public sealed class ClientAuthenticator
{
    /// <summary>The most secrets a client can have that are valid at the same time (rotation overlap).</summary>
    public const int MaxValidSecrets = 2;

    // Compared against when the client is unknown or has fewer valid secrets than the maximum.
    // The comparison count is then the same on every path.
    private static readonly TokenHash DummyHash =
        TokenHash.Compute(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));

    private readonly IClientStore _clients;
    private readonly IClientAssertionValidator _assertions;
    private readonly IClientAssertionReplayStore _replay;
    private readonly TimeProvider _time;

    public ClientAuthenticator(
        IClientStore clients,
        IClientAssertionValidator assertions,
        IClientAssertionReplayStore replay,
        TimeProvider time)
    {
        _clients = clients;
        _assertions = assertions;
        _replay = replay;
        _time = time;
    }

    /// <summary>A request with no client assertion: a public client, or a client with a secret.</summary>
    /// <param name="clientSecret">The secret from the Basic header, or null for a public client.</param>
    public Task<Result<Client>> AuthenticateAsync(
        Guid tenantId,
        string? clientId,
        string? clientSecret,
        CancellationToken cancellationToken) =>
        // Stryker disable once String : with no assertion, the issuer is never read.
        AuthenticateAsync(tenantId, issuer: string.Empty, clientId, clientSecret, clientAssertion: null, cancellationToken);

    /// <param name="issuer">The tenant's issuer: the only <c>aud</c> that a client assertion may name (D48).</param>
    /// <param name="clientId">The <c>client_id</c> of the request, or null. A client assertion names its client itself.</param>
    /// <param name="clientSecret">The secret from the Basic header, or null.</param>
    /// <param name="clientAssertion">The <c>client_assertion</c> (RFC 7523, section 2.2), or null.</param>
    public async Task<Result<Client>> AuthenticateAsync(
        Guid tenantId,
        string issuer,
        string? clientId,
        string? clientSecret,
        string? clientAssertion,
        CancellationToken cancellationToken)
    {
        if (clientAssertion is not null)
        {
            return await AuthenticateWithAssertionAsync(tenantId, issuer, clientId, clientSecret, clientAssertion, cancellationToken)
                .ConfigureAwait(false);
        }

        if (string.IsNullOrWhiteSpace(clientId))
        {
            return Result.Failure<Client>(OAuthError.InvalidClient("client_id missing"));
        }

        var found = await _clients
            .FindForAuthenticationAsync(tenantId, clientId, _time.GetUtcNow(), cancellationToken)
            .ConfigureAwait(false);

        TokenHash? presented = string.IsNullOrEmpty(clientSecret) ? null : TokenHash.Compute(clientSecret);

        if (found is null)
        {
            // Stryker disable once Block : timing only; a unit test cannot observe the extra comparisons.
            if (presented is { } unknownSecret)
            {
                _ = MatchesAny(unknownSecret, []);
            }

            return Result.Failure<Client>(OAuthError.InvalidClient("unknown client"));
        }

        var client = found.Client;

        if (client.TokenEndpointAuthMethod == TokenEndpointAuthMethod.PrivateKeyJwt)
        {
            // D47: the secrets of a private_key_jwt client never work, so a leaked old secret gives nothing.
            return Result.Failure<Client>(OAuthError.InvalidClient("private_key_jwt client sent no assertion"));
        }

        if (client.Type == ClientType.Public)
        {
            // A public client cannot keep a secret. A secret here means a misconfigured or spoofed client.
            if (presented is not null)
            {
                return Result.Failure<Client>(OAuthError.InvalidClient("public client sent a secret"));
            }

            return IsActive(client)
                ? Result.Success(client)
                : Result.Failure<Client>(OAuthError.InvalidClient($"client status {client.Status}"));
        }

        if (presented is not { } secret)
        {
            return Result.Failure<Client>(OAuthError.InvalidClient("confidential client sent no secret"));
        }

        // Compare first, then check the status, so a disabled client takes the same time as a wrong secret.
        var matches = MatchesAny(secret, found.ValidSecretHashes);

        if (!matches)
        {
            return Result.Failure<Client>(OAuthError.InvalidClient("wrong secret"));
        }

        return IsActive(client)
            ? Result.Success(client)
            : Result.Failure<Client>(OAuthError.InvalidClient($"client status {client.Status}"));
    }

    /// <summary>
    /// D45 to D49. The cheap checks run first: the client and its method, then the signature and claims (no database),
    /// then the replay insert. The status check is last, so a disabled client looks like any other failure.
    /// </summary>
    private async Task<Result<Client>> AuthenticateWithAssertionAsync(
        Guid tenantId,
        string issuer,
        string? clientId,
        string? clientSecret,
        string clientAssertion,
        CancellationToken cancellationToken)
    {
        // RFC 6749, section 2.3: a client uses one method in a request. The form reader refuses a Basic header too.
        if (clientSecret is not null)
        {
            return Result.Failure<Client>(OAuthError.InvalidClient("secret and assertion in one request"));
        }

        var assertedId = _assertions.ReadClientId(clientAssertion);
        if (assertedId is null)
        {
            return Result.Failure<Client>(OAuthError.InvalidClient("assertion unreadable"));
        }

        // RFC 7521, section 4.2: a client_id in the body must name the same client as the assertion.
        if (clientId is not null && !string.Equals(clientId, assertedId, StringComparison.Ordinal))
        {
            return Result.Failure<Client>(OAuthError.InvalidClient("client_id differs from the assertion"));
        }

        var found = await _clients
            .FindForAuthenticationAsync(tenantId, assertedId, _time.GetUtcNow(), cancellationToken)
            .ConfigureAwait(false);
        if (found is null)
        {
            return Result.Failure<Client>(OAuthError.InvalidClient("unknown client"));
        }

        var client = found.Client;
        if (client.TokenEndpointAuthMethod != TokenEndpointAuthMethod.PrivateKeyJwt)
        {
            return Result.Failure<Client>(OAuthError.InvalidClient("client does not use private_key_jwt"));
        }

        var assertion = _assertions.Validate(clientAssertion, client, issuer);
        if (!assertion.IsSuccess)
        {
            return Result.Failure<Client>(assertion.Error);
        }

        // D49: one statement records the jti. A second use, also on another server at the same time, fails.
        if (!await _replay.TryUseAsync(tenantId, client.Id, assertion.Value, cancellationToken).ConfigureAwait(false))
        {
            return Result.Failure<Client>(OAuthError.InvalidClient("assertion replayed"));
        }

        return IsActive(client)
            ? Result.Success(client)
            : Result.Failure<Client>(OAuthError.InvalidClient($"client status {client.Status}"));
    }

    private static bool IsActive(Client client) => client.Status == ClientStatus.Active;

    /// <summary>
    /// Compares against every slot without an early exit. The number of comparisons does not depend on
    /// how many secrets the client has, or on which one matches.
    /// </summary>
    private static bool MatchesAny(TokenHash presented, IReadOnlyList<TokenHash> valid)
    {
        var match = false;
        var slots = Math.Max(MaxValidSecrets, valid.Count);

        // Stryker disable once Equality : one more comparison with DummyHash changes the time, not the result.
        for (var i = 0; i < slots; i++)
        {
            var candidate = i < valid.Count ? valid[i] : DummyHash;
            // Stryker disable once Assignment : the valid hashes are distinct, so at most one slot matches.
            match |= presented.Equals(candidate);
        }

        return match;
    }
}
