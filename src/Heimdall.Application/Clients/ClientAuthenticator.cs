using System.Security.Cryptography;
using Heimdall.Application.Common;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;

namespace Heimdall.Application.Clients;

/// <summary>
/// Authenticates a client at /token and /revoke (D10). Every failure returns the same <c>invalid_client</c>
/// error (D5). The reason goes to <see cref="OAuthError.AuditDetail"/> only.
/// </summary>
public sealed class ClientAuthenticator
{
    /// <summary>The most secrets a client can have that are valid at the same time (rotation overlap).</summary>
    public const int MaxValidSecrets = 2;

    // Compared against when the client is unknown or has fewer valid secrets than the maximum.
    // The comparison count is then the same on every path.
    private static readonly TokenHash DummyHash =
        TokenHash.Compute(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));

    private readonly IClientStore _clients;
    private readonly TimeProvider _time;

    public ClientAuthenticator(IClientStore clients, TimeProvider time)
    {
        _clients = clients;
        _time = time;
    }

    /// <param name="clientSecret">The secret from the Basic header, or null for a public client.</param>
    public async Task<Result<Client>> AuthenticateAsync(
        Guid tenantId,
        string? clientId,
        string? clientSecret,
        CancellationToken cancellationToken)
    {
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
