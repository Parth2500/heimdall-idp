using Heimdall.Domain.Common;

namespace Heimdall.Domain.Tokens;

public enum CodeRedemptionResult
{
    Redeemed,
    Expired,

    /// <summary>The code was used before. The caller must revoke the family that came from it.</summary>
    AlreadyRedeemed,
}

/// <summary>
/// A single-use code. The database enforces the same rule with one atomic UPDATE
/// (docs/schema-design.md). This class holds the rule for tests and for the use case.
/// </summary>
public sealed class AuthorizationCode
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    private AuthorizationCode(
        Guid id,
        Guid tenantId,
        Guid clientPk,
        Guid userId,
        TokenHash codeHash,
        string redirectUri,
        string scope,
        string codeChallenge,
        string? nonce,
        DateTimeOffset authTime,
        DateTimeOffset createdAt)
    {
        Id = id;
        TenantId = tenantId;
        ClientPk = clientPk;
        UserId = userId;
        CodeHash = codeHash;
        RedirectUri = redirectUri;
        Scope = scope;
        CodeChallenge = codeChallenge;
        Nonce = nonce;
        AuthTime = authTime;
        CreatedAt = createdAt;
        ExpiresAt = createdAt + Lifetime;
    }

    public Guid Id { get; }

    public Guid TenantId { get; }

    public Guid ClientPk { get; }

    public Guid UserId { get; }

    public TokenHash CodeHash { get; }

    /// <summary>The redirect URI of the /authorize request. /token compares it by exact match.</summary>
    public string RedirectUri { get; }

    public string Scope { get; }

    public string CodeChallenge { get; }

    public string? Nonce { get; }

    public DateTimeOffset AuthTime { get; }

    public DateTimeOffset CreatedAt { get; }

    public DateTimeOffset ExpiresAt { get; }

    public DateTimeOffset? RedeemedAt { get; private set; }

    /// <summary>The family that this code started. It is set when the code is redeemed.</summary>
    public Guid? FamilyId { get; private set; }

    public static AuthorizationCode Create(
        Guid id,
        Guid tenantId,
        Guid clientPk,
        Guid userId,
        TokenHash codeHash,
        string redirectUri,
        string scope,
        string codeChallenge,
        string? nonce,
        DateTimeOffset authTime,
        DateTimeOffset now)
    {
        Guard.NotEmpty(id, nameof(id));
        Guard.NotEmpty(tenantId, nameof(tenantId));
        Guard.NotEmpty(clientPk, nameof(clientPk));
        Guard.NotEmpty(userId, nameof(userId));

        if (!Pkce.IsValidChallenge(codeChallenge))
        {
            throw new DomainException("The code challenge must be a BASE64URL SHA-256 value (S256).");
        }

        return new AuthorizationCode(
            id,
            tenantId,
            clientPk,
            userId,
            codeHash,
            Guard.NotBlank(redirectUri, nameof(redirectUri)),
            Guard.NotBlank(scope, nameof(scope)),
            codeChallenge,
            nonce,
            authTime,
            now);
    }

    /// <summary>Marks the code as used. A used code is reported before an expired one, because reuse is an attack signal.</summary>
    public CodeRedemptionResult Redeem(Guid familyId, DateTimeOffset now)
    {
        Guard.NotEmpty(familyId, nameof(familyId));

        if (RedeemedAt is not null)
        {
            return CodeRedemptionResult.AlreadyRedeemed;
        }

        if (now >= ExpiresAt)
        {
            return CodeRedemptionResult.Expired;
        }

        RedeemedAt = now;
        FamilyId = familyId;
        return CodeRedemptionResult.Redeemed;
    }
}
