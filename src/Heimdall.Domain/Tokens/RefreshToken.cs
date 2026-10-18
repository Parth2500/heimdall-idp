using Heimdall.Domain.Common;

namespace Heimdall.Domain.Tokens;

public enum RefreshTokenUseResult
{
    Used,

    /// <summary>The token was used before. The caller must revoke the whole family.</summary>
    Reused,
}

/// <summary>A single-use refresh token. Each use replaces it with a new one (rotation).</summary>
public sealed class RefreshToken
{
    private RefreshToken(Guid id, Guid tenantId, Guid familyId, TokenHash hash, DateTimeOffset createdAt)
    {
        Id = id;
        TenantId = tenantId;
        FamilyId = familyId;
        Hash = hash;
        CreatedAt = createdAt;
    }

    public Guid Id { get; }

    public Guid TenantId { get; }

    public Guid FamilyId { get; }

    public TokenHash Hash { get; }

    public DateTimeOffset CreatedAt { get; }

    public DateTimeOffset? UsedAt { get; private set; }

    public Guid? ReplacedById { get; private set; }

    public static RefreshToken Create(Guid id, Guid tenantId, Guid familyId, TokenHash hash, DateTimeOffset now)
    {
        Guard.NotEmpty(id, nameof(id));
        Guard.NotEmpty(tenantId, nameof(tenantId));
        Guard.NotEmpty(familyId, nameof(familyId));

        return new RefreshToken(id, tenantId, familyId, hash, now);
    }

    public RefreshTokenUseResult Use(Guid replacedById, DateTimeOffset now)
    {
        Guard.NotEmpty(replacedById, nameof(replacedById));

        if (UsedAt is not null)
        {
            return RefreshTokenUseResult.Reused;
        }

        UsedAt = now;
        ReplacedById = replacedById;
        return RefreshTokenUseResult.Used;
    }
}
