using Heimdall.Domain.Common;
using Heimdall.Domain.Users;

namespace Heimdall.Domain.Sessions;

/// <summary>
/// A login session at Heimdall. The cookie holds a random ID. The server stores only its hash (D12).
/// </summary>
public sealed class Session
{
#pragma warning disable CS8618 // EF Core sets the properties after it calls this constructor.
    private Session()
    {
    }
#pragma warning restore CS8618

    private Session(
        TokenHash idHash,
        Guid tenantId,
        Guid userId,
        DateTimeOffset createdAt,
        DateTimeOffset absoluteExpiresAt)
    {
        IdHash = idHash;
        TenantId = tenantId;
        UserId = userId;
        CreatedAt = createdAt;
        LastSeenAt = createdAt;
        AuthTime = createdAt;
        AbsoluteExpiresAt = absoluteExpiresAt;
    }

    public TokenHash IdHash { get; }

    public Guid TenantId { get; }

    public Guid UserId { get; }

    public DateTimeOffset CreatedAt { get; }

    public DateTimeOffset LastSeenAt { get; private set; }

    /// <summary>When the user last entered credentials. Used for <c>max_age</c> and the <c>auth_time</c> claim.</summary>
    public DateTimeOffset AuthTime { get; }

    public DateTimeOffset AbsoluteExpiresAt { get; }

    public DateTimeOffset? RevokedAt { get; private set; }

    /// <summary>Starts a session after a successful sign-in. The caller creates a new ID each time (D13).</summary>
    public static Session Start(TokenHash idHash, Guid tenantId, Guid userId, TimeSpan absoluteLifetime, DateTimeOffset now)
    {
        Guard.NotEmpty(tenantId, nameof(tenantId));
        Guard.NotEmpty(userId, nameof(userId));
        Guard.Positive(absoluteLifetime, nameof(absoluteLifetime));

        return new Session(idHash, tenantId, userId, now, now + absoluteLifetime);
    }

    /// <summary>
    /// Checks every rule for a valid session. The tenant must match the request (see "Tenants" in the threat model),
    /// and a password change or a disabled account ends the session.
    /// </summary>
    public bool IsValid(Guid requestTenantId, User user, TimeSpan idleTimeout, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(user);

        return RevokedAt is null
            && TenantId == requestTenantId
            && user.Id == UserId
            && user.TenantId == TenantId
            && user.Status == UserStatus.Active
            && CreatedAt >= user.PasswordChangedAt
            && now < AbsoluteExpiresAt
            && now < LastSeenAt + idleTimeout;
    }

    /// <summary>True when the user entered credentials no longer than <paramref name="maxAge"/> ago.</summary>
    public bool IsAuthenticatedWithin(TimeSpan maxAge, DateTimeOffset now) => now - AuthTime <= maxAge;

    /// <summary>Records activity. This moves the idle limit, never the absolute limit.</summary>
    public void Touch(DateTimeOffset now)
    {
        if (RevokedAt is not null)
        {
            throw new DomainException("A revoked session cannot be used.");
        }

        if (now > LastSeenAt)
        {
            LastSeenAt = now;
        }
    }

    public void Revoke(DateTimeOffset now) => RevokedAt ??= now;
}
