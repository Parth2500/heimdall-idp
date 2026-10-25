using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;

namespace Heimdall.Domain.Tokens;

public enum FamilyRevocationReason
{
    ReuseDetected,
    UserLogout,
    Admin,
    UserDisabled,
    ConsentRemoved,
}

/// <summary>
/// All refresh tokens that come from one code redemption. One revocation ends all of them.
/// </summary>
public sealed class TokenFamily
{
#pragma warning disable CS8618 // EF Core sets the properties after it calls this constructor.
    private TokenFamily()
    {
    }
#pragma warning restore CS8618

    private TokenFamily(
        Guid id,
        Guid tenantId,
        Guid clientPk,
        Guid userId,
        Guid sourceCodeId,
        string scope,
        DateTimeOffset createdAt,
        DateTimeOffset absoluteExpiresAt,
        DateTimeOffset idleExpiresAt,
        string? dpopKeyThumbprint,
        string? sid)
    {
        Id = id;
        Sid = sid;
        DpopKeyThumbprint = dpopKeyThumbprint;
        TenantId = tenantId;
        ClientPk = clientPk;
        UserId = userId;
        SourceCodeId = sourceCodeId;
        Scope = scope;
        CreatedAt = createdAt;
        AbsoluteExpiresAt = absoluteExpiresAt;
        IdleExpiresAt = idleExpiresAt;
    }

    /// <summary>This value is the TokenFamilyId.</summary>
    public Guid Id { get; }

    public Guid TenantId { get; }

    public Guid ClientPk { get; }

    public Guid UserId { get; }

    public Guid SourceCodeId { get; }

    /// <summary>The scope at the start. Refresh can only reduce it.</summary>
    public string Scope { get; }

    public DateTimeOffset CreatedAt { get; }

    /// <summary>Fixed at creation. Rotation does not change it.</summary>
    public DateTimeOffset AbsoluteExpiresAt { get; }

    /// <summary>Moves forward at each rotation. It never passes <see cref="AbsoluteExpiresAt"/>.</summary>
    public DateTimeOffset IdleExpiresAt { get; private set; }

    public DateTimeOffset? RevokedAt { get; private set; }

    /// <summary>
    /// The DPoP key that the family is bound to, or null for an unbound family (D24). Each refresh of a bound family
    /// needs a proof from this key. Only a public client's family is bound.
    /// </summary>
    public string? DpopKeyThumbprint { get; }

    public FamilyRevocationReason? RevocationReason { get; private set; }

    /// <summary>
    /// The <c>sid</c> of the session that issued the code (D29). A sign-out revokes every family of its session (D33).
    /// Null only for a family whose code is from before the column existed.
    /// </summary>
    public string? Sid { get; }

    public static TokenFamily Start(
        Guid id,
        Guid tenantId,
        Guid clientPk,
        Guid userId,
        Guid sourceCodeId,
        string scope,
        TokenLifetimes lifetimes,
        DateTimeOffset now,
        string? dpopKeyThumbprint = null,
        string? sid = null)
    {
        Guard.NotEmpty(id, nameof(id));
        Guard.NotEmpty(tenantId, nameof(tenantId));
        Guard.NotEmpty(clientPk, nameof(clientPk));
        Guard.NotEmpty(userId, nameof(userId));
        Guard.NotEmpty(sourceCodeId, nameof(sourceCodeId));
        ArgumentNullException.ThrowIfNull(lifetimes);

        var absolute = now + lifetimes.RefreshAbsolute;
        var idle = Earlier(now + lifetimes.RefreshIdle, absolute);

        var thumbprint = dpopKeyThumbprint is null ? null : KeyThumbprint.Require(dpopKeyThumbprint, nameof(dpopKeyThumbprint));

        var sessionSid = sid is null ? null : SessionSid.Require(sid, nameof(sid));

        return new TokenFamily(id, tenantId, clientPk, userId, sourceCodeId, Guard.NotBlank(scope, nameof(scope)), now, absolute, idle, thumbprint, sessionSid);
    }

    public bool IsActive(DateTimeOffset now) =>
        RevokedAt is null && now < AbsoluteExpiresAt && now < IdleExpiresAt;

    /// <summary>Ends the family. A second call changes nothing, so the first reason stays.</summary>
    public void Revoke(FamilyRevocationReason reason, DateTimeOffset now)
    {
        if (RevokedAt is not null)
        {
            return;
        }

        RevokedAt = now;
        RevocationReason = reason;
    }

    /// <summary>Moves the idle limit after a successful rotation. It never passes the absolute limit.</summary>
    public void ExtendIdle(TimeSpan idleTimeout, DateTimeOffset now)
    {
        Guard.Positive(idleTimeout, nameof(idleTimeout));

        if (!IsActive(now))
        {
            throw new DomainException("An inactive family cannot be extended.");
        }

        IdleExpiresAt = Earlier(now + idleTimeout, AbsoluteExpiresAt);
    }

    /// <summary>Refresh can keep or reduce the scope. It can never add to it.</summary>
    public bool IsScopeAllowed(IEnumerable<string> requested)
    {
        ArgumentNullException.ThrowIfNull(requested);

        var original = Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return requested.All(s => original.Contains(s, StringComparer.Ordinal));
    }

    private static DateTimeOffset Earlier(DateTimeOffset a, DateTimeOffset b) => a < b ? a : b;
}
