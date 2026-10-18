using Heimdall.Domain.Common;

namespace Heimdall.Domain.Consents;

/// <summary>
/// A user's approval for one client and a set of scopes. A revoked consent stays as evidence (repudiation).
/// There is one row for each tenant, user, and client.
/// </summary>
public sealed class Consent
{
    private List<string> _scopes;

    private Consent(Guid id, Guid tenantId, Guid userId, Guid clientPk, List<string> scopes, DateTimeOffset grantedAt)
    {
        Id = id;
        TenantId = tenantId;
        UserId = userId;
        ClientPk = clientPk;
        _scopes = scopes;
        GrantedAt = grantedAt;
    }

    public Guid Id { get; }

    public Guid TenantId { get; }

    public Guid UserId { get; }

    public Guid ClientPk { get; }

    public IReadOnlyList<string> Scopes => _scopes;

    public DateTimeOffset GrantedAt { get; private set; }

    public DateTimeOffset? RevokedAt { get; private set; }

    public static Consent Grant(Guid id, Guid tenantId, Guid userId, Guid clientPk, IEnumerable<string> scopes, DateTimeOffset now)
    {
        Guard.NotEmpty(id, nameof(id));
        Guard.NotEmpty(tenantId, nameof(tenantId));
        Guard.NotEmpty(userId, nameof(userId));
        Guard.NotEmpty(clientPk, nameof(clientPk));

        var normalized = ScopeRules.Normalize(scopes);
        if (normalized.Count == 0)
        {
            throw new DomainException("A consent needs at least one scope.");
        }

        return new Consent(id, tenantId, userId, clientPk, normalized, now);
    }

    /// <summary>True when the consent is active and contains every requested scope.</summary>
    public bool Covers(IEnumerable<string> requested)
    {
        ArgumentNullException.ThrowIfNull(requested);
        return RevokedAt is null && requested.All(s => _scopes.Contains(s, StringComparer.Ordinal));
    }

    /// <summary>
    /// Records a new approval. An active consent gets the new scopes added. A revoked consent starts again with
    /// only the new scopes, so an old approval never comes back by accident.
    /// </summary>
    public void Approve(IEnumerable<string> scopes, DateTimeOffset now)
    {
        var normalized = ScopeRules.Normalize(scopes);
        if (normalized.Count == 0)
        {
            throw new DomainException("A consent needs at least one scope.");
        }

        _scopes = RevokedAt is null
            ? _scopes.Union(normalized, StringComparer.Ordinal).ToList()
            : normalized;
        RevokedAt = null;
        GrantedAt = now;
    }

    public void Revoke(DateTimeOffset now) => RevokedAt ??= now;
}
