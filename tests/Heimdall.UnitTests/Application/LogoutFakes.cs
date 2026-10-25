using Heimdall.Application.Logout;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Tokens;

namespace Heimdall.UnitTests.Application;

/// <summary>A test fake of the hint validator: a registered text gives its claims. Any other text fails.</summary>
internal sealed class FakeIdTokenHintValidator : IIdTokenHintValidator
{
    public Dictionary<string, VerifiedIdTokenHint> Hints { get; } = new(StringComparer.Ordinal);

    public List<(Guid TenantId, string Token)> Checked { get; } = [];

    public ValueTask<VerifiedIdTokenHint?> ValidateAsync(Guid tenantId, string token, CancellationToken cancellationToken)
    {
        Checked.Add((tenantId, token));
        return ValueTask.FromResult(Hints.GetValueOrDefault(token));
    }
}

/// <summary>
/// A test fake of the sign-out transaction. It has the conditions of each statement of <c>EfLogoutStore</c>. The
/// integration tests check the SQL itself.
/// </summary>
internal sealed class InMemoryLogoutStore : ILogoutStore
{
    public required InMemorySessionStore Sessions { get; init; }

    public required InMemoryTokenStore Tokens { get; init; }

    public required IReadOnlyList<Client> Clients { get; init; }

    public List<(Guid TenantId, Guid ClientPk, Guid UserId, string Sid)> Queued { get; } = [];

    public int Calls { get; private set; }

    /// <summary>When true, the next call matches no session row, as when a concurrent sign-out ended it first.</summary>
    public bool LoseNextEnd { get; set; }

    public Task<SessionEnd> EndSessionAsync(Guid tenantId, TokenHash sessionIdHash, string sid, DateTimeOffset now, CancellationToken cancellationToken)
    {
        Calls++;
        if (LoseNextEnd)
        {
            LoseNextEnd = false;
            return Task.FromResult(SessionEnd.None);
        }

        var session = Sessions.Sessions.SingleOrDefault(s => s.TenantId == tenantId && s.IdHash == sessionIdHash && s.RevokedAt is null);
        if (session is null)
        {
            return Task.FromResult(SessionEnd.None);
        }

        InMemoryTokenStore.Set(session, nameof(Session.RevokedAt), (DateTimeOffset?)now);

        var families = Tokens.Families.Where(f => f.TenantId == tenantId && f.Sid == sid).ToList();
        var revoked = new List<RevokedFamily>();
        foreach (var family in families.Where(f => f.RevokedAt is null))
        {
            InMemoryTokenStore.Set(family, nameof(TokenFamily.RevokedAt), (DateTimeOffset?)now);
            InMemoryTokenStore.Set(family, nameof(TokenFamily.RevocationReason), (FamilyRevocationReason?)FamilyRevocationReason.UserLogout);
            revoked.Add(new RevokedFamily(family.Id, family.ClientPk, family.UserId));
        }

        var queued = families
            .Select(f => (f.TenantId, f.ClientPk, f.UserId, Sid: f.Sid!))
            .Distinct()
            .Where(f => Clients.Any(c => c.TenantId == f.TenantId && c.Id == f.ClientPk && c.BackchannelLogoutUri is not null))
            .ToList();
        Queued.AddRange(queued);
        return Task.FromResult(new SessionEnd(true, revoked, queued.Select(q => q.ClientPk).ToList()));
    }
}
