using Heimdall.Domain.Common;

namespace Heimdall.Application.Logout;

/// <summary>A family that a sign-out revoked, for the audit log.</summary>
public sealed record RevokedFamily(Guid FamilyId, Guid ClientPk, Guid UserId);

/// <param name="Ended">True when this call ended the session. False when it was already ended, so nothing changed.</param>
/// <param name="Families">The families that this call revoked.</param>
/// <param name="QueuedClients">The clients that get a back-channel logout (D34).</param>
public sealed record SessionEnd(bool Ended, IReadOnlyList<RevokedFamily> Families, IReadOnlyList<Guid> QueuedClients)
{
    public static SessionEnd None { get; } = new(false, [], []);
}

/// <summary>The sign-out transaction (D33). The statements are in docs/schema-design.md, "End a session".</summary>
public interface ILogoutStore
{
    /// <summary>
    /// One transaction: sets <c>revoked_at</c> on the session when it is not yet set, revokes every unrevoked family with
    /// its <c>sid</c> (reason <c>user_logout</c>), and queues one back-channel logout for each client with a family of
    /// that <c>sid</c> and a registered <c>backchannel_logout_uri</c>. When the session update matches no row, another
    /// request ended it first, and this call changes nothing.
    /// </summary>
    Task<SessionEnd> EndSessionAsync(Guid tenantId, TokenHash sessionIdHash, string sid, DateTimeOffset now, CancellationToken cancellationToken);
}
