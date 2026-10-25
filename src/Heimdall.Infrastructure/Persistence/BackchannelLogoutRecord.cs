namespace Heimdall.Infrastructure.Persistence;

/// <summary>
/// A row in <c>backchannel_logouts</c>: one <c>logout_token</c> that Heimdall must send to one client's server (D34, D35).
/// The sign-out transaction inserts it. The delivery job deletes it after a success, or after the last retry.
/// </summary>
public sealed class BackchannelLogoutRecord
{
    public Guid Id { get; set; }

    public Guid TenantId { get; set; }

    public Guid ClientPk { get; set; }

    /// <summary>The <c>sub</c> of the logout token.</summary>
    public Guid UserId { get; set; }

    /// <summary>The <c>sid</c> of the logout token (D29).</summary>
    public string Sid { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>The deliveries that a job started. A start counts before the call, so a crash during the call counts too.</summary>
    public int Attempts { get; set; }

    /// <summary>When the next delivery may start. A job that takes the row moves it forward, as a lease.</summary>
    public DateTimeOffset NextAttemptAt { get; set; }
}
