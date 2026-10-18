using Heimdall.Domain.Common;

namespace Heimdall.Infrastructure.Persistence;

/// <summary>
/// A row in <c>client_secrets</c>. Only the hash is stored (D3). A client can have two valid secrets during rotation.
/// </summary>
public sealed class ClientSecretRecord
{
    public Guid Id { get; set; }

    public Guid TenantId { get; set; }

    public Guid ClientPk { get; set; }

    public TokenHash SecretHash { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? ExpiresAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }
}
