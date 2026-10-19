using Heimdall.Application.Clients;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;

namespace Heimdall.UnitTests.Application;

/// <summary>A test fake. It keeps clients and secrets in memory and applies the secret validity rule.</summary>
internal sealed class InMemoryClientStore : IClientStore
{
    private readonly List<(Client Client, List<(TokenHash Hash, DateTimeOffset? ExpiresAt)> Secrets)> _entries = [];

    public int Queries { get; private set; }

    public void Add(Client client, params (string Secret, DateTimeOffset? ExpiresAt)[] secrets) =>
        _entries.Add((client, secrets.Select(s => (TokenHash.Compute(s.Secret), s.ExpiresAt)).ToList()));

    public Task<ClientWithSecrets?> FindForAuthenticationAsync(
        Guid tenantId,
        string clientId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        Queries++;

        var entry = _entries.FirstOrDefault(e => e.Client.TenantId == tenantId && e.Client.ClientId == clientId);
        if (entry.Client is null)
        {
            return Task.FromResult<ClientWithSecrets?>(null);
        }

        var valid = entry.Secrets
            .Where(s => s.ExpiresAt is null || s.ExpiresAt > now)
            .Select(s => s.Hash)
            .ToList();

        return Task.FromResult<ClientWithSecrets?>(new ClientWithSecrets(entry.Client, valid));
    }

    public Task<Client?> FindAsync(Guid tenantId, string clientId, CancellationToken cancellationToken) =>
        Task.FromResult<Client?>(_entries.Select(e => e.Client).FirstOrDefault(c => c.TenantId == tenantId && c.ClientId == clientId));

    public Task<Client?> FindByPkAsync(Guid tenantId, Guid clientPk, CancellationToken cancellationToken) =>
        Task.FromResult<Client?>(_entries.Select(e => e.Client).FirstOrDefault(c => c.TenantId == tenantId && c.Id == clientPk));

    // Nothing is cached here: every read sees the current entries.
    public void Invalidate(Guid tenantId)
    {
    }
}
