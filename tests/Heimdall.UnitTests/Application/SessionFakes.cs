using Heimdall.Application.Authorization;
using Heimdall.Application.Common;
using Heimdall.Application.Sessions;
using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Tokens;

namespace Heimdall.UnitTests.Application;

/// <summary>A test fake. It keeps sessions in memory.</summary>
internal sealed class InMemorySessionStore : ISessionStore
{
    public List<Session> Sessions { get; } = [];

    public int SaveCount { get; private set; }

    public int Queries { get; private set; }

    public Task<Session?> FindAsync(Guid tenantId, TokenHash idHash, CancellationToken cancellationToken)
    {
        Queries++;
        return Task.FromResult(Sessions.SingleOrDefault(s => s.TenantId == tenantId && s.IdHash == idHash));
    }

    public void Add(Session session) => Sessions.Add(session);

    public Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        SaveCount++;
        return Task.CompletedTask;
    }
}

/// <summary>
/// A test fake of the authorization store. A save applies all changes or none, as the database transaction does.
/// </summary>
internal sealed class InMemoryAuthorizationStore : IAuthorizationStore
{
    private readonly List<AuthorizationRequest> _added = [];
    private readonly List<AuthorizationRequest> _removed = [];
    private readonly List<AuthorizationCode> _codes = [];

    public List<AuthorizationRequest> Requests { get; } = [];

    public List<AuthorizationCode> Codes { get; } = [];

    public int SaveCount { get; private set; }

    /// <summary>When true, the next save fails as if another caller removed the same request first.</summary>
    public bool LoseNextSave { get; set; }

    public void AddRequest(AuthorizationRequest request) => _added.Add(request);

    public Task<AuthorizationRequest?> FindRequestAsync(Guid tenantId, Guid requestId, CancellationToken cancellationToken) =>
        Task.FromResult(Requests.SingleOrDefault(r => r.TenantId == tenantId && r.Id == requestId));

    public void RemoveRequest(AuthorizationRequest request) => _removed.Add(request);

    public void AddCode(AuthorizationCode code) => _codes.Add(code);

    public Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        var conflict = LoseNextSave || _removed.Any(r => !Requests.Contains(r));
        if (conflict)
        {
            LoseNextSave = false;
            Clear();
            throw new ConcurrentUpdateException();
        }

        Requests.AddRange(_added);
        Requests.RemoveAll(_removed.Contains);
        Codes.AddRange(_codes);
        Clear();
        SaveCount++;
        return Task.CompletedTask;
    }

    private void Clear()
    {
        _added.Clear();
        _removed.Clear();
        _codes.Clear();
    }
}
