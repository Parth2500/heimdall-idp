using Heimdall.Application.Users;
using Heimdall.Domain.Users;

namespace Heimdall.UnitTests.Application;

/// <summary>A test fake. It keeps users in memory.</summary>
internal sealed class InMemoryUserStore : IUserStore
{
    public List<User> Users { get; } = [];

    public int SaveCount { get; private set; }

    public Task<User?> FindByEmailAsync(Guid tenantId, string emailNormalized, CancellationToken cancellationToken) =>
        Task.FromResult(Users.SingleOrDefault(u => u.TenantId == tenantId && u.EmailNormalized == emailNormalized));

    public Task<User?> FindByIdAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken) =>
        Task.FromResult(Users.SingleOrDefault(u => u.TenantId == tenantId && u.Id == userId));

    public void Add(User user) => Users.Add(user);

    public Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        SaveCount++;
        return Task.CompletedTask;
    }
}
