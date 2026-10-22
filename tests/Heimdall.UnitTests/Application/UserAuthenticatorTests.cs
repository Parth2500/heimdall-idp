using System.Net;
using Heimdall.Application.Common;
using Heimdall.Application.Users;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Users;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Application;

public class UserAuthenticatorTests
{
    private const string Password = "correct horse battery staple";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private readonly Tenant _tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);
    private readonly FakeTimeProvider _time = new(Now);
    private readonly InMemoryUserStore _users = new();
    private readonly FakePasswordHasher _hasher = new();
    private readonly RecordingAuditLog _audit = new();
    private readonly InMemoryLoginThrottleStore _throttle = new();
    private readonly LoginThrottleOptions _throttleOptions = new() { FreeFailures = 3, MaxDelay = TimeSpan.FromMinutes(15) };
    private readonly UserAuthenticator _authenticator;

    public UserAuthenticatorTests()
    {
        _authenticator = new UserAuthenticator(_users, _hasher, _throttle, _throttleOptions, _audit, _time);
    }

    private RequestContext Context => ContextFrom("203.0.113.7");

    private RequestContext ContextFrom(string ip) => new(_tenant, "https://acme.example.com", "corr-1", IPAddress.Parse(ip));

    private User AddUser(string email = "Alice@Example.com")
    {
        var user = User.Create(Guid.CreateVersion7(), _tenant.Id, email, FakePasswordHasher.HashOf(Password), Now);
        _users.Users.Add(user);
        return user;
    }

    private Task<LoginResult> Login(string? email, string? password) =>
        _authenticator.AuthenticateAsync(Context, email, password, CancellationToken.None);

    private void AssertFailedWith(LoginResult result, string reason)
    {
        Assert.False(result.Succeeded);
        var failed = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.LoginFailed, failed.Type);
        Assert.Equal(reason, failed.Data["reason"]);
        Assert.Equal("corr-1", failed.CorrelationId);
    }

    [Fact]
    public async Task Right_password_signs_in_and_is_audited()
    {
        var user = AddUser();

        var result = await Login("alice@example.com", Password);

        Assert.Same(user, result.User);
        var succeeded = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.LoginSucceeded, succeeded.Type);
        Assert.Equal(user.Id, succeeded.SubjectUserId);
        Assert.False(succeeded.Data.ContainsKey("reason"));
    }

    [Fact]
    public async Task Email_match_ignores_case()
    {
        AddUser("alice@example.com");

        Assert.True((await Login("ALICE@EXAMPLE.COM", Password)).Succeeded);
    }

    [Fact]
    public async Task Unknown_user_still_runs_one_verification()
    {
        var result = await Login("nobody@example.com", Password);

        AssertFailedWith(result, "unknown user");
        Assert.Equal([null], _hasher.Verified);
    }

    [Fact]
    public async Task Wrong_password_runs_one_verification()
    {
        var user = AddUser();

        var result = await Login("alice@example.com", "wrong password here");

        AssertFailedWith(result, "wrong password");
        Assert.Equal(user.Id, _audit.Events[0].SubjectUserId);
        Assert.Single(_hasher.Verified);
    }

    [Fact]
    public async Task Disabled_user_fails_after_the_verification()
    {
        var user = AddUser();
        user.Disable();

        var result = await Login("alice@example.com", Password);

        AssertFailedWith(result, "user disabled");
        Assert.Single(_hasher.Verified);
    }

    [Fact]
    public async Task Suspended_tenant_refuses_sign_in()
    {
        AddUser();
        _tenant.Suspend();

        AssertFailedWith(await Login("alice@example.com", Password), "tenant suspended");
    }

    [Theory]
    [InlineData(null, Password)]
    [InlineData(" ", Password)]
    [InlineData("alice@example.com", null)]
    [InlineData("alice@example.com", "")]
    public async Task Missing_input_fails_without_a_hash_or_an_audit_event(string? email, string? password)
    {
        AddUser();

        var result = await Login(email, password);

        Assert.False(result.Succeeded);
        Assert.Empty(_hasher.Verified);
        Assert.Empty(_audit.Events);
    }

    [Fact]
    public async Task Overlong_password_is_refused_before_any_hash()
    {
        AddUser();

        var result = await Login("alice@example.com", new string('a', 10_000));

        Assert.False(result.Succeeded);
        Assert.Empty(_hasher.Verified);
    }

    [Fact]
    public async Task Old_hash_is_upgraded_without_ending_sessions()
    {
        var user = AddUser();
        _hasher.ReportNeedsRehash = true;
        _time.Advance(TimeSpan.FromDays(1));

        var result = await Login("alice@example.com", Password);

        Assert.True(result.Succeeded);
        Assert.Equal(FakePasswordHasher.HashOf(Password) + ":v2", user.PasswordHash);
        Assert.Equal(Now, user.PasswordChangedAt);
        Assert.Equal(1, _users.SaveCount);
    }

    [Fact]
    public async Task Failed_sign_in_never_upgrades_a_hash()
    {
        var user = AddUser();
        _hasher.ReportNeedsRehash = true;

        await Login("alice@example.com", "wrong password here");

        Assert.Equal(FakePasswordHasher.HashOf(Password), user.PasswordHash);
        Assert.Equal(0, _users.SaveCount);
    }

    [Fact]
    public async Task Busy_hasher_is_not_a_failed_sign_in()
    {
        AddUser();
        _hasher.Busy = true;

        await Assert.ThrowsAsync<PasswordHasherBusyException>(() => Login("alice@example.com", Password));
        Assert.Empty(_audit.Events);
    }

    private async Task FailAsync(int times, string ip = "203.0.113.7")
    {
        for (var i = 0; i < times; i++)
        {
            Assert.False((await _authenticator.AuthenticateAsync(ContextFrom(ip), "alice@example.com", "wrong password value", CancellationToken.None)).Succeeded);
        }
    }

    [Fact]
    public async Task Free_failures_cost_no_wait()
    {
        AddUser();
        await FailAsync(3);

        Assert.True((await Login("alice@example.com", Password)).Succeeded);
    }

    [Fact]
    public async Task During_a_wait_the_right_password_is_not_checked_and_fails_like_any_failure()
    {
        AddUser();
        await FailAsync(4);
        _audit.Events.Clear();
        _hasher.Verified.Clear();

        var result = await Login("alice@example.com", Password);

        // The dummy verification runs (same cost), the real hash is never checked, the answer is the generic failure.
        AssertFailedWith(result, "throttled");
        Assert.Equal([null], _hasher.Verified);
    }

    [Fact]
    public async Task The_wait_ends_by_itself_and_success_forgets_the_failures()
    {
        AddUser();
        await FailAsync(4);
        _time.Advance(TimeSpan.FromSeconds(1));

        Assert.True((await Login("alice@example.com", Password)).Succeeded);
        Assert.Empty(_throttle.Rows);
    }

    [Fact]
    public async Task An_attackers_failures_do_not_slow_the_user_at_another_source()
    {
        AddUser();
        await FailAsync(10, ip: "198.51.100.66");

        var result = await _authenticator.AuthenticateAsync(ContextFrom("203.0.113.7"), "alice@example.com", Password, CancellationToken.None);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task Attempts_during_a_wait_do_not_make_it_longer()
    {
        AddUser();
        await FailAsync(4);
        var until = _throttle.Rows.Single().Value.Until;

        await FailAsync(5);

        Assert.Equal(until, _throttle.Rows.Single().Value.Until);
    }

    [Fact]
    public async Task Unknown_user_gets_no_throttle_row()
    {
        await FailAsync(10);

        Assert.Empty(_throttle.Rows);
    }

    private sealed class InMemoryLoginThrottleStore : ILoginThrottleStore
    {
        public Dictionary<(Guid Tenant, Guid User, string Source), (int Failures, DateTimeOffset Last, DateTimeOffset? Until)> Rows { get; } = [];

        public Task<DateTimeOffset?> GetThrottledUntilAsync(Guid tenantId, Guid userId, string sourceKey, CancellationToken cancellationToken) =>
            Task.FromResult(Rows.TryGetValue((tenantId, userId, sourceKey), out var row) ? row.Until : null);

        public Task<int> RecordFailureAsync(Guid tenantId, Guid userId, string sourceKey, DateTimeOffset now, DateTimeOffset resetBefore, CancellationToken cancellationToken)
        {
            var key = (tenantId, userId, sourceKey);
            var row = Rows.TryGetValue(key, out var existing) && existing.Last >= resetBefore
                ? (existing.Failures + 1, now, existing.Until)
                : (1, now, (DateTimeOffset?)null);
            Rows[key] = row;
            return Task.FromResult(row.Item1);
        }

        public Task ThrottleUntilAsync(Guid tenantId, Guid userId, string sourceKey, DateTimeOffset until, CancellationToken cancellationToken)
        {
            var key = (tenantId, userId, sourceKey);
            var row = Rows[key];
            Rows[key] = (row.Failures, row.Last, row.Until is { } current && current > until ? current : until);
            return Task.CompletedTask;
        }

        public Task ResetAsync(Guid tenantId, Guid userId, string sourceKey, CancellationToken cancellationToken)
        {
            Rows.Remove((tenantId, userId, sourceKey));
            return Task.CompletedTask;
        }
    }

    private sealed class InMemoryUserStore : IUserStore
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

    /// <summary>Records every verification. A "hash" is the password with a prefix, so tests stay fast.</summary>
    private sealed class FakePasswordHasher : IPasswordHasher
    {
        public List<string?> Verified { get; } = [];

        public bool ReportNeedsRehash { get; set; }

        public bool Busy { get; set; }

        public static string HashOf(string password) => "fake:" + password;

        public ValueTask<string> HashAsync(string password, CancellationToken cancellationToken) =>
            ValueTask.FromResult(HashOf(password) + ":v2");

        public ValueTask<PasswordCheck> VerifyAsync(string? hash, string password, CancellationToken cancellationToken)
        {
            if (Busy)
            {
                throw new PasswordHasherBusyException();
            }

            Verified.Add(hash);
            var verified = hash is not null && hash == HashOf(password);
            return ValueTask.FromResult(new PasswordCheck(verified, verified && ReportNeedsRehash));
        }
    }
}
