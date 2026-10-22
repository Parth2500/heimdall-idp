using System.Net;
using Heimdall.Application.Common;
using Heimdall.Application.Sessions;
using Heimdall.Application.Users;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Users;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Application;

public class SessionServiceTests
{
    private const string Password = "correct horse battery staple";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private readonly Tenant _tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);
    private readonly FakeTimeProvider _time = new(Now);
    private readonly InMemoryUserStore _users;
    private readonly InMemorySessionStore _sessions;
    private readonly RecordingAuditLog _audit = new();
    private readonly SessionService _service;
    private readonly User _user;

    public SessionServiceTests()
    {
        _users = new InMemoryUserStore();
        _sessions = new InMemorySessionStore { Users = _users };
        var authenticator = new UserAuthenticator(
            _users,
            new FakePasswordHasher(),
            new InMemoryLoginThrottleStore(),
            new LoginThrottleOptions(),
            _audit,
            _time);
        _service = new SessionService(authenticator, _sessions, _audit, _time);
        _user = User.Create(Guid.CreateVersion7(), _tenant.Id, "alice@example.com", FakePasswordHasher.HashOf(Password), Now);
        _users.Add(_user);
    }

    private RequestContext Context => new(_tenant, "https://acme.example.com", "corr-1", IPAddress.Parse("203.0.113.7"), "Firefox/140");

    private Task<SignInResult> SignIn(string password = Password, string? existing = null, RequestContext? context = null) =>
        _service.SignInAsync(context ?? Context, "alice@example.com", password, existing, CancellationToken.None);

    private Task<ValidSession?> Validate(string? sessionId) => _service.ValidateAsync(Context, sessionId, CancellationToken.None);

    [Fact]
    public async Task Sign_in_starts_a_session_and_stores_only_the_hash()
    {
        var result = await SignIn();

        Assert.True(result.Succeeded);
        Assert.Same(_user, result.User);
        Assert.Equal(SessionService.SessionIdLength, result.SessionId!.Length);
        Assert.True(System.Buffers.Text.Base64Url.IsValid(result.SessionId));

        var session = Assert.Single(_sessions.Sessions);
        Assert.Equal(TokenHash.Compute(result.SessionId), session.IdHash);
        Assert.Equal(_tenant.Id, session.TenantId);
        Assert.Equal(_user.Id, session.UserId);
        Assert.Equal(Now, session.AuthTime);
        Assert.Equal(Now + TenantSettings.Default.SessionAbsolute, session.AbsoluteExpiresAt);
        Assert.Equal(1, _sessions.SaveCount);

        var started = _audit.Events.Single(e => e.Type == AuditEventTypes.SessionStarted);
        Assert.Equal(_user.Id, started.SubjectUserId);
        Assert.Equal("corr-1", started.CorrelationId);
        Assert.Equal(Convert.ToHexStringLower(session.IdHash.AsSpan()), started.Data["session_hash"]);
        Assert.Equal("Firefox/140", started.Data["user_agent"]);
        Assert.DoesNotContain(result.SessionId, started.Data.Values);
    }

    [Fact]
    public async Task Sign_in_without_a_user_agent_audits_none()
    {
        await SignIn(context: Context with { UserAgent = null });

        Assert.False(_audit.Events.Single(e => e.Type == AuditEventTypes.SessionStarted).Data.ContainsKey("user_agent"));
    }

    [Fact]
    public async Task Each_sign_in_gets_a_new_session_id()
    {
        var first = await SignIn();
        var second = await SignIn();

        Assert.NotEqual(first.SessionId, second.SessionId);
    }

    [Fact]
    public async Task Sign_in_ends_the_previous_session_of_the_browser()
    {
        // D13, session fixation: an ID that existed before the sign-in must not survive it.
        var first = await SignIn();
        _time.Advance(TimeSpan.FromMinutes(2));

        var second = await SignIn(existing: first.SessionId);

        Assert.Equal(Now.AddMinutes(2), _sessions.Sessions[0].RevokedAt);
        Assert.Null(await Validate(first.SessionId));
        Assert.NotNull(await Validate(second.SessionId));
    }

    [Fact]
    public async Task Failed_sign_in_starts_no_session()
    {
        var result = await SignIn("wrong password here");

        Assert.False(result.Succeeded);
        Assert.Null(result.SessionId);
        Assert.Null(result.User);
        Assert.Empty(_sessions.Sessions);
        Assert.DoesNotContain(_audit.Events, e => e.Type == AuditEventTypes.SessionStarted);
    }

    [Fact]
    public async Task Failed_sign_in_keeps_the_previous_session()
    {
        var first = await SignIn();

        await SignIn("wrong password here", existing: first.SessionId);

        Assert.Null(_sessions.Sessions[0].RevokedAt);
    }

    [Fact]
    public async Task Valid_session_returns_the_session_and_its_user()
    {
        var id = (await SignIn()).SessionId;

        var valid = await Validate(id);

        Assert.Same(_sessions.Sessions[0], valid!.Session);
        Assert.Same(_user, valid.User);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("too-short")]
    [InlineData("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")] // 43 characters, not base64url
    public async Task Malformed_session_id_is_refused_before_the_store(string? id)
    {
        Assert.Null(await Validate(id));
        Assert.Equal(0, _sessions.Queries);
    }

    [Fact]
    public async Task Unknown_session_id_is_refused()
    {
        Assert.Null(await Validate(new string('A', SessionService.SessionIdLength)));
    }

    [Fact]
    public async Task Session_of_a_deleted_user_is_refused()
    {
        var id = (await SignIn()).SessionId;
        _users.Users.Clear();

        Assert.Null(await Validate(id));
    }

    [Fact]
    public async Task Session_of_a_disabled_user_is_refused()
    {
        var id = (await SignIn()).SessionId;
        _user.Disable();

        Assert.Null(await Validate(id));
    }

    [Fact]
    public async Task Session_after_the_idle_limit_is_refused()
    {
        var id = (await SignIn()).SessionId;
        _time.Advance(TenantSettings.Default.SessionIdle);

        Assert.Null(await Validate(id));
    }

    [Fact]
    public async Task Activity_within_a_minute_writes_nothing()
    {
        var id = (await SignIn()).SessionId;
        var saves = _sessions.SaveCount;
        _time.Advance(TimeSpan.FromMinutes(1) - TimeSpan.FromTicks(1));

        await Validate(id);

        Assert.Equal(saves, _sessions.SaveCount);
        Assert.Equal(Now, _sessions.Sessions[0].LastSeenAt);
    }

    [Fact]
    public async Task Activity_after_a_minute_moves_the_idle_limit()
    {
        var id = (await SignIn()).SessionId;
        var saves = _sessions.SaveCount;
        _time.Advance(TimeSpan.FromMinutes(1));

        await Validate(id);

        Assert.Equal(saves + 1, _sessions.SaveCount);
        Assert.Equal(Now.AddMinutes(1), _sessions.Sessions[0].LastSeenAt);
    }

    [Fact]
    public async Task Sign_out_ends_the_session_and_is_audited()
    {
        var id = (await SignIn()).SessionId;
        _time.Advance(TimeSpan.FromMinutes(5));
        var saves = _sessions.SaveCount;

        await _service.SignOutAsync(Context, id, CancellationToken.None);

        var session = _sessions.Sessions[0];
        Assert.Equal(Now.AddMinutes(5), session.RevokedAt);
        Assert.Equal(saves + 1, _sessions.SaveCount);
        Assert.Null(await Validate(id));
        var revoked = _audit.Events.Single(e => e.Type == AuditEventTypes.SessionRevoked);
        Assert.Equal(_user.Id, revoked.SubjectUserId);
        Assert.Equal(Convert.ToHexStringLower(session.IdHash.AsSpan()), revoked.Data["session_hash"]);
    }

    [Fact]
    public async Task Second_sign_out_does_nothing()
    {
        var id = (await SignIn()).SessionId;
        await _service.SignOutAsync(Context, id, CancellationToken.None);
        var events = _audit.Events.Count;
        var saves = _sessions.SaveCount;

        await _service.SignOutAsync(Context, id, CancellationToken.None);

        Assert.Equal(events, _audit.Events.Count);
        Assert.Equal(saves, _sessions.SaveCount);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not-a-session")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task Sign_out_without_a_session_does_nothing(string? id)
    {
        await _service.SignOutAsync(Context, id, CancellationToken.None);

        Assert.Empty(_audit.Events);
        Assert.Equal(id is { Length: SessionService.SessionIdLength } ? 1 : 0, _sessions.Queries);
        Assert.Equal(0, _sessions.SaveCount);
    }
}
