using System.Net;
using Heimdall.Application.Common;
using Heimdall.Application.UserInfo;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Users;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Application;

public class UserInfoServiceTests
{
    private const string Issuer = "https://acme.example.com";
    private const string Audience = Issuer + "/oauth/v1/userinfo";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private readonly Tenant _tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);
    private readonly FakeTimeProvider _time = new(Now);
    private readonly FakeValidator _validator = new();
    private readonly InMemoryUserStore _users = new();
    private readonly RecordingAuditLog _audit = new();
    private readonly UserInfoService _service;
    private readonly User _user;

    public UserInfoServiceTests()
    {
        _service = new UserInfoService(_validator, _users, _audit, _time);
        _user = User.Create(Guid.CreateVersion7(), _tenant.Id, "Alice@Example.com", "hash", Now);
        _users.Add(_user);
    }

    private RequestContext Context => new(_tenant, Issuer, "corr-1", IPAddress.Parse("203.0.113.7"));

    private VerifiedAccessToken Token(
        string issuer = Issuer,
        string? subject = null,
        string audience = Audience,
        string scope = "openid email",
        DateTimeOffset? expiresAt = null) =>
        new(issuer, subject ?? _user.Id.ToString(), audience, "spa", scope.Split(' '), expiresAt ?? Now.AddMinutes(5));

    private Task<Result<UserInfoClaims>> Get(VerifiedAccessToken? token)
    {
        _validator.Result = token;
        return _service.GetAsync(Context, "the.access.token", CancellationToken.None);
    }

    private void AssertInvalid(Result<UserInfoClaims> result, string reason)
    {
        Assert.False(result.IsSuccess);
        Assert.Equal(UserInfoService.InvalidTokenCode, result.Error!.Code);
        Assert.Equal(reason, result.Error.AuditDetail);
        Assert.Empty(_audit.Events);
    }

    [Fact]
    public async Task Email_scope_releases_the_email_and_the_read_is_audited()
    {
        var result = await Get(Token());

        var claims = result.Value;
        Assert.Equal(_user.Id.ToString(), claims.Subject);
        Assert.Equal(_user.Email, claims.Email);
        Assert.False(claims.EmailVerified);
        Assert.Equal((_tenant.Id, "the.access.token"), _validator.Called);

        var read = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.UserInfoRead, read.Type);
        Assert.Equal(_user.Id, read.SubjectUserId);
        Assert.Equal("corr-1", read.CorrelationId);
        Assert.Equal("spa", read.Data["client_id"]);
        Assert.Equal("openid email", read.Data["scope"]);
        Assert.DoesNotContain(_user.Email, read.Data.Values);
    }

    [Fact]
    public async Task Without_the_email_scope_only_the_subject_is_released()
    {
        var claims = (await Get(Token(scope: "openid profile"))).Value;

        Assert.Equal(_user.Id.ToString(), claims.Subject);
        Assert.Null(claims.Email);
        Assert.Null(claims.EmailVerified);
    }

    [Fact]
    public async Task Token_that_fails_validation_is_invalid_token()
    {
        AssertInvalid(await Get(null), "format, header, or signature");
    }

    [Fact]
    public async Task Token_of_another_issuer_is_invalid_token()
    {
        AssertInvalid(await Get(Token(issuer: "https://other.example.com")), "iss is not this tenant");
    }

    [Fact]
    public async Task Token_for_a_resource_server_is_invalid_token()
    {
        // D22: a token for an API cannot read user claims.
        AssertInvalid(await Get(Token(audience: "https://api.example.com")), "aud is not the userinfo endpoint");
    }

    [Fact]
    public async Task Token_works_until_one_tick_before_it_expires()
    {
        Assert.True((await Get(Token(expiresAt: Now.AddTicks(1)))).IsSuccess);
    }

    [Fact]
    public async Task Expired_token_is_invalid_token()
    {
        AssertInvalid(await Get(Token(expiresAt: Now)), "expired");
    }

    [Fact]
    public async Task Client_credentials_token_is_invalid_token()
    {
        AssertInvalid(await Get(Token(subject: "billing-service")), "sub is not a user");
    }

    [Fact]
    public async Task Token_of_an_unknown_user_is_invalid_token()
    {
        AssertInvalid(await Get(Token(subject: Guid.CreateVersion7().ToString())), "unknown user");
    }

    [Fact]
    public async Task Token_of_a_disabled_user_is_invalid_token()
    {
        _user.Disable();

        AssertInvalid(await Get(Token()), "user disabled");
    }

    [Fact]
    public async Task Token_without_openid_is_insufficient_scope()
    {
        var result = await Get(Token(scope: "email"));

        Assert.Equal(UserInfoService.InsufficientScopeCode, result.Error!.Code);
        Assert.Equal("openid scope missing", result.Error.AuditDetail);
        Assert.Empty(_audit.Events);
    }

    private sealed class FakeValidator : IAccessTokenValidator
    {
        public VerifiedAccessToken? Result { get; set; }

        public (Guid TenantId, string Token)? Called { get; private set; }

        public ValueTask<VerifiedAccessToken?> ValidateAsync(Guid tenantId, string token, CancellationToken cancellationToken)
        {
            Called = (tenantId, token);
            return ValueTask.FromResult(Result);
        }
    }
}
