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
    private readonly FakeDpopProofValidator _proofs = new();
    private readonly InMemoryDpopReplayStore _replay = new();
    private readonly InMemoryUserStore _users = new();
    private readonly RecordingAuditLog _audit = new();
    private readonly UserInfoService _service;
    private readonly User _user;

    public UserInfoServiceTests()
    {
        _service = new UserInfoService(_validator, _proofs, _replay, _users, _audit, _time);
        _user = User.Create(Guid.CreateVersion7(), _tenant.Id, "Alice@Example.com", "hash", Now);
        _users.Add(_user);
    }

    private RequestContext Context => new(_tenant, Issuer, "corr-1", IPAddress.Parse("203.0.113.7"));

    private VerifiedAccessToken Token(
        string issuer = Issuer,
        string? subject = null,
        string audience = Audience,
        string scope = "openid email",
        DateTimeOffset? expiresAt = null,
        string? boundKey = null) =>
        new(issuer, subject ?? _user.Id.ToString(), audience, "spa", scope.Split(' '), expiresAt ?? Now.AddMinutes(5), boundKey);

    private Task<Result<UserInfoClaims>> Get(
        VerifiedAccessToken? token,
        TokenScheme scheme = TokenScheme.Bearer,
        string? proof = null,
        string method = "GET")
    {
        _validator.Result = token;
        return _service.GetAsync(Context, new UserInfoRequest("the.access.token", scheme, method, proof), CancellationToken.None);
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

    // D28 and RFC 9449, section 7: a bound token needs the DPoP scheme and an unused proof from its key.

    private const string Key = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    private const string OtherKey = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    private void AssertDpopRefused(Result<UserInfoClaims> result, string reason)
    {
        Assert.False(result.IsSuccess);
        Assert.Equal(OAuthError.InvalidDpopProofCode, result.Error!.Code);
        Assert.Equal(reason, result.Error.AuditDetail);
        Assert.Empty(_audit.Events);
    }

    [Fact]
    public async Task Bound_token_with_a_proof_from_its_key_releases_the_claims()
    {
        var result = await Get(Token(boundKey: Key), TokenScheme.Dpop, FakeDpopProofValidator.Proof(Key), method: "POST");

        Assert.Equal(_user.Id.ToString(), result.Value.Subject);
        var (_, request) = Assert.Single(_proofs.Checked);
        Assert.Equal("POST", request.Method);
        Assert.Equal(new Uri(Audience), request.Url);
        Assert.Equal("the.access.token", request.AccessToken);
    }

    [Fact]
    public async Task Bound_token_sent_as_a_bearer_token_is_refused()
    {
        AssertInvalid(await Get(Token(boundKey: Key), TokenScheme.Bearer, FakeDpopProofValidator.Proof(Key)), "bound token sent as a bearer token");
    }

    [Fact]
    public async Task Unbound_token_with_the_DPoP_scheme_is_refused()
    {
        AssertInvalid(await Get(Token(), TokenScheme.Dpop, FakeDpopProofValidator.Proof(Key)), "unbound token with the DPoP scheme");
    }

    [Fact]
    public async Task Bound_token_without_a_proof_is_refused()
    {
        AssertDpopRefused(await Get(Token(boundKey: Key), TokenScheme.Dpop), "proof missing");
    }

    [Fact]
    public async Task Invalid_proof_is_refused()
    {
        AssertDpopRefused(await Get(Token(boundKey: Key), TokenScheme.Dpop, "not a proof"), "fake refused");
    }

    [Fact]
    public async Task Proof_from_another_key_is_refused()
    {
        AssertDpopRefused(await Get(Token(boundKey: Key), TokenScheme.Dpop, FakeDpopProofValidator.Proof(OtherKey)), "proof key differs from cnf.jkt");
        Assert.Empty(_replay.Seen);
    }

    [Fact]
    public async Task Proof_works_once()
    {
        var proof = FakeDpopProofValidator.Proof(Key);
        Assert.True((await Get(Token(boundKey: Key), TokenScheme.Dpop, proof)).IsSuccess);
        _audit.Events.Clear();

        AssertDpopRefused(await Get(Token(boundKey: Key), TokenScheme.Dpop, proof), "proof replayed");
    }

    [Fact]
    public async Task Binding_is_checked_after_the_token_and_before_the_user()
    {
        // An expired token fails first and costs no replay write. A refused binding never loads the user.
        AssertInvalid(await Get(Token(boundKey: Key, expiresAt: Now), TokenScheme.Dpop, FakeDpopProofValidator.Proof(Key)), "expired");
        Assert.Empty(_proofs.Checked);

        _users.Users.Remove(_user);
        AssertDpopRefused(await Get(Token(boundKey: Key), TokenScheme.Dpop), "proof missing");
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
