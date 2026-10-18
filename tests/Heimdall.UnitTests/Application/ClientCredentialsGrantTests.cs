using System.Net;
using Heimdall.Application.Audit;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Application.Tokens;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Tenants;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Application;

public class ClientCredentialsGrantTests
{
    private const string Secret = "s3cret-value-1";
    private const string Api = "https://api.example.com";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private readonly Tenant _tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);
    private readonly InMemoryClientStore _store = new();
    private readonly FakeTimeProvider _time = new(Now);
    private readonly FakeSigner _signer = new();
    private readonly FakeAuditLog _audit = new();
    private readonly ClientCredentialsGrant _grant;

    public ClientCredentialsGrantTests()
    {
        _grant = new ClientCredentialsGrant(new ClientAuthenticator(_store, _time), _signer, _audit, _time);
    }

    private RequestContext Context => new(_tenant, "https://acme.example.com", "corr-1", IPAddress.Parse("203.0.113.7"));

    private Client AddClient(
        string[]? scopes = null,
        string[]? audiences = null,
        GrantType[]? grants = null,
        ClientTokenOverrides? overrides = null)
    {
        var client = Client.Create(
            Guid.CreateVersion7(),
            _tenant.Id,
            "billing-service",
            "Billing service",
            ClientType.Confidential,
            grants ?? [GrantType.ClientCredentials],
            scopes ?? ["invoices.read", "invoices.write"],
            grants is not null && grants.Contains(GrantType.AuthorizationCode) ? ["https://app.example.com/cb"] : [],
            requireConsent: false,
            overrides,
            Now,
            audiences ?? [Api]);
        client.Approve();
        _store.Add(client, (Secret, null));
        return client;
    }

    private Task<Result<TokenResponse>> Request(string? scope = null, string? resource = null, string secret = Secret) =>
        _grant.HandleAsync(Context, new ClientCredentialsRequest("billing-service", secret, scope, resource), CancellationToken.None);

    private void AssertError(Result<TokenResponse> result, string code)
    {
        Assert.False(result.IsSuccess);
        Assert.Equal(code, result.Error.Code);
        Assert.Empty(_signer.Signed);
        var rejected = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.TokenRejected, rejected.Type);
        Assert.Equal(code, rejected.Data["error"]);
    }

    [Fact]
    public async Task Valid_request_gets_a_token_with_the_right_claims()
    {
        var client = AddClient();

        var result = await Request("invoices.read");

        Assert.True(result.IsSuccess);
        Assert.Equal("Bearer", result.Value.TokenType);
        Assert.Equal(300, result.Value.ExpiresIn);
        Assert.Equal("invoices.read", result.Value.Scope);

        var (tenantId, claims) = Assert.Single(_signer.Signed);
        Assert.Equal(_tenant.Id, tenantId);
        Assert.Equal("https://acme.example.com", claims.Issuer);
        Assert.Equal("billing-service", claims.Subject);
        Assert.Equal("billing-service", claims.ClientId);
        Assert.Equal(Api, claims.Audience);
        Assert.Equal(["invoices.read"], claims.Scopes);
        Assert.Equal(Now, claims.IssuedAt);
        Assert.Equal(Now.AddMinutes(5), claims.ExpiresAt);
        Assert.False(string.IsNullOrEmpty(claims.JwtId));

        var issued = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.TokenIssued, issued.Type);
        Assert.Equal(client.Id, issued.ClientPk);
        Assert.Equal(claims.JwtId, issued.Data["jti"]);
        Assert.Equal("corr-1", issued.CorrelationId);
    }

    [Fact]
    public async Task Each_token_gets_a_new_jti()
    {
        AddClient();

        await Request();
        await Request();

        Assert.NotEqual(_signer.Signed[0].Claims.JwtId, _signer.Signed[1].Claims.JwtId);
    }

    [Fact]
    public async Task No_scope_means_all_allowed_scopes()
    {
        AddClient();

        var result = await Request();

        Assert.Equal("invoices.read invoices.write", result.Value.Scope);
    }

    [Fact]
    public async Task Client_lifetime_override_is_used()
    {
        AddClient(overrides: new ClientTokenOverrides(TimeSpan.FromMinutes(15), null, null));

        var result = await Request();

        Assert.Equal(900, result.Value.ExpiresIn);
        Assert.Equal(Now.AddMinutes(15), _signer.Signed[0].Claims.ExpiresAt);
    }

    [Fact]
    public async Task Wrong_secret_is_invalid_client()
    {
        AddClient();

        AssertError(await Request(secret: "wrong"), OAuthError.InvalidClientCode);
    }

    [Fact]
    public async Task Suspended_tenant_issues_nothing()
    {
        AddClient();
        _tenant.Suspend();

        AssertError(await Request(), OAuthError.InvalidClientCode);
    }

    [Fact]
    public async Task Client_without_the_grant_is_unauthorized_client()
    {
        AddClient(grants: [GrantType.AuthorizationCode], audiences: []);

        AssertError(await Request(), OAuthError.UnauthorizedClientCode);
    }

    [Fact]
    public async Task Scope_that_is_not_allowed_is_rejected_not_reduced()
    {
        AddClient();

        AssertError(await Request("invoices.read admin"), OAuthError.InvalidScopeCode);
    }

    [Theory]
    [InlineData("openid")]
    [InlineData("invoices.read offline_access")]
    public async Task User_scopes_are_rejected(string scope)
    {
        AddClient(scopes: ["invoices.read", "openid", "offline_access"]);

        AssertError(await Request(scope), OAuthError.InvalidScopeCode);
    }

    [Theory]
    [InlineData("invoices.read \"quoted\"")]
    [InlineData("invoices\\read")]
    [InlineData("invoices.read\tadmin")]
    public async Task Malformed_scope_is_rejected(string scope)
    {
        AddClient();

        AssertError(await Request(scope), OAuthError.InvalidScopeCode);
    }

    [Fact]
    public async Task Resource_that_is_not_allowed_is_invalid_target()
    {
        AddClient();

        AssertError(await Request(resource: "https://evil.example.com"), OAuthError.InvalidTargetCode);
    }

    [Fact]
    public async Task Several_audiences_and_no_resource_is_invalid_target()
    {
        AddClient(audiences: [Api, "https://orders.example.com"]);

        AssertError(await Request(), OAuthError.InvalidTargetCode);
    }

    [Fact]
    public async Task Requested_resource_becomes_the_audience()
    {
        AddClient(audiences: [Api, "https://orders.example.com"]);

        var result = await Request(resource: "https://orders.example.com");

        Assert.True(result.IsSuccess);
        Assert.Equal("https://orders.example.com", _signer.Signed[0].Claims.Audience);
    }

    [Fact]
    public async Task Long_client_id_is_truncated_in_the_audit_log()
    {
        var longId = new string('x', 5000);

        await _grant.HandleAsync(Context, new ClientCredentialsRequest(longId, Secret, null, null), CancellationToken.None);

        Assert.Equal(128, _audit.Events[0].Data["client_id"].Length);
    }

    private sealed class FakeSigner : ITokenSigner
    {
        public List<(Guid TenantId, AccessTokenClaims Claims)> Signed { get; } = [];

        public Task<string> SignAccessTokenAsync(Guid tenantId, AccessTokenClaims claims, CancellationToken cancellationToken)
        {
            Signed.Add((tenantId, claims));
            return Task.FromResult("signed." + claims.JwtId);
        }
    }

    private sealed class FakeAuditLog : IAuditLog
    {
        public List<AuditEvent> Events { get; } = [];

        public Task WriteAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
        {
            Events.Add(auditEvent);
            return Task.CompletedTask;
        }
    }
}
