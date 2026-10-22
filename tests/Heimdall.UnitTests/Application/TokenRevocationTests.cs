using System.Net;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Application.Tokens;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Tokens;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Application;

public class TokenRevocationTests
{
    private const string Token = "refresh-token-value";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private readonly Tenant _tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);
    private readonly Guid _userId = Guid.CreateVersion7();
    private readonly InMemoryClientStore _clients = new();
    private readonly InMemoryTokenStore _tokens = new();
    private readonly FakeTimeProvider _time = new(Now);
    private readonly RecordingAuditLog _audit = new();
    private readonly TokenRevocation _revocation;
    private readonly Client _spa;
    private readonly TokenFamily _family;

    public TokenRevocationTests()
    {
        _revocation = new TokenRevocation(new ClientAuthenticator(_clients, _time), _tokens, _audit, _time);
        _spa = AddPublicClient("spa");
        _family = StartFamily(_spa, Token);
    }

    private RequestContext Context => new(_tenant, "https://acme.example.com", "corr-1", IPAddress.Parse("203.0.113.7"));

    private Client AddPublicClient(string clientId)
    {
        var client = Client.Create(
            Guid.CreateVersion7(), _tenant.Id, clientId, "Single-page app", ClientType.Public,
            [GrantType.AuthorizationCode, GrantType.RefreshToken], ["openid", "offline_access"],
            ["https://app.example.com/callback"], requireConsent: false, overrides: null, Now);
        client.Approve();
        _clients.Add(client);
        return client;
    }

    private TokenFamily StartFamily(Client client, string token, Guid? tenantId = null)
    {
        var tenant = tenantId ?? _tenant.Id;
        var family = TokenFamily.Start(
            Guid.CreateVersion7(), tenant, client.Id, _userId, Guid.CreateVersion7(), "openid offline_access",
            client.ResolveLifetimes(_tenant.Settings), Now);
        _tokens.Families.Add(family);
        _tokens.RefreshTokens.Add(RefreshToken.Create(Guid.CreateVersion7(), tenant, family.Id, TokenHash.Compute(token), Now));
        return family;
    }

    private Task<Result<RevocationOutcome>> Revoke(string? token = Token, string? clientId = "spa", string? secret = null) =>
        _revocation.RevokeAsync(Context, new RevocationRequest(clientId, secret, token), CancellationToken.None);

    [Fact]
    public async Task Refresh_token_revokes_its_family()
    {
        _time.Advance(TimeSpan.FromMinutes(3));

        var result = await Revoke();

        Assert.Equal(RevocationOutcome.FamilyRevoked, result.Value);
        Assert.Equal(Now.AddMinutes(3), _family.RevokedAt);
        Assert.Equal(FamilyRevocationReason.UserLogout, _family.RevocationReason);

        var revoked = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.FamilyRevoked, revoked.Type);
        Assert.Equal(_spa.Id, revoked.ClientPk);
        Assert.Equal(_userId, revoked.SubjectUserId);
        Assert.Equal(_family.Id, revoked.FamilyId);
        Assert.Equal("corr-1", revoked.CorrelationId);
        Assert.Equal("user_logout", revoked.Data["reason"]);
        Assert.Equal("revocation_endpoint", revoked.Data["source"]);
        Assert.Equal("spa", revoked.Data["client_id"]);
    }

    [Fact]
    public async Task Used_token_still_revokes_its_family_and_is_not_reuse()
    {
        var used = _tokens.RefreshTokens.Single();
        InMemoryTokenStore.Set(used, nameof(RefreshToken.UsedAt), (DateTimeOffset?)Now);

        Assert.Equal(RevocationOutcome.FamilyRevoked, (await Revoke()).Value);
        Assert.Equal(FamilyRevocationReason.UserLogout, _family.RevocationReason);
    }

    [Fact]
    public async Task Second_revocation_changes_nothing()
    {
        await Revoke();
        var auditBefore = _audit.Events.Count;

        Assert.Equal(RevocationOutcome.AlreadyRevoked, (await Revoke()).Value);
        Assert.Equal(auditBefore, _audit.Events.Count);
    }

    [Fact]
    public async Task Token_of_another_client_changes_nothing_and_is_audited()
    {
        var other = AddPublicClient("other");

        var result = await Revoke(clientId: "other");

        Assert.Equal(RevocationOutcome.ForeignToken, result.Value);
        Assert.Null(_family.RevokedAt);
        var refused = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.RevocationRefused, refused.Type);
        Assert.Equal(_spa.Id, refused.ClientPk);
        Assert.Equal(_family.Id, refused.FamilyId);
        Assert.Equal(_userId, refused.SubjectUserId);
        Assert.Equal(other.ClientId, refused.Data["client_id"]);
        Assert.Equal("refresh token of another client", refused.Data["reason"]);
    }

    [Fact]
    public async Task Unknown_token_is_not_found_and_not_audited()
    {
        Assert.Equal(RevocationOutcome.NotFound, (await Revoke("an.access.token")).Value);
        Assert.Empty(_audit.Events);
    }

    [Fact]
    public async Task Token_of_another_tenant_is_not_found()
    {
        var other = StartFamily(_spa, "other-tenant-token", Guid.CreateVersion7());

        Assert.Equal(RevocationOutcome.NotFound, (await Revoke("other-tenant-token")).Value);
        Assert.Null(other.RevokedAt);
    }

    [Fact]
    public async Task Suspended_tenant_can_still_revoke()
    {
        _tenant.Suspend();

        Assert.Equal(RevocationOutcome.FamilyRevoked, (await Revoke()).Value);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Missing_token_is_invalid_request(string? token)
    {
        var result = await Revoke(token);

        Assert.Equal(OAuthError.InvalidRequestCode, result.Error!.Code);
        Assert.Equal("token missing", result.Error.AuditDetail);
    }

    [Fact]
    public async Task Failed_client_authentication_is_refused_and_audited()
    {
        var result = await Revoke(clientId: "no-such-client");

        Assert.Equal(OAuthError.InvalidClientCode, result.Error!.Code);
        Assert.Null(_family.RevokedAt);
        var refused = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.RevocationRefused, refused.Type);
        Assert.Null(refused.ClientPk);
        Assert.Null(refused.FamilyId);
        Assert.Equal("no-such-client", refused.Data["client_id"]);
        Assert.Equal(OAuthError.InvalidClientCode, refused.Data["error"]);
        Assert.Equal("unknown client", refused.Data["reason"]);
    }

    [Theory]
    [InlineData(128, 128)]
    [InlineData(129, 128)]
    public async Task Refusal_audit_caps_the_client_id(int length, int audited)
    {
        await Revoke(clientId: new string('x', length));

        Assert.Equal(audited, _audit.Events[0].Data["client_id"].Length);
    }

    [Fact]
    public async Task Missing_client_id_is_audited_as_empty()
    {
        await Revoke(clientId: null);

        Assert.Equal(string.Empty, _audit.Events[0].Data["client_id"]);
    }
}
