using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Application.Dpop;
using Heimdall.Application.Keys;
using Heimdall.Application.Tokens;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Tokens;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Application;

public class AuthorizationCodeGrantTests
{
    private const string Issuer = "https://acme.example.com";
    private const string UserInfoAudience = Issuer + "/oauth/v1/userinfo";
    private const string Callback = "https://app.example.com/callback";
    private const string Code = "the-authorization-code";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset AuthTime = Now.AddMinutes(-1);

    private readonly Tenant _tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);
    private readonly Guid _userId = Guid.CreateVersion7();
    private readonly InMemoryClientStore _clients = new();
    private readonly InMemoryTokenStore _tokens = new();
    private readonly FakeTimeProvider _time = new(Now);
    private readonly FakeDpopProofValidator _dpop = new();
    private readonly InMemoryDpopReplayStore _dpopReplay = new();
    private readonly RecordingTokenSigner _signer = new();
    private readonly RecordingAuditLog _audit = new();
    private readonly RecordingSecurityAlerts _alerts = new();
    private readonly AuthorizationCodeGrant _grant;
    private readonly Client _spa;

    public AuthorizationCodeGrantTests()
    {
        _grant = new AuthorizationCodeGrant(new ClientAuthenticator(_clients, _time), new DpopTokenCheck(_dpop, _dpopReplay), _tokens, _signer, _audit, _alerts, _time);
        _spa = AddPublicClient("spa");
    }

    private RequestContext Context => new(_tenant, Issuer, "corr-1", IPAddress.Parse("203.0.113.7"));

    private static string ChallengeOf(string verifier) =>
        Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

    private Client AddPublicClient(
        string clientId,
        string[]? redirectUris = null,
        GrantType[]? grants = null,
        string[]? audiences = null,
        bool requireDpop = false)
    {
        var client = Client.Create(
            Guid.CreateVersion7(),
            _tenant.Id,
            clientId,
            "Single-page app",
            ClientType.Public,
            grants ?? [GrantType.AuthorizationCode, GrantType.RefreshToken],
            ["openid", "profile", "offline_access"],
            redirectUris ?? [Callback],
            requireConsent: false,
            overrides: null,
            Now,
            audiences,
            requireDpop);
        client.Approve();
        _clients.Add(client);
        return client;
    }

    private AuthorizationCode IssueCode(
        Client? client = null,
        string scope = "openid offline_access",
        string redirectUri = Callback,
        string code = Code,
        string? nonce = "n-0S6_WzA2Mj",
        string? dpopKey = null)
    {
        var issued = AuthorizationCode.Create(
            Guid.CreateVersion7(),
            _tenant.Id,
            (client ?? _spa).Id,
            _userId,
            TokenHash.Compute(code),
            redirectUri,
            scope,
            ChallengeOf(Verifier),
            nonce,
            AuthTime,
            _time.GetUtcNow(),
            dpopKey);
        _tokens.Codes.Add(issued);
        return issued;
    }

    private Task<Result<TokenResponse>> Redeem(
        string? clientId = "spa",
        string? code = Code,
        string? verifier = Verifier,
        string? redirectUri = Callback,
        string? resource = null,
        string? secret = null,
        string? dpop = null) =>
        _grant.HandleAsync(
            Context,
            new AuthorizationCodeRequest(clientId, secret, code, verifier, redirectUri, resource, dpop),
            CancellationToken.None);

    private AuditEvent Rejected(Result<TokenResponse> result, string error, string reason)
    {
        Assert.False(result.IsSuccess);
        Assert.Equal(error, result.Error!.Code);
        Assert.Equal(reason, result.Error.AuditDetail);
        var rejected = _audit.Events.Last(e => e.Type == AuditEventTypes.TokenRejected);
        Assert.Equal("authorization_code", rejected.Data["grant_type"]);
        Assert.Equal(error, rejected.Data["error"]);
        Assert.Equal(reason, rejected.Data["reason"]);
        return rejected;
    }

    [Fact]
    public async Task Code_gives_an_access_token_an_id_token_and_a_refresh_token()
    {
        var code = IssueCode();

        var result = await Redeem();

        Assert.True(result.IsSuccess);
        var response = result.Value;
        Assert.Equal("Bearer", response.TokenType);
        Assert.Equal(300, response.ExpiresIn);
        Assert.Equal("openid offline_access", response.Scope);
        Assert.NotNull(response.IdToken);
        Assert.NotNull(response.RefreshToken);

        var (tenantId, access) = Assert.Single(_signer.Signed);
        Assert.Equal(_tenant.Id, tenantId);
        Assert.Equal(Issuer, access.Issuer);
        Assert.Equal(_userId.ToString(), access.Subject);
        Assert.Equal(UserInfoAudience, access.Audience);
        Assert.Equal("spa", access.ClientId);
        Assert.Equal(["openid", "offline_access"], access.Scopes);
        Assert.Equal(Now, access.IssuedAt);
        Assert.Equal(Now.AddMinutes(5), access.ExpiresAt);
        Assert.Matches("^[0-9a-f]{32}$", access.JwtId);
        Assert.Equal(AuthTime, access.AuthTime);

        var (idTenantId, id) = Assert.Single(_signer.SignedIdTokens);
        Assert.Equal(_tenant.Id, idTenantId);
        Assert.Equal(Issuer, id.Issuer);
        Assert.Equal(_userId.ToString(), id.Subject);
        Assert.Equal("spa", id.ClientId);
        Assert.Equal(Now, id.IssuedAt);
        Assert.Equal(Now.AddMinutes(5), id.ExpiresAt);
        Assert.Equal(AuthTime, id.AuthTime);
        Assert.Equal("n-0S6_WzA2Mj", id.Nonce);

        var family = Assert.Single(_tokens.Families);
        Assert.Equal(_tenant.Id, family.TenantId);
        Assert.Equal(_spa.Id, family.ClientPk);
        Assert.Equal(_userId, family.UserId);
        Assert.Equal(code.Id, family.SourceCodeId);
        Assert.Equal("openid offline_access", family.Scope);
        Assert.Equal(Now + TenantSettings.Default.RefreshAbsolute, family.AbsoluteExpiresAt);
        Assert.Equal(Now, code.RedeemedAt);
        Assert.Equal(family.Id, code.FamilyId);

        var refresh = Assert.Single(_tokens.RefreshTokens);
        Assert.Equal(TokenHash.Compute(response.RefreshToken!), refresh.Hash);
        Assert.Equal(family.Id, refresh.FamilyId);
        Assert.Equal(_tenant.Id, refresh.TenantId);
        Assert.Equal(1, _tokens.Commits);

        var redeemed = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.CodeRedeemed, redeemed.Type);
        Assert.Equal(_spa.Id, redeemed.ClientPk);
        Assert.Equal(_userId, redeemed.SubjectUserId);
        Assert.Equal(family.Id, redeemed.FamilyId);
        Assert.Equal("corr-1", redeemed.CorrelationId);
        Assert.Equal("authorization_code", redeemed.Data["grant_type"]);
        Assert.Equal("openid offline_access", redeemed.Data["scope"]);
        Assert.Equal(UserInfoAudience, redeemed.Data["aud"]);
        Assert.Equal("yes", redeemed.Data["refresh_issued"]);
    }

    [Fact]
    public async Task Each_refresh_token_is_new_random_text()
    {
        IssueCode();
        IssueCode(code: "second-code");

        var first = await Redeem();
        var second = await Redeem(code: "second-code");

        Assert.NotEqual(first.Value.RefreshToken, second.Value.RefreshToken);
        Assert.Equal(43, first.Value.RefreshToken!.Length); // 32 random bytes in BASE64URL
    }

    [Fact]
    public async Task Without_offline_access_there_is_no_refresh_token()
    {
        IssueCode(scope: "openid profile");

        var result = await Redeem();

        Assert.Null(result.Value.RefreshToken);
        Assert.Single(_tokens.Families);
        Assert.Empty(_tokens.RefreshTokens);
        Assert.Equal("no", _audit.Events[0].Data["refresh_issued"]);
    }

    [Fact]
    public async Task Client_without_the_refresh_grant_gets_no_refresh_token()
    {
        var client = AddPublicClient("no-refresh", grants: [GrantType.AuthorizationCode]);
        IssueCode(client);

        var result = await Redeem(clientId: "no-refresh");

        Assert.Null(result.Value.RefreshToken);
        Assert.Empty(_tokens.RefreshTokens);
    }

    [Fact]
    public async Task Without_openid_there_is_no_id_token()
    {
        IssueCode(scope: "profile");

        var result = await Redeem();

        Assert.Null(result.Value.IdToken);
        Assert.Empty(_signer.SignedIdTokens);
    }

    [Fact]
    public async Task Suspended_tenant_redeems_nothing()
    {
        var code = IssueCode();
        _tenant.Suspend();

        Rejected(await Redeem(), OAuthError.InvalidClientCode, "tenant suspended");
        Assert.Null(code.RedeemedAt);
    }

    [Fact]
    public async Task Unauthenticated_client_redeems_nothing()
    {
        var code = IssueCode();

        Rejected(await Redeem(clientId: "no-such-client"), OAuthError.InvalidClientCode, "unknown client");
        Assert.Null(code.RedeemedAt);
    }

    [Fact]
    public async Task Client_without_the_grant_is_unauthorized_client()
    {
        var service = Client.Create(
            Guid.CreateVersion7(), _tenant.Id, "billing", "Billing service", ClientType.Confidential,
            [GrantType.ClientCredentials], ["invoices.read"], [], requireConsent: false, overrides: null, Now,
            ["https://api.example.com"]);
        service.Approve();
        _clients.Add(service, ("billing-secret", null));

        Rejected(
            await Redeem(clientId: "billing", secret: "billing-secret"),
            OAuthError.UnauthorizedClientCode,
            "authorization_code not allowed");
    }

    [Theory]
    [InlineData(null, Verifier)]
    [InlineData("", Verifier)]
    [InlineData(Code, null)]
    [InlineData(Code, "")]
    public async Task Missing_code_or_verifier_is_invalid_request(string? code, string? verifier)
    {
        var issued = IssueCode();

        Rejected(await Redeem(code: code, verifier: verifier), OAuthError.InvalidRequestCode, "code or code_verifier missing");
        Assert.Null(issued.RedeemedAt);
    }

    [Fact]
    public async Task Malformed_verifier_is_refused_before_the_store()
    {
        var code = IssueCode();

        // 42 characters: one below the RFC 7636 minimum.
        Rejected(await Redeem(verifier: Verifier[..42]), OAuthError.InvalidGrantCode, "code_verifier malformed");
        Assert.Null(code.RedeemedAt);
    }

    [Fact]
    public async Task Missing_redirect_uri_uses_the_only_registered_one()
    {
        IssueCode();

        Assert.True((await Redeem(redirectUri: null)).IsSuccess);
    }

    [Fact]
    public async Task Sent_redirect_uri_must_match_even_when_one_is_registered()
    {
        // RFC 6749, section 4.1.3: a redirect_uri that the client sends must match. The default applies only when it is absent.
        var code = IssueCode();

        Rejected(
            await Redeem(redirectUri: "https://app.example.com/other"),
            OAuthError.InvalidGrantCode,
            "redirect_uri mismatch");
        Assert.Null(code.RedeemedAt);
    }

    [Fact]
    public async Task Missing_redirect_uri_with_several_registered_is_invalid_request()
    {
        var client = AddPublicClient("two-uris", redirectUris: [Callback, "https://app.example.com/other"]);
        IssueCode(client);

        Rejected(await Redeem(clientId: "two-uris", redirectUri: null), OAuthError.InvalidRequestCode, "redirect_uri missing");
    }

    [Fact]
    public async Task Resource_that_is_not_allowed_is_invalid_target()
    {
        IssueCode();

        Rejected(await Redeem(resource: "https://evil.example.com"), OAuthError.InvalidTargetCode, "resource missing or not allowed");
    }

    [Fact]
    public async Task Requested_resource_becomes_the_audience()
    {
        var client = AddPublicClient("api-client", audiences: ["https://api.example.com"]);
        IssueCode(client);

        await Redeem(clientId: "api-client", resource: "https://api.example.com");

        Assert.Equal("https://api.example.com", _signer.Signed[0].Claims.Audience);
    }

    [Fact]
    public async Task Unknown_code_is_invalid_grant()
    {
        Rejected(await Redeem(), OAuthError.InvalidGrantCode, "unknown code");
        Assert.Empty(_alerts.Raised);
    }

    [Fact]
    public async Task Code_of_another_tenant_is_unknown()
    {
        var other = AuthorizationCode.Create(
            Guid.CreateVersion7(), Guid.CreateVersion7(), _spa.Id, _userId, TokenHash.Compute(Code),
            Callback, "openid", ChallengeOf(Verifier), null, AuthTime, Now);
        _tokens.Codes.Add(other);

        Rejected(await Redeem(), OAuthError.InvalidGrantCode, "unknown code");
        Assert.Null(other.RedeemedAt);
    }

    [Fact]
    public async Task Code_works_until_one_tick_before_it_expires()
    {
        IssueCode();
        _time.Advance(AuthorizationCode.Lifetime - TimeSpan.FromTicks(1));

        Assert.True((await Redeem()).IsSuccess);
    }

    [Fact]
    public async Task Expired_code_is_invalid_grant()
    {
        var code = IssueCode();
        _time.Advance(AuthorizationCode.Lifetime);

        Rejected(await Redeem(), OAuthError.InvalidGrantCode, "code expired");
        Assert.Null(code.RedeemedAt);
        Assert.Empty(_alerts.Raised);
    }

    [Fact]
    public async Task Code_of_one_client_cannot_be_redeemed_by_another()
    {
        // The confused deputy: a code issued to "spa" must not work for "other", and must stay usable for "spa".
        var code = IssueCode();
        AddPublicClient("other");

        Rejected(await Redeem(clientId: "other"), OAuthError.InvalidGrantCode, "code issued to another client");
        Assert.Null(code.RedeemedAt);
        Assert.True((await Redeem()).IsSuccess);
    }

    [Fact]
    public async Task Different_redirect_uri_is_invalid_grant()
    {
        var client = AddPublicClient("two-uris", redirectUris: [Callback, "https://app.example.com/other"]);
        var code = IssueCode(client);

        Rejected(
            await Redeem(clientId: "two-uris", redirectUri: "https://app.example.com/other"),
            OAuthError.InvalidGrantCode,
            "redirect_uri mismatch");
        Assert.Null(code.RedeemedAt);
    }

    [Fact]
    public async Task Wrong_verifier_does_not_burn_the_code()
    {
        var code = IssueCode();

        Rejected(await Redeem(verifier: new string('a', 43)), OAuthError.InvalidGrantCode, "code_verifier mismatch");
        Assert.Null(code.RedeemedAt);
        Assert.True((await Redeem()).IsSuccess);
    }

    [Fact]
    public async Task Reused_code_revokes_the_family_it_started_and_raises_an_alert()
    {
        var code = IssueCode();
        await Redeem();
        var family = Assert.Single(_tokens.Families);
        _time.Advance(TimeSpan.FromSeconds(10));

        var rejected = Rejected(await Redeem(), OAuthError.InvalidGrantCode, "code reused");

        Assert.Equal(Now.AddSeconds(10), family.RevokedAt);
        Assert.Equal(FamilyRevocationReason.ReuseDetected, family.RevocationReason);
        Assert.Equal("spa", rejected.Data["client_id"]);

        var reuse = Assert.Single(_audit.Events, e => e.Type == AuditEventTypes.CodeReuseDetected);
        Assert.Equal(_spa.Id, reuse.ClientPk);
        Assert.Equal(_userId, reuse.SubjectUserId);
        Assert.Equal(family.Id, reuse.FamilyId);
        Assert.Equal("spa", reuse.Data["client_id"]);
        Assert.Equal(code.Id.ToString(), reuse.Data["code_id"]);
        Assert.Equal("yes", reuse.Data["family_revoked"]);

        var revoked = Assert.Single(_audit.Events, e => e.Type == AuditEventTypes.FamilyRevoked);
        Assert.Equal(_spa.Id, revoked.ClientPk);
        Assert.Equal(_userId, revoked.SubjectUserId);
        Assert.Equal(family.Id, revoked.FamilyId);
        Assert.Equal("reuse_detected", revoked.Data["reason"]);

        var alert = Assert.Single(_alerts.Raised);
        Assert.Equal(AuditEventTypes.CodeReuseDetected, alert.Type);
        Assert.Equal(_tenant.Id, alert.TenantId);
        Assert.Equal(code.Id.ToString(), alert.Data["code_id"]);
    }

    [Fact]
    public async Task Reuse_by_another_client_still_revokes_the_family()
    {
        // A stolen code that the thief presents after the real client is still reuse.
        IssueCode();
        await Redeem();
        AddPublicClient("thief");

        Rejected(await Redeem(clientId: "thief"), OAuthError.InvalidGrantCode, "code reused");
        Assert.NotNull(Assert.Single(_tokens.Families).RevokedAt);
    }

    [Fact]
    public async Task Second_reuse_finds_the_family_already_revoked()
    {
        IssueCode();
        await Redeem();
        await Redeem();
        var auditBefore = _audit.Events.Count;

        await Redeem();

        var events = _audit.Events.Skip(auditBefore).ToList();
        Assert.Equal("already revoked", Assert.Single(events, e => e.Type == AuditEventTypes.CodeReuseDetected).Data["family_revoked"]);
        Assert.DoesNotContain(events, e => e.Type == AuditEventTypes.FamilyRevoked);
        Assert.Equal(2, _alerts.Raised.Count);
    }

    [Fact]
    public async Task Failed_signing_rolls_back_and_leaves_the_code_usable()
    {
        var code = IssueCode();
        _signer.Unavailable = true;

        await Assert.ThrowsAsync<SigningKeyUnavailableException>(() => Redeem());

        Assert.Null(code.RedeemedAt);
        Assert.Null(code.FamilyId);
        Assert.Empty(_tokens.Families);
        Assert.Empty(_tokens.RefreshTokens);
        Assert.Equal(1, _tokens.Rollbacks);
        Assert.Empty(_audit.Events);

        _signer.Unavailable = false;
        Assert.True((await Redeem()).IsSuccess);
    }

    [Fact]
    public async Task Confidential_client_authenticates_with_its_secret()
    {
        var client = Client.Create(
            Guid.CreateVersion7(), _tenant.Id, "web", "Web app", ClientType.Confidential,
            [GrantType.AuthorizationCode], ["openid"], [Callback], requireConsent: false, overrides: null, Now);
        client.Approve();
        _clients.Add(client, ("web-secret", null));
        IssueCode(client, scope: "openid");

        Rejected(await Redeem(clientId: "web", secret: "wrong"), OAuthError.InvalidClientCode, "wrong secret");
        Assert.True((await Redeem(clientId: "web", secret: "web-secret")).IsSuccess);
    }

    [Fact]
    public async Task Rejection_audit_caps_the_client_id()
    {
        await Redeem(clientId: new string('x', 5000));

        Assert.Equal(128, _audit.Events[0].Data["client_id"].Length);
    }

    [Fact]
    public async Task Missing_client_id_is_audited_as_empty()
    {
        await Redeem(clientId: null);

        Assert.Equal(string.Empty, _audit.Events[0].Data["client_id"]);
    }

    private const string DpopKey = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

    [Fact]
    public async Task DPoP_proof_binds_the_access_token_and_the_public_client_family()
    {
        IssueCode();

        var result = await Redeem(dpop: FakeDpopProofValidator.Proof(DpopKey));

        Assert.Equal("DPoP", result.Value.TokenType);
        Assert.Equal(DpopKey, _signer.Signed[0].Claims.KeyThumbprint);
        Assert.Equal(DpopKey, Assert.Single(_tokens.Families).DpopKeyThumbprint);
        Assert.Equal(DpopKey, _audit.Events[0].Data["dpop_jkt"]);
    }

    [Fact]
    public async Task Confidential_client_family_stays_unbound_but_its_access_token_is_bound()
    {
        // D24: a confidential client authenticates at each refresh, so only its access token is bound.
        var client = Client.Create(
            Guid.CreateVersion7(), _tenant.Id, "web", "Web app", ClientType.Confidential,
            [GrantType.AuthorizationCode, GrantType.RefreshToken], ["openid", "offline_access"], [Callback],
            requireConsent: false, overrides: null, Now);
        client.Approve();
        _clients.Add(client, ("web-secret", null));
        IssueCode(client);

        var result = await Redeem(clientId: "web", secret: "web-secret", dpop: FakeDpopProofValidator.Proof(DpopKey));

        Assert.Equal("DPoP", result.Value.TokenType);
        Assert.Equal(DpopKey, _signer.Signed[0].Claims.KeyThumbprint);
        Assert.Null(Assert.Single(_tokens.Families).DpopKeyThumbprint);
    }

    [Fact]
    public async Task Without_a_proof_the_family_is_unbound()
    {
        IssueCode();

        var result = await Redeem();

        Assert.Equal("Bearer", result.Value.TokenType);
        Assert.Null(Assert.Single(_tokens.Families).DpopKeyThumbprint);
    }

    [Fact]
    public async Task Invalid_proof_does_not_redeem_the_code()
    {
        var code = IssueCode();

        Rejected(await Redeem(dpop: "not a proof"), OAuthError.InvalidDpopProofCode, "fake refused");
        Assert.Null(code.RedeemedAt);
    }

    [Fact]
    public async Task Client_that_requires_DPoP_cannot_redeem_without_a_proof()
    {
        var client = AddPublicClient("dpop-only", requireDpop: true);
        var code = IssueCode(client);

        Rejected(await Redeem(clientId: "dpop-only"), OAuthError.InvalidDpopProofCode, "client requires DPoP");
        Assert.Null(code.RedeemedAt);
    }

    private const string OtherDpopKey = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    [Fact]
    public async Task Code_bound_by_dpop_jkt_redeems_with_a_proof_from_that_key()
    {
        IssueCode(dpopKey: DpopKey);

        var result = await Redeem(dpop: FakeDpopProofValidator.Proof(DpopKey));

        Assert.Equal("DPoP", result.Value.TokenType);
        Assert.Equal(DpopKey, Assert.Single(_tokens.Families).DpopKeyThumbprint);
    }

    [Fact]
    public async Task Code_bound_by_dpop_jkt_needs_a_proof_and_a_request_without_one_does_not_use_it_up()
    {
        var code = IssueCode(dpopKey: DpopKey);

        Rejected(await Redeem(), OAuthError.InvalidDpopProofCode, "proof required for a code bound by dpop_jkt");

        Assert.Null(code.RedeemedAt);
        Assert.True((await Redeem(dpop: FakeDpopProofValidator.Proof(DpopKey))).IsSuccess);
    }

    [Fact]
    public async Task Code_bound_by_dpop_jkt_refuses_another_key_and_stays_usable()
    {
        var code = IssueCode(dpopKey: DpopKey);

        Rejected(await Redeem(dpop: FakeDpopProofValidator.Proof(OtherDpopKey)), OAuthError.InvalidGrantCode, "DPoP key differs from dpop_jkt");

        Assert.Null(code.RedeemedAt);
        Assert.Null(code.FamilyId);
        Assert.True((await Redeem(dpop: FakeDpopProofValidator.Proof(DpopKey, jti: "jti-2"))).IsSuccess);
    }

    [Fact]
    public async Task Code_of_another_client_reports_the_client_and_not_the_key()
    {
        // The client check comes first, so another client learns nothing about the code's key.
        var other = AddPublicClient("other");
        IssueCode(other, dpopKey: DpopKey);

        Rejected(await Redeem(), OAuthError.InvalidGrantCode, "code issued to another client");
    }
}
