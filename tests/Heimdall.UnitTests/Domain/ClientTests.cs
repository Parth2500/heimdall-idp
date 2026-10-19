using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Tenants;

namespace Heimdall.UnitTests.Domain;

public class ClientTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private static Client CreateClient(
        ClientType type = ClientType.Confidential,
        GrantType[]? grants = null,
        string[]? redirectUris = null,
        ClientTokenOverrides? overrides = null,
        string[]? audiences = null) =>
        Client.Create(
            Guid.CreateVersion7(),
            Guid.CreateVersion7(),
            "web-app",
            "Web app",
            type,
            grants ?? [GrantType.AuthorizationCode, GrantType.RefreshToken],
            ["openid", "profile"],
            redirectUris ?? ["https://app.example.com/callback"],
            requireConsent: true,
            overrides,
            Now,
            audiences);

    [Fact]
    public void Public_client_does_not_authenticate()
    {
        var client = CreateClient(ClientType.Public);

        Assert.Equal(TokenEndpointAuthMethod.None, client.TokenEndpointAuthMethod);
    }

    [Fact]
    public void Confidential_client_uses_client_secret_basic()
    {
        var client = CreateClient(ClientType.Confidential);

        Assert.Equal(TokenEndpointAuthMethod.ClientSecretBasic, client.TokenEndpointAuthMethod);
    }

    [Fact]
    public void New_client_is_pending_until_approved()
    {
        var client = CreateClient();
        Assert.Equal(ClientStatus.Pending, client.Status);

        client.Approve();

        Assert.Equal(ClientStatus.Active, client.Status);
    }

    [Fact]
    public void Approve_does_not_enable_a_disabled_client()
    {
        var client = CreateClient();
        client.Disable();

        client.Approve();

        Assert.Equal(ClientStatus.Disabled, client.Status);
    }

    [Fact]
    public void Public_client_cannot_use_client_credentials()
    {
        Assert.Throws<DomainException>(() =>
            CreateClient(ClientType.Public, grants: [GrantType.ClientCredentials], redirectUris: []));
    }

    [Fact]
    public void Refresh_grant_needs_authorization_code_grant()
    {
        Assert.Throws<DomainException>(() =>
            CreateClient(grants: [GrantType.ClientCredentials, GrantType.RefreshToken], redirectUris: []));
    }

    [Fact]
    public void Authorization_code_grant_needs_a_redirect_uri()
    {
        Assert.Throws<DomainException>(() => CreateClient(redirectUris: []));
    }

    [Fact]
    public void Client_credentials_client_needs_no_redirect_uri()
    {
        var client = CreateClient(grants: [GrantType.ClientCredentials], redirectUris: [], audiences: ["https://api.example.com"]);

        Assert.False(client.RefreshEnabled);
    }

    [Fact]
    public void Client_credentials_client_needs_an_audience()
    {
        Assert.Throws<DomainException>(() => CreateClient(grants: [GrantType.ClientCredentials], redirectUris: []));
    }

    [Theory]
    [InlineData("api.example.com")]
    [InlineData("http://api.example.com")]
    [InlineData("https://api.example.com/#x")]
    [InlineData("https://api.example.com/?tenant=1")]
    [InlineData("https://user@api.example.com")]
    public void Invalid_audience_is_rejected(string audience)
    {
        Assert.Throws<DomainException>(() => CreateClient(audiences: [audience]));
    }

    [Fact]
    public void Single_audience_is_the_default()
    {
        var client = CreateClient(audiences: ["https://api.example.com"]);

        Assert.Equal("https://api.example.com", client.ResolveAudience(null));
    }

    [Fact]
    public void Several_audiences_need_an_explicit_resource()
    {
        var client = CreateClient(audiences: ["https://billing.example.com", "https://orders.example.com"]);

        Assert.Null(client.ResolveAudience(null));
        Assert.Equal("https://orders.example.com", client.ResolveAudience("https://orders.example.com"));
    }

    private const string UserInfo = "https://acme.example.com/oauth/v1/userinfo";

    [Fact]
    public void User_grant_of_a_client_with_no_audience_defaults_to_userinfo()
    {
        var client = CreateClient();

        Assert.Equal(UserInfo, client.ResolveUserAudience(null, UserInfo));
        Assert.Null(client.ResolveAudience(null));
    }

    [Fact]
    public void User_grant_may_name_userinfo_but_keeps_the_registered_default()
    {
        var client = CreateClient(audiences: ["https://api.example.com"]);

        Assert.Equal("https://api.example.com", client.ResolveUserAudience(null, UserInfo));
        Assert.Equal(UserInfo, client.ResolveUserAudience(UserInfo, UserInfo));
        Assert.Equal("https://api.example.com", client.ResolveUserAudience("https://api.example.com", UserInfo));
        Assert.Null(client.ResolveUserAudience("https://evil.example.com", UserInfo));
        Assert.Null(client.ResolveUserAudience(UserInfo + "/", UserInfo));
    }

    [Theory]
    [InlineData("https://api.example.com/")]
    [InlineData("https://API.example.com")]
    [InlineData("https://evil.example.com")]
    public void Resource_must_match_an_audience_exactly(string resource)
    {
        var client = CreateClient(audiences: ["https://api.example.com"]);

        Assert.Null(client.ResolveAudience(resource));
    }

    [Theory]
    [InlineData("https://*.example.com/callback")]
    [InlineData("https://app.example.com/callback#fragment")]
    [InlineData("http://app.example.com/callback")]
    [InlineData("https://user:pass@app.example.com/callback")]
    [InlineData("/relative/callback")]
    [InlineData("not a uri")]
    public void Unsafe_redirect_uri_is_rejected(string uri)
    {
        Assert.Throws<DomainException>(() => CreateClient(redirectUris: [uri]));
    }

    [Theory]
    [InlineData("http://localhost:5173/callback")]
    [InlineData("http://127.0.0.1:8080/callback")]
    [InlineData("https://app.example.com/callback?tab=1")]
    public void Safe_redirect_uri_is_accepted(string uri)
    {
        var client = CreateClient(redirectUris: [uri]);

        Assert.True(client.IsRedirectUriAllowed(uri));
    }

    [Theory]
    [InlineData("https://app.example.com/callback/")]
    [InlineData("https://app.example.com/callback?x=1")]
    [InlineData("https://APP.example.com/callback")]
    [InlineData("https://app.example.com/callback/extra")]
    [InlineData("https://app.example.com.evil.test/callback")]
    [InlineData("")]
    [InlineData(null)]
    public void Redirect_uri_must_match_exactly(string? candidate)
    {
        var client = CreateClient();

        Assert.False(client.IsRedirectUriAllowed(candidate));
    }

    [Fact]
    public void Scope_with_white_space_is_rejected()
    {
        Assert.Throws<DomainException>(() =>
            Client.Create(
                Guid.CreateVersion7(),
                Guid.CreateVersion7(),
                "web-app",
                "Web app",
                ClientType.Confidential,
                [GrantType.ClientCredentials],
                ["read write"],
                [],
                requireConsent: false,
                overrides: null,
                Now));
    }

    [Fact]
    public void Requested_scopes_are_limited_to_allowed_scopes()
    {
        var client = CreateClient();

        var granted = client.FilterAllowedScopes(["openid", "admin", "profile", "openid"]);

        Assert.Equal(["openid", "profile"], granted);
    }

    [Fact]
    public void Lifetimes_fall_back_to_the_tenant_values()
    {
        var client = CreateClient();

        var lifetimes = client.ResolveLifetimes(TenantSettings.Default);

        Assert.Equal(TenantSettings.Default.AccessToken, lifetimes.AccessToken);
        Assert.Equal(TenantSettings.Default.RefreshIdle, lifetimes.RefreshIdle);
        Assert.Equal(TenantSettings.Default.RefreshAbsolute, lifetimes.RefreshAbsolute);
    }

    [Fact]
    public void Client_override_wins_over_the_tenant_value()
    {
        var client = CreateClient(overrides: new ClientTokenOverrides(TimeSpan.FromMinutes(10), null, null));

        var lifetimes = client.ResolveLifetimes(TenantSettings.Default);

        Assert.Equal(TimeSpan.FromMinutes(10), lifetimes.AccessToken);
        Assert.Equal(TenantSettings.Default.RefreshIdle, lifetimes.RefreshIdle);
    }

    [Fact]
    public void Override_that_makes_idle_longer_than_absolute_is_rejected()
    {
        var client = CreateClient(overrides: new ClientTokenOverrides(null, TimeSpan.FromDays(60), null));

        Assert.Throws<DomainException>(() => client.ResolveLifetimes(TenantSettings.Default));
    }

    [Fact]
    public void Override_must_be_positive()
    {
        Assert.Throws<DomainException>(() => new ClientTokenOverrides(TimeSpan.Zero, null, null));
    }

    [Fact]
    public void Browser_origins_of_an_active_public_client_use_the_browser_serialization()
    {
        var client = CreateClient(
            ClientType.Public,
            redirectUris: ["https://App.Example.com/callback", "https://app.example.com/other", "https://app.example.com:443/x", "https://spa.example.com:4300/cb"]);
        client.Approve();

        Assert.Equal(["https://app.example.com", "https://spa.example.com:4300"], client.BrowserOrigins());
    }

    [Fact]
    public void Loopback_http_redirect_gives_no_browser_origin()
    {
        var client = CreateClient(ClientType.Public, redirectUris: ["http://127.0.0.1:8400/callback"]);
        client.Approve();

        Assert.Empty(client.BrowserOrigins());
    }

    [Fact]
    public void Confidential_pending_and_disabled_clients_have_no_browser_origin()
    {
        var confidential = CreateClient(ClientType.Confidential);
        confidential.Approve();
        var pending = CreateClient(ClientType.Public);
        var disabled = CreateClient(ClientType.Public);
        disabled.Approve();
        disabled.Disable();

        Assert.Empty(confidential.BrowserOrigins());
        Assert.Empty(pending.BrowserOrigins());
        Assert.Empty(disabled.BrowserOrigins());
    }
}
