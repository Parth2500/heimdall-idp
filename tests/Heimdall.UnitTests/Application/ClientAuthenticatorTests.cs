using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Domain.Clients;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Application;

public class ClientAuthenticatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid TenantId = Guid.CreateVersion7();

    private readonly InMemoryClientStore _store = new();
    private readonly FakeTimeProvider _time = new(Now);
    private readonly ClientAuthenticator _authenticator;

    public ClientAuthenticatorTests()
    {
        _authenticator = new ClientAuthenticator(_store, _time);
    }

    private static Client Confidential(string clientId = "billing-service", bool approve = true)
    {
        var client = Client.Create(
            Guid.CreateVersion7(),
            TenantId,
            clientId,
            "Billing service",
            ClientType.Confidential,
            [GrantType.ClientCredentials],
            ["invoices.read"],
            [],
            requireConsent: false,
            overrides: null,
            Now,
            ["https://api.example.com"]);
        if (approve)
        {
            client.Approve();
        }

        return client;
    }

    private static Client Public(string clientId = "spa")
    {
        var client = Client.Create(
            Guid.CreateVersion7(),
            TenantId,
            clientId,
            "Single-page app",
            ClientType.Public,
            [GrantType.AuthorizationCode],
            ["openid"],
            ["https://app.example.com/callback"],
            requireConsent: true,
            overrides: null,
            Now);
        client.Approve();
        return client;
    }

    private Task<Result<Client>> Authenticate(string? clientId, string? secret, Guid? tenantId = null) =>
        _authenticator.AuthenticateAsync(tenantId ?? TenantId, clientId, secret, CancellationToken.None);

    private static void AssertInvalidClient(Result<Client> result)
    {
        Assert.False(result.IsSuccess);
        Assert.Equal(OAuthError.InvalidClientCode, result.Error!.Code);
    }

    [Fact]
    public async Task Confidential_client_with_correct_secret_is_authenticated()
    {
        var client = Confidential();
        _store.Add(client, ("s3cret-value-1", null));

        var result = await Authenticate("billing-service", "s3cret-value-1");

        Assert.True(result.IsSuccess);
        Assert.Same(client, result.Value);
    }

    [Fact]
    public async Task Wrong_secret_is_rejected()
    {
        _store.Add(Confidential(), ("s3cret-value-1", null));

        AssertInvalidClient(await Authenticate("billing-service", "wrong"));
    }

    [Fact]
    public async Task Missing_secret_for_confidential_client_is_rejected()
    {
        _store.Add(Confidential(), ("s3cret-value-1", null));

        AssertInvalidClient(await Authenticate("billing-service", null));
    }

    [Fact]
    public async Task Unknown_client_gets_the_same_error_as_a_wrong_secret()
    {
        _store.Add(Confidential(), ("s3cret-value-1", null));

        var unknown = await Authenticate("no-such-client", "s3cret-value-1");
        var wrong = await Authenticate("billing-service", "wrong");

        Assert.Equal(wrong.Error!.Code, unknown.Error!.Code);
        Assert.NotEqual(wrong.Error.AuditDetail, unknown.Error.AuditDetail);
    }

    [Fact]
    public async Task Client_of_another_tenant_is_unknown()
    {
        _store.Add(Confidential(), ("s3cret-value-1", null));

        AssertInvalidClient(await Authenticate("billing-service", "s3cret-value-1", Guid.CreateVersion7()));
    }

    [Fact]
    public async Task Either_of_two_valid_secrets_works_during_rotation()
    {
        _store.Add(Confidential(), ("old-secret", Now.AddDays(7)), ("new-secret", null));

        Assert.True((await Authenticate("billing-service", "old-secret")).IsSuccess);
        Assert.True((await Authenticate("billing-service", "new-secret")).IsSuccess);
    }

    [Fact]
    public async Task Expired_secret_is_rejected()
    {
        _store.Add(Confidential(), ("old-secret", Now.AddDays(7)), ("new-secret", null));
        _time.Advance(TimeSpan.FromDays(7));

        AssertInvalidClient(await Authenticate("billing-service", "old-secret"));
        Assert.True((await Authenticate("billing-service", "new-secret")).IsSuccess);
    }

    [Fact]
    public async Task Pending_client_is_rejected_even_with_the_correct_secret()
    {
        _store.Add(Confidential(approve: false), ("s3cret-value-1", null));

        var result = await Authenticate("billing-service", "s3cret-value-1");

        AssertInvalidClient(result);
        Assert.Contains("Pending", result.Error!.AuditDetail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Disabled_client_is_rejected()
    {
        var client = Confidential();
        client.Disable();
        _store.Add(client, ("s3cret-value-1", null));

        AssertInvalidClient(await Authenticate("billing-service", "s3cret-value-1"));
    }

    [Fact]
    public async Task Public_client_is_accepted_without_a_secret()
    {
        _store.Add(Public());

        Assert.True((await Authenticate("spa", null)).IsSuccess);
    }

    [Fact]
    public async Task Public_client_that_sends_a_secret_is_rejected()
    {
        _store.Add(Public());

        AssertInvalidClient(await Authenticate("spa", "anything"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Missing_client_id_is_rejected_without_a_store_query(string? clientId)
    {
        AssertInvalidClient(await Authenticate(clientId, "s3cret-value-1"));
        Assert.Equal(0, _store.Queries);
    }

    [Fact]
    public async Task Each_attempt_uses_one_store_query()
    {
        _store.Add(Confidential(), ("s3cret-value-1", null));

        await Authenticate("billing-service", "s3cret-value-1");
        await Authenticate("no-such-client", "s3cret-value-1");

        Assert.Equal(2, _store.Queries);
    }
}
