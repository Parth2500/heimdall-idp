using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Domain.Clients;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Application;

public class ClientAuthenticatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid TenantId = Guid.CreateVersion7();

    private const string Issuer = "https://acme.example.com";
    private const string Jwks = """{"keys":[{"kty":"EC","kid":"k1","crv":"P-256","x":"x","y":"y"}]}""";

    private readonly InMemoryClientStore _store = new();
    private readonly FakeTimeProvider _time = new(Now);
    private readonly FakeClientAssertionValidator _assertions = new();
    private readonly InMemoryClientAssertionReplayStore _replay = new();
    private readonly ClientAuthenticator _authenticator;

    public ClientAuthenticatorTests()
    {
        _authenticator = new ClientAuthenticator(_store, _assertions, _replay, _time);
    }

    /// <summary>A private_key_jwt client, and a fake validator that reads its client_id and accepts the assertion.</summary>
    private Client KeyClient(string clientId = "billing-service", bool approve = true)
    {
        var client = Confidential(clientId, approve);
        client.UsePrivateKeyJwt(Jwks);
        _store.Add(client, ("old-secret-of-the-client", null));
        _assertions.Reader = _ => clientId;
        _assertions.Validator = (_, _, _) => Result.Success(new ClientAssertion("jti-1", Now.AddMinutes(1)));
        return client;
    }

    private Task<Result<Client>> AuthenticateWithAssertion(string? clientId, string? secret = null, string assertion = "a.b.c") =>
        _authenticator.AuthenticateAsync(TenantId, Issuer, clientId, secret, assertion, CancellationToken.None);

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

        var result = await Authenticate("billing-service", null);

        // The wrong-secret path also returns invalid_client. Only the audit detail shows which check rejected it.
        AssertInvalidClient(result);
        Assert.Equal("confidential client sent no secret", result.Error!.AuditDetail);
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
    public async Task Disabled_public_client_is_rejected()
    {
        var client = Public();
        client.Disable();
        _store.Add(client);

        var result = await Authenticate("spa", null);

        AssertInvalidClient(result);
        Assert.Contains("Disabled", result.Error!.AuditDetail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Every_valid_secret_is_compared_when_there_are_more_than_the_maximum()
    {
        // The store returns what is valid. Slots above MaxValidSecrets must still be compared.
        _store.Add(Confidential(), ("first", null), ("second", null), ("third", null));

        Assert.True((await Authenticate("billing-service", "third")).IsSuccess);
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

    [Theory]
    [InlineData(null)]
    [InlineData("billing-service")]
    public async Task Private_key_jwt_client_with_a_valid_assertion_is_authenticated(string? bodyClientId)
    {
        var client = KeyClient();

        var result = await AuthenticateWithAssertion(bodyClientId);

        Assert.Same(client, result.Value);
        var validated = Assert.Single(_assertions.Validated);
        Assert.Equal(("billing-service", Issuer), (validated.ClientId, validated.Issuer));
        Assert.Contains((TenantId, client.Id, "jti-1"), _replay.Used);
    }

    [Fact]
    public async Task Assertion_used_twice_is_refused()
    {
        KeyClient();
        Assert.True((await AuthenticateWithAssertion(null)).IsSuccess);

        var replay = await AuthenticateWithAssertion(null);

        AssertInvalidClient(replay);
        Assert.Equal("assertion replayed", replay.Error!.AuditDetail);
    }

    [Fact]
    public async Task Private_key_jwt_client_with_its_old_secret_is_refused()
    {
        // D47: one method for each client. A secret that was valid before the change gives nothing.
        KeyClient();

        var result = await Authenticate("billing-service", "old-secret-of-the-client");

        AssertInvalidClient(result);
        Assert.Equal("private_key_jwt client sent no assertion", result.Error!.AuditDetail);
    }

    [Fact]
    public async Task Secret_client_with_an_assertion_is_refused_before_any_check()
    {
        _store.Add(Confidential(), ("s3cret-value-1", null));
        _assertions.Reader = _ => "billing-service";

        var result = await AuthenticateWithAssertion(null);

        AssertInvalidClient(result);
        Assert.Equal("client does not use private_key_jwt", result.Error!.AuditDetail);
        Assert.Empty(_assertions.Validated);
    }

    [Theory]
    [InlineData("other-client", null, "client_id differs from the assertion")]
    [InlineData(null, "a-secret", "secret and assertion in one request")]
    public async Task Mixed_or_conflicting_credentials_are_refused(string? bodyClientId, string? secret, string reason)
    {
        KeyClient();

        var result = await AuthenticateWithAssertion(bodyClientId, secret);

        AssertInvalidClient(result);
        Assert.Equal(reason, result.Error!.AuditDetail);
        Assert.Empty(_replay.Used);
    }

    [Fact]
    public async Task Unreadable_assertion_or_unknown_client_is_refused()
    {
        _assertions.Reader = _ => null;
        Assert.Equal("assertion unreadable", (await AuthenticateWithAssertion(null)).Error!.AuditDetail);

        _assertions.Reader = _ => "nobody";
        Assert.Equal("unknown client", (await AuthenticateWithAssertion(null)).Error!.AuditDetail);
    }

    [Fact]
    public async Task Invalid_assertion_is_refused_and_not_recorded()
    {
        KeyClient();
        _assertions.Validator = (_, _, _) => Result.Failure<ClientAssertion>(OAuthError.InvalidClient("aud is not the issuer"));

        var result = await AuthenticateWithAssertion(null);

        Assert.Equal("aud is not the issuer", result.Error!.AuditDetail);
        Assert.Empty(_replay.Used);
    }

    [Fact]
    public async Task Disabled_private_key_jwt_client_is_refused_after_the_checks()
    {
        KeyClient(approve: false);

        var result = await AuthenticateWithAssertion(null);

        Assert.Equal("client status Pending", result.Error!.AuditDetail);
    }
}
