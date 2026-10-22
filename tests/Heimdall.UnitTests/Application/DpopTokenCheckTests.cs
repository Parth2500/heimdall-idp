using System.Net;
using Heimdall.Application.Common;
using Heimdall.Application.Dpop;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Tenants;

namespace Heimdall.UnitTests.Application;

public class DpopTokenCheckTests
{
    private const string Key = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private readonly Tenant _tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);
    private readonly FakeDpopProofValidator _validator = new();
    private readonly InMemoryDpopReplayStore _replay = new();
    private readonly DpopTokenCheck _check;

    public DpopTokenCheckTests()
    {
        _check = new DpopTokenCheck(_validator, _replay);
    }

    private RequestContext Context => new(_tenant, "https://acme.example.com", "corr-1", IPAddress.Loopback);

    private Client NewClient(bool requireDpop) => Client.Create(
        Guid.CreateVersion7(), _tenant.Id, "spa", "SPA", ClientType.Public, [GrantType.AuthorizationCode], ["openid"],
        ["https://app.example.com/cb"], requireConsent: false, overrides: null, Now, requireDpop: requireDpop);

    private Task<Result<string?>> Check(string? proof, bool requireDpop = false) =>
        _check.CheckAsync(Context, NewClient(requireDpop), proof, CancellationToken.None);

    [Fact]
    public async Task No_proof_gives_no_binding()
    {
        var result = await Check(null);

        Assert.True(result.IsSuccess);
        Assert.Null(result.Value);
        Assert.Empty(_validator.Checked);
    }

    [Fact]
    public async Task No_proof_fails_for_a_client_that_requires_DPoP()
    {
        var result = await Check(null, requireDpop: true);

        Assert.Equal(OAuthError.InvalidDpopProofCode, result.Error!.Code);
        Assert.Equal("client requires DPoP", result.Error.AuditDetail);
    }

    [Fact]
    public async Task Valid_proof_gives_its_key_and_is_checked_against_POST_to_the_token_endpoint()
    {
        var result = await Check(FakeDpopProofValidator.Proof(Key));

        Assert.Equal(Key, result.Value);
        var (_, request) = Assert.Single(_validator.Checked);
        Assert.Equal("POST", request.Method);
        Assert.Equal(new Uri("https://acme.example.com/oauth/v1/token"), request.Url);
        Assert.Null(request.AccessToken);
        Assert.Contains((_tenant.Id, Key, "jti-1"), _replay.Seen);
    }

    [Fact]
    public async Task Invalid_proof_fails_with_the_validator_error_and_is_not_recorded()
    {
        var result = await Check("not a proof");

        Assert.Equal(OAuthError.InvalidDpopProofCode, result.Error!.Code);
        Assert.Equal("fake refused", result.Error.AuditDetail);
        Assert.Empty(_replay.Seen);
    }

    [Fact]
    public async Task Replayed_proof_fails()
    {
        await Check(FakeDpopProofValidator.Proof(Key));

        var result = await Check(FakeDpopProofValidator.Proof(Key));

        Assert.Equal(OAuthError.InvalidDpopProofCode, result.Error!.Code);
        Assert.Equal("proof replayed", result.Error.AuditDetail);
    }
}
