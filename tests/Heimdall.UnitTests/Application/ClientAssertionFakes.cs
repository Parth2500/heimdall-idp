using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Domain.Clients;

namespace Heimdall.UnitTests.Application;

/// <summary>
/// A test fake of the client assertion validator. By default it reads no client and accepts nothing, so a test that
/// does not set it up sees every assertion fail. <c>ClientAssertionValidatorTests</c> tests the real one.
/// </summary>
internal sealed class FakeClientAssertionValidator : IClientAssertionValidator
{
    public Func<string, string?> Reader { get; set; } = _ => null;

    public Func<string, Client, string, Result<ClientAssertion>> Validator { get; set; } =
        (_, _, _) => Result.Failure<ClientAssertion>(OAuthError.InvalidClient("fake refuses"));

    public List<(string Assertion, string ClientId, string Issuer)> Validated { get; } = [];

    public string? ReadClientId(string assertion) => Reader(assertion);

    public Result<ClientAssertion> Validate(string assertion, Client client, string issuer)
    {
        Validated.Add((assertion, client.ClientId, issuer));
        return Validator(assertion, client, issuer);
    }
}

/// <summary>The replay store with the same condition as the unique key of <c>client_assertions</c>.</summary>
internal sealed class InMemoryClientAssertionReplayStore : IClientAssertionReplayStore
{
    public HashSet<(Guid TenantId, Guid ClientPk, string Jti)> Used { get; } = [];

    public Task<bool> TryUseAsync(Guid tenantId, Guid clientPk, ClientAssertion assertion, CancellationToken cancellationToken) =>
        Task.FromResult(Used.Add((tenantId, clientPk, assertion.Jti)));
}
