using System.Buffers.Text;
using System.Text;
using CsCheck;
using Heimdall.Domain.Clients;
using Heimdall.Infrastructure.Clients;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Properties;

/// <summary>The client assertion arrives before any authentication, so no value may make the validator throw.</summary>
public class ClientAssertionValidatorProperties
{
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private static readonly Client KeyClient = NewKeyClient();

    /// <summary>Three dot-separated parts: random text, or base64url of random JSON-like text, or of random bytes.</summary>
    private static readonly Gen<string> Part = Gen.Frequency(
        (1, Generators.AnyString),
        (2, Generators.UnicodeText.Select(s => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(s)))),
        (2, Gen.OneOf(
                Gen.Const("""{"alg":"ES256","kid":"k1"}"""),
                Gen.Const("""{"alg":"RS256","kid":"k1","crit":[]}"""),
                Gen.Const("""{"iss":"billing","sub":"billing","aud":"https://acme.example.com","jti":"j","exp":1e308}"""),
                Gen.Const("""{"sub":7,"exp":"x","iat":-1e309,"nbf":null}"""))
            .Select(s => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(s)))),
        (1, Gen.Byte.Array[0, 64].Select(b => Base64Url.EncodeToString(b))));

    private static Client NewKeyClient()
    {
        var client = Client.Create(
            Guid.CreateVersion7(), Guid.CreateVersion7(), "billing", "Billing", ClientType.Confidential, [GrantType.ClientCredentials],
            ["invoices.read"], [], requireConsent: false, overrides: null, Now, ["https://api.example.com"]);
        client.UsePrivateKeyJwt("""{"keys":[{"kty":"EC","kid":"k1","crv":"P-256","x":"AAAA","y":"AAAA"},{"kty":"RSA","kid":"k2","n":"AA","e":"AQAB"}]}""");
        return client;
    }

    [Fact]
    public void Any_assertion_gives_a_result_and_never_an_exception()
    {
        var validator = new ClientAssertionValidator(new FakeTimeProvider(Now));

        Gen.Select(Part, Part, Part).Sample((header, payload, signature) =>
        {
            var assertion = header + "." + payload + "." + signature;

            _ = validator.ReadClientId(assertion);
            var result = validator.Validate(assertion, KeyClient, "https://acme.example.com");

            Assert.False(result.IsSuccess);
        });
    }
}
