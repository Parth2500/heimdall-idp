using System.Text.Json;
using Heimdall.Application.Keys;

namespace Heimdall.UnitTests.Application;

public class RsaPublicJwkTests
{
    // The example key from RFC 7638, section 3.1.
    private const string RfcN =
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
        "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5h" +
        "ajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    private const string RfcE = "AQAB";
    private const string RfcThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    [Fact]
    public void Thumbprint_matches_the_RFC_7638_example()
    {
        Assert.Equal(RfcThumbprint, RsaPublicJwk.ComputeThumbprint(RfcN, RfcE));
    }

    [Fact]
    public void Kid_is_the_thumbprint()
    {
        var jwk = RsaPublicJwk.FromPublicParameters(RfcN, RfcE);

        Assert.Equal(RfcThumbprint, jwk.Kid);
    }

    [Fact]
    public void Json_has_only_the_public_members()
    {
        var json = RsaPublicJwk.FromPublicParameters(RfcN, RfcE).ToJson();

        using var document = JsonDocument.Parse(json);
        var names = document.RootElement.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal);
        Assert.Equal(["alg", "e", "kid", "kty", "n", "use"], names);
        Assert.Equal("RS256", document.RootElement.GetProperty("alg").GetString());
        Assert.Equal("RSA", document.RootElement.GetProperty("kty").GetString());
        Assert.Equal("sig", document.RootElement.GetProperty("use").GetString());
    }

    [Fact]
    public void Json_round_trips()
    {
        var jwk = RsaPublicJwk.FromPublicParameters(RfcN, RfcE);

        Assert.Equal(jwk, RsaPublicJwk.FromJson(jwk.ToJson()));
    }

    [Theory]
    [InlineData("", "AQAB")]
    [InlineData("abc", " ")]
    public void Blank_parameters_are_rejected(string n, string e)
    {
        Assert.ThrowsAny<ArgumentException>(() => RsaPublicJwk.FromPublicParameters(n, e));
    }
}
