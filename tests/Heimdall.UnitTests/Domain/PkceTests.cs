using Heimdall.Domain.Tokens;

namespace Heimdall.UnitTests.Domain;

public class PkceTests
{
    // The test vector from RFC 7636, Appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    [Fact]
    public void Rfc_7636_test_vector_verifies()
    {
        Assert.True(Pkce.VerifyS256(Verifier, Challenge));
    }

    [Fact]
    public void Wrong_verifier_fails()
    {
        var other = new string('a', 43);

        Assert.False(Pkce.VerifyS256(other, Challenge));
    }

    [Fact]
    public void Challenge_used_as_verifier_fails()
    {
        // This is the "plain" downgrade: an attacker who saw the challenge sends it as the verifier.
        Assert.False(Pkce.VerifyS256(Challenge, Challenge));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("too-short")]
    public void Verifier_with_wrong_length_is_invalid(string? verifier)
    {
        Assert.False(Pkce.IsValidVerifier(verifier));
    }

    [Fact]
    public void Verifier_longer_than_128_characters_is_invalid()
    {
        Assert.False(Pkce.IsValidVerifier(new string('a', 129)));
        Assert.True(Pkce.IsValidVerifier(new string('a', 128)));
        Assert.True(Pkce.IsValidVerifier(new string('a', 43)));
        Assert.False(Pkce.IsValidVerifier(new string('a', 42)));
    }

    [Theory]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=")]
    public void Verifier_with_characters_outside_the_unreserved_set_is_invalid(string verifier)
    {
        Assert.False(Pkce.IsValidVerifier(verifier));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cMM")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM")]
    public void Challenge_with_wrong_shape_is_invalid(string? challenge)
    {
        Assert.False(Pkce.IsValidChallenge(challenge));
    }

    [Fact]
    public void Missing_verifier_fails()
    {
        Assert.False(Pkce.VerifyS256(null, Challenge));
    }
}
