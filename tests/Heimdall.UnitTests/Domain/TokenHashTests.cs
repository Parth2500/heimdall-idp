using Heimdall.Domain.Common;

namespace Heimdall.UnitTests.Domain;

public class TokenHashTests
{
    [Fact]
    public void Same_secret_gives_equal_hashes()
    {
        Assert.Equal(TokenHash.Compute("secret-value"), TokenHash.Compute("secret-value"));
        Assert.True(TokenHash.Compute("secret-value") == TokenHash.Compute("secret-value"));
    }

    [Fact]
    public void Different_secrets_give_different_hashes()
    {
        Assert.NotEqual(TokenHash.Compute("secret-a"), TokenHash.Compute("secret-b"));
        Assert.True(TokenHash.Compute("secret-a") != TokenHash.Compute("secret-b"));
    }

    [Fact]
    public void Hash_is_32_bytes_and_survives_a_round_trip()
    {
        var hash = TokenHash.Compute("secret-value");

        var restored = TokenHash.FromBytes(hash.AsSpan());

        Assert.Equal(TokenHash.Length, hash.AsSpan().Length);
        Assert.Equal(hash, restored);
    }

    [Fact]
    public void Bytes_of_the_wrong_length_are_rejected()
    {
        Assert.Throws<DomainException>(() => TokenHash.FromBytes(new byte[16]));
    }

    [Fact]
    public void Default_hash_equals_nothing()
    {
        Assert.False(default(TokenHash).Equals(default));
        Assert.False(default(TokenHash).Equals(TokenHash.Compute("secret-value")));
    }

    [Fact]
    public void ToString_does_not_show_the_value()
    {
        Assert.DoesNotContain("-", TokenHash.Compute("secret-value").ToString(), StringComparison.Ordinal);
        Assert.Equal("TokenHash(redacted)", TokenHash.Compute("secret-value").ToString());
    }

    [Fact]
    public void Blank_secret_is_rejected()
    {
        Assert.Throws<DomainException>(() => TokenHash.Compute(" "));
    }
}
