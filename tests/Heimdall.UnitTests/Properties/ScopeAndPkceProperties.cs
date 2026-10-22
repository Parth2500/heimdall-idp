using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using CsCheck;
using Heimdall.Application.Common;
using Heimdall.Domain.Tokens;

namespace Heimdall.UnitTests.Properties;

public class ScopeAndPkceProperties
{
    private const string Unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

    [Fact]
    public void Scope_parser_never_throws_and_returns_only_valid_distinct_tokens()
    {
        Generators.AnyString.Sample(scope =>
        {
            var values = ScopeParser.Parse(scope);
            if (values is null)
            {
                // Null only when some character is outside the scope-token set.
                Assert.Contains(scope, c => c != ' ' && !IsScopeChar(c));
                return;
            }

            Assert.All(values, v => Assert.True(v.Length > 0 && v.All(IsScopeChar)));
            Assert.Equal(values.Count, values.Distinct(StringComparer.Ordinal).Count());
        }, iter: 5_000);
    }

    [Fact]
    public void Scope_tokens_joined_by_any_spaces_parse_back_in_order_without_duplicates()
    {
        Gen.Select(Generators.ScopeToken.Array[0, 8], Gen.Int[1, 3], Gen.Int[0, 2])
            .Sample((tokens, gap, edge) =>
            {
                var scope = new string(' ', edge) + string.Join(new string(' ', gap), tokens) + new string(' ', edge);

                Assert.Equal(tokens.Distinct(StringComparer.Ordinal), ScopeParser.Parse(scope)!);
            }, iter: 2_000);
    }

    [Fact]
    public void Verifier_check_matches_RFC_7636_for_any_input()
    {
        // RFC 7636, section 4.1: 43 to 128 characters from the unreserved set.
        var gen = Gen.Frequency(
            (1, Generators.AnyString),
            (3, Gen.String[Gen.Char[Unreserved + "+/= %"], 40, 131]));

        gen.Sample(verifier =>
        {
            var expected = verifier.Length is >= 43 and <= 128 && verifier.All(c => Unreserved.Contains(c, StringComparison.Ordinal));

            Assert.Equal(expected, Pkce.IsValidVerifier(verifier));
        }, iter: 5_000);
    }

    [Fact]
    public void Challenge_check_never_throws()
    {
        // A lambda that returns bool is a predicate to CsCheck, so the result is discarded: only a throw fails here.
        Generators.TokenLike.Sample(challenge => { _ = Pkce.IsValidChallenge(challenge); }, iter: 5_000);
    }

    [Fact]
    public void Every_valid_verifier_matches_only_its_own_S256_challenge()
    {
        var verifier = Gen.String[Gen.Char[Unreserved], 43, 128];

        Gen.Select(verifier, verifier).Sample((v, other) =>
        {
            var challenge = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(v)));

            Assert.True(Pkce.IsValidChallenge(challenge));
            Assert.True(Pkce.VerifyS256(v, challenge));
            Assert.Equal(v == other, Pkce.VerifyS256(other, challenge));
        }, iter: 2_000);
    }

    private static bool IsScopeChar(char c) => c is >= '!' and <= '~' and not '"' and not '\\';
}
