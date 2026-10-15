using FluentAssertions;
using OidcProxy.Net.Native;

namespace OidcProxy.Net.Tests.UnitTests.Native;

public class PkceTests
{
    // Test vector from RFC 7636, appendix B.
    private const string Rfc7636Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Rfc7636Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    [Fact]
    public void ComputeS256Challenge_matches_the_rfc7636_test_vector()
    {
        Pkce.ComputeS256Challenge(Rfc7636Verifier).Should().Be(Rfc7636Challenge);
    }

    [Fact]
    public void Verify_accepts_the_matching_verifier()
    {
        Pkce.Verify(Rfc7636Verifier, Rfc7636Challenge).Should().BeTrue();
    }

    [Fact]
    public void Verify_rejects_another_verifier()
    {
        Pkce.Verify(new string('a', 43), Rfc7636Challenge).Should().BeFalse();
    }

    [Theory]
    [InlineData(42, false)]
    [InlineData(43, true)]
    [InlineData(128, true)]
    [InlineData(129, false)]
    public void Code_verifier_length_is_bounded(int length, bool expected)
    {
        Pkce.IsValidCodeVerifier(new string('x', length)).Should().Be(expected);
    }

    [Fact]
    public void Code_verifier_rejects_characters_outside_the_unreserved_set()
    {
        Pkce.IsValidCodeVerifier(new string('x', 42) + "+").Should().BeFalse();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("too-short")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM=")]
    public void Code_challenge_must_be_43_base64url_characters(string? value)
    {
        Pkce.IsValidCodeChallenge(value).Should().BeFalse();
    }

    [Fact]
    public void Generated_codes_are_valid_and_unique()
    {
        var first = Pkce.GenerateCode();
        var second = Pkce.GenerateCode();

        Pkce.IsValidCode(first).Should().BeTrue();
        Pkce.IsValidCode(second).Should().BeTrue();
        first.Should().NotBe(second);
    }
}
