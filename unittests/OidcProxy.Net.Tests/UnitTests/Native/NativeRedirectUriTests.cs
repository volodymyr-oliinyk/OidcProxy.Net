using FluentAssertions;
using OidcProxy.Net.Native;

namespace OidcProxy.Net.Tests.UnitTests.Native;

public class NativeRedirectUriTests
{
    [Theory]
    [InlineData("https://app.example.com/auth/callback", true)]
    [InlineData("com.example.app:/callback", true)]
    [InlineData("com.example.app://callback", true)]
    [InlineData("http://app.example.com/auth/callback", false)]
    [InlineData("myapp://callback", false)]
    [InlineData("https://app.example.com/cb#fragment", false)]
    [InlineData("/relative/path", false)]
    [InlineData("not a uri", false)]
    public void IsValid_applies_the_rfc8252_rules(string value, bool expected)
    {
        NativeRedirectUri.IsValid(value, out _).Should().Be(expected);
    }

    [Fact]
    public void IsAllowed_requires_an_exact_match()
    {
        var allowList = new[] { "com.example.app:/callback" };

        NativeRedirectUri.IsAllowed("com.example.app:/callback", allowList).Should().BeTrue();
        NativeRedirectUri.IsAllowed("com.example.app:/callback/", allowList).Should().BeFalse();
        NativeRedirectUri.IsAllowed("COM.EXAMPLE.APP:/callback", allowList).Should().BeFalse();
        NativeRedirectUri.IsAllowed("com.example.app:/callback?x=1", allowList).Should().BeFalse();
        NativeRedirectUri.IsAllowed(null, allowList).Should().BeFalse();
        NativeRedirectUri.IsAllowed("", allowList).Should().BeFalse();
    }

    [Fact]
    public void AppendQuery_encodes_values_and_respects_an_existing_query()
    {
        NativeRedirectUri.AppendQuery("com.example.app:/callback",
                KeyValuePair.Create("code", "a b&c"),
                KeyValuePair.Create("state", "x=y"))
            .Should().Be("com.example.app:/callback?code=a%20b%26c&state=x%3Dy");

        NativeRedirectUri.AppendQuery("https://app.example.com/cb?src=app", KeyValuePair.Create("code", "abc"))
            .Should().Be("https://app.example.com/cb?src=app&code=abc");
    }

    [Fact]
    public void TryReplaceQueryParameter_replaces_only_an_existing_parameter()
    {
        var endSession = new Uri("https://idp.example.com/connect/endsession?id_token_hint=a.b.c" +
                                 "&post_logout_redirect_uri=https%3A%2F%2Fportal.example.com%2F");

        NativeRedirectUri.TryReplaceQueryParameter(endSession, "post_logout_redirect_uri", "com.example.app:/logout", out var replaced)
            .Should().BeTrue();
        replaced.ToString().Should().Be("https://idp.example.com/connect/endsession?id_token_hint=a.b.c" +
                                        "&post_logout_redirect_uri=com.example.app%3A%2Flogout");

        var withoutParameter = new Uri("https://idp.example.com/v2/logout?returnTo=https%3A%2F%2Fportal.example.com%2F");
        NativeRedirectUri.TryReplaceQueryParameter(withoutParameter, "post_logout_redirect_uri", "com.example.app:/logout", out var unchanged)
            .Should().BeFalse();
        unchanged.Should().BeSameAs(withoutParameter);
    }
}
