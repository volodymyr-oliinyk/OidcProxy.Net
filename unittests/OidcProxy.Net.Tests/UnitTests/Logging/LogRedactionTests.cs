using FluentAssertions;
using OidcProxy.Net.Jwt;
using OidcProxy.Net.Logging;

namespace OidcProxy.Net.Tests.UnitTests.Logging;

public class LogRedactionTests
{
    [Theory]
    [InlineData("https://idp.test/connect/endsession?id_token_hint=eyJ.a.b&post_logout_redirect_uri=x", "https://idp.test/connect/endsession")]
    [InlineData("https://idp.test/authorize?client_id=c&state=s&nonce=n&code_challenge=x", "https://idp.test/authorize")]
    [InlineData("https://idp.test/authorize#fragment", "https://idp.test/authorize")]
    [InlineData("http://localhost:4180/oauth2/callback?code=abc", "http://localhost:4180/oauth2/callback")]
    [InlineData("https://idp.test/authorize", "https://idp.test/authorize")]
    public void WithoutQuery_drops_query_and_fragment_of_absolute_uris(string uri, string expected)
    {
        LogRedaction.WithoutQuery(new Uri(uri)).Should().Be(expected);
    }

    [Theory]
    [InlineData("/oauth2/callback?code=abc", "/oauth2/callback")]
    [InlineData("/landing#x", "/landing")]
    [InlineData("/plain", "/plain")]
    public void WithoutQuery_handles_relative_uris(string uri, string expected)
    {
        LogRedaction.WithoutQuery(new Uri(uri, UriKind.Relative)).Should().Be(expected);
    }
}

public class JwtParserMessageTests
{
    [Theory]
    [InlineData("header.payload-with-secret")]
    [InlineData("a.b.c.d")]
    public void A_malformed_token_is_not_echoed_in_the_exception(string token)
    {
        var act = () => new JwtParser().ParseJwtPayload(token);

        act.Should().Throw<NotSupportedException>()
            .Which.Message.Should().NotContain(token).And.Contain("dot-separated segments");
    }
}
