using FluentAssertions;
using OidcProxy.Net.ModuleInitializers;

namespace OidcProxy.Net.Tests.UnitTests.OptionsTests;

public class SetNativeRedirectUrisTests
{
    [Fact]
    public void Nothing_configured_keeps_native_login_disabled()
    {
        var options = new ProxyOptions();

        options.NativeLoginEnabled.Should().BeFalse();

        options.SetNativeRedirectUris(null);
        options.NativeLoginEnabled.Should().BeFalse();

        options.SetNativeRedirectUris(new[] { "", "   " });
        options.NativeLoginEnabled.Should().BeFalse();
    }

    [Fact]
    public void Valid_uris_enable_native_login_and_are_deduplicated()
    {
        var options = new ProxyOptions();

        options.SetNativeRedirectUris(new[]
        {
            "com.example.app:/callback",
            " com.example.app:/callback ",
            "https://app.example.com/auth/callback"
        });

        options.NativeLoginEnabled.Should().BeTrue();
        options.NativeRedirectUris.Should().Equal("com.example.app:/callback", "https://app.example.com/auth/callback");
    }

    [Theory]
    [InlineData("http://app.example.com/callback")]
    [InlineData("myapp://callback")]
    [InlineData("https://app.example.com/callback#fragment")]
    [InlineData("/callback")]
    public void An_invalid_uri_fails_fast(string redirectUri)
    {
        var options = new ProxyOptions();

        var act = () => options.SetNativeRedirectUris(new[] { redirectUri });

        act.Should().Throw<NotSupportedException>().WithMessage("*GNC-B-7c1e2a9d0f44*");
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("  ", null)]
    [InlineData(" com.example.app:/logout ", "com.example.app:/logout")]
    [InlineData("https://app.example.com/auth/logout", "https://app.example.com/auth/logout")]
    public void Post_logout_redirect_uri_is_optional_and_trimmed(string? value, string? expected)
    {
        var options = new ProxyOptions();

        options.SetNativePostLogoutRedirectUri(value);

        options.NativePostLogoutRedirectUri.Should().Be(expected);
    }

    [Theory]
    [InlineData("http://app.example.com/logout")]
    [InlineData("myapp://logout")]
    public void An_invalid_post_logout_redirect_uri_fails_fast(string value)
    {
        var options = new ProxyOptions();

        var act = () => options.SetNativePostLogoutRedirectUri(value);

        act.Should().Throw<NotSupportedException>().WithMessage("*GNC-B-3f9a6d2b8e51*");
    }
}
