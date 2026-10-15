using Microsoft.AspNetCore.Http;
using OidcProxy.Net.ModuleInitializers;

namespace OidcProxy.Net;

internal static class SessionCookie
{
    /// <summary>
    /// Cookie options matching the session cookie, for deleting it.
    /// </summary>
    public static CookieOptions DeleteOptions(ProxyOptions options) => new()
    {
        HttpOnly = true,
        IsEssential = true,
        Domain = options.CookieDomain,
        Secure = options.CookieSecure ?? false,
        SameSite = options.CookieSameSite ?? SameSiteMode.Unspecified,
        Path = "/"
    };
}
