using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OidcProxy.Net.IdentityProviders;
using OidcProxy.Net.Logging;
using OidcProxy.Net.ModuleInitializers;
using OidcProxy.Net.OpenIdConnect;

namespace OidcProxy.Net.Endpoints;

internal static class EndSessionEndpoint
{
    public static async Task<IResult> Get(HttpContext context,
        [FromServices] AuthSession authSession,
        [FromServices] ILogger logger,
        [FromServices] ProxyOptions proxyOptions,
        [FromServices] IRedirectUriFactory redirectUriFactory,
        [FromServices] IIdentityProvider identityProvider)
    {

        var baseAddress = $"{redirectUriFactory.DetermineHostName(context)}";

        if (!authSession.HasAccessToken())
        {
            await logger.InformAsync($"Redirect to {baseAddress}");

            return Results.Redirect(baseAddress);
        }

        await TokenRevocation.RevokeSessionTokensAsync(authSession, identityProvider, logger, context.TraceIdentifier);

        string? idToken = null;
        if (authSession.HasIdToken())
        {
            idToken = authSession.GetIdToken();
        }

        context.Session.Clear();

        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            IsEssential = true,
            Domain = proxyOptions.CookieDomain,
            Secure = proxyOptions.CookieSecure ?? false,
            SameSite = proxyOptions.CookieSameSite ?? SameSiteMode.Unspecified
        };

        context.Response.Cookies.Delete(proxyOptions.CookieName, cookieOptions);

        var endSessionEndpoint = await identityProvider.GetEndSessionEndpointAsync(idToken, baseAddress);

        // The end-session URL carries the id_token in id_token_hint.
        await logger.InformAsync($"Redirect to {LogRedaction.WithoutQuery(endSessionEndpoint)}");

        return Results.Redirect(endSessionEndpoint.ToString());
    }
}
