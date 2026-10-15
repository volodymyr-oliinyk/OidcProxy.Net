using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OidcProxy.Net.IdentityProviders;
using OidcProxy.Net.Logging;
using OidcProxy.Net.ModuleInitializers;
using OidcProxy.Net.Native;
using OidcProxy.Net.OpenIdConnect;

namespace OidcProxy.Net.Endpoints;

/// <summary>
/// Ends the session of a native client: revokes the tokens, clears the session and deletes the cookie.
/// Returns the end-session URL of the identity provider so the app can also end the browser-side IdP session.
/// </summary>
internal static class NativeSignOutEndpoint
{
    public static async Task<IResult> Post(HttpContext context,
        [FromServices] AuthSession authSession,
        [FromServices] ILogger logger,
        [FromServices] ProxyOptions proxyOptions,
        [FromServices] IRedirectUriFactory redirectUriFactory,
        [FromServices] IIdentityProvider identityProvider)
    {
        context.Response.Headers.CacheControl = "no-store";

        if (!context.Request.Headers.ContainsKey(NativeLogin.ClientHeaderName))
        {
            return NativeResults.Error(StatusCodes.Status400BadRequest, "invalid_request",
                $"The {NativeLogin.ClientHeaderName} header is required.");
        }

        if (!authSession.HasAccessToken())
        {
            return NativeResults.Error(StatusCodes.Status401Unauthorized, "unauthorized", "There is no active session.");
        }

        await TokenRevocation.RevokeSessionTokensAsync(authSession, identityProvider, logger, context.TraceIdentifier);

        var idToken = authSession.HasIdToken() ? authSession.GetIdToken() : null;

        context.Session.Clear();
        await context.Session.CommitAsync();
        context.Response.Cookies.Delete(proxyOptions.CookieName, SessionCookie.DeleteOptions(proxyOptions));

        var baseAddress = redirectUriFactory.DetermineHostName(context);
        var endSessionEndpoint = await identityProvider.GetEndSessionEndpointAsync(idToken, baseAddress);

        // Send the browser back to the app after the IdP session ends, instead of to the web landing page.
        var postLogoutRedirectUri = proxyOptions.NativePostLogoutRedirectUri;
        if (postLogoutRedirectUri != null)
        {
            if (NativeRedirectUri.TryReplaceQueryParameter(endSessionEndpoint, "post_logout_redirect_uri",
                    postLogoutRedirectUri, out var nativeEndSessionEndpoint))
            {
                endSessionEndpoint = nativeEndSessionEndpoint;
            }
            else
            {
                await logger.WarnAsync("Native sign-out: the end-session URL of the identity provider has no " +
                                       "post_logout_redirect_uri parameter, so the native post-logout redirect URI is not applied.");
            }
        }

        await logger.InformAsync("Native sign-out completed.");

        return Results.Json(new { end_session_url = endSessionEndpoint.ToString() });
    }
}
