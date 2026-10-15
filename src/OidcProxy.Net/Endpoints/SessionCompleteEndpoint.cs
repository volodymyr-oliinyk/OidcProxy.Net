using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OidcProxy.Net.Jwt;
using OidcProxy.Net.Logging;
using OidcProxy.Net.ModuleInitializers;
using OidcProxy.Net.OpenIdConnect;

namespace OidcProxy.Net.Endpoints;

/// <summary>
/// Endpoint that completes session regeneration after OAuth callback.
/// This is phase 2 of the session fixation protection flow.
/// </summary>
internal static class SessionCompleteEndpoint
{
    public static async Task<IResult> Get(HttpContext context,
        [FromServices] AuthSession authSession,
        [FromServices] ILogger logger,
        [FromServices] ProxyOptions proxyOptions,
        [FromServices] IPendingTokenStore pendingTokenStore,
        [FromServices] ITokenParser tokenParser,
        [FromServices] IAuthenticationCallbackHandler authenticationCallbackHandler)
    {
        var pendingKey = context.Request.Query["key"].FirstOrDefault();

        if (string.IsNullOrEmpty(pendingKey))
        {
            await logger.WarnAsync("Session complete called without pending key.");
            return Results.Redirect(proxyOptions.ErrorPage.ToString());
        }

        var pending = await pendingTokenStore.RetrieveAndRemoveAsync(pendingKey);

        if (pending == null)
        {
            await logger.WarnAsync("Pending token not found or expired. Possible replay attack or timeout.");
            return Results.Redirect(proxyOptions.ErrorPage.ToString());
        }

        if (pending.CodeChallenge != null)
        {
            // A code issued to a native app is bound to its PKCE verifier and must be redeemed at /native/token.
            // Redeeming it through the browser would let whoever intercepted the app redirect take over the login.
            await logger.WarnAsync("Pending token was issued to a native client and cannot be redeemed through the browser.");
            return Results.Redirect(proxyOptions.ErrorPage.ToString());
        }

        // Save tokens to the new session
        await authSession.SaveAsync(pending.TokenResponse);

        await logger.InformAsync($"Session regeneration complete. Redirect({proxyOptions.LandingPage})");

        var jwtPayload = tokenParser.ParseJwtPayload(pending.TokenResponse.access_token);

        return await authenticationCallbackHandler.OnAuthenticated(context,
            jwtPayload,
            proxyOptions.LandingPage.ToString(),
            pending.UserPreferredLandingPage);
    }
}
