using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OidcProxy.Net.IdentityProviders;
using OidcProxy.Net.Jwt;
using OidcProxy.Net.Jwt.SignatureValidation;
using OidcProxy.Net.Logging;
using OidcProxy.Net.ModuleInitializers;
using OidcProxy.Net.Native;
using OidcProxy.Net.OpenIdConnect;
using System.Security.Cryptography;

namespace OidcProxy.Net.Endpoints;

internal static class CallbackEndpoint
{
    public static async Task<IResult> Get(HttpContext context,
        [FromServices] AuthSession authSession,
        [FromServices] ILogger logger,
        [FromServices] IRedirectUriFactory redirectUriFactory,
        [FromServices] ProxyOptions proxyOptions,
        [FromServices] IIdentityProvider identityProvider,
        [FromServices] ITokenParser tokenParser,
        [FromServices] IJwtSignatureValidator jwtSignatureValidator,
        [FromServices] IAuthenticationCallbackHandler authenticationCallbackHandler,
        [FromServices] IPendingTokenStore pendingTokenStore)
    {
        try
        {
            var userPreferredLandingPage = authSession.GetUserPreferredLandingPage();

            // Present when the login was started by a native (iOS/Android) app through /{endpoint}/native/start.
            var nativeLogin = authSession.GetNativeLoginContext();

            if (nativeLogin != null && nativeLogin.IsExpired(DateTime.UtcNow))
            {
                // Do not exchange the code: the app gave up on this login long ago.
                await logger.WarnAsync("Native login context expired before the callback. The code is not exchanged.");
                return await FailNativeLogin(authSession, logger, nativeLogin, "access_denied");
            }

            var code = context.Request.Query["code"].SingleOrDefault();
            if (string.IsNullOrEmpty(code))
            {
                await logger.InformAsync("Unable to obtain access token. Querystring parameter 'code' has no value.");

                if (nativeLogin != null)
                {
                    return await FailNativeLogin(authSession, logger, nativeLogin, "access_denied");
                }

                var redirectUri = $"{proxyOptions.ErrorPage}{context.Request.QueryString}";
                return await authenticationCallbackHandler.OnAuthenticationFailed(context, redirectUri, userPreferredLandingPage);
            }

            var endpointName = context.Request.Path.RemoveQueryString().TrimEnd("/callback");
            var redirectUrl = redirectUriFactory.DetermineRedirectUri(context, endpointName);

            var codeVerifier = authSession.GetCodeVerifier();

            await logger.InformAsync("Exchanging code for access_token.");
            var tokenResponse = await identityProvider.GetTokenAsync(redirectUrl, code, codeVerifier, context.TraceIdentifier);

            if (!(await jwtSignatureValidator.Validate(tokenResponse.access_token)))
            {
                if (nativeLogin != null)
                {
                    return await FailNativeLogin(authSession, logger, nativeLogin, "invalid_token");
                }

                return await authenticationCallbackHandler.OnAuthenticationFailed(context,
                    proxyOptions.LandingPage.ToString(),
                    userPreferredLandingPage);
            }

            if (nativeLogin != null)
            {
                return await CompleteNativeLogin(authSession, logger, pendingTokenStore, proxyOptions, nativeLogin, tokenResponse);
            }

            // Phase 1: Session regeneration to prevent session fixation attacks
            // Store tokens temporarily and redirect to complete with a fresh session
            var pendingKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            await pendingTokenStore.StoreAsync(pendingKey, tokenResponse, userPreferredLandingPage);

            // Clear old session and delete the session cookie
            context.Session.Clear();
            await context.Session.CommitAsync();

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                IsEssential = true,
                Domain = proxyOptions.CookieDomain,
                Secure = proxyOptions.CookieSecure ?? false,
                SameSite = proxyOptions.CookieSameSite ?? SameSiteMode.Unspecified,
                Path = "/"
            };
            context.Response.Cookies.Delete(proxyOptions.CookieName, cookieOptions);

            // Redirect to session complete endpoint - browser will get a new session
            var baseAddress = redirectUriFactory.DetermineHostName(context);
            var sessionCompleteUrl = $"{baseAddress}/{proxyOptions.EndpointName}/session-complete?key={Uri.EscapeDataString(pendingKey)}";

            await logger.InformAsync($"Session regeneration phase 1 complete. Redirect to session-complete endpoint.");

            return Results.Redirect(sessionCompleteUrl);
        }
        catch (Exception e)
        {
            await logger.ErrorAsync(e);
            await authenticationCallbackHandler.OnError(context, e);
            throw;
        }
        finally
        {
            await authSession.RemoveCodeVerifierAsync();
        }
    }

    /// <summary>
    /// Native flow: the tokens are parked under a one-time code that is bound to the PKCE challenge of the app, and
    /// the browser is sent back into the app. The browser session never holds the tokens. The app redeems the code
    /// from its own HTTP client at /{endpoint}/native/token, which creates the session and sets the cookie there.
    /// </summary>
    private static async Task<IResult> CompleteNativeLogin(AuthSession authSession,
        ILogger logger,
        IPendingTokenStore pendingTokenStore,
        ProxyOptions proxyOptions,
        NativeLoginContext nativeLogin,
        TokenResponse tokenResponse)
    {
        var oneTimeCode = Pkce.GenerateCode();
        await pendingTokenStore.StoreAsync(oneTimeCode, tokenResponse, null, nativeLogin.CodeChallenge, proxyOptions.NativeCodeTtl);
        await authSession.RemoveNativeLoginContextAsync();

        var location = NativeRedirectUri.AppendQuery(nativeLogin.RedirectUri,
            KeyValuePair.Create("code", oneTimeCode),
            KeyValuePair.Create("state", nativeLogin.State));

        await logger.InformAsync("Native login: issued a one-time code. Redirecting to the native application.");

        return Results.Redirect(location);
    }

    private static async Task<IResult> FailNativeLogin(AuthSession authSession,
        ILogger logger,
        NativeLoginContext nativeLogin,
        string error)
    {
        await authSession.RemoveNativeLoginContextAsync();

        var location = NativeRedirectUri.AppendQuery(nativeLogin.RedirectUri,
            KeyValuePair.Create("error", error),
            KeyValuePair.Create("state", nativeLogin.State));

        await logger.WarnAsync($"Native login failed ({error}). Redirecting to the native application.");

        return Results.Redirect(location);
    }
}
