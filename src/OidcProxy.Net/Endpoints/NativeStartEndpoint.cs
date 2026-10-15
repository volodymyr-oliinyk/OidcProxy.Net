using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OidcProxy.Net.Logging;
using OidcProxy.Net.ModuleInitializers;
using OidcProxy.Net.Native;

namespace OidcProxy.Net.Endpoints;

/// <summary>
/// Starts an authorization-code login on behalf of a native (iOS/Android) application. The app opens this URL in
/// the system browser (ASWebAuthenticationSession, Auth Tab / Custom Tabs). Query parameters:
/// redirect_uri (must be in the configured allow-list), code_challenge, code_challenge_method=S256, state.
/// </summary>
internal static class NativeStartEndpoint
{
    private const int MaxStateLength = 512;

    public static async Task<IResult> Get(HttpContext context,
        [FromServices] AuthSession authSession,
        [FromServices] ProxyOptions options,
        [FromServices] ILogger logger)
    {
        context.Response.Headers.CacheControl = "no-store";

        var query = context.Request.Query;
        var redirectUri = query["redirect_uri"].ToString();
        var codeChallenge = query["code_challenge"].ToString();
        var codeChallengeMethod = query["code_challenge_method"].ToString();
        var state = query["state"].ToString();

        if (!NativeRedirectUri.IsAllowed(redirectUri, options.NativeRedirectUris))
        {
            await logger.WarnAsync("Native login rejected: redirect_uri is missing or not in the configured allow-list.");
            return NativeResults.Error(StatusCodes.Status400BadRequest, "invalid_request", "redirect_uri is missing or not allowed.");
        }

        if (!Pkce.IsValidCodeChallenge(codeChallenge))
        {
            await logger.WarnAsync("Native login rejected: code_challenge is missing or malformed.");
            return NativeResults.Error(StatusCodes.Status400BadRequest, "invalid_request", "code_challenge is missing or malformed.");
        }

        if (codeChallengeMethod != Pkce.S256)
        {
            await logger.WarnAsync("Native login rejected: code_challenge_method must be S256.");
            return NativeResults.Error(StatusCodes.Status400BadRequest, "invalid_request", "code_challenge_method must be S256.");
        }

        if (string.IsNullOrEmpty(state) || state.Length > MaxStateLength)
        {
            await logger.WarnAsync("Native login rejected: state is missing or too long.");
            return NativeResults.Error(StatusCodes.Status400BadRequest, "invalid_request", "state is required.");
        }

        // Same sequence the anonymous-access redirect uses: it stores the PKCE verifier of the proxy itself (for the
        // identity provider) in the browser session. The native context is stored afterwards, because starting a
        // sequence discards any stale native context.
        var authorizeRequest = await authSession.InitiateAuthenticationSequence(string.Empty);
        await authSession.SetNativeLoginContextAsync(new NativeLoginContext(redirectUri, codeChallenge, state, DateTime.UtcNow));

        await logger.InformAsync($"Native login started. Redirect({LogRedaction.WithoutQuery(authorizeRequest.AuthorizeUri)})");

        return Results.Redirect(authorizeRequest.AuthorizeUri.ToString());
    }
}
