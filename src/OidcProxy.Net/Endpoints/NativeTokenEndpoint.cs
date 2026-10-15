using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OidcProxy.Net.Jwt;
using OidcProxy.Net.Logging;
using OidcProxy.Net.ModuleInitializers;
using OidcProxy.Net.Native;
using OidcProxy.Net.OpenIdConnect;

namespace OidcProxy.Net.Endpoints;

internal sealed class NativeTokenRequest
{
    [JsonPropertyName("code")]
    public string? Code { get; set; }

    [JsonPropertyName("code_verifier")]
    public string? CodeVerifier { get; set; }
}

/// <summary>
/// Redeems the one-time code a native app received at the end of the browser login for a session cookie.
/// Called by the app from its own HTTP client with a JSON body { "code": "...", "code_verifier": "..." }.
/// The session middleware adds the Set-Cookie header to the response, because the request carries no session
/// cookie and the session is written here.
/// </summary>
internal static class NativeTokenEndpoint
{
    public static async Task<IResult> Post(HttpContext context,
        [FromBody] NativeTokenRequest? request,
        [FromServices] AuthSession authSession,
        [FromServices] ProxyOptions options,
        [FromServices] ILogger logger,
        [FromServices] IPendingTokenStore pendingTokenStore,
        [FromServices] ITokenParser tokenParser,
        [FromServices] IAuthenticationCallbackHandler authenticationCallbackHandler)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";

        if (request == null || !Pkce.IsValidCode(request.Code) || !Pkce.IsValidCodeVerifier(request.CodeVerifier))
        {
            await logger.WarnAsync("Native token exchange rejected: malformed request.");
            return NativeResults.Error(StatusCodes.Status400BadRequest, "invalid_request", "code and code_verifier are required.");
        }

        var pending = await pendingTokenStore.RetrieveAndRemoveAsync(request.Code!);
        if (pending == null)
        {
            await logger.WarnAsync("Native token exchange rejected: unknown, expired or already redeemed code.");
            return NativeResults.Error(StatusCodes.Status400BadRequest, "invalid_grant", "The code is invalid, expired or has already been redeemed.");
        }

        if (pending.CodeChallenge == null || !Pkce.Verify(request.CodeVerifier!, pending.CodeChallenge))
        {
            // The entry is already gone, so a wrong verifier burns the code: an interceptor gets exactly one guess.
            await logger.WarnAsync("Native token exchange rejected: PKCE verification failed.");
            return NativeResults.Error(StatusCodes.Status400BadRequest, "invalid_grant", "PKCE verification failed.");
        }

        // Drop whatever a stale cookie may have loaded, then store the tokens in the session of this client.
        context.Session.Clear();
        await authSession.SaveAsync(pending.TokenResponse);

        var jwtPayload = tokenParser.ParseJwtPayload(pending.TokenResponse.access_token);

        await logger.InformAsync("Native token exchange succeeded. Session established for the native client.");

        var sessionInfo = new NativeSessionInfo(pending.TokenResponse.ExpiryDate, options.SessionIdleTimeout);
        return await authenticationCallbackHandler.OnNativeAuthenticated(context, jwtPayload, sessionInfo);
    }
}
