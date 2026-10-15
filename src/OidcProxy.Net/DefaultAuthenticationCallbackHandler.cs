using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Http;
using OidcProxy.Net.Native;
using ILogger = OidcProxy.Net.Logging.ILogger;

namespace OidcProxy.Net;

public class DefaultAuthenticationCallbackHandler(ILogger logger) : IAuthenticationCallbackHandler
{
    public virtual Task<IResult> OnAuthenticationFailed(HttpContext context,
        string defaultLandingPage,
        string? userPreferredLandingPage)
    {
        var result = Results.Unauthorized();
        return Task.FromResult(result);
    }

    public virtual async Task<IResult> OnAuthenticated(HttpContext context,
        JwtPayload? jwtPayload,
        string defaultLandingPage,
        string? userPreferredLandingPage)
    {
        var landingPage = userPreferredLandingPage ?? defaultLandingPage;

        await logger.InformAsync($"Redirect({landingPage})");
        return Results.Redirect(landingPage);
    }

    public virtual Task OnError(HttpContext context, Exception e)
    {
        return Task.CompletedTask;
    }

    /// <summary>
    /// Invoked after a native (iOS/Android) client redeemed its one-time code and the session has been created.
    /// Returns a JSON description of the session; the Set-Cookie header is added by the session middleware.
    /// </summary>
    public virtual async Task<IResult> OnNativeAuthenticated(HttpContext context,
        JwtPayload? jwtPayload,
        NativeSessionInfo sessionInfo)
    {
        await logger.InformAsync("Native session established.");
        return NativeResults.SessionEstablished(sessionInfo);
    }
}
