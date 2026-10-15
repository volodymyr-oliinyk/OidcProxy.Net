using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Http;
using OidcProxy.Net.Native;

namespace OidcProxy.Net;

public interface IAuthenticationCallbackHandler
{
    Task<IResult> OnAuthenticationFailed(HttpContext context,
        string defaultLandingPage,
        string? userPreferredLandingPage);

    Task<IResult> OnAuthenticated(HttpContext context,
        JwtPayload? jwtPayload,
        string defaultLandingPage,
        string? userPreferredLandingPage);

    Task OnError(HttpContext context, Exception e);

    /// <summary>
    /// Invoked after a native (iOS/Android) client redeemed its one-time code and the session has been created.
    /// The default returns a JSON description of the session. Override it to record session metadata.
    /// </summary>
    Task<IResult> OnNativeAuthenticated(HttpContext context,
        JwtPayload? jwtPayload,
        NativeSessionInfo sessionInfo)
        => Task.FromResult(NativeResults.SessionEstablished(sessionInfo));
}
