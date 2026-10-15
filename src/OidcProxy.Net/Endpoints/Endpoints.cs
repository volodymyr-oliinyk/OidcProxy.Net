using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using OidcProxy.Net.ModuleInitializers;

namespace OidcProxy.Net.Endpoints;

internal static class Endpoints
{
    public static void MapAuthenticationEndpoints(this WebApplication app, ProxyOptions options)
    {
        var endpointName = options.EndpointName;

        app.MapGet($"/{endpointName}/userinfo", MeEndpoint.Get);

        app.MapGet($"/{endpointName}/sign_in", LoginEndpoint.Get);

        app.MapGet($"/{endpointName}/callback", CallbackEndpoint.Get);

        app.MapGet($"/{endpointName}/session-complete", SessionCompleteEndpoint.Get);

        app.MapGet($"/{endpointName}/error", () => Results.Text("Login failed."));

        app.MapGet($"/{endpointName}/sign_out", EndSessionEndpoint.Get);

        app.Map($"/{endpointName}/auth", AuthEndpoint.Request);

        if (!options.NativeLoginEnabled)
        {
            return;
        }

        // Native (iOS/Android) application support. Only mapped when a redirect-uri allow-list is configured.
        app.MapGet($"/{endpointName}/native/start", NativeStartEndpoint.Get);

        var tokenEndpoint = app.MapPost($"/{endpointName}/native/token", NativeTokenEndpoint.Post);
        if (!string.IsNullOrEmpty(options.NativeTokenRateLimitPolicy))
        {
            tokenEndpoint.RequireRateLimiting(options.NativeTokenRateLimitPolicy);
        }

        // Guest sessions for native clients, without a browser. Shares the rate limit of the token endpoint: both
        // create sessions for anonymous callers.
        var guestEndpoint = app.MapPost($"/{endpointName}/native/guest", NativeGuestEndpoint.Post);
        if (!string.IsNullOrEmpty(options.NativeTokenRateLimitPolicy))
        {
            guestEndpoint.RequireRateLimiting(options.NativeTokenRateLimitPolicy);
        }

        app.MapPost($"/{endpointName}/native/sign_out", NativeSignOutEndpoint.Post);
    }
}
