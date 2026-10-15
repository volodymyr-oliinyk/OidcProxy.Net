using OidcProxy.Net.Logging;
using Microsoft.AspNetCore.Http;
using OidcProxy.Net.ModuleInitializers;
using OidcProxy.Net.ModuleInitializers.Configuration;
using OidcProxy.Net.OpenIdConnect;

namespace OidcProxy.Net.Middleware;

internal class TokenRenewalMiddleware(TokenFactory tokenFactory,
    ILogger logger,
    ISkipAuthRoutes skipAuthRoutes,
    IApiRoutes apiRoutes,
    IRedirectUriFactory redirectUriFactory,
    EndpointName endpointName,
    ProxyOptions proxyOptions) : IYarpMiddleware
{
    public async Task Apply(HttpContext context, Func<HttpContext, Task> next)
    {
        if (!skipAuthRoutes.ShouldBypass(context.Request.Method, context.Request.Path))
        {
            // Check expiry again because another thread may have updated the token
            try
            {
                await tokenFactory.RenewAccessTokenIfExpiredAsync(context.TraceIdentifier);
            }
            catch (TokenRenewalFailedException e)
            {
                await logger.ErrorAsync(e);

                if (apiRoutes.Matches(context.Request.Method, context.Request.Path))
                {
                    // Api clients (XHR calls from a SPA, native apps) cannot follow a redirect to the identity
                    // provider. Terminate the session and tell the client to authenticate again.
                    await logger.WarnAsync("Token renewal failed on an api route. Terminating the session and responding 401.");

                    context.Session.Clear();
                    await context.Session.CommitAsync();
                    context.Response.Cookies.Delete(proxyOptions.CookieName, SessionCookie.DeleteOptions(proxyOptions));

                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.Headers.CacheControl = "no-store";
                    await context.Response.WriteAsJsonAsync(new { error = "token_renewal_failed" });
                    return;
                }

                var url = redirectUriFactory.DetermineHostName(context) + endpointName + "/sign_out";
                await logger.WarnAsync($"Token renewal failed. Redirecting to {url}.");
                context.Response.Redirect(url);
                return; // And stop the pipeline here. The request will not be forwarded down-stream.
            }
        }

        await next(context);
    }
}
