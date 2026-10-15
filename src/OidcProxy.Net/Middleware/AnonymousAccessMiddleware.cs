using Microsoft.AspNetCore.Http;
using OidcProxy.Net.Logging;
using OidcProxy.Net.ModuleInitializers.Configuration;

namespace OidcProxy.Net.Middleware;

internal class AnonymousAccessMiddleware(
    EndpointName oidcProxyReservedEndpointName,
    IAuthSession authSession,
    ILogger logger,
    IHttpContextAccessor httpContextAccessor,
    ISkipAuthRoutes skipAuthRoutes,
    IApiRoutes apiRoutes)
    : IMiddleware
{

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var currentPath = context.Request.Path + context.Request.QueryString;

        // Whole path segments only: /oauth2 and /oauth2/... are the proxy's own endpoints, /oauth2foo is not.
        if (context.Request.Path.StartsWithSegments(oidcProxyReservedEndpointName.ToString(), StringComparison.OrdinalIgnoreCase))
        {
            await next(context);
            return;
        }

        if (context.User.Identity?.IsAuthenticated ?? false)
        {
            await next(context);
            return;
        }

        var session = httpContextAccessor.HttpContext?.Session;
        if (session?.GetAccessToken() != null || skipAuthRoutes.ShouldBypass(context.Request.Method, context.Request.Path))
        {
            await next(context);
            return;
        }

        if (apiRoutes.Matches(context.Request.Method, context.Request.Path))
        {
            await logger.InformAsync($"Api route {context.Request.Path} returning 401");
            context.Response.StatusCode = 401;
            return;
        }
        
        var authorizeRequest = await authSession.InitiateAuthenticationSequence(currentPath);
        
        await logger.InformAsync($"Redirect({LogRedaction.WithoutQuery(authorizeRequest.AuthorizeUri)})");
        
        context.Response.Redirect(authorizeRequest.AuthorizeUri.ToString());
    }
}