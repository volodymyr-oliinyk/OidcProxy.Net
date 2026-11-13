using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace OidcProxy.Net.Middleware;

internal static class WebApplicationExtensions
{
    public static void RegisterYarpMiddleware(this WebApplication app, IEnumerable<Type> types)
    {
        if (!types.Any())
        {
            return;
        }

        // Wrap from the last registration outwards, so the first registered middleware runs first.
        var outermostLast = types.Reverse().ToArray();

        app.UseEndpoints(e =>
        {
            e.MapReverseProxy(x => x.Use((context, next) =>
            {
                Func<HttpContext, Task> pipeline = _ => next();

                foreach (var type in outermostLast)
                {
                    var instance = (IYarpMiddleware)x.ApplicationServices.GetRequiredService(type);
                    var inner = pipeline;
                    pipeline = ctx => instance.Apply(ctx, inner);
                }

                return pipeline(context);
            }));
        });
    }
}