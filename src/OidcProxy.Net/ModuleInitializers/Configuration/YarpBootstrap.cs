using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OidcProxy.Net.Middleware;
using Yarp.ReverseProxy.Configuration;

namespace OidcProxy.Net.ModuleInitializers.Configuration;

internal class YarpBootstrap : IBootstrap
{
    // Seeded by ProxyOptions, whose list already starts with TokenRenewalMiddleware.
    private readonly List<Type> _yarpMiddlewareRegistrations = [];

    private IList<Action<IReverseProxyBuilder>> _configuration = new List<Action<IReverseProxyBuilder>>();

    public void AddYarpMiddleware(IEnumerable<Type> handlerType)
    {
        _yarpMiddlewareRegistrations.AddRange(handlerType);
    }

    public void Configure(ProxyOptions options, IServiceCollection services)
    {
        foreach (var type in _yarpMiddlewareRegistrations)
        {
            services.TryAddTransient(type);
        }

        var proxyBuilder = services
            .AddReverseProxy();
            //.AddTransforms<HttpHeaderTransformation>();

        foreach (var config in _configuration)
        {
            config.Invoke(proxyBuilder);
        }
    }

    public void Configure(ProxyOptions options, WebApplication app)
    {
        app.RegisterYarpMiddleware(_yarpMiddlewareRegistrations);
    }

    public void ConfigureProxyBuilder(Action<IReverseProxyBuilder> configuration)
    {
        _configuration.Add(configuration);
    }
}