using OidcProxy.Net.ModuleInitializers;

// ReSharper disable once CheckNamespace
namespace OidcProxy.Net;

public class ProxyConfig : IAppSettingsSection
{
    public Mode Mode { get; set; }
    public string? EndpointName { get; set; }
    public string? ErrorPage { get; set; }
    public string? LandingPage { get; set; }
    public string? NameClaim { get; set; }
    public string? RoleClaim { get; set; }
    public IEnumerable<string> AllowedLandingPages { get; set; } = Array.Empty<string>();
    public bool EnableUserPreferredLandingPages { get; set; } = false;
    public bool? AlwaysRedirectToHttps { get; set; }
    public bool? AllowAnonymousAccess { get; set; }
    public Uri? CustomHostName { get; set; }
    public string? CookieName { get; set; }
    public TimeSpan? SessionIdleTimeout { get; set; }

    public bool? CookieSecure { get; set; }

    public string? CookieDomain { get; set; }

    public YarpConfig? ReverseProxy { get; set; }

    public IList<string> SkipAuthRoutes { get; set; } = new List<string>();

    public IList<string> ApiRoutes { get; set; } = new List<string>();

    /// <summary>
    /// Exact-match allow-list of redirect URIs for native (iOS/Android) logins. Configuring at least one enables
    /// the /{EndpointName}/native/* endpoints.
    /// </summary>
    public IList<string> NativeRedirectUris { get; set; } = new List<string>();

    /// <summary>
    /// Where the identity provider redirects after a native sign-out, for example com.example.app:/logout.
    /// Default: the post-logout redirect of the browser flow.
    /// </summary>
    public string? NativePostLogoutRedirectUri { get; set; }

    /// <summary>
    /// Lifetime of the one-time code handed to a native application. Default: 2 minutes.
    /// </summary>
    public TimeSpan? NativeCodeTtl { get; set; }

    /// <summary>
    /// Lifetime of tokens parked between /callback and session completion. Default: 1 minute.
    /// </summary>
    public TimeSpan? PendingTokenTtl { get; set; }

    /// <summary>
    /// Name of a host-registered rate-limiting policy for /{EndpointName}/native/token.
    /// </summary>
    public string? NativeTokenRateLimitPolicy { get; set; }

    /// <summary>
    /// Tolerance applied to the exp and nbf claims of access tokens. Default: 60 seconds.
    /// </summary>
    public TimeSpan? JwtClockSkew { get; set; }

    /// <summary>
    /// When not empty, access tokens must carry one of these values in the iss claim.
    /// </summary>
    public IList<string> ValidIssuers { get; set; } = new List<string>();

    /// <summary>
    /// When not empty, access tokens must carry one of these values in the aud claim.
    /// </summary>
    public IList<string> ValidAudiences { get; set; } = new List<string>();

    public virtual bool Validate(out IEnumerable<string> errors)
    {
        errors = Array.Empty<string>();
        return true;
    }

    public virtual void Apply(ProxyOptions options)
    {
        AssignIfNotNull(ErrorPage, options.SetAuthenticationErrorPage);
        AssignIfNotNull(LandingPage, options.SetLandingPage);
        AssignIfNotNull(CustomHostName, options.SetCustomHostName);
        AssignIfNotNull(CookieName, cookieName => options.CookieName = cookieName);
        AssignIfNotNull(NameClaim, nameClaim => options.NameClaim = nameClaim);
        AssignIfNotNull(RoleClaim, roleClaim => options.RoleClaim = roleClaim);
        AssignIfNotNull(NativeTokenRateLimitPolicy, policy => options.NativeTokenRateLimitPolicy = policy);

        options.Mode = Mode;
        options.EnableUserPreferredLandingPages = EnableUserPreferredLandingPages;
        options.AlwaysRedirectToHttps = !AlwaysRedirectToHttps.HasValue || AlwaysRedirectToHttps.Value;
        options.AllowAnonymousAccess = !AllowAnonymousAccess.HasValue || AllowAnonymousAccess.Value;
        options.EndpointName = EndpointName ?? "oauth2";
        options.SetAllowedLandingPages(AllowedLandingPages);
        options.SkipAuthRoutes = SkipAuthRoutes;
        options.CookieSecure = CookieSecure;
        options.CookieDomain = CookieDomain;
        options.ApiRoutes = ApiRoutes;
        options.SkipJwtBearerTokens = SkipJwtBearerTokens;
        options.SetNativeRedirectUris(NativeRedirectUris);
        options.SetNativePostLogoutRedirectUri(NativePostLogoutRedirectUri);
        options.ValidIssuers = ValidIssuers;
        options.ValidAudiences = ValidAudiences;

        if (SessionIdleTimeout.HasValue)
        {
            options.SessionIdleTimeout = SessionIdleTimeout.Value;
        }

        if (NativeCodeTtl.HasValue)
        {
            options.NativeCodeTtl = NativeCodeTtl.Value;
        }

        if (PendingTokenTtl.HasValue)
        {
            options.PendingTokenTtl = PendingTokenTtl.Value;
        }

        if (JwtClockSkew.HasValue)
        {
            options.JwtClockSkew = JwtClockSkew.Value;
        }

        if (options.Mode != Mode.AuthenticateOnly)
        {
            var routes = ReverseProxy?.Routes.ToRouteConfig();
            var clusters = ReverseProxy?.Clusters.ToClusterConfig();

            options.ConfigureYarp(routes, clusters);
        }
    }

    public bool SkipJwtBearerTokens { get; set; } = false;

    private static void AssignIfNotNull<T>(T? value, Action<T> @do)
    {
        if (value != null)
        {
            @do(value);
        }
    }
}
