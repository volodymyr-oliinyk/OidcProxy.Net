namespace OidcProxy.Net;

/// <summary>
/// Constants shared between the proxy and native (iOS/Android) clients.
/// </summary>
public static class NativeLogin
{
    /// <summary>
    /// Header a native client must send on state-changing native endpoints that rely on the session cookie.
    /// A cross-site form post cannot add custom headers, which keeps those endpoints out of reach of CSRF.
    /// </summary>
    public const string ClientHeaderName = "X-OidcProxy-Native";
}

/// <summary>
/// Information about the session that was established for a native client.
/// </summary>
/// <param name="TokenExpiresAtUtc">When the access_token held in the session expires. The proxy renews it automatically.</param>
/// <param name="SessionIdleTimeout">Inactivity period after which the session (and the cookie) stops working.</param>
public sealed record NativeSessionInfo(DateTime TokenExpiresAtUtc, TimeSpan SessionIdleTimeout);
