using OidcProxy.Net.IdentityProviders;

namespace OidcProxy.Net;

/// <summary>
/// Optional hook that lets a native (iOS/Android) client obtain a guest session without a browser.
/// The proxy calls it from POST /{endpoint}/native/guest. Register an implementation in the service collection to
/// enable guest sessions for native clients; without one, that endpoint always answers "login_required".
/// </summary>
public interface INativeGuestTokenProvider
{
    /// <summary>
    /// Acquires a guest token for a request to <paramref name="path"/> on <paramref name="host"/>.
    /// </summary>
    /// <param name="host">The host name of the request, without the port.</param>
    /// <param name="path">The path the client wants to call, starting with '/'.</param>
    /// <param name="traceIdentifier">The trace identifier of the current request, for logging.</param>
    /// <returns>The token to store in the new session, or null when the host and path do not allow guest access.</returns>
    Task<TokenResponse?> AcquireGuestTokenAsync(string host, string path, string traceIdentifier);
}
