using OidcProxy.Net.IdentityProviders;

namespace OidcProxy.Net.OpenIdConnect;

/// <summary>
/// A token response parked between /callback and the request that establishes the session.
/// </summary>
/// <param name="TokenResponse">The tokens obtained from the identity provider.</param>
/// <param name="UserPreferredLandingPage">Browser flow only: where to send the user afterwards.</param>
/// <param name="CodeChallenge">Native flow only: the PKCE challenge the redeeming client must prove knowledge of.</param>
internal sealed record PendingToken(TokenResponse TokenResponse, string? UserPreferredLandingPage, string? CodeChallenge);

/// <summary>
/// Temporary store for token responses during session regeneration.
/// Tokens are stored briefly between callback and session completion.
/// </summary>
internal interface IPendingTokenStore
{
    /// <summary>
    /// Stores a token response with a unique key.
    /// </summary>
    /// <param name="key">A unique identifier for the pending token.</param>
    /// <param name="tokenResponse">The token response to store.</param>
    /// <param name="userPreferredLandingPage">The preferred landing page of the user (browser flow).</param>
    /// <param name="codeChallenge">The PKCE code_challenge the entry is bound to (native flow), or null.</param>
    /// <param name="ttl">Lifetime of the entry. Defaults to ProxyOptions.PendingTokenTtl.</param>
    Task StoreAsync(string key, TokenResponse tokenResponse, string? userPreferredLandingPage, string? codeChallenge = null, TimeSpan? ttl = null);

    /// <summary>
    /// Retrieves and removes a token response by key. Each key can be redeemed at most once.
    /// </summary>
    /// <param name="key">The unique identifier for the pending token.</param>
    /// <returns>The pending token, or null if not found or expired.</returns>
    Task<PendingToken?> RetrieveAndRemoveAsync(string key);
}
