namespace OidcProxy.Net.Native;

/// <summary>
/// The parameters a native (iOS/Android) application supplied when it started a login through the system browser.
/// Lives in the browser session between /{endpoint}/native/start and /{endpoint}/callback.
/// </summary>
internal sealed record NativeLoginContext(string RedirectUri, string CodeChallenge, string State, DateTime CreatedUtc)
{
    /// <summary>
    /// How long a started native login may take. Well beyond identity-provider login-page timeouts, so a real login
    /// never hits it; it stops an abandoned context from completing a login much later in the same browser session.
    /// </summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(30);

    public bool IsExpired(DateTime utcNow) => utcNow - CreatedUtc > MaxAge;
}
