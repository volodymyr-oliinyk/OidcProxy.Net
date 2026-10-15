namespace OidcProxy.Net.Native;

/// <summary>
/// The parameters a native (iOS/Android) application supplied when it started a login through the system browser.
/// Lives in the browser session between /{endpoint}/native/start and /{endpoint}/callback.
/// </summary>
internal sealed record NativeLoginContext(string RedirectUri, string CodeChallenge, string State, DateTime CreatedUtc);
