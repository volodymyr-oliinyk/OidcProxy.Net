namespace OidcProxy.Net.Logging;

/// <summary>
/// Keeps credentials out of log lines. Authorize, end-session and native redirect URLs carry state, nonce,
/// PAR request_uri, one-time codes or an id_token_hint in their query string; logging scheme, host and path is
/// enough to follow a flow.
/// </summary>
internal static class LogRedaction
{
    public static string WithoutQuery(Uri uri)
        => uri.IsAbsoluteUri ? uri.GetLeftPart(UriPartial.Path) : uri.OriginalString.Split('?', '#')[0];
}
