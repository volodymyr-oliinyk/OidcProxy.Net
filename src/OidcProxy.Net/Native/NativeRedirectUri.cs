using Microsoft.AspNetCore.WebUtilities;

namespace OidcProxy.Net.Native;

/// <summary>
/// Validation and composition of redirect URIs that point back into a native application.
/// Follows RFC 8252 (OAuth 2.0 for Native Apps) section 7 and RFC 9700 section 4.1.3 (exact string matching).
/// </summary>
internal static class NativeRedirectUri
{
    public static bool IsValid(string value, out string reason)
    {
        reason = string.Empty;

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            reason = "The value must be an absolute URI.";
            return false;
        }

        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            reason = "A redirect URI may not contain a fragment.";
            return false;
        }

        if (uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            reason = "Plain http redirect URIs are not supported. Use a claimed https URI or a private-use scheme.";
            return false;
        }

        if (!uri.Scheme.Contains('.'))
        {
            reason = "A private-use URI scheme must be based on a domain name under the control of the app owner, " +
                     "in reverse order, for example com.example.app:/callback (RFC 8252, section 7.1).";
            return false;
        }

        return true;
    }

    /// <summary>
    /// Exact string comparison as required by RFC 9700 section 4.1.3. No pattern matching, no normalisation.
    /// </summary>
    public static bool IsAllowed(string? value, IReadOnlyList<string> allowList)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        return allowList.Any(allowed => string.Equals(allowed, value, StringComparison.Ordinal));
    }

    public static string AppendQuery(string redirectUri, params KeyValuePair<string, string>[] parameters)
    {
        var separator = redirectUri.Contains('?') ? '&' : '?';
        var query = string.Join('&', parameters.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
        return $"{redirectUri}{separator}{query}";
    }

    /// <summary>
    /// Replaces the value of an existing query parameter. Returns false and leaves the URI untouched when the
    /// parameter is absent, so callers never add parameters an identity provider did not ask for.
    /// </summary>
    public static bool TryReplaceQueryParameter(Uri uri, string name, string value, out Uri result)
    {
        result = uri;

        var query = QueryHelpers.ParseQuery(uri.Query);
        if (!query.ContainsKey(name))
        {
            return false;
        }

        query[name] = value;
        var rebuilt = string.Join('&', query.SelectMany(p => p.Value.Select(v =>
            $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(v ?? string.Empty)}")));

        result = new UriBuilder(uri) { Query = rebuilt }.Uri;
        return true;
    }
}
