using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.WebUtilities;

namespace OidcProxy.Net.Native;

/// <summary>
/// PKCE helpers (RFC 7636) for the native-app leg of the login. The one-time code the proxy hands to the app is
/// bound to the code_challenge of the app and can only be redeemed together with the matching code_verifier.
/// </summary>
internal static partial class Pkce
{
    public const string S256 = "S256";

    /// <summary>Length of BASE64URL(SHA-256(x)) without padding, and of the 32-byte one-time code.</summary>
    private const int S256Length = 43;

    public static bool IsValidCodeChallenge(string? value)
        => value is { Length: S256Length } && Base64UrlRegex().IsMatch(value);

    public static bool IsValidCodeVerifier(string? value)
        => value != null && CodeVerifierRegex().IsMatch(value);

    public static bool IsValidCode(string? value)
        => value is { Length: S256Length } && Base64UrlRegex().IsMatch(value);

    public static string ComputeS256Challenge(string codeVerifier)
        => WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));

    /// <summary>Constant-time comparison of S256(code_verifier) with the stored code_challenge.</summary>
    public static bool Verify(string codeVerifier, string codeChallenge)
    {
        var expected = Encoding.ASCII.GetBytes(ComputeS256Challenge(codeVerifier));
        var actual = Encoding.ASCII.GetBytes(codeChallenge);
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    /// <summary>A 256-bit random, URL-safe one-time code.</summary>
    public static string GenerateCode()
        => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

    [GeneratedRegex("^[A-Za-z0-9_-]+$")]
    private static partial Regex Base64UrlRegex();

    [GeneratedRegex("^[A-Za-z0-9._~-]{43,128}$")]
    private static partial Regex CodeVerifierRegex();
}
