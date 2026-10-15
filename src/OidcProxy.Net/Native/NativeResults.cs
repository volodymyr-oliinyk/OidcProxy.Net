using Microsoft.AspNetCore.Http;

namespace OidcProxy.Net.Native;

internal static class NativeResults
{
    /// <summary>OAuth2-style JSON error body: { "error": "...", "error_description": "..." }.</summary>
    public static IResult Error(int statusCode, string error, string description)
        => Results.Json(new { error, error_description = description }, statusCode: statusCode);

    public static IResult SessionEstablished(NativeSessionInfo sessionInfo)
        => Results.Json(new
        {
            session_idle_timeout = (int)sessionInfo.SessionIdleTimeout.TotalSeconds,
            token_expires_at = sessionInfo.TokenExpiresAtUtc
        });
}
