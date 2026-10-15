using OidcProxy.Net.IdentityProviders;
using OidcProxy.Net.Logging;

namespace OidcProxy.Net.Endpoints;

internal static class TokenRevocation
{
    /// <summary>
    /// Revokes the access_token and the refresh_token held in the session. Failures are logged, not thrown:
    /// the session is terminated regardless.
    /// </summary>
    public static async Task RevokeSessionTokensAsync(AuthSession authSession,
        IIdentityProvider identityProvider,
        ILogger logger,
        string traceIdentifier)
    {
        await logger.InformAsync("Revoking access_token.");
        var accessToken = authSession.GetAccessToken();

        try
        {
            await identityProvider.RevokeAsync(accessToken!, traceIdentifier);
        }
        catch (Exception e) when (e is ApplicationException || e is ArgumentException)
        {
            await logger.WarnAsync($"Unexpected: Failed to revoke access_token during end-session. " +
                                   $"Access_token will be removed from the OidcProxy.Net http-session. " +
                                   $"This event is only visible in the logs. " +
                                   $"The following error occurred: {e}");
        }

        await logger.InformAsync("Revoking refresh_token.");
        var refreshToken = authSession.GetRefreshToken();

        try
        {
            await identityProvider.RevokeAsync(refreshToken!, traceIdentifier);
        }
        catch (Exception e) when (e is ApplicationException || e is ArgumentException)
        {
            await logger.WarnAsync($"Unexpected: Failed to revoke refresh_token during end-session. " +
                                   $"Refresh_token will be removed from the OidcProxy.Net http-session. " +
                                   $"This event is only visible in the logs. " +
                                   $"The following error occurred: {e}");
        }
    }
}
