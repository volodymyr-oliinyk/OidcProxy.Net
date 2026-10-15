using Microsoft.Extensions.Caching.Memory;

namespace OidcProxy.Net.IdentityProviders;

/// <summary>
/// Limits forced JWKS refreshes. A token whose kid is not in the cached key set makes the validator re-fetch the
/// JWKS once, to pick up a key rotation. Without a limit, anyone can send tokens with random kids and turn every
/// request into a call to the identity provider. A key set is re-fetched at most once per <see cref="Cooldown"/>;
/// in between, the cached keys are used. Each key-set location has its own limit, so a refresh for one identity
/// provider never delays another.
/// </summary>
public static class JwksRefreshThrottle
{
    /// <summary>Minimum time between two forced refreshes of the same key set.</summary>
    public static readonly TimeSpan Cooldown = TimeSpan.FromSeconds(30);

    private static readonly object Gate = new();

    /// <summary>
    /// Returns true when a forced refresh of the key set identified by <paramref name="keySetId"/> may go ahead now,
    /// and starts the cooldown. Returns false while a previous refresh is less than <see cref="Cooldown"/> old.
    /// </summary>
    public static bool TryBeginForcedRefresh(IMemoryCache cache, string keySetId)
    {
        var markerKey = $"jwks-forced-refresh:{keySetId}";

        lock (Gate)
        {
            if (cache.TryGetValue(markerKey, out _))
            {
                return false;
            }

            cache.Set(markerKey, true, Cooldown);
            return true;
        }
    }
}
