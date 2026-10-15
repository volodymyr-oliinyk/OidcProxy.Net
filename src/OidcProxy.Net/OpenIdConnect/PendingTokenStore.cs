using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using OidcProxy.Net.IdentityProviders;
using OidcProxy.Net.ModuleInitializers;

namespace OidcProxy.Net.OpenIdConnect;

/// <summary>
/// Implementation of IPendingTokenStore using distributed cache.
/// Tokens are stored with a short TTL to minimize security exposure.
/// </summary>
internal class PendingTokenStore : IPendingTokenStore
{
    private readonly IDistributedCache _cache;
    private readonly ProxyOptions _options;
    private const string KeyPrefix = "pending_token:";

    public PendingTokenStore(IDistributedCache cache, ProxyOptions options)
    {
        _cache = cache;
        _options = options;
    }

    public async Task StoreAsync(string key, TokenResponse tokenResponse, string? userPreferredLandingPage, string? codeChallenge = null, TimeSpan? ttl = null)
    {
        var entry = new PendingTokenEntry
        {
            AccessToken = tokenResponse.access_token,
            IdToken = tokenResponse.id_token,
            RefreshToken = tokenResponse.refresh_token,
            ExpiryDate = tokenResponse.ExpiryDate,
            UserPreferredLandingPage = userPreferredLandingPage,
            CodeChallenge = codeChallenge
        };

        var json = JsonSerializer.Serialize(entry);

        await _cache.SetStringAsync(
            KeyPrefix + key,
            json,
            new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl ?? _options.PendingTokenTtl
            });
    }

    public async Task<PendingToken?> RetrieveAndRemoveAsync(string key)
    {
        var fullKey = KeyPrefix + key;
        var json = await _cache.GetStringAsync(fullKey);

        if (string.IsNullOrEmpty(json))
        {
            return null;
        }

        // Remove immediately to prevent replay
        await _cache.RemoveAsync(fullKey);

        var entry = JsonSerializer.Deserialize<PendingTokenEntry>(json);
        if (entry == null)
        {
            return null;
        }

        var tokenResponse = new TokenResponse(
            entry.AccessToken,
            entry.IdToken,
            entry.RefreshToken,
            entry.ExpiryDate
        );

        return new PendingToken(tokenResponse, entry.UserPreferredLandingPage, entry.CodeChallenge);
    }

    private class PendingTokenEntry
    {
        public string? AccessToken { get; set; }
        public string? IdToken { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime ExpiryDate { get; set; }
        public string? UserPreferredLandingPage { get; set; }
        public string? CodeChallenge { get; set; }
    }
}
