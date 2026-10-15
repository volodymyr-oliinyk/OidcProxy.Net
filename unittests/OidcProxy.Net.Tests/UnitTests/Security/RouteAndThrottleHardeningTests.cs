using System.Diagnostics;
using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using OidcProxy.Net.IdentityProviders;
using OidcProxy.Net.ModuleInitializers.Configuration;
using OidcProxy.Net.Native;

namespace OidcProxy.Net.Tests.UnitTests.Security;

public class SkipAuthRoutesHardeningTests
{
    // Catastrophic backtracking on a non-matching input.
    private const string EvilPattern = "^(a+)+$";
    private static readonly string EvilPath = new string('a', 40) + "!";

    [Fact]
    public void A_pattern_that_times_out_does_not_let_the_request_through()
    {
        var routes = new SkipAuthRoutes([EvilPattern]);

        var stopwatch = Stopwatch.StartNew();
        var bypass = routes.ShouldBypass("GET", EvilPath);

        bypass.Should().BeFalse();
        stopwatch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void A_negated_pattern_that_times_out_does_not_let_the_request_through_either()
    {
        var routes = new SkipAuthRoutes(["GET!=" + EvilPattern]);

        routes.ShouldBypass("GET", EvilPath).Should().BeFalse();
    }

    [Fact]
    public void Matching_is_unchanged_for_ordinary_patterns()
    {
        var routes = new SkipAuthRoutes(["GET=/health", "^/public/", "POST!=^/api"]);

        routes.ShouldBypass("GET", "/api/x/health").Should().BeTrue("unanchored patterns still match anywhere");
        routes.ShouldBypass("POST", "/health").Should().BeTrue("negated rule: POST to anything but ^/api");
        routes.ShouldBypass("PUT", "/public/file").Should().BeTrue();
        routes.ShouldBypass("PUT", "/private").Should().BeFalse();
        routes.ShouldBypass("POST", "/api/data").Should().BeFalse();
    }

    [Fact]
    public void Reports_routes_that_are_not_anchored_at_both_ends()
    {
        var routes = new SkipAuthRoutes(["GET=/health", "^/public/", "GET=^/robots\\.txt$", "/metrics$"]);

        routes.UnanchoredRoutes.Should().BeEquivalentTo("GET=/health", "^/public/", "/metrics$");
    }
}

public class JwksRefreshThrottleTests
{
    [Fact]
    public void The_first_forced_refresh_goes_ahead_and_the_next_one_waits_for_the_cooldown()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());

        JwksRefreshThrottle.TryBeginForcedRefresh(cache, "https://idp.test/jwks").Should().BeTrue();
        JwksRefreshThrottle.TryBeginForcedRefresh(cache, "https://idp.test/jwks").Should().BeFalse();
    }

    [Fact]
    public void Key_sets_are_throttled_independently()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());

        JwksRefreshThrottle.TryBeginForcedRefresh(cache, "https://idp.test/jwks").Should().BeTrue();
        JwksRefreshThrottle.TryBeginForcedRefresh(cache, "guest:https://other.test").Should().BeTrue();
    }

    [Fact]
    public void A_refresh_is_allowed_again_after_the_cooldown()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        JwksRefreshThrottle.TryBeginForcedRefresh(cache, "k").Should().BeTrue();

        // Expiring the marker is what the cooldown does; removing it simulates the passage of time.
        cache.Remove("jwks-forced-refresh:k");

        JwksRefreshThrottle.TryBeginForcedRefresh(cache, "k").Should().BeTrue();
    }

    [Fact]
    public void Concurrent_callers_get_one_refresh()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());

        var granted = Enumerable.Range(0, 50)
            .AsParallel()
            .Count(_ => JwksRefreshThrottle.TryBeginForcedRefresh(cache, "k"));

        granted.Should().Be(1);
    }
}

public class NativeLoginContextTests
{
    [Fact]
    public void A_context_expires_after_its_max_age()
    {
        var created = new DateTime(2026, 10, 15, 10, 0, 0, DateTimeKind.Utc);
        var context = new NativeLoginContext("com.example.app:/cb", "challenge", "state", created);

        context.IsExpired(created + NativeLoginContext.MaxAge).Should().BeFalse();
        context.IsExpired(created + NativeLoginContext.MaxAge + TimeSpan.FromSeconds(1)).Should().BeTrue();
    }
}
