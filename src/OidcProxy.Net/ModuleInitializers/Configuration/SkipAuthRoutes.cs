using System.Text.RegularExpressions;

namespace OidcProxy.Net.ModuleInitializers.Configuration;

public class SkipAuthRoutes : ISkipAuthRoutes, IApiRoutes
{
    /// <summary>
    /// Upper bound for matching one route pattern against a path, so a pathological pattern cannot stall requests.
    /// A match that times out counts as "no match": the request is not let through without authentication.
    /// </summary>
    public static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(100);

    private readonly List<(string? Method, Regex PathRegex, bool Negate)> rules = new();

    private readonly List<string> _unanchoredRoutes = new();

    public SkipAuthRoutes(IEnumerable<string> bypassAuthConfiguration)
    {
        ParseConfig(bypassAuthConfiguration.SelectMany(c => c.Split(",")));
    }

    /// <summary>
    /// Configured routes whose path pattern lacks a leading '^' or a trailing '$'. Patterns are matched anywhere in
    /// the path, so "GET=/health" also matches GET /api/x/health. Meant for a startup warning.
    /// </summary>
    public IReadOnlyList<string> UnanchoredRoutes => _unanchoredRoutes;

    private void ParseConfig(IEnumerable<string> bypassAuthConfiguration)
    {
        foreach (var line in bypassAuthConfiguration)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;

            var match = Regex.Match(trimmed, "^(?:(\\w+)(!?))?=?(.+)$");
            if (!match.Success)
            {
                throw new ArgumentException($"Invalid config format: {trimmed}");
            }

            var method = match.Groups[1].Success ? match.Groups[1].Value : null;
            var negate = match.Groups[2].Success && match.Groups[2].Value == "!";
            var pathPattern = match.Groups[3].Value;
            var pathRegex = new Regex(pathPattern, RegexOptions.None, MatchTimeout);

            rules.Add((method, pathRegex, negate));

            if (!pathPattern.StartsWith('^') || !pathPattern.EndsWith('$'))
            {
                _unanchoredRoutes.Add(trimmed);
            }
        }
    }

    public bool ShouldBypass(string method, string path)
    {
        foreach (var (ruleMethod, pathRegex, negate) in rules)
        {
            bool methodMatches = ruleMethod == null || ruleMethod.Equals(method, StringComparison.OrdinalIgnoreCase);
            if (!methodMatches)
            {
                continue;
            }

            bool pathMatches;
            try
            {
                pathMatches = pathRegex.IsMatch(path);
            }
            catch (RegexMatchTimeoutException)
            {
                // Fail closed: neither a plain nor a negated rule lets the request through.
                continue;
            }

            if (negate ? !pathMatches : pathMatches)
            {
                return true;
            }
        }
        return false;
    }

    public bool Matches(string method, string path)
    {
        return ShouldBypass(method, path);
    }
}