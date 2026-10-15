using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using OidcProxy.Net.IdentityProviders;
using OidcProxy.Net.Jwt.SignatureValidation;
using OidcProxy.Net.Logging;
using OidcProxy.Net.ModuleInitializers;
using OidcProxy.Net.Native;

namespace OidcProxy.Net.Endpoints;

internal sealed class NativeGuestRequest
{
    [JsonPropertyName("path")]
    public string? Path { get; set; }
}

/// <summary>
/// Gives a native client a guest session without a browser. The app calls it from its own HTTP client after an API
/// call answered 401, with a JSON body { "path": "/the/path/it/called" }. When the host and path are configured for
/// guest access, the proxy acquires a guest token, stores it in a fresh session and answers 200 with the session
/// cookie. Otherwise it answers 403 "login_required" and the app starts the browser login at /{endpoint}/native/start.
/// </summary>
internal static class NativeGuestEndpoint
{
    private const int MaxPathLength = 2048;

    public static async Task<IResult> Post(HttpContext context,
        [FromBody] NativeGuestRequest? request,
        [FromServices] AuthSession authSession,
        [FromServices] ProxyOptions options,
        [FromServices] ILogger logger,
        [FromServices] IJwtSignatureValidator jwtSignatureValidator)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";

        // A cross-site form post cannot add a custom header, so a web page cannot plant a guest session.
        if (!context.Request.Headers.ContainsKey(NativeLogin.ClientHeaderName))
        {
            return NativeResults.Error(StatusCodes.Status400BadRequest, "invalid_request",
                $"The {NativeLogin.ClientHeaderName} header is required.");
        }

        var path = request?.Path;
        if (!IsValidPath(path))
        {
            await logger.WarnAsync("Native guest session rejected: path is missing or malformed.");
            return NativeResults.Error(StatusCodes.Status400BadRequest, "invalid_request",
                "path is required and must be an absolute path such as /api/resource.");
        }

        var provider = context.RequestServices.GetService<INativeGuestTokenProvider>();
        if (provider == null)
        {
            return LoginRequired();
        }

        TokenResponse? tokenResponse;
        try
        {
            tokenResponse = await provider.AcquireGuestTokenAsync(context.Request.Host.Host, path!, context.TraceIdentifier);
        }
        catch (Exception e)
        {
            await logger.ErrorAsync(e);
            return NativeResults.Error(StatusCodes.Status503ServiceUnavailable, "temporarily_unavailable",
                "A guest token could not be acquired.");
        }

        if (tokenResponse == null)
        {
            await logger.InformAsync("Native guest session refused: the host and path are not configured for guest access.");
            return LoginRequired();
        }

        if (!await jwtSignatureValidator.Validate(tokenResponse.access_token))
        {
            await logger.ErrorAsync("Native guest session refused: the guest access_token failed validation. " +
                                    "Check the guest credential and its authority.");
            return NativeResults.Error(StatusCodes.Status500InternalServerError, "server_error",
                "The guest token could not be validated.");
        }

        // Drop whatever a stale cookie may have loaded, then store the guest token in the session of this client.
        context.Session.Clear();
        await authSession.SaveAsync(tokenResponse);

        await logger.InformAsync("Native guest session established.");

        return NativeResults.SessionEstablished(new NativeSessionInfo(tokenResponse.ExpiryDate, options.SessionIdleTimeout));
    }

    private static IResult LoginRequired()
        => NativeResults.Error(StatusCodes.Status403Forbidden, "login_required",
            "This resource is not available to guests. Start the login at the native start endpoint.");

    internal static bool IsValidPath(string? path)
    {
        if (string.IsNullOrEmpty(path) || path.Length > MaxPathLength)
        {
            return false;
        }

        // An absolute path on this host only: no scheme, no protocol-relative or backslash forms, no control characters.
        return path[0] == '/'
               && !path.StartsWith("//", StringComparison.Ordinal)
               && !path.Contains('\\')
               && !path.Any(char.IsControl);
    }
}
