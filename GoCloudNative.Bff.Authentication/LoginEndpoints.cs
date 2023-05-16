using System.Text;
using GoCloudNative.Bff.Authentication.IdentityProviders;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace GoCloudNative.Bff.Authentication;

public static class LoginEndpoints
{
    internal static readonly string VerifierKey = "verifier_key";

    internal static readonly string TokenKey = "token_key";

    internal static readonly string IdTokenKey = "id_token_key";
    
    internal static readonly string RefreshTokenKey = "refresh_token_key";

    public static void MapAuthenticationEndpoints(this WebApplication app, string endpointName)
    {
        app.Map($"/{endpointName}/me", async (HttpContext context, [FromServices] IIdentityProvider identityProvider) =>
        {
            if (!context.Session.Keys.Contains(IdTokenKey))
            {
                return Results.NotFound();
            }

            var idToken = context.Session.GetString(IdTokenKey);
            return Results.Ok(idToken.ParseJwtPayload());
        });
        
        app.Map($"/{endpointName}/login", async (HttpContext context, [FromServices] IIdentityProvider identityProvider) =>
        {
            var redirectUri = CreateRedirectUri(context, endpointName);
            
            var authorizeRequest = await identityProvider.GetAuthorizeUrlAsync(redirectUri);

            if (!string.IsNullOrEmpty(authorizeRequest.CodeVerifier))
            {
                context.Session.SetString(VerifierKey, authorizeRequest.CodeVerifier);
            }

            context.Response.Redirect(authorizeRequest.AuthorizeUri.ToString());
        });

        app.Map($"/{endpointName}/login/callback", async (HttpContext context, [FromServices] IIdentityProvider identityProvider) =>
        {
            var code = context.Request.Query["code"].SingleOrDefault();
            if (string.IsNullOrEmpty(code))
            {
                throw new ArgumentException("The querystring parameter 'code' cannot be empty. Invoke the /login endpoint first.");
            }
            
            var redirectUrl = CreateRedirectUri(context, endpointName);

            var codeVerifier = context.Session.GetString(VerifierKey); 
            var tokenResponse = await identityProvider.GetTokenAsync(redirectUrl, code, codeVerifier);
            
            context.Session.Remove(VerifierKey);
            
            context.Session.Save(TokenKey, tokenResponse.access_token);
            context.Session.Save(IdTokenKey, tokenResponse.id_token);
            context.Session.Save(RefreshTokenKey, tokenResponse.refresh_token);
            
            context.Response.Redirect("/");

        });
        
        app.Map($"/{endpointName}/revoke", async (HttpContext context, [FromServices] IIdentityProvider identityProvider) =>
        {
            context.Session.Remove(IdTokenKey);
            
            if (context.Session.TryGetValue(TokenKey, out var accessTokenBytes))
            {
                var accessToken = Encoding.UTF8.GetString(accessTokenBytes);
                await identityProvider.Revoke(accessToken);
                context.Session.Remove(TokenKey);
            }

            if (context.Session.TryGetValue(RefreshTokenKey, out var refreshTokenBytes))
            {
                var refreshToken = Encoding.UTF8.GetString(refreshTokenBytes);
                await identityProvider.Revoke(refreshToken);
                context.Session.Remove(RefreshTokenKey);
            }
        });
    }

    private static string CreateRedirectUri(HttpContext context, string endpointName)
    {
        var protocol = context.Request.IsHttps ? "https://" : "http://";
        var redirectUrl = $"{protocol}{context.Request.Host}/{endpointName}/login/callback";
        return redirectUrl;
    }
}