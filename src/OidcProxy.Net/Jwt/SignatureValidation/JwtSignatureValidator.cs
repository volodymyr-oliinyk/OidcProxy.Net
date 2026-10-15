using System.IdentityModel.Tokens.Jwt;
using OidcProxy.Net.Cryptography;
using OidcProxy.Net.IdentityProviders;
using OidcProxy.Net.Logging;
using OidcProxy.Net.ModuleInitializers;

namespace OidcProxy.Net.Jwt.SignatureValidation;

internal class JwtSignatureValidator(IIdentityProvider identityProvider,
    ILogger logger,
    IEncryptionKey? jwtEncryptionKey,
    Rs256SignatureValidator rs256SignatureValidator,
    Hs256SignatureValidator hs256SignatureValidator,
    ProxyOptions proxyOptions) : IJwtSignatureValidator
{
    public virtual async Task<bool> Validate(string? token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return false;
        }

        if (JweParser.IsJwe(token))
        {
            if (jwtEncryptionKey is null)
            {
                return false;
            }

            string decrypted;
            try
            {
                decrypted = jwtEncryptionKey.Decrypt(token);
            }
            catch (Exception)
            {
                return false;
            }

            // The decrypted content is normally a signed JWT. Its signature is not verified here (unchanged
            // behaviour: the JWE itself is integrity protected), but its time, issuer and audience claims are.
            return !IsJws(decrypted) || await ValidateClaimsAsync(decrypted);
        }

        var header = JwtParser.ParseJwtHeader(token);
        if (header == null)
        {
            await logger.WarnAsync("Unable to determine how to validate the access_token. " +
                                   "The JWT does not have a header. " +
                                   "The signature has not been verified and the JWT is considered to be invalid.");
            return false; // Removing the header from a tampered JWT should not mark the token valid.
        }

        var signatureValidator = CreateValidator(header);
        if (signatureValidator == null)
        {
            // Changing the algorithm in the header of tampered JWT should not mark the token valid.
            await logger.ErrorAsync("Unable to determine how to validate the access_token. " +
                                    "Unable to find a validator for the algorithm specified in the JWT header. " +
                                    "The signature has not been verified and the JWT is considered to be invalid.");
            return false;
        }

        var keys = await identityProvider.GetJwksAsync();
        bool isSignatureValid;
        try
        {
            isSignatureValid = await signatureValidator.Validate(token, keys);
        }
        catch (KeySetNotFoundException)
        {
            // If the signature verification fails because the key wasn't found, it is very well possible the keys have
            // rotated in that case it is common practice to re-obtain the key-set and verify again.
            await logger.WarnAsync($"Unable to match JWT signing key on first attempt. " +
                                   $"alg={header.Alg}, tokenKid={header.Kid ?? "<none>"}, availableKids={DescribeKids(keys)}. " +
                                   "Refreshing JWKS and retrying.");

            keys = await identityProvider.GetJwksAsync(true);

            try
            {
                isSignatureValid = await signatureValidator.Validate(token, keys);
            }
            catch (KeySetNotFoundException)
            {
                await logger.ErrorAsync($"Unable to match JWT signing key after JWKS refresh. " +
                                        $"alg={header.Alg}, tokenKid={header.Kid ?? "<none>"}, availableKids={DescribeKids(keys)}. " +
                                        "The access token signature cannot be validated.");
                return false;
            }
        }

        return isSignatureValid && await ValidateClaimsAsync(token);
    }

    /// <summary>
    /// A valid signature only proves who issued the token. This checks that the token is current (exp, nbf) and,
    /// when configured, that it comes from an expected issuer and is meant for this proxy (iss, aud).
    /// exp is optional on purpose: OpenID Connect back-channel logout tokens may omit it.
    /// </summary>
    private async Task<bool> ValidateClaimsAsync(string jwt)
    {
        JwtPayload? payload;
        try
        {
            payload = JwtParser.ParsePayload(jwt);
        }
        catch (Exception)
        {
            payload = null;
        }

        if (payload == null)
        {
            await logger.WarnAsync("The JWT signature is valid but its payload cannot be parsed. " +
                                   "The JWT is considered to be invalid.");
            return false;
        }

        var now = DateTime.UtcNow;
        var skew = proxyOptions.JwtClockSkew;

        if (payload.Expiration.HasValue && DateTime.UnixEpoch.AddSeconds(payload.Expiration.Value) + skew < now)
        {
            await logger.WarnAsync("The JWT has expired (exp claim). The JWT is considered to be invalid.");
            return false;
        }

        if (payload.NotBefore.HasValue && DateTime.UnixEpoch.AddSeconds(payload.NotBefore.Value) - skew > now)
        {
            await logger.WarnAsync("The JWT is not valid yet (nbf claim). The JWT is considered to be invalid.");
            return false;
        }

        var validIssuers = proxyOptions.ValidIssuers.ToArray();
        if (validIssuers.Length > 0 && !validIssuers.Contains(payload.Iss, StringComparer.Ordinal))
        {
            await logger.WarnAsync("The JWT was issued by an issuer that is not in the list of valid issuers (iss claim). " +
                                   "The JWT is considered to be invalid.");
            return false;
        }

        var validAudiences = proxyOptions.ValidAudiences.ToArray();
        if (validAudiences.Length > 0 && !payload.Aud.Any(audience => validAudiences.Contains(audience, StringComparer.Ordinal)))
        {
            await logger.WarnAsync("The JWT is not intended for this proxy (aud claim). The JWT is considered to be invalid.");
            return false;
        }

        return true;
    }

    private static bool IsJws(string? token) => !string.IsNullOrEmpty(token) && token.Split('.').Length == 3;

    private static string DescribeKids(IEnumerable<KeySet> keys)
    {
        var kids = keys.Select(k => string.IsNullOrWhiteSpace(k.Kid) ? "<none>" : k.Kid)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return kids.Length == 0
            ? "<empty-jwks>"
            : string.Join(',', kids);
    }

    private SignatureValidator? CreateValidator(JwtHeader header)
    {
        return header.Alg switch
        {
            "RS256" => rs256SignatureValidator,
            "HS256" => hs256SignatureValidator,
            _ => null
        };
    }
}
