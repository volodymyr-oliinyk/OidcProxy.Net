namespace OidcProxy.Net.Jwt.SignatureValidation;

public interface IJwtSignatureValidator
{
    /// <summary>
    /// Validates an access token: signature, exp (required), nbf and, when configured, iss and aud.
    /// </summary>
    Task<bool> Validate(string? token);

    /// <summary>
    /// Validates an OpenID Connect back-channel logout token. Same checks as <see cref="Validate"/>, except that exp
    /// is optional: logout tokens may omit it. Implementations that do not distinguish token types inherit
    /// <see cref="Validate"/>.
    /// </summary>
    Task<bool> ValidateLogoutToken(string? token) => Validate(token);
}