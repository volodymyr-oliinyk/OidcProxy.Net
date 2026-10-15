using System.Security.Cryptography;
using FluentAssertions;
using Jose;
using NSubstitute;
using OidcProxy.Net.Cryptography;
using OidcProxy.Net.IdentityProviders;
using OidcProxy.Net.Jwt.SignatureValidation;
using OidcProxy.Net.ModuleInitializers;
using ILogger = OidcProxy.Net.Logging.ILogger;

namespace OidcProxy.Net.Tests.UnitTests.Security;

public class JwtSignatureValidatorHardeningTests : IDisposable
{
    private const string Kid = "key-1";

    private readonly RSA _signingKey = RSA.Create(2048);
    private readonly IIdentityProvider _identityProvider = Substitute.For<IIdentityProvider>();

    public JwtSignatureValidatorHardeningTests()
    {
        var parameters = _signingKey.ExportParameters(false);
        _identityProvider.GetJwksAsync(Arg.Any<bool>())
            .Returns(new[] { new KeySet(parameters.Exponent!, parameters.Modulus!, Kid) });
    }

    public void Dispose() => _signingKey.Dispose();

    [Fact]
    public async Task An_access_token_without_exp_is_rejected()
    {
        var token = Sign(new Dictionary<string, object> { ["sub"] = "user-1" });

        (await CreateValidator().Validate(token)).Should().BeFalse();
    }

    [Fact]
    public async Task An_access_token_with_exp_is_accepted()
    {
        var token = Sign(new Dictionary<string, object>
        {
            ["sub"] = "user-1",
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()
        });

        (await CreateValidator().Validate(token)).Should().BeTrue();
    }

    [Fact]
    public async Task A_logout_token_may_omit_exp()
    {
        var token = Sign(new Dictionary<string, object> { ["sid"] = "sid-1" });

        (await CreateValidator().ValidateLogoutToken(token)).Should().BeTrue();
    }

    [Fact]
    public async Task A_logout_token_still_needs_a_valid_signature()
    {
        var token = Sign(new Dictionary<string, object> { ["sid"] = "sid-1" });
        var tampered = token[..^4] + (token[^4..] == "AAAA" ? "BBBB" : "AAAA");

        (await CreateValidator().ValidateLogoutToken(tampered)).Should().BeFalse();
    }

    [Fact]
    public async Task The_default_logout_validation_of_other_validators_is_their_access_token_validation()
    {
        IJwtSignatureValidator validator = new AcceptOnly("expected");

        (await validator.ValidateLogoutToken("expected")).Should().BeTrue();
        (await validator.ValidateLogoutToken("other")).Should().BeFalse();
    }

    [Fact]
    public async Task The_signed_token_inside_a_jwe_is_verified()
    {
        using var otherKey = RSA.Create(2048);
        var forged = JWT.Encode(ValidPayload(), otherKey, JwsAlgorithm.RS256,
            new Dictionary<string, object> { ["kid"] = Kid });

        var validator = CreateValidator(new FixedDecryption(forged));

        (await validator.Validate(FakeJwe)).Should().BeFalse("anyone can encrypt to a public key; the inner signature is what proves the issuer");
    }

    [Fact]
    public async Task A_jwe_with_a_validly_signed_inner_token_is_accepted()
    {
        var validator = CreateValidator(new FixedDecryption(Sign(ValidPayload())));

        (await validator.Validate(FakeJwe)).Should().BeTrue();
    }

    private const string FakeJwe = "eyJhbGciOiJSU0EtT0FFUCJ9.a.b.c.d";

    private static Dictionary<string, object> ValidPayload() => new()
    {
        ["sub"] = "user-1",
        ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()
    };

    private string Sign(Dictionary<string, object> payload)
        => JWT.Encode(payload, _signingKey, JwsAlgorithm.RS256, new Dictionary<string, object> { ["kid"] = Kid });

    private JwtSignatureValidator CreateValidator(IEncryptionKey? encryptionKey = null)
        => new(_identityProvider, Substitute.For<ILogger>(), encryptionKey, new Rs256SignatureValidator(), null!,
            new ProxyOptions());

    private sealed class FixedDecryption(string plaintext) : IEncryptionKey
    {
        public string Decrypt(string token) => plaintext;
    }

    private sealed class AcceptOnly(string accepted) : IJwtSignatureValidator
    {
        public Task<bool> Validate(string? token) => Task.FromResult(token == accepted);
    }
}
