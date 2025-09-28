using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using DataLayer.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServiceLayer.Options;

namespace ServiceLayer.Auth;

public interface IJwtTokenService
{
    JwtTokenResult GenerateToken(User user);
}

public sealed class JwtTokenService : IJwtTokenService
{
    private readonly JwtSettings _settings;
    private readonly SymmetricSecurityKey _signingKey;

    public JwtTokenService(IOptions<JwtSettings> options)
    {
        _settings = options.Value;
        if (string.IsNullOrWhiteSpace(_settings.SecretKey))
        {
            throw new InvalidOperationException("JWT secret key is not configured.");
        }

        _signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.SecretKey));
    }

    public JwtTokenResult GenerateToken(User user)
    {
        ArgumentNullException.ThrowIfNull(user);

        var expiresAtUtc = DateTime.UtcNow.AddMinutes(_settings.AccessTokenExpirationMinutes);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.UserId.ToString(CultureInfo.InvariantCulture)),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.UniqueName, user.FullName),
            new(ClaimTypes.NameIdentifier, user.UserId.ToString(CultureInfo.InvariantCulture)),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.Name, user.FullName)
        };

        var credentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256);

        var tokenDescriptor = new JwtSecurityToken(
            issuer: _settings.Issuer,
            audience: _settings.Audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: expiresAtUtc,
            signingCredentials: credentials);

        var token = new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);

        return new JwtTokenResult(token, (int)TimeSpan.FromMinutes(_settings.AccessTokenExpirationMinutes).TotalSeconds, expiresAtUtc);
    }
}

public sealed record JwtTokenResult(string Token, int ExpiresInSeconds, DateTime ExpiresAtUtc);