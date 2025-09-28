using DataLayer.DTOs.Auth;
using DataLayer.Models;
using Google.Apis.Auth;
using lumina.Options;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ServiceLayer.Auth;
using System;
using System.Globalization;
using System.Text;

namespace lumina.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private const string GoogleProvider = "Google";
    private const int UsernameMaxLength = 50;

    private readonly LuminaSystemContext _context;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly ILogger<AuthController> _logger;
    private readonly IConfiguration _configuration;
    private readonly int _defaultRoleId;

    public AuthController(
        LuminaSystemContext context,
        IJwtTokenService jwtTokenService,
        ILogger<AuthController> logger,
        IConfiguration configuration,
        IOptionsSnapshot<JwtSettings> jwtOptions)
    {
        _context = context;
        _jwtTokenService = jwtTokenService;
        _logger = logger;
        _configuration = configuration;
        _ = jwtOptions.Value; // ensure options validation runs
        _defaultRoleId = configuration.GetValue<int?>("Auth:DefaultRoleId") ?? 1;
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginRequestDTO request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse("Invalid login request."));
        }

        var normalizedUsername = NormalizeUsername(request.Username);
        if (string.IsNullOrEmpty(normalizedUsername))
        {
            return BadRequest(new ErrorResponse("Invalid login request."));
        }

        var account = await _context.Accounts
            .Include(a => a.User)
            .FirstOrDefaultAsync(a => a.Username == normalizedUsername, cancellationToken);

        if (account?.User == null || string.IsNullOrEmpty(account.PasswordHash))
        {
            return Unauthorized(new ErrorResponse("Invalid username or password"));
        }

        var passwordMatches = BCrypt.Net.BCrypt.Verify(request.Password, account.PasswordHash);
        if (!passwordMatches)
        {
            return Unauthorized(new ErrorResponse("Invalid username or password"));
        }

        if (account.User.IsActive is false)
        {
            return Unauthorized(new ErrorResponse("Account is inactive"));
        }

        var token = _jwtTokenService.GenerateToken(account.User);

        return Ok(new LoginResponse
        {
            Token = token.Token,
            ExpiresIn = token.ExpiresInSeconds,
            User = new AuthUserResponse
            {
                Id = account.User.UserId.ToString(CultureInfo.InvariantCulture),
                Username = account.Username,
                Email = account.User.Email,
                Name = account.User.FullName
            }
        });
    }

    [HttpPost("google-login")]
    [AllowAnonymous]
    public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginRequest request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse("Invalid Google login request."));
        }

        var clientId = _configuration.GetValue<string>("Google:ClientId");
        if (string.IsNullOrWhiteSpace(clientId))
        {
            _logger.LogError("Google ClientId configuration is missing.");
            return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse("Google login is not configured."));
        }

        GoogleJsonWebSignature.Payload payload;
        try
        {
            payload = await GoogleJsonWebSignature.ValidateAsync(
                request.Token,
                new GoogleJsonWebSignature.ValidationSettings { Audience = new[] { clientId } });
        }
        catch (InvalidJwtException ex)
        {
            _logger.LogWarning(ex, "Invalid Google token received.");
            return Unauthorized(new ErrorResponse("Invalid Google token."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error validating Google token.");
            return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse("Failed to verify Google token."));
        }

        if (string.IsNullOrWhiteSpace(payload.Email))
        {
            return BadRequest(new ErrorResponse("Google account email is required."));
        }

        var normalizedEmail = NormalizeEmail(payload.Email);

        var account = await _context.Accounts
            .Include(a => a.User)
            .FirstOrDefaultAsync(
                a => a.AuthProvider == GoogleProvider && a.ProviderUserId == payload.Subject,
                cancellationToken);

        if (account == null)
        {
            try
            {
                account = await UpsertGoogleAccountAsync(payload, normalizedEmail, request.Token, cancellationToken);
            }
            catch (InvalidOperationException ex)
            {
                _logger.LogError(ex, "Unable to upsert Google account for {Email}", normalizedEmail);
                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse("Unable to complete Google login."));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during Google login for {Email}", normalizedEmail);
                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse("Unable to complete Google login."));
            }
        }

        if (account.User.IsActive is false)
        {
            return Unauthorized(new ErrorResponse("Account is inactive"));
        }

        var token = _jwtTokenService.GenerateToken(account.User);
        return Ok(new LoginResponse
        {
            Token = token.Token,
            ExpiresIn = token.ExpiresInSeconds,
            User = new AuthUserResponse
            {
                Id = account.User.UserId.ToString(CultureInfo.InvariantCulture),
                Username = account.Username,
                Email = account.User.Email,
                Name = account.User.FullName
            }
        });
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] DataLayer.DTOs.Auth.RegisterRequest request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse("Invalid registration request."));
        }

        var normalizedEmail = NormalizeEmail(request.Email);
        var trimmedName = request.Name.Trim();
        var normalizedUsername = NormalizeUsername(request.Username);

        if (string.IsNullOrWhiteSpace(trimmedName))
        {
            return BadRequest(new ErrorResponse("Name is required."));
        }

        if (trimmedName.Length > 50)
        {
            trimmedName = trimmedName[..50];
        }

        if (string.IsNullOrEmpty(normalizedUsername))
        {
            return BadRequest(new ErrorResponse("Username is required."));
        }

        if (normalizedUsername.Length > UsernameMaxLength)
        {
            normalizedUsername = normalizedUsername[..UsernameMaxLength];
        }

        var emailExists = await _context.Users.AnyAsync(u => u.Email == normalizedEmail, cancellationToken);
        if (emailExists)
        {
            return Conflict(new ErrorResponse("Email already exists"));
        }

        var usernameExists = await _context.Accounts.AnyAsync(a => a.Username == normalizedUsername, cancellationToken);
        if (usernameExists)
        {
            return Conflict(new ErrorResponse("Username already exists"));
        }

        await using var transaction = await _context.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            var user = new User
            {
                Email = normalizedEmail,
                FullName = trimmedName,
                RoleId = _defaultRoleId,
                IsActive = true
            };

            await _context.Users.AddAsync(user, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);

            var account = new Account
            {
                UserId = user.UserId,
                Username = normalizedUsername,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password)
            };

            await _context.Accounts.AddAsync(account, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            return Ok(new RegisterResponse
            {
                Message = "User registered successfully",
                UserId = user.UserId.ToString(CultureInfo.InvariantCulture)
            });
        }
        catch (DbUpdateException ex)
        {
            await transaction.RollbackAsync(cancellationToken);
            _logger.LogError(ex, "Failed to register user for email {Email}", normalizedEmail);
            var message = ResolveRegistrationConflictMessage(ex);
            return Conflict(new ErrorResponse(message));
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync(cancellationToken);
            _logger.LogError(ex, "Unexpected error registering user for email {Email}", normalizedEmail);
            return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse("Failed to register user."));
        }
    }

    [HttpPost("forgot-password")]
    [AllowAnonymous]
    public async Task<IActionResult> ForgotPassword([FromBody] DataLayer.DTOs.Auth.ForgotPasswordRequest request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse("Invalid forgot password request."));
        }

        var normalizedEmail = NormalizeEmail(request.Email);

        var user = await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Email == normalizedEmail, cancellationToken);

        if (user == null)
        {
            return NotFound(new ErrorResponse("Email not found"));
        }

        _logger.LogInformation("Password reset requested for user {UserId}", user.UserId);

        return Ok(new ForgotPasswordResponse
        {
            Message = "Password reset link has been sent to your email"
        });
    }

    private async Task<Account> UpsertGoogleAccountAsync(
        GoogleJsonWebSignature.Payload payload,
        string normalizedEmail,
        string accessToken,
        CancellationToken cancellationToken)
    {
        await using var transaction = await _context.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == normalizedEmail, cancellationToken);
            if (user == null)
            {
                var googleName = (payload.Name ?? payload.Email ?? "Google User").Trim();
                if (string.IsNullOrWhiteSpace(googleName))
                {
                    googleName = "Google User";
                }

                if (googleName.Length > 50)
                {
                    googleName = googleName[..50];
                }

                user = new User
                {
                    Email = normalizedEmail,
                    FullName = googleName,
                    RoleId = _defaultRoleId,
                    IsActive = true
                };
                await _context.Users.AddAsync(user, cancellationToken);
                await _context.SaveChangesAsync(cancellationToken);
            }

            var account = await _context.Accounts
                .FirstOrDefaultAsync(a => a.UserId == user.UserId && a.AuthProvider == GoogleProvider, cancellationToken);

            if (account == null)
            {
                account = await _context.Accounts
                    .FirstOrDefaultAsync(a => a.UserId == user.UserId && a.AuthProvider == null, cancellationToken);
            }

            if (account == null)
            {
                var usernameSeed = CreateUsernameCandidateFromEmail(normalizedEmail);
                var username = await GenerateUniqueUsernameAsync(usernameSeed, cancellationToken);
                account = new Account
                {
                    UserId = user.UserId,
                    Username = username,
                    AuthProvider = GoogleProvider,
                    ProviderUserId = payload.Subject,
                    AccessToken = accessToken,
                    TokenExpiresAt = payload.ExpirationTimeSeconds.HasValue
                        ? DateTimeOffset.FromUnixTimeSeconds(payload.ExpirationTimeSeconds.Value).UtcDateTime
                        : null
                };
                await _context.Accounts.AddAsync(account, cancellationToken);
            }
            else
            {
                account.AuthProvider = GoogleProvider;
                account.ProviderUserId = payload.Subject;
                account.AccessToken = accessToken;
                account.TokenExpiresAt = payload.ExpirationTimeSeconds.HasValue
                    ? DateTimeOffset.FromUnixTimeSeconds(payload.ExpirationTimeSeconds.Value).UtcDateTime
                    : null;
                account.UpdateAt = DateTime.UtcNow;

                if (string.IsNullOrWhiteSpace(account.Username))
                {
                    var usernameSeed = CreateUsernameCandidateFromEmail(normalizedEmail);
                    account.Username = await GenerateUniqueUsernameAsync(usernameSeed, cancellationToken);
                }
            }

            await _context.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return await _context.Accounts
                .Include(a => a.User)
                .FirstAsync(a => a.AccountId == account.AccountId, cancellationToken);
        }
        catch (DbUpdateException ex)
        {
            await transaction.RollbackAsync(cancellationToken);
            _logger.LogError(ex, "Failed to upsert Google account for email {Email}", normalizedEmail);
            throw new InvalidOperationException("Unable to link Google account at this time.", ex);
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }

    private async Task<string> GenerateUniqueUsernameAsync(string baseUsername, CancellationToken cancellationToken)
    {
        var normalizedBase = NormalizeUsername(baseUsername);
        if (string.IsNullOrEmpty(normalizedBase))
        {
            normalizedBase = "user";
        }

        if (normalizedBase.Length > UsernameMaxLength)
        {
            normalizedBase = normalizedBase[..UsernameMaxLength];
        }

        var candidate = normalizedBase;
        var suffix = 0;
        while (await _context.Accounts.AnyAsync(a => a.Username == candidate, cancellationToken))
        {
            suffix++;
            var suffixText = $"-{suffix}";
            var maxBaseLength = UsernameMaxLength - suffixText.Length;
            if (maxBaseLength < 1)
            {
                maxBaseLength = 1;
            }

            var truncatedBase = normalizedBase.Length > maxBaseLength
                ? normalizedBase[..maxBaseLength]
                : normalizedBase;

            candidate = $"{truncatedBase}{suffixText}";
        }

        return candidate;
    }

    private static string ResolveRegistrationConflictMessage(DbUpdateException exception)
    {
        var innerMessage = exception.InnerException?.Message;
        if (!string.IsNullOrWhiteSpace(innerMessage))
        {
            if (innerMessage.Contains("Username", StringComparison.OrdinalIgnoreCase))
            {
                return "Username already exists";
            }

            if (innerMessage.Contains("Email", StringComparison.OrdinalIgnoreCase))
            {
                return "Email already exists";
            }
        }

        return "Email or username already exists";
    }

    private static string CreateUsernameCandidateFromEmail(string normalizedEmail)
    {
        if (string.IsNullOrWhiteSpace(normalizedEmail))
        {
            return "user";
        }

        var localPart = normalizedEmail.Split('@')[0];
        if (string.IsNullOrWhiteSpace(localPart))
        {
            localPart = normalizedEmail;
        }

        var builder = new StringBuilder(localPart.Length);
        foreach (var character in localPart)
        {
            if (char.IsLetterOrDigit(character) || character is '.' or '_' or '-')
            {
                builder.Append(char.ToLowerInvariant(character));
            }
        }

        if (builder.Length == 0)
        {
            builder.Append("user");
        }

        var candidate = builder.ToString();
        return candidate.Length > UsernameMaxLength ? candidate[..UsernameMaxLength] : candidate;
    }

    private static string NormalizeUsername(string username)
    {
        return string.IsNullOrWhiteSpace(username) ? string.Empty : username.Trim().ToLowerInvariant();
    }

    private static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();
}