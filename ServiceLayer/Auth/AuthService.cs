using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using DataLayer.DTOs.Auth;
using DataLayer.Models;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ServiceLayer.Abstractions;
using ServiceLayer.Email;
using ServiceLayer.Options;

namespace ServiceLayer.Auth;

public class AuthService : IAuthService
{
    private const string GoogleProvider = "Google";
    private const int UsernameMaxLength = 50;

    private readonly LuminaSystemContext _context;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly ILogger<AuthService> _logger;
    private readonly IEmailSender _emailSender;
    private readonly GoogleSettings _googleSettings;
    private readonly PasswordResetSettings _passwordResetSettings;
    private readonly int _defaultRoleId;

    public AuthService(
        LuminaSystemContext context,
        IJwtTokenService jwtTokenService,
        ILogger<AuthService> logger,
        IEmailSender emailSender,
        IOptions<GoogleSettings> googleOptions,
        IOptions<PasswordResetSettings> passwordResetOptions,
        IOptions<AuthSettings> authOptions)
    {
        _context = context;
        _jwtTokenService = jwtTokenService;
        _logger = logger;
        _emailSender = emailSender;
        _googleSettings = googleOptions.Value;
        _passwordResetSettings = passwordResetOptions.Value;
        _defaultRoleId = authOptions.Value.DefaultRoleId;
    }

    public async Task<ServiceResult<LoginResponse>> LoginAsync(LoginRequestDTO request, CancellationToken cancellationToken)
    {
        var identifier = request.Username.Trim();
        var accountsQuery = _context.Accounts
            .Include(a => a.User)
            .Where(a => a.AuthProvider == null);

        Account? account = null;
        if (LooksLikeEmail(identifier))
        {
            var email = NormalizeEmail(identifier);
            account = await accountsQuery.FirstOrDefaultAsync(a => a.User.Email == email, cancellationToken);
        }

        if (account == null)
        {
            var username = NormalizeUsername(identifier);
            account = await accountsQuery.FirstOrDefaultAsync(a => a.Username == username, cancellationToken);
        }

        if (account?.User == null || string.IsNullOrEmpty(account.PasswordHash))
        {
            return ServiceResult<LoginResponse>.Fail("Invalid username or password", StatusCodes.Status401Unauthorized);
        }

        var passwordMatches = BCrypt.Net.BCrypt.Verify(request.Password, account.PasswordHash);
        if (!passwordMatches)
        {
            return ServiceResult<LoginResponse>.Fail("Invalid username or password", StatusCodes.Status401Unauthorized);
        }

        if (account.User.IsActive is false)
        {
            return ServiceResult<LoginResponse>.Fail("Account is inactive", StatusCodes.Status401Unauthorized);
        }

        var token = _jwtTokenService.GenerateToken(account.User);
        var response = new LoginResponse
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
        };

        return ServiceResult<LoginResponse>.Ok(response);
    }

    public async Task<ServiceResult<LoginResponse>> GoogleLoginAsync(GoogleLoginRequest request, CancellationToken cancellationToken)
    {
        if (!_googleSettings.IsConfigured)
        {
            _logger.LogError("Google login was attempted but the ClientId is not configured.");
            return ServiceResult<LoginResponse>.Fail("Google login is not configured.", StatusCodes.Status500InternalServerError);
        }

        GoogleJsonWebSignature.Payload payload;
        try
        {
            payload = await GoogleJsonWebSignature.ValidateAsync(
                request.Token,
                new GoogleJsonWebSignature.ValidationSettings { Audience = new[] { _googleSettings.ClientId } });
        }
        catch (InvalidJwtException ex)
        {
            _logger.LogWarning(ex, "Invalid Google token received.");
            return ServiceResult<LoginResponse>.Fail("Invalid Google token.", StatusCodes.Status401Unauthorized);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error validating Google token.");
            return ServiceResult<LoginResponse>.Fail("Failed to verify Google token.", StatusCodes.Status500InternalServerError);
        }

        if (string.IsNullOrWhiteSpace(payload.Email))
        {
            return ServiceResult<LoginResponse>.Fail("Google account email is required.", StatusCodes.Status400BadRequest);
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
                return ServiceResult<LoginResponse>.Fail("Unable to complete Google login.", StatusCodes.Status500InternalServerError);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during Google login for {Email}", normalizedEmail);
                return ServiceResult<LoginResponse>.Fail("Unable to complete Google login.", StatusCodes.Status500InternalServerError);
            }
        }

        if (account.User.IsActive is false)
        {
            return ServiceResult<LoginResponse>.Fail("Account is inactive", StatusCodes.Status401Unauthorized);
        }

        var token = _jwtTokenService.GenerateToken(account.User);
        var response = new LoginResponse
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
        };

        return ServiceResult<LoginResponse>.Ok(response);
    }

    public async Task<ServiceResult<RegisterResponse>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken)
    {
        var normalizedEmail = NormalizeEmail(request.Email);
        var trimmedName = request.Name.Trim();
        var normalizedUsername = NormalizeUsername(request.Username);

        if (string.IsNullOrWhiteSpace(trimmedName))
        {
            return ServiceResult<RegisterResponse>.Fail("Name is required.", StatusCodes.Status400BadRequest);
        }

        if (trimmedName.Length > 50)
        {
            trimmedName = trimmedName[..50];
        }

        if (string.IsNullOrEmpty(normalizedUsername))
        {
            return ServiceResult<RegisterResponse>.Fail("Username is required.", StatusCodes.Status400BadRequest);
        }

        if (normalizedUsername.Length > UsernameMaxLength)
        {
            normalizedUsername = normalizedUsername[..UsernameMaxLength];
        }

        if (await _context.Users.AnyAsync(u => u.Email == normalizedEmail, cancellationToken))
        {
            return ServiceResult<RegisterResponse>.Fail("Email already exists", StatusCodes.Status409Conflict);
        }

        if (await _context.Accounts.AnyAsync(a => a.Username == normalizedUsername, cancellationToken))
        {
            return ServiceResult<RegisterResponse>.Fail("Username already exists", StatusCodes.Status409Conflict);
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

            var response = new RegisterResponse
            {
                Message = "User registered successfully",
                UserId = user.UserId.ToString(CultureInfo.InvariantCulture)
            };

            return ServiceResult<RegisterResponse>.Ok(response, StatusCodes.Status201Created);
        }
        catch (DbUpdateException ex)
        {
            await transaction.RollbackAsync(cancellationToken);
            _logger.LogError(ex, "Failed to register user for email {Email}", normalizedEmail);
            var message = ResolveRegistrationConflictMessage(ex);
            return ServiceResult<RegisterResponse>.Fail(message, StatusCodes.Status409Conflict);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync(cancellationToken);
            _logger.LogError(ex, "Unexpected error registering user for email {Email}", normalizedEmail);
            return ServiceResult<RegisterResponse>.Fail("Failed to register user.", StatusCodes.Status500InternalServerError);
        }
    }

    public async Task<ServiceResult<ForgotPasswordResponse>> SendPasswordResetCodeAsync(ForgotPasswordRequest request, CancellationToken cancellationToken)
    {
        var normalizedEmail = NormalizeEmail(request.Email);

        var user = await _context.Users
            .Include(u => u.Accounts)
            .FirstOrDefaultAsync(u => u.Email == normalizedEmail, cancellationToken);

        if (user == null)
        {
            return ServiceResult<ForgotPasswordResponse>.Fail("Email not found", StatusCodes.Status404NotFound);
        }

        var account = user.Accounts.FirstOrDefault(a => a.AuthProvider == null);
        if (account == null || string.IsNullOrEmpty(account.PasswordHash))
        {
            return ServiceResult<ForgotPasswordResponse>.Fail("This account does not have a password set.", StatusCodes.Status400BadRequest);
        }

        var otpCode = GenerateOtpCode();
        var otpHash = BCrypt.Net.BCrypt.HashPassword(otpCode);
        var now = DateTime.UtcNow;
        var expiresAt = now.AddMinutes(_passwordResetSettings.CodeExpiryMinutes);

        var existingTokens = await _context.PasswordResetTokens
            .Where(token => token.UserId == user.UserId && token.UsedAt == null)
            .ToListAsync(cancellationToken);

        if (existingTokens.Count > 0)
        {
            _context.PasswordResetTokens.RemoveRange(existingTokens);
        }

        var resetToken = new PasswordResetToken
        {
            UserId = user.UserId,
            CodeHash = otpHash,
            CreatedAt = now,
            ExpiresAt = expiresAt
        };

        await _context.PasswordResetTokens.AddAsync(resetToken, cancellationToken);
        await _context.SaveChangesAsync(cancellationToken);

        try
        {
            await _emailSender.SendPasswordResetCodeAsync(user.Email, user.FullName, otpCode, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send password reset OTP to {Email}", user.Email);
            resetToken.UsedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync(cancellationToken);
            return ServiceResult<ForgotPasswordResponse>.Fail("Failed to send OTP email.", StatusCodes.Status500InternalServerError);
        }

        _logger.LogInformation("Password reset OTP generated for user {UserId}", user.UserId);

        var response = new ForgotPasswordResponse
        {
            Message = "An OTP has been sent to your email"
        };

        return ServiceResult<ForgotPasswordResponse>.Ok(response);
    }

    public async Task<ServiceResult<VerifyResetCodeResponse>> VerifyResetCodeAsync(VerifyResetCodeRequest request, CancellationToken cancellationToken)
    {
        var normalizedEmail = NormalizeEmail(request.Email);
        var user = await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Email == normalizedEmail, cancellationToken);

        if (user == null)
        {
            return ServiceResult<VerifyResetCodeResponse>.Fail("Email not found", StatusCodes.Status404NotFound);
        }

        var resetToken = await GetActiveResetTokenAsync(user.UserId, cancellationToken, asTracking: false);
        if (resetToken == null || !BCrypt.Net.BCrypt.Verify(request.OtpCode, resetToken.CodeHash))
        {
            return ServiceResult<VerifyResetCodeResponse>.Fail("Invalid or expired OTP code.", StatusCodes.Status400BadRequest);
        }

        var response = new VerifyResetCodeResponse
        {
            Message = "OTP verified successfully"
        };

        return ServiceResult<VerifyResetCodeResponse>.Ok(response);
    }

    public async Task<ServiceResult<ResetPasswordResponse>> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken cancellationToken)
    {
        var normalizedEmail = NormalizeEmail(request.Email);
        var user = await _context.Users
            .Include(u => u.Accounts)
            .FirstOrDefaultAsync(u => u.Email == normalizedEmail, cancellationToken);

        if (user == null)
        {
            return ServiceResult<ResetPasswordResponse>.Fail("Email not found", StatusCodes.Status404NotFound);
        }

        var account = user.Accounts.FirstOrDefault(a => a.AuthProvider == null);
        if (account == null)
        {
            return ServiceResult<ResetPasswordResponse>.Fail("This account does not support password login.", StatusCodes.Status400BadRequest);
        }

        var resetToken = await GetActiveResetTokenAsync(user.UserId, cancellationToken, asTracking: true);
        if (resetToken == null || !BCrypt.Net.BCrypt.Verify(request.OtpCode, resetToken.CodeHash))
        {
            return ServiceResult<ResetPasswordResponse>.Fail("Invalid or expired OTP code.", StatusCodes.Status400BadRequest);
        }

        if (!string.IsNullOrEmpty(account.PasswordHash) && BCrypt.Net.BCrypt.Verify(request.NewPassword, account.PasswordHash))
        {
            return ServiceResult<ResetPasswordResponse>.Fail("New password must be different from the current password.", StatusCodes.Status400BadRequest);
        }

        account.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
        account.UpdateAt = DateTime.UtcNow;
        resetToken.UsedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync(cancellationToken);

        var response = new ResetPasswordResponse
        {
            Message = "Password has been reset successfully"
        };

        return ServiceResult<ResetPasswordResponse>.Ok(response);
    }

    private async Task<PasswordResetToken?> GetActiveResetTokenAsync(int userId, CancellationToken cancellationToken, bool asTracking)
    {
        IQueryable<PasswordResetToken> query = _context.PasswordResetTokens
            .Where(token => token.UserId == userId && token.UsedAt == null && token.ExpiresAt > DateTime.UtcNow)
            .OrderByDescending(token => token.CreatedAt);

        if (!asTracking)
        {
            query = query.AsNoTracking();
        }

        return await query.FirstOrDefaultAsync(cancellationToken);
    }

    private string GenerateOtpCode()
    {
        var length = Math.Clamp(_passwordResetSettings.CodeLength, 4, 12);
        Span<char> buffer = length <= 128 ? stackalloc char[length] : new char[length];

        for (var i = 0; i < buffer.Length; i++)
        {
            buffer[i] = (char)('0' + RandomNumberGenerator.GetInt32(0, 10));
        }

        return new string(buffer);
    }

    private static bool LooksLikeEmail(string value) => value.Contains('@');

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
                account = new Account
                {
                    UserId = user.UserId,
                    AuthProvider = GoogleProvider,
                    ProviderUserId = payload.Subject,
                    AccessToken = accessToken,
                    TokenExpiresAt = GetTokenExpiry(payload)
                };

                account.Username = await GenerateUniqueUsernameAsync(CreateUsernameCandidateFromEmail(normalizedEmail), cancellationToken);
                await _context.Accounts.AddAsync(account, cancellationToken);
            }
            else
            {
                account.AccessToken = accessToken;
                account.TokenExpiresAt = GetTokenExpiry(payload);
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

    private static DateTime? GetTokenExpiry(GoogleJsonWebSignature.Payload payload)
        => payload.ExpirationTimeSeconds.HasValue
            ? DateTimeOffset.FromUnixTimeSeconds(payload.ExpirationTimeSeconds.Value).UtcDateTime
            : null;

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
