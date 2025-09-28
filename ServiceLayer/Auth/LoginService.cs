using DataLayer.Models;
using Microsoft.EntityFrameworkCore;
using ServiceLayer.Auth;

namespace Services.Auth;

public class LoginService : ILoginService
{
    private readonly LuminaSystemContext _context;

    public LoginService(LuminaSystemContext context)
    {
        _context = context;
    }

    public async Task<Account?> FindByCredentialsAsync(string username, string passwordHash, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(passwordHash))
        {
            return null;
        }

        return await _context.Accounts
            .AsNoTracking()
            .FirstOrDefaultAsync(
                account => account.Username == username && account.PasswordHash == passwordHash,
                cancellationToken);
    }

    public async Task<Account?> FindByExternalProviderAsync(string authProvider, string providerUserId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(authProvider) || string.IsNullOrWhiteSpace(providerUserId))
        {
            return null;
        }

        return await _context.Accounts
            .AsNoTracking()
            .FirstOrDefaultAsync(
                account => account.AuthProvider == authProvider && account.ProviderUserId == providerUserId,
                cancellationToken);
    }
}