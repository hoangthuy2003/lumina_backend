using DataLayer.Models;

namespace ServiceLayer.Auth;

public interface ILoginService
{
    Task<Account?> FindByCredentialsAsync(string username, string passwordHash, CancellationToken cancellationToken = default);

    Task<Account?> FindByExternalProviderAsync(string authProvider, string providerUserId, CancellationToken cancellationToken = default);
}