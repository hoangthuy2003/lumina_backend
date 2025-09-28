using DataLayer.DTOs.Auth;
using ServiceLayer.Abstractions;

namespace ServiceLayer.Auth;

public interface IAuthService
{
    Task<ServiceResult<LoginResponse>> LoginAsync(LoginRequestDTO request, CancellationToken cancellationToken);

    Task<ServiceResult<LoginResponse>> GoogleLoginAsync(GoogleLoginRequest request, CancellationToken cancellationToken);

    Task<ServiceResult<RegisterResponse>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken);

    Task<ServiceResult<ForgotPasswordResponse>> SendPasswordResetCodeAsync(ForgotPasswordRequest request, CancellationToken cancellationToken);

    Task<ServiceResult<VerifyResetCodeResponse>> VerifyResetCodeAsync(VerifyResetCodeRequest request, CancellationToken cancellationToken);

    Task<ServiceResult<ResetPasswordResponse>> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken cancellationToken);
}
