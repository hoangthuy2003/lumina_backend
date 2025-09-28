using DataLayer.DTOs.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ServiceLayer.Abstractions;
using ServiceLayer.Auth;

namespace lumina.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginRequestDTO request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse("Invalid login request."));
        }

        var result = await _authService.LoginAsync(request, cancellationToken);
        return ToActionResult(result);
    }

    [HttpPost("google-login")]
    [AllowAnonymous]
    public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginRequest request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse("Invalid Google login request."));
        }

        var result = await _authService.GoogleLoginAsync(request, cancellationToken);
        return ToActionResult(result);
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse("Invalid registration request."));
        }

        var result = await _authService.RegisterAsync(request, cancellationToken);
        return ToActionResult(result);
    }

    [HttpPost("forgot-password")]
    [AllowAnonymous]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse("Invalid forgot password request."));
        }

        var result = await _authService.SendPasswordResetCodeAsync(request, cancellationToken);
        return ToActionResult(result);
    }

    [HttpPost("forgot-password/verify-otp")]
    [AllowAnonymous]
    public async Task<IActionResult> VerifyForgotPasswordOtp([FromBody] VerifyResetCodeRequest request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse("Invalid verification request."));
        }

        var result = await _authService.VerifyResetCodeAsync(request, cancellationToken);
        return ToActionResult(result);
    }

    [HttpPost("forgot-password/reset")]
    [AllowAnonymous]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse("Invalid password reset request."));
        }

        var result = await _authService.ResetPasswordAsync(request, cancellationToken);
        return ToActionResult(result);
    }

    private IActionResult ToActionResult<T>(ServiceResult<T> result)
    {
        if (result.Success)
        {
            if (result.StatusCode == StatusCodes.Status204NoContent)
            {
                return StatusCode(result.StatusCode);
            }

            return StatusCode(result.StatusCode, result.Data);
        }

        return StatusCode(result.StatusCode, new ErrorResponse(result.Error ?? "An error occurred."));
    }
}
