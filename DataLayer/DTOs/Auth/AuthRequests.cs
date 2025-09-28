using System.ComponentModel.DataAnnotations;

namespace DataLayer.DTOs.Auth;

public class LoginRequestDTO
{
    [Required]
    [MinLength(3)]
    [MaxLength(50)]
    [RegularExpression("^[a-zA-Z0-9_.-]+$", ErrorMessage = "Username can only contain letters, numbers, and ._- characters.")]
    public string Username { get; set; } = string.Empty;

    [Required]
    [MinLength(6)]
    [MaxLength(100)]
    public string Password { get; set; } = string.Empty;
}

public class GoogleLoginRequest
{
    [Required]
    [MinLength(10)]
    public string Token { get; set; } = string.Empty;
}

public class RegisterRequest
{
    [Required]
    [MaxLength(50)]
    public string Name { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    [MaxLength(256)]
    public string Email { get; set; } = string.Empty;

    [Required]
    [MinLength(3)]
    [MaxLength(50)]
    [RegularExpression("^[a-zA-Z0-9_.-]+$", ErrorMessage = "Username can only contain letters, numbers, and ._- characters.")]
    public string Username { get; set; } = string.Empty;

    [Required]
    [MinLength(6)]
    [MaxLength(100)]
    public string Password { get; set; } = string.Empty;
}

public class ForgotPasswordRequest
{
    [Required]
    [EmailAddress]
    [MaxLength(256)]
    public string Email { get; set; } = string.Empty;
}