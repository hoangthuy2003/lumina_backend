using System.ComponentModel.DataAnnotations;

namespace ServiceLayer.Options;

public class SmtpSettings
{
    public const string SectionName = "SmtpSettings";

    [Display(Name = "SMTP server host name")]
    public string Server { get; set; } = string.Empty;

    [Range(1, 65535)]
    public int Port { get; set; } = 587;

    public bool EnableSsl { get; set; } = true;

    [EmailAddress]
    public string SenderEmail { get; set; } = string.Empty;

    public string SenderName { get; set; } = string.Empty;

    public string Username { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(Server) &&
        !string.IsNullOrWhiteSpace(SenderEmail) &&
        !string.IsNullOrWhiteSpace(SenderName) &&
        !string.IsNullOrWhiteSpace(Username) &&
        !string.IsNullOrWhiteSpace(Password);
}
