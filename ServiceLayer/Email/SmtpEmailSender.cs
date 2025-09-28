using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ServiceLayer.Options;

namespace ServiceLayer.Email;

public class SmtpEmailSender : IEmailSender
{
    private readonly SmtpSettings _settings;
    private readonly ILogger<SmtpEmailSender> _logger;

    public SmtpEmailSender(IOptionsSnapshot<SmtpSettings> options, ILogger<SmtpEmailSender> logger)
    {
        _settings = options.Value;
        _logger = logger;

        if (!_settings.IsConfigured)
        {
            throw new InvalidOperationException("SMTP settings are incomplete.");
        }
    }

    public async Task SendPasswordResetCodeAsync(string toEmail, string toName, string otpCode, CancellationToken cancellationToken)
    {
        using var message = new MailMessage
        {
            From = new MailAddress(_settings.SenderEmail, _settings.SenderName),
            Subject = "Your Lumina password reset code",
            Body = BuildPasswordResetBody(toName, otpCode),
            IsBodyHtml = false
        };

        message.To.Add(new MailAddress(toEmail, toName));

        using var client = new SmtpClient(_settings.Server, _settings.Port)
        {
            Credentials = new NetworkCredential(_settings.Username, _settings.Password),
            EnableSsl = _settings.EnableSsl
        };

        try
        {
            await client.SendMailAsync(message, cancellationToken);
            _logger.LogInformation("Sent password reset OTP email to {Email}", toEmail);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send password reset email to {Email}", toEmail);
            throw;
        }
    }

    private static string BuildPasswordResetBody(string name, string otpCode)
    {
        var greeting = string.IsNullOrWhiteSpace(name) ? "Hello" : $"Hello {name}";
        return $"{greeting},\n\n" +
               "We received a request to reset the password for your Lumina account. " +
               $"Use the following verification code to continue: {otpCode}.\n\n" +
               "If you did not request this code, you can safely ignore this email.";
    }
}
