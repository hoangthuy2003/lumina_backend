using Microsoft.Extensions.Logging;

namespace ServiceLayer.Email;

public class NullEmailSender : IEmailSender
{
    private readonly ILogger<NullEmailSender> _logger;

    public NullEmailSender(ILogger<NullEmailSender> logger)
    {
        _logger = logger;
    }

    public Task SendPasswordResetCodeAsync(string toEmail, string toName, string otpCode, CancellationToken cancellationToken)
    {
        _logger.LogWarning(
            "SMTP settings are not configured. Skipping password reset email to {Email}.",
            toEmail);

        throw new InvalidOperationException(
            "Email delivery is not configured. Please provide SMTP settings before requesting password resets.");
    }
}
