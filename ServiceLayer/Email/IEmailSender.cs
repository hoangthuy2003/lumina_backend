namespace ServiceLayer.Email;

public interface IEmailSender
{
    Task SendPasswordResetCodeAsync(string toEmail, string toName, string otpCode, CancellationToken cancellationToken);
}
