using System.ComponentModel.DataAnnotations;

namespace ServiceLayer.Options;

public class PasswordResetSettings
{
    public const string SectionName = "PasswordReset";

    private int _codeLength = 6;

    [Range(1, 60)]
    public int CodeExpiryMinutes { get; set; } = 10;

    [Range(4, 12)]
    public int CodeLength
    {
        get => _codeLength;
        set => _codeLength = value;
    }
}
