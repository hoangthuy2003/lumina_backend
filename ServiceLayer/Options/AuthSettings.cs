namespace ServiceLayer.Options;

public class AuthSettings
{
    public const string SectionName = "Auth";

    public int DefaultRoleId { get; set; } = 1;
}
