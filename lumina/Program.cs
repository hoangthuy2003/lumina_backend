using DataLayer.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using ServiceLayer.Auth;
using ServiceLayer.Email;
using ServiceLayer.Options;
using Services.Upload;
using System.Text;

namespace lumina
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddDbContext<LuminaSystemContext>(options =>
                options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

            builder.Services
                .AddOptions<JwtSettings>()
                .Bind(builder.Configuration.GetSection(JwtSettings.SectionName))
                .ValidateDataAnnotations()
                .Validate(settings => !string.IsNullOrWhiteSpace(settings.SecretKey), "JWT SecretKey must be provided.");

            builder.Services
                .AddOptions<AuthSettings>()
                .Bind(builder.Configuration.GetSection(AuthSettings.SectionName));

            builder.Services
                .AddOptions<GoogleSettings>()
                .Bind(builder.Configuration.GetSection(GoogleSettings.SectionName));

            builder.Services
                .AddOptions<PasswordResetSettings>()
                .Bind(builder.Configuration.GetSection(PasswordResetSettings.SectionName));

            var smtpSection = builder.Configuration.GetSection(SmtpSettings.SectionName);
            builder.Services
                .AddOptions<SmtpSettings>()
                .Bind(smtpSection)
                .Validate(settings => !settings.IsConfigured || (
                    !string.IsNullOrWhiteSpace(settings.Server) &&
                    !string.IsNullOrWhiteSpace(settings.SenderEmail) &&
                    !string.IsNullOrWhiteSpace(settings.SenderName) &&
                    !string.IsNullOrWhiteSpace(settings.Username) &&
                    !string.IsNullOrWhiteSpace(settings.Password)), "SMTP settings are incomplete.");

            builder.Services.AddSingleton<IJwtTokenService, JwtTokenService>();
            builder.Services.AddCors(options =>
            {
                options.AddDefaultPolicy(policy =>
                {
                    policy.WithOrigins("http://localhost:4200", "https://localhost:4200") // ? Specific origin
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
                       
                });
            });

            builder.Services.AddScoped<IUploadService, UploadService>();
            builder.Services.AddScoped<IAuthService, AuthService>();

            var smtpSettings = smtpSection.Get<SmtpSettings>() ?? new SmtpSettings();
            if (smtpSettings.IsConfigured)
            {
                builder.Services.AddTransient<IEmailSender, SmtpEmailSender>();
            }
            else
            {
                builder.Services.AddSingleton<IEmailSender, NullEmailSender>();
            }

            var jwtSettings = builder.Configuration
                .GetSection(JwtSettings.SectionName)
                .Get<JwtSettings>() ?? throw new InvalidOperationException("JWT settings are not configured.");

            builder.Services
                .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = jwtSettings.Issuer,
                        ValidAudience = jwtSettings.Audience,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey))
                    };
                });

            builder.Services.AddAuthorization();

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}