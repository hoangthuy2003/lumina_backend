
using DataLayer.Models;
using Microsoft.EntityFrameworkCore;
using ServiceLayer.Auth;
using Services.Auth;
using Services.Upload;

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
            builder.Services.AddScoped<ILoginService, LoginService>();
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

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
