using AuthService.DatabaseContext;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using DotNetEnv;
using PidrobitOK.AuthService.Models;
using Microsoft.OpenApi.Models;
using System.Security.Claims;
using PidrobitOK.AuthService.Services;
using PidrobitOK.AuthService.Options;

public class Program
{
    private static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        var ownEnvironment = builder.Environment.EnvironmentName;
        var connectionString = string.Empty;

        if (builder.Environment.IsDevelopment())
        {
            var envPath = Path.Combine(AppContext.BaseDirectory, ".env");
            Env.Load(envPath);

            connectionString = $"Data Source=ARTEXXX;Database={Environment.GetEnvironmentVariable("SQL_DATABASE")};Integrated Security=True;Encrypt=True;Trust Server Certificate=True";
        }


        else if (ownEnvironment == "DockerDevelopment")
        {
            connectionString = $"Server={Environment.GetEnvironmentVariable("SQL_SERVER")};" +
            $"Database={Environment.GetEnvironmentVariable("SQL_DATABASE")};" +
            $"User Id={Environment.GetEnvironmentVariable("SQL_USER")};" +
            $"Password={Environment.GetEnvironmentVariable("SQL_PASSWORD")};" +
            "TrustServerCertificate=True";
        }

        builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(connectionString));

        builder.Services.AddIdentity<PidrobitokUser, IdentityRole<Guid>>(options =>
        {
            options.Password.RequireNonAlphanumeric = false;
            options.Password.RequireUppercase = false;
        })
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();

        // 3. JWT Authentication
        var issuer = Environment.GetEnvironmentVariable("JWT_ISSUER");
        var audience = Environment.GetEnvironmentVariable("JWT_AUDIENCE");
        var secret = Environment.GetEnvironmentVariable("JWT_SECRET");
        var tokenLifetime = int.Parse(Environment.GetEnvironmentVariable("JWT_TOKEN_LIFETIME"));

        var jwtSettings = new JwtSettings
        {
            Issuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? throw new InvalidOperationException("JWT_ISSUER not set"),
            Audience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? throw new InvalidOperationException("JWT_AUDIENCE not set"),
            Secret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? throw new InvalidOperationException("JWT_SECRET not set"),
            TokenLifetimeMin = int.TryParse(Environment.GetEnvironmentVariable("JWT_TOKEN_LIFETIME"), out var result)
        ? result
        : throw new InvalidOperationException("JWT_TOKEN_LIFETIME is not a valid integer")
        };

        builder.Services.AddSingleton(jwtSettings);

        builder.Services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.RequireHttpsMetadata = true;
            options.SaveToken = true;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = issuer,
                ValidAudience = audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                RoleClaimType = ClaimTypes.Role
            };
        });

        builder.Services.AddCors(options =>
        {
            options.AddPolicy("AllowAll", policy =>
            {
                policy
                    .AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader();
            });
        });

        builder.Services.AddScoped<IJwtTokenService, JwtTokenService>();
        builder.Services.AddScoped<StartupTasksService>();

        builder.Services.AddControllers();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new OpenApiInfo { Title = "AuthService", Version = "v1" });

            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Name = "Authorization",
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header,
                Description = "Format: \"Bearer {your JWT token}\""
            });

            c.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Id = "Bearer",
                    Type = ReferenceType.SecurityScheme
                }
            },
            Array.Empty<string>()
        }
            });
        });

        var app = builder.Build();

        /*if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }*/

        app.UseSwagger();
        app.UseSwaggerUI();

        app.UseCors("AllowAll");
        app.UseHttpsRedirection();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        using (var scope = app.Services.CreateScope())
        {
            if (builder.Environment.EnvironmentName == "DockerDevelopment")
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                if (dbContext != null)
                {
                    dbContext.Database.Migrate();
                }
                else
                {
                    throw new Exception("An error occurred while migrating a database to PidrobitOK.AuthService. DbContext is null");
                }
            }

            var startupTasksService = scope.ServiceProvider.GetRequiredService<StartupTasksService>();
            if (startupTasksService != null)
            {
                await startupTasksService.EnsureRolesExist();
                await startupTasksService.EnsureAdminExist();
            }
            else
            {
                throw new Exception("An error occurred while running a startup tasks to PidrobitOK.AuthService. StartupTasksService is null");
            }
        }


        app.Run();
    }
}