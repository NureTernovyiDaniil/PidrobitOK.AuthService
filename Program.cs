using AuthService.DatabaseContext;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using DotNetEnv;
using PidrobitOK.AuthService.Models;

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

// Override database connection
// 1. EF
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// 2. Identity + User
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
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret))
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

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

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
    if(builder.Environment.EnvironmentName == "DockerDevelopment")
    {
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        dbContext.Database.Migrate();
    }
}


app.Run();