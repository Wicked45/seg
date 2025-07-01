using Microsoft.EntityFrameworkCore;
using MyApi.Application.Services;
using MyApi.Infrastructure.Services;
using MyApi.Infrastructure.Repositories;
using MyApi.Domain.Entities;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddJsonFile("appsettings.Jwt.json", optional: true, reloadOnChange: true);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

var jwtSettings = builder.Configuration.GetSection("Jwt");
var keyString = jwtSettings["Key"];
if (string.IsNullOrEmpty(keyString))
{
    throw new Exception("JWT Key is not configured.");
}
var key = System.Text.Encoding.ASCII.GetBytes(keyString);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(key)
    };
});

builder.Services.AddOpenApi();
builder.Services.AddScoped<UsuarioRepository>();
builder.Services.AddScoped<EmailService>();
builder.Services.AddMemoryCache();

builder.Services.AddScoped<AuthService>(provider =>
{
    var usuarioRepository = provider.GetRequiredService<UsuarioRepository>();
    var emailService = provider.GetRequiredService<EmailService>();
    var cache = provider.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>();
    var configuration = provider.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    var jwtSettings = configuration.GetSection("Jwt");
    var jwtKey = jwtSettings["Key"] ?? throw new Exception("JWT Key is not configured.");
    var jwtIssuer = jwtSettings["Issuer"] ?? throw new Exception("JWT Issuer is not configured.");
    var jwtAudience = jwtSettings["Audience"] ?? throw new Exception("JWT Audience is not configured.");
    var jwtExpireMinutes = int.Parse(jwtSettings["ExpireMinutes"] ?? "60");
    return new AuthService(usuarioRepository, emailService, cache, jwtKey, jwtIssuer, jwtAudience, jwtExpireMinutes);
});
builder.Services.AddScoped<UsuarioService>();
builder.Services.AddScoped<UsuarioRepository>();

builder.Services.AddControllers();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    SeedData.Initialize(services);
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.MapControllers();

app.Run();
