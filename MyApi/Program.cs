using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;
using System.Net.Mail;
using System.Net;
using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddOpenApi();

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

var captchaStore = new ConcurrentDictionary<string, string>();
var twoFactorStore = new ConcurrentDictionary<string, string>();

var logFilePath = "auth_log.txt";
void Log(string message)
{
    var logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}";
    File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
}

string Sanitizar(string input)
{
    if (string.IsNullOrEmpty(input)) return string.Empty;
    return Regex.Replace(input, @"[^\w@.-]", "");
}

string CalcularHashSha256(string rawData)
{
    using (SHA256 sha256Hash = SHA256.Create())
    {
        byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < bytes.Length; i++)
        {
            builder.Append(bytes[i].ToString("x2"));
        }
        return builder.ToString();
    }
}

bool EnviarEmail(string toEmail, string subject, string body)
{
    try
    {
        var smtpHost = builder.Configuration["Smtp:Host"];
        var smtpPort = int.Parse(builder.Configuration["Smtp:Port"] ?? "25");
        var smtpUser = builder.Configuration["Smtp:User"];
        var smtpPass = builder.Configuration["Smtp:Pass"];
        var fromEmail = builder.Configuration["Smtp:From"];

        using var client = new SmtpClient(smtpHost, smtpPort)
        {
            Credentials = new NetworkCredential(smtpUser, smtpPass),
            EnableSsl = true,
        };
        var mailMessage = new MailMessage(fromEmail, toEmail, subject, body);
        client.Send(mailMessage);
        return true;
    }
    catch (Exception ex)
    {
        Log($"Falha ao enviar email para {toEmail}: {ex.Message}");
        return false;
    }
}

app.MapPost("/register", async (AppDbContext db, UsuarioCreateRequest createRequest) =>
{
    var username = Sanitizar(createRequest.Username);
    var password = Sanitizar(createRequest.Password);
    var nome = Sanitizar(createRequest.Nome);
    var email = Sanitizar(createRequest.Email);
    var perfil = Sanitizar(createRequest.Perfil);
    var ipAutorizado = Sanitizar(createRequest.IPAutorizado);

    if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password) || string.IsNullOrEmpty(nome) || string.IsNullOrEmpty(email))
    {
        return Results.BadRequest("Username, password, nome e email são obrigatórios.");
    }

    var existingUser = await db.Usuarios.FirstOrDefaultAsync(u => u.Username == username);
    if (existingUser != null)
    {
        return Results.BadRequest("Usuário já existe.");
    }

    var hashedPassword = CalcularHashSha256(password);

    var newUser = new Usuario
    {
        Username = username,
        Senha = hashedPassword,
        Nome = nome,
        Email = email,
        Perfil = perfil,
        IPAutorizado = ipAutorizado
    };

    db.Usuarios.Add(newUser);
    await db.SaveChangesAsync();

    Log($"Novo usuário registrado: {username}");

    return Results.Ok(new { message = "Usuário registrado com sucesso." });
});

app.MapPost("/login", async (HttpContext http, AppDbContext db, LoginRequest loginRequest) =>
{
    var username = Sanitizar(loginRequest.Username);
    var password = Sanitizar(loginRequest.Password);
    var ipAddress = http.Connection.RemoteIpAddress?.ToString() ?? "";

    Log($"Tentativa de login para o usuário '{username}' do IP {ipAddress}");

    if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
    {
        Log($"Falha no login para o usuário '{username}': Usuário ou senha ausentes");
        return Results.BadRequest("Usuário e senha são obrigatórios.");
    }

    var user = await db.Usuarios.FirstOrDefaultAsync(u => u.Username == username);
    if (user == null)
    {
        Log($"Falha no login para o usuário '{username}': Usuário não encontrado");
        return Results.BadRequest("Usuário ou senha inválidos.");
    }

    var hashedPassword = CalcularHashSha256(password);
    if (user.Senha != hashedPassword)
    {
        var captcha = new Random().Next(100000, 999999).ToString();
        captchaStore[username] = captcha;
        Log($"Senha incorreta para o usuário '{username}'. Captcha gerado: {captcha}");
        return Results.BadRequest(Results.Json(new { message = "Senha inválida.", captchaRequired = true, captcha }));
    }

    if (captchaStore.ContainsKey(username))
    {
        if (string.IsNullOrEmpty(loginRequest.Captcha) || loginRequest.Captcha != captchaStore[username])
        {
            Log($"Falha na validação do captcha para o usuário '{username}'");
            return Results.BadRequest(Results.Json(new { message = "Falha na validação do captcha.", captchaRequired = true }));
        }
        else
        {
            captchaStore.TryRemove(username, out _);
            Log($"Captcha validado para o usuário '{username}'");
        }
    }

    // Verificação de IP desabilitada temporariamente
    /*
    if (!string.IsNullOrEmpty(user.IPAutorizado))
    {
        var ipsAutorizados = user.IPAutorizado.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (!ipsAutorizados.Contains(ipAddress))
        {
            Log($"IP não autorizado para o usuário '{username}'. Esperado(s): {user.IPAutorizado}, Atual: {ipAddress}");
            return Results.BadRequest("IP não autorizado.");
        }
    }
    */

    Log($"Login efetuado com sucesso para o usuário '{username}'");

    return Results.Json(new { message = "Login efetuado com sucesso.", success = true });
});



app.MapPost("/verify-2fa", async (AppDbContext db, TwoFactorRequest twoFactorRequest) =>
{
    var username = Sanitizar(twoFactorRequest.Username);
    var code = Sanitizar(twoFactorRequest.Code);

    Log($"Tentativa de verificação 2FA para o usuário '{username}'");

    if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(code))
    {
        Log($"Falha na verificação 2FA para o usuário '{username}': Usuário ou código ausentes");
        return Results.BadRequest("Usuário e código 2FA são obrigatórios.");
    }

    if (!twoFactorStore.TryGetValue(username, out var expectedCode) || expectedCode != code)
    {
        Log($"Falha na verificação 2FA para o usuário '{username}': Código inválido");
        return Results.BadRequest("Código 2FA inválido.");
    }

    twoFactorStore.TryRemove(username, out _);
    Log($"Verificação 2FA bem-sucedida para o usuário '{username}'");

    return Results.Json(new { message = "Autenticação bem-sucedida." });
});

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => TemperatureC;
}

record LoginRequest(string Username, string Password, string? Captcha);
record TwoFactorRequest(string Username, string Code);

record UsuarioCreateRequest(string Username, string Password, string Nome, string Email, string Perfil, string IPAutorizado);
