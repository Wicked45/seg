using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using MyApi.Infrastructure.Repositories;
using MyApi.Domain.Entities;
using MyApi.Utils;

namespace MyApi.Application.Services
{
    public class AuthService
    {
        private readonly UsuarioRepository _usuarioRepository;
        private readonly MyApi.Infrastructure.Services.EmailService _emailService;
        private readonly IMemoryCache _cache;
        private readonly string _jwtKey;
        private readonly string _jwtIssuer;
        private readonly string _jwtAudience;
        private readonly int _jwtExpireMinutes;

        public AuthService(UsuarioRepository usuarioRepository, MyApi.Infrastructure.Services.EmailService emailService, IMemoryCache cache, string jwtKey, string jwtIssuer, string jwtAudience, int jwtExpireMinutes)
        {
            _usuarioRepository = usuarioRepository;
            _emailService = emailService;
            _cache = cache;
            _jwtKey = jwtKey;
            _jwtIssuer = jwtIssuer;
            _jwtAudience = jwtAudience;
            _jwtExpireMinutes = jwtExpireMinutes;
        }

        public async Task<(bool Success, string? Captcha, string? Message)> LoginAsync(string username, string password, string? captcha = null)
        {
            username = Helper.Sanitizar(username);
            password = Helper.Sanitizar(password);

            Helper.Log($"Tentativa de login para o usuário '{username}'");

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                Helper.Log($"Falha no login para o usuário '{username}': Usuário ou senha ausentes");
                return (false, null, "Usuário e senha são obrigatórios.");
            }

            var user = await _usuarioRepository.GetByUsernameAsync(username);
            if (user == null)
            {
                Helper.Log($"Falha no login para o usuário '{username}': Usuário não encontrado");
                return (false, null, "Usuário ou senha inválidos.");
            }

            var ipAddress = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName())
                .AddressList.FirstOrDefault(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.ToString() ?? "";

            if (!string.IsNullOrEmpty(user.IPAutorizado))
            {
                var ipsAutorizados = user.IPAutorizado.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (!ipsAutorizados.Contains(ipAddress))
                {
                    Helper.Log($"IP não autorizado para o usuário '{username}'. Esperado(s): {user.IPAutorizado}, Atual: {ipAddress}");
                    return (false, null, "IP não autorizado.");
                }
            }

            var hashedPassword = Helper.CalcularHashSha256(password);
            if (user.Senha != hashedPassword)
            {
                Helper.Log($"Senha incorreta para o usuário '{username}'.");
                return (false, null, "Senha inválida.");
            }

            // Enviar código 2FA por email
            var twoFactorCode = new Random().Next(100000, 999999).ToString();
            var cacheEntryOptions = new MemoryCacheEntryOptions()
                .SetAbsoluteExpiration(TimeSpan.FromMinutes(3));
            _cache.Set(username, twoFactorCode, cacheEntryOptions);
            var emailSent = _emailService.EnviarEmail(user.Email, "Seu código 2FA", $"Seu código de autenticação é: {twoFactorCode}");
            if (!emailSent)
            {
                Helper.Log($"Falha ao enviar código 2FA para o usuário '{username}'");
                return (false, null, "Falha ao enviar código 2FA.");
            }

            Helper.Log($"Código 2FA enviado para o usuário '{username}'");

            return (true, null, "Código 2FA enviado por email.");
        }

        public string GenerateJwtToken(Usuario user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtKey);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim("Perfil", user.Perfil ?? "")
                }),
                Expires = DateTime.UtcNow.AddMinutes(_jwtExpireMinutes),
                Issuer = _jwtIssuer,
                Audience = _jwtAudience,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public bool VerifyTwoFactorCode(string username, string code)
        {
            username = Helper.Sanitizar(username);
            code = Helper.Sanitizar(code);

            Helper.Log($"Tentativa de verificação 2FA para o usuário '{username}'");

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(code))
            {
                Helper.Log($"Falha na verificação 2FA para o usuário '{username}': Usuário ou código ausentes");
                return false;
            }

            if (!_cache.TryGetValue(username, out string expectedCode))
            {
                Helper.Log($"Falha na verificação 2FA para o usuário '{username}': Código não encontrado");
                return false;
            }

            Helper.Log($"Código esperado: {expectedCode}, Código recebido: {code}");

            if (expectedCode != code)
            {
                Helper.Log($"Falha na verificação 2FA para o usuário '{username}': Código inválido");
                return false;
            }

            _cache.Remove(username);
            Helper.Log($"Verificação 2FA bem-sucedida para o usuário '{username}'");
            return true;
        }
    }
}
