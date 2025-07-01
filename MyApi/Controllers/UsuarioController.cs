using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using MyApi.Application.Services;
using MyApi.Models;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace MyApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UsuarioController : ControllerBase
    {
        private readonly UsuarioService _usuarioService;
        private readonly AuthService _authService;
        private readonly ILogger<UsuarioController> _logger;

        public UsuarioController(UsuarioService usuarioService, AuthService authService, ILogger<UsuarioController> logger)
        {
            _usuarioService = usuarioService;
            _authService = authService;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UsuarioCreateRequest createRequest)
        {
            // Validação dos campos obrigatórios
            if (string.IsNullOrEmpty(createRequest.Username) || string.IsNullOrEmpty(createRequest.Password) ||
                string.IsNullOrEmpty(createRequest.Nome) || string.IsNullOrEmpty(createRequest.Email))
            {
                _logger.LogWarning("Tentativa de registro com campos obrigatórios faltando.");
                return BadRequest("Username, password, nome e email são obrigatórios.");
            }

            // Validação do formato do email
            if (!Regex.IsMatch(createRequest.Email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
            {
                _logger.LogWarning("Tentativa de registro com email inválido: {Email}", createRequest.Email);
                return BadRequest("Formato de email inválido.");
            }

            // Validação da força da senha (mínimo 8 caracteres, pelo menos uma letra e um número)
            if (!Regex.IsMatch(createRequest.Password, @"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$"))
            {
                _logger.LogWarning("Tentativa de registro com senha fraca.");
                return BadRequest("Senha deve ter no mínimo 8 caracteres, incluindo letras e números.");
            }

            // Obter IP do cliente do contexto HTTP
            var ipCliente = HttpContext.Connection.RemoteIpAddress?.ToString();

            // Removido o retorno de erro caso o IP do cliente seja nulo ou vazio
            // O IP será tratado conforme necessário em outro lugar

            if (await _usuarioService.UsuarioExisteAsync(createRequest.Username))
            {
                _logger.LogWarning("Tentativa de registro com usuário já existente: {Username}", createRequest.Username);
                return BadRequest("Usuário já existe.");
            }

            try
            {
await _usuarioService.RegistrarUsuarioAsync(
    createRequest.Username,
    createRequest.Password,
    createRequest.Nome,
    createRequest.Email,
    createRequest.Perfil,
    createRequest.IPAutorizado);

                _logger.LogInformation("Usuário registrado com sucesso: {Username}", createRequest.Username);
                return Ok(new { message = "Usuário registrado com sucesso." });
            }
            catch (System.Exception ex)
            {
                _logger.LogError(ex, "Erro ao registrar usuário: {Username}", createRequest.Username);
                return StatusCode(500, "Erro interno ao registrar usuário.");
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest loginRequest)
        {
            var (success, captcha, message) = await _authService.LoginAsync(loginRequest.Username, loginRequest.Password, loginRequest.Captcha);
            if (!success)
            {
                return BadRequest(new { message, captcha });
            }
            return Ok(new { message });
        }

        [HttpPost("verify-2fa")]
        public async Task<IActionResult> VerifyTwoFactor([FromBody] TwoFactorRequest twoFactorRequest)
        {
            var valid = _authService.VerifyTwoFactorCode(twoFactorRequest.Username, twoFactorRequest.Code);
            if (!valid)
            {
                return BadRequest(new { message = "Código 2FA inválido." });
            }
            var user = await _usuarioService.GetByUsernameAsync(twoFactorRequest.Username);
            var token = _authService.GenerateJwtToken(user);
            return Ok(new { token });
        }
    }

    public record LoginRequest(string Username, string Password, string? Captcha);
    public record TwoFactorRequest(string Username, string Code);
}
