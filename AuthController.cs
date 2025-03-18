using Microsoft.AspNetCore.Mvc;

namespace AuthExample
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        [HttpPost("register")]
        public IActionResult Register([FromBody] User user)
        {
            return Ok($"Usuário {user.Username} registrado com a senha: {user.Password}");
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] User user)
        {
            return Ok($"Usuário {user.Username} tentou fazer login com a senha: {user.Password}");
        }
    }
}
