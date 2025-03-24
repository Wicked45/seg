using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;

namespace AuthExample
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private static List<User> users = new List<User>(); // Lista para armazenar usuários temporariamente

        [HttpPost("register")]
        public IActionResult Register([FromBody] User user)
        {
            if (!User.IsValid(user.Username) || !User.IsValid(user.PasswordHash))
                return BadRequest("Nome de usuário ou senha inválidos. Use apenas letras, números e '_', entre 3 e 20 caracteres.");

            if (users.Any(u => u.Username == user.Username))
                return BadRequest("Usuário já existe.");

            users.Add(new User(user.Username, user.PasswordHash));
            return Ok($"Usuário {user.Username} registrado com sucesso!");
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] User user)
        {
            var existingUser = users.FirstOrDefault(u => u.Username == user.Username);

            if (existingUser != null && existingUser.PasswordHash == new User("", user.PasswordHash).PasswordHash)
                return Ok("Login bem-sucedido!");
            
            return Unauthorized("Usuário ou senha inválidos.");
        }
    }
}
