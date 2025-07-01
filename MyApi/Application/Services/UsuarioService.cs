using System.Threading.Tasks;
using MyApi.Domain.Entities;
using MyApi.Infrastructure.Repositories;
using System;
using System.Text.RegularExpressions;

namespace MyApi.Application.Services
{
    public class UsuarioService
    {
        private readonly UsuarioRepository _usuarioRepository;

        public UsuarioService(UsuarioRepository usuarioRepository)
        {
            _usuarioRepository = usuarioRepository;
        }

        public async Task<bool> UsuarioExisteAsync(string username)
        {
            var user = await _usuarioRepository.GetByUsernameAsync(username);
            return user != null;
        }

        private void ValidarEmail(string email)
        {
            if (!Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
            {
                throw new ArgumentException("Formato de email inválido.");
            }
        }

        private void ValidarSenha(string password)
        {
            if (!Regex.IsMatch(password, @"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$"))
            {
                throw new ArgumentException("Senha deve ter no mínimo 8 caracteres, incluindo letras e números.");
            }
        }

        private void ValidarIPAutorizado(string ipAutorizado)
        {
            if (!string.IsNullOrEmpty(ipAutorizado?.Trim()))
            {
                if (!Regex.IsMatch(ipAutorizado.Trim(), @"^(\d{1,3}\.){3}\d{1,3}$"))
                {
                    throw new ArgumentException("IP autorizado inválido.");
                }
            }
        }

        public async Task RegistrarUsuarioAsync(string username, string password, string nome, string email, string perfil, string ipAutorizado)
        {
            ValidarEmail(email);
            ValidarSenha(password);
            ValidarIPAutorizado(ipAutorizado);

            var hashedPassword = Utils.Helper.CalcularHashSha256(password);

            var newUser = new Usuario
            {
                Username = username,
                Senha = hashedPassword,
                Nome = nome,
                Email = email,
                Perfil = perfil,
                IPAutorizado = ipAutorizado
            };

            await _usuarioRepository.AddAsync(newUser);
        }

        public async Task<Usuario> GetByUsernameAsync(string username)
        {
            return await _usuarioRepository.GetByUsernameAsync(username);
        }
    }
}
