using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;

public static class SeedData
{
    public static void Initialize(IServiceProvider serviceProvider)
    {
        using var context = new AppDbContext(serviceProvider.GetRequiredService<DbContextOptions<AppDbContext>>());

        if (context.Usuarios.Any())
        {
            return;   // DB já foi populado
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

        context.Usuarios.Add(new Usuario
        {
            Username = "testuser",
            Senha = CalcularHashSha256("Keury2004"),
            Nome = "Usuário de Teste",
            Email = "testuser@example.com",
            Perfil = "User",
            IPAutorizado = "127.0.0.1, ::1"
        });

        context.SaveChanges();
    }
}
