using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthExample
{
    public class User
    {
        public string Username { get; set; }
        public string PasswordHash { get; set; }

        public User(string username, string password)
        {
            Username = username;
            PasswordHash = ComputeSha256Hash(password);
        }

        // Método para validar nome de usuário e senha
        public static bool IsValid(string input)
        {
            string pattern = @"^[a-zA-Z0-9_]{3,20}$"; // Apenas letras, números e "_", entre 3 e 20 caracteres
            return Regex.IsMatch(input, pattern);
        }

        // Método para gerar o hash SHA-256
        private static string ComputeSha256Hash(string rawData)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                StringBuilder builder = new StringBuilder();
                foreach (byte b in bytes)
                {
                    builder.Append(b.ToString("x2"));
                }
                return builder.ToString();
            }
        }
    }
}
