using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System;

namespace MyApi.Utils
{
    public static class Helper
    {
        public static string CalcularHashSha256(string input)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(input);
                byte[] hash = sha256.ComputeHash(bytes);
                StringBuilder builder = new StringBuilder();
                foreach (byte b in hash)
                {
                    builder.Append(b.ToString("x2"));
                }
                return builder.ToString();
            }
        }

        public static string Sanitizar(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            // Remove leading/trailing whitespace and any non-printable characters
            string sanitized = input.Trim();
            sanitized = Regex.Replace(sanitized, @"[^\u0020-\u007E]", string.Empty);
            return sanitized;
        }

        private static readonly object _lock = new object();
        private static readonly string logFilePath = System.IO.Path.Combine(AppContext.BaseDirectory, "auth_log.txt");

        public static void Log(string message)
        {
            string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
            Console.WriteLine(logEntry);
            try
            {
                lock (_lock)
                {
                    System.IO.File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao gravar log de autenticação: {ex.Message}");
            }
        }
    }
}
