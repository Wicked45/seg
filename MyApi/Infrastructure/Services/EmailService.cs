using System.Net;
using System.Net.Mail;

namespace MyApi.Infrastructure.Services
{
    public class EmailService
    {
        private readonly string _smtpHost;
        private readonly int _smtpPort;
        private readonly string _smtpUser;
        private readonly string _smtpPass;
        private readonly string _smtpFrom;

        public EmailService()
        {
            _smtpHost = "smtp.gmail.com";
            _smtpPort = 587;
            _smtpUser = "keuryryan45@gmail.com";
            _smtpPass = "lisq lqys dxje fuac";
            _smtpFrom = "keuryryan45@gmail.com";
        }

        public bool EnviarEmail(string to, string subject, string body)
        {
            try
            {
                var client = new SmtpClient(_smtpHost, _smtpPort)
                {
                    Credentials = new NetworkCredential(_smtpUser, _smtpPass),
                    EnableSsl = true
                };

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(_smtpFrom),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = false,
                };
                mailMessage.To.Add(to);

                client.Send(mailMessage);
                System.Console.WriteLine($"Email enviado para {to} com assunto '{subject}'");
                return true;
            }
            catch (System.Exception ex)
            {
                System.Console.WriteLine($"Erro ao enviar email: {ex.Message}");
                return false;
            }
        }
    }
}
