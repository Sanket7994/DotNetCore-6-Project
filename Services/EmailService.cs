
using SendGrid;
using SendGrid.Helpers.Mail;
using System.Text.RegularExpressions;
using System.Net;

namespace DotNetCore6DemoProject.Services
{
    public interface IEmailService
    {
        Task SendEmailAsync(string toEmail, string subject, string message);
    }

    public class SendGridEmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly SendGridClient _sendGridClient;

        public SendGridEmailService(IConfiguration configuration)
        {
            _configuration = configuration;
            _sendGridClient = new SendGridClient(_configuration["SendGridSettings:ApiKey"]);
        }

        public async Task SendEmailAsync(string toEmail, string subject, string message)
        {
            try
            {
                var from = new EmailAddress(
                    _configuration["SendGridSettings:SenderEmail"],
                    _configuration["SendGridSettings:SenderName"]);
                var to = new EmailAddress(toEmail);
                var plainTextContent = message;
                var htmlContent = message;

                var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);

                var response = await _sendGridClient.SendEmailAsync(msg);

                if (response.StatusCode == HttpStatusCode.Accepted)
                {
                    Console.WriteLine("Email sent");
                }
                else
                {
                    Console.WriteLine($"Failed to send email to: {toEmail}, Status Code: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw; 
            }
        }
    }
}




