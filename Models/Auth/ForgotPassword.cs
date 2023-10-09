using System.ComponentModel.DataAnnotations;

namespace DotNetCore6DemoProject.Models.Auth
{
    public class ForgotPassword
    {
        [Required(ErrorMessage = "Provide Email to find your profile!")]
        public string? Email { get; set; }
    }
}
