using System.ComponentModel.DataAnnotations;


namespace DotNetCore6DemoProject.Models.Auth
{
    public class Login
    {
        [Required]
        public string? Email { get; set; }

        [Required]
        public string? Password { get; set; }
    }
}
