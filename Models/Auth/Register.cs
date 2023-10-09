using System.ComponentModel.DataAnnotations;


namespace DotNetCore6DemoProject.Models.Auth
{
    public class Register
    {
        [Required]
        public string Firstname { get; set; } = string.Empty;

        public string Lastname { get; set; } = string.Empty;

        [Required]
        public string Username { get; set; } = string.Empty;

        [EmailAddress]
        [Required]
        public string Email { get; set; } = string.Empty;

        [Required]
        [RegularExpression(@"^(?=.*[A-Z])(?=.*\d).{8,}$", 
            ErrorMessage = "Password must contain at least one uppercase letter, one number, and be at least 8 characters long.")]
        public string Password { get; set; } = string.Empty;
    }
}
