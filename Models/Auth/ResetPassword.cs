﻿using System.ComponentModel.DataAnnotations;

namespace DotNetCore6DemoProject.Models.Auth
{
    public class ResetPassword
    {
        [Required(ErrorMessage = "OTP is required for verification")]
        public string Otp { get; set; } = string.Empty;

        [Required]
        public string NewPassword { get; set; } = string.Empty;

        [Required]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}