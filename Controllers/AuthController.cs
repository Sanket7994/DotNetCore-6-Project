
// Libraries
using DotNetCore6DemoProject.Context;
using DotNetCore6DemoProject.Models.Auth;
using DotNetCore6DemoProject.Models.Auth.HelperFunctions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using shortid.Configuration;
using shortid;
using System.Security.Claims;
using DotNetCore6DemoProject.Services;
using System.Collections.Concurrent;
using static System.Net.Mime.MediaTypeNames;
using static System.Net.WebRequestMethods;
using Newtonsoft.Json.Linq;

// Controller
namespace DotNetCore6DemoProject.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ProjectDB _dbContext;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        public AuthController(ProjectDB dbContext, IConfiguration configuration, IEmailService emailService)
        {
            _dbContext = dbContext;
            _configuration = configuration;
            _emailService = emailService;
        }


        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<ActionResult<UserDTO>> Register(Register request)
        {
            // Sanity Check 
            if (string.IsNullOrWhiteSpace(request.Email) 
                || string.IsNullOrWhiteSpace(request.Username) 
                || string.IsNullOrWhiteSpace(request.Password))
            {
                return StatusCode(400, "Insufficient information provided");
            }

            // Check if the user with the provided email or username exists in the database
            bool userExists = await _dbContext.Users.AnyAsync(
                u => u.Email == request.Email || u.Username == request.Username);

            if (userExists)
            {
                return StatusCode(401, "Username or Email already exists. Please login!");
            }

            // Generate a random salt
            byte[] passwordSalt = FunctionManager.HelperFunctionsInstance.GenerateSalt();

            // Create password hash using the generated salt
            FunctionManager.HelperFunctionsInstance.CreatePasswordHash(
                request.Password, passwordSalt, out byte[] passwordHash);

            UserDTO newUser = new UserDTO
            {
                Id = FunctionManager.HelperFunctionsInstance.GenratedShortIDs(12),
                Username = request.Username,
                Firstname = request.Firstname,
                Lastname = request.Lastname,
                Email = request.Email,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt
            };
            try
            {
                // Add the user to the database
                _dbContext.Users.Add(newUser);
                await _dbContext.SaveChangesAsync();

                // Send user a confirmation email
                string subject = "Successful Account Registration";
                string htmlBody = "<!DOCTYPE html>\r\n<html lang=\"en\">\r\n<head>\r\n    <meta charset=\"UTF-8\">\r\n    <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\r\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\r\n    <title>Account Registration Successful</title>\r\n</head>\r\n<body>\r\n    <div style=\"text-align: center;\">\r\n        <h1>Welcome to Our Website!</h1>\r\n        <p>Your account has been successfully registered.</p>\r\n        <p>Thank you for joining us. You can now log in and start exploring our services.</p>\r\n        <p>If you have any questions or need assistance, please don't hesitate to contact us.</p>\r\n    </div>\r\n</body>\r\n</html>\r\n"; ;

                await _emailService.SendEmailAsync(request.Email, subject, htmlBody);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "An error occurred while sending the confirmation email. Please try again later.");
            }
            // Return a response indicating success
            return Ok(newUser);
        }

        //Login
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login(Login request)
        {
            try
            {
                // Sanity Check
                if (request.Email == null || request.Password == null)
                {
                    return Unauthorized(new { message = "Please Enter Email and Password!" });
                }
                
                // Retrieve the user from the database based on the provided username
                var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
                
                // Check users existence in db
                if (user == null)
                {
                    return Unauthorized(new { message = "Invalid username or password." });
                }
                
                // Verify the password using the user's salt
                if (!FunctionManager.HelperFunctionsInstance.VerifyPasswordHash(
                    request.Password, user.PasswordHash, user.PasswordSalt))
                {
                    return Unauthorized(new { message = "Invalid password entered." });
                }
                
                // Creating claims
                List<Claim> claims = new List<Claim>
                {
                    new Claim("id", user.Id.ToString())
                };
                
                // Creating token
                var ServerSecretKey = _configuration["JWT:ServerSecret"];
                var Issuer = _configuration["JWT:Issuer"];
                var Audience = _configuration["JWT:Audience"];

                // Check if any of the configuration values is null
                if (ServerSecretKey == null || Issuer == null || Audience == null)
                {
                    return BadRequest("JWT App settings are missing or invalid");
                }
                var token = FunctionManager.HelperFunctionsInstance.GenerateToken(
                    user, ServerSecretKey, Issuer, Audience, claims);

                // Return a successful response with the token
                return Ok(new { token });
            }
            catch (Exception ex)
            {
                // Log the exception for debugging purposes
                return StatusCode(500, new { message = ex });
            }
        }


        // Forget Password
        private static readonly ConcurrentDictionary<string, string>
            OtpPayloads = new ConcurrentDictionary<string, string>();
        [AllowAnonymous]
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(ForgotPassword request)
        {
            try
            {
                // Retrieve the user from the database based on the provided username
                var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
                // Check user existence in db
                if (user == null)
                {
                    return Unauthorized(new { message = "Provided Email doesn't exist in records" });
                }
                // Generate a random 6-digit otp token
                string token = FunctionManager.HelperFunctionsInstance.GeneratedOTP(user.Id);
                string encryptedToken = HelperFunctions.EncryptString(
                    token, _configuration["CryptoKey"]);

                // Store the OTP and user id in the dictionary
                OtpPayloads.TryAdd(user.Id.ToString(), token.ToString());

                // Send the email with the token to the user
                var subject = "Account Password Reset Notification";
                var htmlBody = $"<p>Please click on the password reset link: {encryptedToken}</p>";
                if (user.Email != null)
                {
                    //Send the email
                    await _emailService.SendEmailAsync(user.Email, subject, htmlBody);
                }
                return Ok($"OTP verification email has been sent successfully");
            }
            catch (Exception ex)
            {
                // Log the exception for debugging purposes
                return StatusCode(500, new { message = ex });
            }
        }


        // Reset Password 
        [AllowAnonymous]
        [HttpPost("reset-password")]
        public IActionResult ResetPasswordwithOTP(ResetPassword request)
        {
            try
            {
                // Sanity check
                if (request.Otp == null || request.NewPassword == null)
                {
                    return BadRequest(new { message = "Invalid OTP or password entered" });
                }
                // Check if the new password and confirm password match
                if (request.NewPassword != request.ConfirmPassword)
                {
                    return BadRequest(new { message = "New password and confirm password do not match" });
                }
                // Decryt fetched token
                string decryptedToken = HelperFunctions.EncryptString(
                    request.Otp.ToString(), _configuration["CryptoKey"]);

                // Extracting userId and OTP from the request
                string[] extracts = decryptedToken.Split('-');
                if (extracts.Length == 2)
                {
                    string extractedUserId = extracts[0].ToString();
                    string extractedOtp = extracts[1];

                    // Retrieve the stored OTP for the user
                    if (OtpPayloads.TryGetValue(extractedUserId.ToString(), out string? storedOtp))
                    {
                        if (storedOtp == extractedOtp)
                        {
                            // Retrieve the user from the database by user ID
                            var user = _dbContext.Users.FirstOrDefault(u => u.Id == extractedUserId);
                            if (user == null)
                            {
                                return BadRequest(new { message = "User not found" });
                            }
                            // Generate a random salt
                            byte[] passwordSalt = FunctionManager.HelperFunctionsInstance.GenerateSalt();
                            // Create password hash using the generated salt
                            FunctionManager.HelperFunctionsInstance.CreatePasswordHash(
                                request.NewPassword, passwordSalt, out byte[] passwordHash);

                            // Update the user's password salt and password hash in the database
                            user.PasswordSalt = passwordSalt;
                            user.PasswordHash = passwordHash;

                            // Save the changes to the database
                            _dbContext.SaveChanges();

                            // Sending Notification email for password reset
                            var subject = "Successful Account Password Reset Notification";
                            var htmlBody = "<p>Hi, Your password has been successfully changed, Login On!</p>";

                            _emailService.SendEmailAsync(user.Email, subject, htmlBody);
                            return Ok(new { message = "Password reset successful" });
                        }
                        else
                        {
                            return BadRequest(new { message = "Invalid OTP" });
                        }
                    }
                    else
                    {
                        return BadRequest(new { message = "Invalid OTP format" });
                    }
                }
                else
                {
                    return BadRequest(new { message = "Invalid OTP format" });
                }
            }
            catch (Exception ex)
            {
                // Log the exception for debugging purposes
                return StatusCode(500, new { message = ex });
            }
        }


        // Fetch active user profile info by ID
        [Authorize]
        [HttpGet("user/{Id}")]
        public async Task<ActionResult<UserDTO>> GetUserProfile(int Id)
        {
            // Check if the database context is null (this is unlikely to happen in practice)
            if (_dbContext == null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "Database context is not available.");
            }
            // Attempt to find the user by ID
            var user = await _dbContext.Users.FindAsync(Id);
            // Check if the user was not found
            if (user == null)
            {
                return NotFound("User not found.");
            }
            return Ok(user);
        }















    }
}
