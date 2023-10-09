using Microsoft.IdentityModel.Tokens;
using shortid.Configuration;
using shortid;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace DotNetCore6DemoProject.Models.Auth.HelperFunctions
{
    public class FunctionManager
    {
        // Static field to hold the global instance of HelperFunctions
        public static HelperFunctions HelperFunctionsInstance { get; } = new HelperFunctions();
    }

    public class HelperFunctions
    {
        // Short Id Config with specified length 
        public string GenratedShortIDs(int userIdLength)
        {
            var shortIdConfig = new GenerationOptions(
                useNumbers: true, useSpecialCharacters: false, length: userIdLength);

            int minimumLength = userIdLength;
            string generatedShortId;
            do
            {
                generatedShortId = ShortId.Generate(shortIdConfig);
            } while (generatedShortId.Length < minimumLength);

            return generatedShortId;
        }


        // Password hashing is the process of taking a user's password and converting it into a
        public void CreatePasswordHash(string password, byte[] salt, out byte[] passwordHash)
        {
            using (var hmac = new HMACSHA512(salt))
            {
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }

        // A salt is a random value that is generated for each user when they create an account or change their password.
        // This salt is then combined with the user's password before hashing.
        // The purpose of the salt is to add randomness and uniqueness to the hashing process.
        // It ensures that even if two users have the same password, their hashes will be different due to the unique salt.
        public bool VerifyPasswordHash(string password, byte[] storedHash, byte[] salt)
        {
            using (var hmac = new HMACSHA512(salt))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(storedHash);
            }
        }


        //Generating random salts
        public byte[] GenerateSalt()
        {
            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }


        // Generate a 6-digit Token
        public string GeneratedOTP(string userId)
        {
            Random random = new Random();
            int otp = random.Next(100000, 999999);
            var token = $"{userId}-{otp}";
            return token;
        }


        // Generate JWT Token with claims
        public string GenerateToken(UserDTO user, string ServerSecretKey, string Issuer, 
            string Audience, List<Claim> claims)
        {
            // Get the JWT server secret from configuration
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(ServerSecretKey));
            var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha512);
            var token = new JwtSecurityToken(
                Issuer,
                Audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(5),
                signingCredentials: credentials
                );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        // Encrypting a string token
        public static string EncryptString(string text, string keyString)
        {
            var key = Encoding.UTF8.GetBytes(keyString);

            using (var aesAlg = Aes.Create())
            {
                using (var encryptor = aesAlg.CreateEncryptor(key, aesAlg.IV))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(text);
                        }

                        var iv = aesAlg.IV;

                        var decryptedContent = msEncrypt.ToArray();

                        var result = new byte[iv.Length + decryptedContent.Length];

                        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                        Buffer.BlockCopy(decryptedContent, 0, result, iv.Length, decryptedContent.Length);

                        return Convert.ToBase64String(result);
                    }
                }
            }
        }

        // Derypting a string token
        public static string DecryptString(string cipherText, string keyString)
        {
            var fullCipher = Convert.FromBase64String(cipherText);

            var iv = new byte[16];
            var cipher = new byte[16];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, iv.Length);
            var key = Encoding.UTF8.GetBytes(keyString);

            using (var aesAlg = Aes.Create())
            {
                using (var decryptor = aesAlg.CreateDecryptor(key, iv))
                {
                    string result;
                    using (var msDecrypt = new MemoryStream(cipher))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(csDecrypt))
                            {
                                result = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                    return result;
                }
            }
        }
    }
}
