using System.Reflection.Metadata.Ecma335;
using System.Security.Cryptography;

namespace AngularAuthAPI.Helpers
{
    public class PasswordHasher
    {
        private static int SaltSize = 16; // Size of the salt in bytes
        private static int HashSize = 32; // Size of the hash in bytes
        private static int Iterations = 100000; // Number of iterations for the PBKDF2 algorithm

        private static readonly HashAlgorithmName Algorithm = HashAlgorithmName.SHA512; // Hash algorithm to use

        public static string HashPassword(string password)
        {
           byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
                password: password,
                salt: salt,
                iterations: Iterations,
                hashAlgorithm: Algorithm,
                outputLength: HashSize);

            return $"{Convert.ToHexString(hash)}-{Convert.ToHexString(salt)}";
        }

        public static bool VerifyPassword(string password, string hashedPassword)
        {
            // Split the hashed password into hash and salt
            var parts = hashedPassword.Split('-');
            if (parts.Length != 2)
            {
                throw new ArgumentException("Invalid hashed password format.");
            }
            byte[] hash = Convert.FromHexString(parts[0]);
            byte[] salt = Convert.FromHexString(parts[1]);
            // Hash the provided password with the same salt
            byte[] computedHash = Rfc2898DeriveBytes.Pbkdf2(
                password: password,
                salt: salt,
                iterations: Iterations,
                hashAlgorithm: Algorithm,
                outputLength: HashSize);
            // Compare the computed hash with the stored hash, we are using this method bcz it avoid malicious attacks
            return CryptographicOperations.FixedTimeEquals(computedHash, hash);
        }
    }
}
