namespace SecureStorage
{
    using NBitcoin;
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Security.Cryptography;
    using System.Threading;

    public static class Cryptography
    {
        // Thread-local AES instance (one per thread)
        // Lazily initialized when first used by each thread
        private static readonly ThreadLocal<Aes> _aes = new ThreadLocal<Aes>(() =>
        {
            var aes = Aes.Create();          // Create new AES instance
            aes.KeySize = 256;               // Set 256-bit key size (AES-256)
            aes.Mode = CipherMode.CBC;       // Use Cipher Block Chaining mode
            aes.Padding = PaddingMode.PKCS7; // Use PKCS7 padding
            return aes;
        });

        /// <summary>
        /// Encrypts data using AES-256-CBC with the provided key
        /// </summary>
        /// <param name="clearBytes">Data to encrypt</param>
        /// <param name="password">32-byte encryption key</param>
        /// <returns>Encrypted data with IV prepended</returns>
        public static byte[] Encrypt(byte[] clearBytes, byte[] password)
        {
            // Get thread-specific AES instance
            var aes = _aes.Value;
            aes.Key = password;            // Set encryption key
            aes.GenerateIV();               // Generate random Initialization Vector

            using (var encryptor = aes.CreateEncryptor())  // Create encryptor
            using (var ms = new MemoryStream())           // Output stream
            {
                // Write IV at the beginning of the stream
                ms.Write(aes.IV, 0, aes.IV.Length);

                // Encrypt data and write to stream
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(clearBytes, 0, clearBytes.Length);
                }
                return ms.ToArray();  // Return IV + encrypted data
            }
        }

        /// <summary>
        /// Decrypts data encrypted with Encrypt() method
        /// </summary>
        /// <param name="cipherBytes">Encrypted data (IV + ciphertext)</param>
        /// <param name="password">32-byte decryption key</param>
        /// <returns>Decrypted data or null if decryption fails</returns>
        public static byte[] Decrypt(byte[] cipherBytes, byte[] password)
        {
            try
            {
                // Get thread-specific AES instance
                var aes = _aes.Value;
                aes.Key = password;  // Set decryption key

                // Extract IV from first 16 bytes
                var iv = new byte[16];
                Array.Copy(cipherBytes, 0, iv, 0, iv.Length);
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor())  // Create decryptor
                using (var ms = new MemoryStream())           // Output stream
                {
                    // Decrypt data and write to stream
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                    {
                        // Skip IV (first 16 bytes) when decrypting
                        cs.Write(cipherBytes, iv.Length, cipherBytes.Length - iv.Length);
                    }
                    return ms.ToArray();  // Return decrypted data
                }
            }
            catch (Exception ex)
            {
                try
                {
                    // Fallback to legacy decryption (backward compatibility)
                    var privateKey = new Key(password, fCompressedIn: false);
                    return privateKey.Decrypt(cipherBytes);
                }
                catch (Exception)
                {
                    // All decryption attempts failed
                    return null;
                }
            }
        }
    }
}