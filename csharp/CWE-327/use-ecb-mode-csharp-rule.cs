using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace CryptographyExamples
{
    public class EncryptionExamples : Controller
    {
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public void bad_case_1()
        {
            string plainText = "Sensitive data to be encrypted";
            string key = "ABCDEFGHIJKLMNOP";
            
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(key);
                // ruleid: use-ecb-mode-csharp-rule
                aesAlg.Mode = CipherMode.ECB;
                
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public void bad_case_2()
        {
            byte[] key = new byte[16];
            Random random = new Random();
            random.NextBytes(key);
            
            SymmetricAlgorithm algorithm = SymmetricAlgorithm.Create("AES");
            // ruleid: use-ecb-mode-csharp-rule
            algorithm.Mode = CipherMode.ECB;
            algorithm.Key = key;
            
            byte[] encrypted = EncryptData("Secret message", algorithm);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        
        public void bad_case_3()
        {
            using (var rijndael = new RijndaelManaged())
            {
                rijndael.Key = Encoding.UTF8.GetBytes("0123456789ABCDEF");
                // ruleid: use-ecb-mode-csharp-rule
                rijndael.Mode = CipherMode.ECB;
                rijndael.Padding = PaddingMode.PKCS7;
                
                ICryptoTransform encryptor = rijndael.CreateEncryptor();
                byte[] encrypted = encryptor.TransformFinalBlock(Encoding.UTF8.GetBytes("Confidential data"), 0, 16);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        
        [HttpPost]
        public IActionResult bad_case_4([FromBody] string userData)
        {
            byte[] keyBytes = new byte[32];
            new RNGCryptoServiceProvider().GetBytes(keyBytes);
            
            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                // ruleid: use-ecb-mode-csharp-rule
                aes.Mode = CipherMode.ECB;
                
                var encryptor = aes.CreateEncryptor();
                byte[] encryptedData = encryptor.TransformFinalBlock(
                    Encoding.UTF8.GetBytes(userData), 0, userData.Length);
                
                return Ok(Convert.ToBase64String(encryptedData));
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        
        public void bad_case_5()
        {
            var cipher = CipherMode.ECB;
            using (var aes = new AesManaged())
            {
                // ruleid: use-ecb-mode-csharp-rule
                aes.Mode = cipher;
                aes.Key = GenerateRandomKey(32);
                aes.Padding = PaddingMode.PKCS7;
                
                // Encrypt some data
                var encryptor = aes.CreateEncryptor();
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        
        [HttpGet]
        public async Task<IActionResult> bad_case_6()
        {
            string apiKey = Request.Headers["X-API-Key"];
            
            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(apiKey.PadRight(32).Substring(0, 32));
                // ruleid: use-ecb-mode-csharp-rule
                aes.Mode = CipherMode.ECB;
                
                // Use the encryption for API authentication
                var encryptor = aes.CreateEncryptor();
            }
            
            return Ok("Authenticated");
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        
        public void bad_case_7()
        {
            const CipherMode insecureMode = CipherMode.ECB;
            
            using (var des = DES.Create())
            {
                des.Key = Encoding.UTF8.GetBytes("12345678");
                // ruleid: use-ecb-mode-csharp-rule
                des.Mode = insecureMode;
                
                // Encrypt data with DES in ECB mode
                var encryptor = des.CreateEncryptor();
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        
        public byte[] bad_case_8(byte[] data, byte[] key)
        {
            using (TripleDES tdes = TripleDES.Create())
            {
                tdes.Key = key;
                // ruleid: use-ecb-mode-csharp-rule
                tdes.Mode = CipherMode.ECB;
                
                ICryptoTransform encryptor = tdes.CreateEncryptor();
                return encryptor.TransformFinalBlock(data, 0, data.Length);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        
        [HttpPost("encrypt")]
        public IActionResult bad_case_9([FromForm] string plaintext)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = GetEncryptionKey();
                // ruleid: use-ecb-mode-csharp-rule
                aes.Mode = CipherMode.ECB;
                
                var encryptor = aes.CreateEncryptor();
                byte[] encrypted = encryptor.TransformFinalBlock(
                    Encoding.UTF8.GetBytes(plaintext), 0, plaintext.Length);
                
                return Ok(Convert.ToBase64String(encrypted));
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        
        public void bad_case_10()
        {
            var modes = new[] { CipherMode.CBC, CipherMode.ECB, CipherMode.CFB };
            int modeIndex = 1; // This will select ECB
            
            using (var aes = Aes.Create())
            {
                // ruleid: use-ecb-mode-csharp-rule
                aes.Mode = modes[modeIndex];
                aes.Key = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
                
                // Use the encryption
                var encryptor = aes.CreateEncryptor();
            }
        }
// {/fact}
        
        public class EncryptionService
        {
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
            public void bad_case_11()
            {
                string configuredMode = "ECB"; // Coming from a config file
                
                using (var aes = Aes.Create())
                {
                    if (configuredMode == "ECB")
                    {
                        // ruleid: use-ecb-mode-csharp-rule
                        aes.Mode = CipherMode.ECB;
                    }
                    else if (configuredMode == "CBC")
                    {
                        aes.Mode = CipherMode.CBC;
                    }
                    
                    aes.Key = GenerateRandomKey(16);
                    var encryptor = aes.CreateEncryptor();
                }
            }
// {/fact}
        }
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        
        [HttpGet("user/{id}")]
        public IActionResult bad_case_12(string id)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes("ThisIsA32ByteKeyForAES12345678901");
                // ruleid: use-ecb-mode-csharp-rule
                aes.Mode = CipherMode.ECB;
                
                // Encrypt the user ID before storing it
                var encryptor = aes.CreateEncryptor();
                byte[] encryptedId = encryptor.TransformFinalBlock(
                    Encoding.UTF8.GetBytes(id), 0, id.Length);
                
                // Store the encrypted ID
                StoreEncryptedData(encryptedId);
                
                return Ok();
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        
        public void bad_case_13()
        {
            CipherMode mode = (CipherMode)Enum.Parse(typeof(CipherMode), "ECB");
            
            using (var aes = Aes.Create())
            {
                // ruleid: use-ecb-mode-csharp-rule
                aes.Mode = mode;
                aes.Key = GenerateRandomKey(16);
                
                // Use the encryption
                var encryptor = aes.CreateEncryptor();
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        
        public void bad_case_14()
        {
            // Creating a custom encryption wrapper that uses ECB mode
            var encryptionSettings = new EncryptionSettings
            {
                Algorithm = "AES",
                KeySize = 256,
                Mode = CipherMode.ECB // This will be used later
            };
            
            using (var aes = Aes.Create())
            {
                // ruleid: use-ecb-mode-csharp-rule
                aes.Mode = encryptionSettings.Mode;
                aes.Key = GenerateRandomKey(32);
                
                // Use the encryption
                var encryptor = aes.CreateEncryptor();
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        
        public void bad_case_15()
        {
            bool useStrongSecurity = false; // Set to false for backward compatibility
            
            using (var aes = Aes.Create())
            {
                if (useStrongSecurity)
                {
                    aes.Mode = CipherMode.CBC;
                    aes.IV = GenerateRandomKey(16);
                }
                else
                {
                    // ruleid: use-ecb-mode-csharp-rule
                    aes.Mode = CipherMode.ECB;
                }
                
                aes.Key = GenerateRandomKey(16);
                var encryptor = aes.CreateEncryptor();
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
        
        // True Negative Examples (Secure Code)
        
        public void good_case_1()
        {
            string plainText = "Sensitive data to be encrypted";
            string key = "ABCDEFGHIJKLMNOP";
            
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(key);
                // ok: use-ecb-mode-csharp-rule
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.IV = new byte[16]; // In a real scenario, use a random IV
                
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
        
        public void good_case_2()
        {
            byte[] key = new byte[16];
            Random random = new Random();
            random.NextBytes(key);
            
            SymmetricAlgorithm algorithm = SymmetricAlgorithm.Create("AES");
            // ok: use-ecb-mode-csharp-rule
            algorithm.Mode = CipherMode.CBC;
            algorithm.Key = key;
            algorithm.IV = GenerateRandomKey(16);
            
            byte[] encrypted = EncryptData("Secret message", algorithm);
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
        
        public void good_case_3()
        {
            using (var rijndael = new RijndaelManaged())
            {
                rijndael.Key = Encoding.UTF8.GetBytes("0123456789ABCDEF");
                // ok: use-ecb-mode-csharp-rule
                rijndael.Mode = CipherMode.CFB;
                rijndael.IV = GenerateRandomKey(16);
                rijndael.Padding = PaddingMode.PKCS7;
                
                ICryptoTransform encryptor = rijndael.CreateEncryptor();
                byte[] encrypted = encryptor.TransformFinalBlock(Encoding.UTF8.GetBytes("Confidential data"), 0, 16);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
        
        [HttpPost]
        public IActionResult good_case_4([FromBody] string userData)
        {
            byte[] keyBytes = new byte[32];
            new RNGCryptoServiceProvider().GetBytes(keyBytes);
            
            byte[] ivBytes = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(ivBytes);
            
            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                // ok: use-ecb-mode-csharp-rule
                aes.Mode = CipherMode.CBC;
                aes.IV = ivBytes;
                
                var encryptor = aes.CreateEncryptor();
                byte[] encryptedData = encryptor.TransformFinalBlock(
                    Encoding.UTF8.GetBytes(userData), 0, userData.Length);
                
                // Combine IV and encrypted data for storage/transmission
                byte[] result = new byte[ivBytes.Length + encryptedData.Length];
                Buffer.BlockCopy(ivBytes, 0, result, 0, ivBytes.Length);
                Buffer.BlockCopy(encryptedData, 0, result, ivBytes.Length, encryptedData.Length);
                
                return Ok(Convert.ToBase64String(result));
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
        
        public void good_case_5()
        {
            var cipher = CipherMode.CBC;
            using (var aes = new AesManaged())
            {
                // ok: use-ecb-mode-csharp-rule
                aes.Mode = cipher;
                aes.Key = GenerateRandomKey(32);
                aes.IV = GenerateRandomKey(16);
                aes.Padding = PaddingMode.PKCS7;
                
                // Encrypt some data
                var encryptor = aes.CreateEncryptor();
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
        
        [HttpGet]
        public async Task<IActionResult> good_case_6()
        {
            string apiKey = Request.Headers["X-API-Key"];
            
            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(apiKey.PadRight(32).Substring(0, 32));
                // ok: use-ecb-mode-csharp-rule
                aes.Mode = CipherMode.GCM;
                aes.IV = GenerateRandomKey(12); // GCM typically uses 12 bytes for IV
                
                // Use the encryption for API authentication
                var encryptor = aes.CreateEncryptor();
            }
            
            return Ok("Authenticated");
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
        
        public void good_case_7()
        {
            const CipherMode secureMode = CipherMode.CBC;
            
            using (var des = DES.Create())
            {
                des.Key = Encoding.UTF8.GetBytes("12345678");
                // ok: use-ecb-mode-csharp-rule
                des.Mode = secureMode;
                des.IV = GenerateRandomKey(8); // DES uses 8-byte IV
                
                // Encrypt data with DES in CBC mode
                var encryptor = des.CreateEncryptor();
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
        
        public byte[] good_case_8(byte[] data, byte[] key)
        {
            using (TripleDES tdes = TripleDES.Create())
            {
                tdes.Key = key;
                // ok: use-ecb-mode-csharp-rule
                tdes.Mode = CipherMode.CBC;
                tdes.IV = GenerateRandomKey(8); // TripleDES uses 8-byte IV
                
                ICryptoTransform encryptor = tdes.CreateEncryptor();
                return encryptor.TransformFinalBlock(data, 0, data.Length);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
        
        [HttpPost("encrypt")]
        public IActionResult good_case_9([FromForm] string plaintext)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = GetEncryptionKey();
                // ok: use-ecb-mode-csharp-rule
                aes.Mode = CipherMode.CBC;
                aes.GenerateIV(); // Automatically generate a random IV
                
                var encryptor = aes.CreateEncryptor();
                byte[] encrypted = encryptor.TransformFinalBlock(
                    Encoding.UTF8.GetBytes(plaintext), 0, plaintext.Length);
                
                // Combine IV and encrypted data
                byte[] result = new byte[aes.IV.Length + encrypted.Length];
                Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
                Buffer.BlockCopy(encrypted, 0, result, aes.IV.Length, encrypted.Length);
                
                return Ok(Convert.ToBase64String(result));
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
        
        public void good_case_10()
        {
            var modes = new[] { CipherMode.CBC, CipherMode.CFB, CipherMode.OFB };
            int modeIndex = 0; // This will select CBC
            
            using (var aes = Aes.Create())
            {
                // ok: use-ecb-mode-csharp-rule
                aes.Mode = modes[modeIndex];
                aes.Key = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
                aes.IV = GenerateRandomKey(16);
                
                // Use the encryption
                var encryptor = aes.CreateEncryptor();
            }
        }
// {/fact}
        
        public class SecureEncryptionService
        {
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
            public void good_case_11()
            {
                string configuredMode = "CBC"; // Coming from a config file
                
                using (var aes = Aes.Create())
                {
                    if (configuredMode == "CBC")
                    {
                        // ok: use-ecb-mode-csharp-rule
                        aes.Mode = CipherMode.CBC;
                    }
                    else if (configuredMode == "CFB")
                    {
                        aes.Mode = CipherMode.CFB;
                    }
                    else
                    {
                        // Default to CBC if unknown
                        aes.Mode = CipherMode.CBC;
                    }
                    
                    aes.Key = GenerateRandomKey(16);
                    aes.IV = GenerateRandomKey(16);
                    var encryptor = aes.CreateEncryptor();
                }
            }
// {/fact}
        }
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
        
        [HttpGet("user/{id}")]
        public IActionResult good_case_12(string id)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes("ThisIsA32ByteKeyForAES12345678901");
                // ok: use-ecb-mode-csharp-rule
                aes.Mode = CipherMode.CBC;
                aes.GenerateIV();
                
                // Encrypt the user ID before storing it
                var encryptor = aes.CreateEncryptor();
                byte[] encryptedId = encryptor.TransformFinalBlock(
                    Encoding.UTF8.GetBytes(id), 0, id.Length);
                
                // Store both IV and encrypted ID
                byte[] dataToStore = new byte[aes.IV.Length + encryptedId.Length];
                Buffer.BlockCopy(aes.IV, 0, dataToStore, 0, aes.IV.Length);
                Buffer.BlockCopy(encryptedId, 0, dataToStore, aes.IV.Length, encryptedId.Length);
                
                // Store the encrypted ID with IV
                StoreEncryptedData(dataToStore);
                
                return Ok();
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
        
        public void good_case_13()
        {
            CipherMode mode = (CipherMode)Enum.Parse(typeof(CipherMode), "CBC");
            
            using (var aes = Aes.Create())
            {
                // ok: use-ecb-mode-csharp-rule
                aes.Mode = mode;
                aes.Key = GenerateRandomKey(16);
                aes.IV = GenerateRandomKey(16);
                
                // Use the encryption
                var encryptor = aes.CreateEncryptor();
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
        
        public void good_case_14()
        {
            // Using authenticated encryption with GCM mode
            using (var aes = Aes.Create())
            {
                // ok: use-ecb-mode-csharp-rule
                aes.Mode = CipherMode.GCM;
                aes.Key = GenerateRandomKey(32);
                aes.IV = GenerateRandomKey(12); // GCM typically uses 12 bytes
                
                // Use the authenticated encryption
                var encryptor = aes.CreateEncryptor();
                
                // In a real implementation, you would also handle the authentication tag
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
        
        public void good_case_15()
        {
            // Using a modern encryption approach with authenticated encryption
            byte[] key = GenerateRandomKey(32);
            byte[] nonce = GenerateRandomKey(12);
            byte[] associatedData = Encoding.UTF8.GetBytes("Additional authenticated data");
            
            // ok: use-ecb-mode-csharp-rule
            // Using AES-GCM which is an authenticated encryption mode
            using (var aesGcm = new AesGcm(key))
            {
                byte[] plaintext = Encoding.UTF8.GetBytes("Secret message");
                byte[] ciphertext = new byte[plaintext.Length];
                byte[] tag = new byte[16]; // Authentication tag
                
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
                
                // Now ciphertext contains the encrypted data and tag contains the authentication tag
            }
        }
// {/fact}
        
        // Helper methods
        private byte[] EncryptData(string data, SymmetricAlgorithm algorithm)
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            ICryptoTransform encryptor = algorithm.CreateEncryptor();
            return encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
        }
        
        private byte[] GenerateRandomKey(int size)
        {
            byte[] key = new byte[size];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
            }
            return key;
        }
        
        private byte[] GetEncryptionKey()
        {
            // In a real scenario, this would retrieve a key from a secure key store
            return new byte[32] {
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
            };
        }
        
        private void StoreEncryptedData(byte[] data)
        {
            // In a real scenario, this would store the data in a database or file
            // Implementation omitted for brevity
        }
    }
    
    public class EncryptionSettings
    {
        public string Algorithm { get; set; }
        public int KeySize { get; set; }
        public CipherMode Mode { get; set; }
    }
}