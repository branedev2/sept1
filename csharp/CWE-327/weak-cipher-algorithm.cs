using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace WeakCipherAlgorithmExamples
{
    public class CryptographyExamples
    {
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public void bad_case_1()
        {
            // Using DES algorithm which is considered insecure
            byte[] key = new byte[8]; // 64-bit key for DES
            byte[] iv = new byte[8];
            string plainText = "Sensitive data to encrypt";
            byte[] encrypted;

            using (var des = new DESCryptoServiceProvider())
            {
                // ruleid: weak-cipher-algorithm
                des.Key = key;
                des.IV = iv;
                
                using (var encryptor = des.CreateEncryptor())
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }
                    encrypted = ms.ToArray();
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public void bad_case_2()
        {
            // Using TripleDES algorithm which is considered insecure
            byte[] key = new byte[24]; // 192-bit key for TripleDES
            byte[] iv = new byte[8];
            byte[] data = Encoding.UTF8.GetBytes("Sensitive data to encrypt");

            // ruleid: weak-cipher-algorithm
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Key = key;
                tdes.IV = iv;
                tdes.Mode = CipherMode.CBC;

                using (ICryptoTransform encryptor = tdes.CreateEncryptor())
                {
                    byte[] encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);
                    Console.WriteLine(Convert.ToBase64String(encrypted));
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public void bad_case_3()
        {
            // Using RC2 algorithm which is considered insecure
            byte[] key = new byte[16]; // 128-bit key for RC2
            byte[] iv = new byte[8];
            string plainText = "Sensitive data to encrypt";

            // ruleid: weak-cipher-algorithm
            using (RC2CryptoServiceProvider rc2 = new RC2CryptoServiceProvider())
            {
                rc2.Key = key;
                rc2.IV = iv;

                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, rc2.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    cs.Write(plainBytes, 0, plainBytes.Length);
                    cs.FlushFinalBlock();
                    byte[] encryptedData = ms.ToArray();
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public void bad_case_4()
        {
            // Creating a DES algorithm instance directly
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Sensitive information");
            byte[] key = new byte[8];
            byte[] iv = new byte[8];
            
            // ruleid: weak-cipher-algorithm
            DES des = DES.Create();
            des.Key = key;
            des.IV = iv;
            
            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                cs.FlushFinalBlock();
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public void bad_case_5()
        {
            // Using TripleDES with a factory method
            byte[] key = new byte[24];
            byte[] iv = new byte[8];
            byte[] data = Encoding.UTF8.GetBytes("Secret message");
            
            // ruleid: weak-cipher-algorithm
            using (SymmetricAlgorithm algorithm = TripleDES.Create())
            {
                algorithm.Key = key;
                algorithm.IV = iv;
                
                using (ICryptoTransform encryptor = algorithm.CreateEncryptor())
                {
                    byte[] encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);
                    Console.WriteLine(Convert.ToBase64String(encryptedData));
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public void bad_case_6()
        {
            // Using RC2 with a specific key size
            byte[] key = new byte[16];
            byte[] iv = new byte[8];
            string plainText = "Confidential data";
            
            // ruleid: weak-cipher-algorithm
            using (RC2 rc2 = RC2.Create())
            {
                rc2.KeySize = 128;
                rc2.Key = key;
                rc2.IV = iv;
                
                using (ICryptoTransform encryptor = rc2.CreateEncryptor())
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    byte[] cipherText = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public void bad_case_7()
        {
            // Using DES for password hashing (very bad practice)
            string password = "UserPassword123";
            byte[] salt = new byte[8];
            
            // ruleid: weak-cipher-algorithm
            using (DES des = DES.Create())
            {
                des.Key = Encoding.UTF8.GetBytes("12345678"); // Fixed key
                des.IV = salt;
                
                using (ICryptoTransform encryptor = des.CreateEncryptor())
                {
                    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                    byte[] hashedPassword = encryptor.TransformFinalBlock(passwordBytes, 0, passwordBytes.Length);
                    string base64Hash = Convert.ToBase64String(hashedPassword);
                    Console.WriteLine($"Hashed password: {base64Hash}");
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public void bad_case_8()
        {
            // Using TripleDES in ECB mode (doubly insecure)
            byte[] key = new byte[24];
            string plainText = "Secret information";
            
            // ruleid: weak-cipher-algorithm
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Key = key;
                tdes.Mode = CipherMode.ECB; // Even worse - ECB mode
                tdes.Padding = PaddingMode.PKCS7;
                
                using (ICryptoTransform encryptor = tdes.CreateEncryptor())
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    byte[] cipherText = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public void bad_case_9()
        {
            // Using RC2 with a custom implementation
            byte[] key = new byte[16];
            byte[] iv = new byte[8];
            byte[] data = Encoding.UTF8.GetBytes("Sensitive data");
            
            // ruleid: weak-cipher-algorithm
            using (RC2CryptoServiceProvider rc2 = new RC2CryptoServiceProvider())
            {
                rc2.Key = key;
                rc2.IV = iv;
                rc2.Mode = CipherMode.CBC;
                rc2.Padding = PaddingMode.PKCS7;
                
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, rc2.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                    }
                    byte[] encrypted = ms.ToArray();
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public void bad_case_10()
        {
            // Using DES for file encryption
            string inputFile = "sensitive.txt";
            string outputFile = "encrypted.bin";
            byte[] key = new byte[8];
            byte[] iv = new byte[8];
            
            // ruleid: weak-cipher-algorithm
            using (DES des = DES.Create())
            {
                des.Key = key;
                des.IV = iv;
                
                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                using (CryptoStream cs = new CryptoStream(fsOutput, des.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        cs.Write(buffer, 0, bytesRead);
                    }
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public void bad_case_11()
        {
            // Using TripleDES for encrypting configuration data
            string configData = "database=localhost;user=admin;password=secret";
            byte[] key = new byte[24];
            byte[] iv = new byte[8];
            
            // ruleid: weak-cipher-algorithm
            using (TripleDES tdes = TripleDES.Create())
            {
                tdes.Key = key;
                tdes.IV = iv;
                
                byte[] dataBytes = Encoding.UTF8.GetBytes(configData);
                byte[] encryptedConfig;
                
                using (ICryptoTransform encryptor = tdes.CreateEncryptor())
                {
                    encryptedConfig = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
                }
                
                File.WriteAllBytes("config.enc", encryptedConfig);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public void bad_case_12()
        {
            // Using RC2 in a custom encryption method
            string secretMessage = "This is a confidential message";
            byte[] key = Encoding.UTF8.GetBytes("MySecretKey12345");
            byte[] iv = new byte[8];
            
            // ruleid: weak-cipher-algorithm
            using (RC2 rc2 = RC2.Create())
            {
                rc2.Key = key;
                rc2.IV = iv;
                
                byte[] messageBytes = Encoding.UTF8.GetBytes(secretMessage);
                byte[] encryptedMessage;
                
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, rc2.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(messageBytes, 0, messageBytes.Length);
                    cs.FlushFinalBlock();
                    encryptedMessage = ms.ToArray();
                }
                
                Console.WriteLine(Convert.ToBase64String(encryptedMessage));
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public void bad_case_13()
        {
            // Using DES in a more complex scenario with key derivation
            string password = "user_password";
            string salt = "salt_value";
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            
            // Derive key from password (still using DES which is weak)
            byte[] key = new byte[8]; // DES key size
            Array.Copy(passwordBytes, key, Math.Min(passwordBytes.Length, key.Length));
            
            string dataToEncrypt = "Sensitive customer information";
            
            // ruleid: weak-cipher-algorithm
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Key = key;
                des.IV = saltBytes.Length >= 8 ? saltBytes.AsSpan(0, 8).ToArray() : new byte[8];
                
                byte[] dataBytes = Encoding.UTF8.GetBytes(dataToEncrypt);
                byte[] encryptedData;
                
                using (ICryptoTransform encryptor = des.CreateEncryptor())
                {
                    encryptedData = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
                }
                
                string encryptedBase64 = Convert.ToBase64String(encryptedData);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public void bad_case_14()
        {
            // Using TripleDES with hardcoded key
            byte[] key = Encoding.UTF8.GetBytes("ThisIsA24ByteTripleDESKey!!");
            byte[] iv = new byte[8];
            string sensitiveData = "Credit card: 4111-1111-1111-1111";
            
            // ruleid: weak-cipher-algorithm
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Key = key;
                tdes.IV = iv;
                tdes.Mode = CipherMode.CBC;
                
                byte[] dataBytes = Encoding.UTF8.GetBytes(sensitiveData);
                byte[] encryptedData;
                
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, tdes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(dataBytes, 0, dataBytes.Length);
                    cs.FlushFinalBlock();
                    encryptedData = ms.ToArray();
                }
                
                // Store encrypted data
                File.WriteAllBytes("encrypted_card.dat", encryptedData);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public void bad_case_15()
        {
            // Using RC2 for API key encryption
            string apiKey = "api_12345_secret_key";
            byte[] key = new byte[16];
            byte[] iv = new byte[8];
            new Random().NextBytes(key); // Random key
            new Random().NextBytes(iv);  // Random IV
            
            // ruleid: weak-cipher-algorithm
            using (RC2CryptoServiceProvider rc2 = new RC2CryptoServiceProvider())
            {
                rc2.Key = key;
                rc2.IV = iv;
                
                byte[] apiKeyBytes = Encoding.UTF8.GetBytes(apiKey);
                byte[] encryptedApiKey;
                
                using (ICryptoTransform encryptor = rc2.CreateEncryptor())
                {
                    encryptedApiKey = encryptor.TransformFinalBlock(apiKeyBytes, 0, apiKeyBytes.Length);
                }
                
                // Store encrypted API key and IV
                string encryptedKeyBase64 = Convert.ToBase64String(encryptedApiKey);
                string ivBase64 = Convert.ToBase64String(iv);
                
                Console.WriteLine($"Encrypted API Key: {encryptedKeyBase64}");
                Console.WriteLine($"IV: {ivBase64}");
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        public void good_case_1()
        {
            // Using AES-256 which is considered secure
            byte[] key = new byte[32]; // 256-bit key for AES
            byte[] iv = new byte[16];  // 128-bit IV for AES
            string plainText = "Sensitive data to encrypt";
            
            // ok: weak-cipher-algorithm
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }
                    byte[] encrypted = ms.ToArray();
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public void good_case_2()
        {
            // Using AES with GCM mode (requires .NET 6.0+)
            byte[] key = new byte[32]; // 256-bit key
            byte[] nonce = new byte[12]; // 96-bit nonce for GCM
            byte[] data = Encoding.UTF8.GetBytes("Sensitive data to encrypt");
            byte[] associatedData = Encoding.UTF8.GetBytes("Additional authenticated data");
            
            // ok: weak-cipher-algorithm
            using (AesGcm aesGcm = new AesGcm(key))
            {
                byte[] ciphertext = new byte[data.Length];
                byte[] tag = new byte[16]; // 128-bit authentication tag
                
                aesGcm.Encrypt(nonce, data, ciphertext, tag, associatedData);
                
                // Store or transmit ciphertext, tag, and nonce
                Console.WriteLine($"Ciphertext length: {ciphertext.Length}");
                Console.WriteLine($"Tag length: {tag.Length}");
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public void good_case_3()
        {
            // Using ChaCha20Poly1305 (requires .NET 6.0+)
            byte[] key = new byte[32]; // 256-bit key
            byte[] nonce = new byte[12]; // 96-bit nonce
            byte[] plaintext = Encoding.UTF8.GetBytes("Sensitive data to encrypt");
            byte[] associatedData = Encoding.UTF8.GetBytes("Header information");
            
            // ok: weak-cipher-algorithm
            using (ChaCha20Poly1305 chacha = new ChaCha20Poly1305(key))
            {
                byte[] ciphertext = new byte[plaintext.Length];
                byte[] tag = new byte[16]; // 128-bit authentication tag
                
                chacha.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
                
                // Store or transmit ciphertext, tag, and nonce
                Console.WriteLine($"Encrypted data length: {ciphertext.Length}");
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public void good_case_4()
        {
            // Using AES-256 in CBC mode with secure padding
            byte[] key = new byte[32]; // 256-bit key
            byte[] iv = new byte[16];  // 128-bit IV
            string plainText = "Sensitive data to encrypt";
            
            // ok: weak-cipher-algorithm
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    byte[] cipherText = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                    Console.WriteLine(Convert.ToBase64String(cipherText));
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public void good_case_5()
        {
            // Using AES for file encryption
            string inputFile = "sensitive.txt";
            string outputFile = "encrypted.bin";
            byte[] key = new byte[32]; // 256-bit key
            byte[] iv = new byte[16];  // 128-bit IV
            
            // ok: weak-cipher-algorithm
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                
                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                using (CryptoStream cs = new CryptoStream(fsOutput, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        cs.Write(buffer, 0, bytesRead);
                    }
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public void good_case_6()
        {
            // Using AES with a derived key from a password
            string password = "UserSecurePassword123!";
            byte[] salt = new byte[16];
            new Random().NextBytes(salt); // In practice, use a cryptographically secure random number generator
            
            // ok: weak-cipher-algorithm
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000))
            {
                byte[] key = pbkdf2.GetBytes(32); // 256-bit key
                byte[] iv = pbkdf2.GetBytes(16);  // 128-bit IV
                
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    
                    string plainText = "Sensitive data to encrypt";
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    
                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    {
                        byte[] cipherText = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                        Console.WriteLine(Convert.ToBase64String(cipherText));
                    }
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public void good_case_7()
        {
            // Using AES-GCM for authenticated encryption (requires .NET 6.0+)
            byte[] key = new byte[32]; // 256-bit key
            byte[] nonce = new byte[12]; // 96-bit nonce
            string plainText = "Sensitive data that needs integrity protection";
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherText = new byte[plainBytes.Length];
            byte[] tag = new byte[16]; // 128-bit authentication tag
            
            // ok: weak-cipher-algorithm
            using (AesGcm aesGcm = new AesGcm(key))
            {
                aesGcm.Encrypt(nonce, plainBytes, cipherText, tag);
                
                // Store or transmit cipherText, tag, and nonce
                Console.WriteLine($"Ciphertext: {Convert.ToBase64String(cipherText)}");
                Console.WriteLine($"Auth Tag: {Convert.ToBase64String(tag)}");
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public void good_case_8()
        {
            // Using modern encryption for API key protection
            string apiKey = "api_12345_secret_key";
            byte[] key = new byte[32]; // 256-bit key
            byte[] nonce = new byte[12]; // 96-bit nonce
            new Random().NextBytes(key);
            new Random().NextBytes(nonce);
            
            // ok: weak-cipher-algorithm
            using (ChaCha20Poly1305 chacha = new ChaCha20Poly1305(key))
            {
                byte[] apiKeyBytes = Encoding.UTF8.GetBytes(apiKey);
                byte[] ciphertext = new byte[apiKeyBytes.Length];
                byte[] tag = new byte[16];
                
                chacha.Encrypt(nonce, apiKeyBytes, ciphertext, tag);
                
                // Store encrypted API key, tag, and nonce
                string encryptedKeyBase64 = Convert.ToBase64String(ciphertext);
                string tagBase64 = Convert.ToBase64String(tag);
                string nonceBase64 = Convert.ToBase64String(nonce);
                
                Console.WriteLine($"Encrypted API Key: {encryptedKeyBase64}");
                Console.WriteLine($"Authentication Tag: {tagBase64}");
                Console.WriteLine($"Nonce: {nonceBase64}");
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public void good_case_9()
        {
            // Using AES for encrypting configuration data
            string configData = "database=localhost;user=admin;password=secret";
            byte[] key = new byte[32]; // 256-bit key
            byte[] iv = new byte[16];  // 128-bit IV
            
            // ok: weak-cipher-algorithm
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                
                byte[] dataBytes = Encoding.UTF8.GetBytes(configData);
                byte[] encryptedConfig;
                
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    encryptedConfig = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
                }
                
                File.WriteAllBytes("config.enc", encryptedConfig);
                File.WriteAllBytes("config.iv", iv); // Store IV separately
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public void good_case_10()
        {
            // Using AES with a key from a secure key management system
            byte[] key = GetKeyFromSecureStorage(); // Simulated secure key retrieval
            byte[] iv = new byte[16];
            new Random().NextBytes(iv);
            string sensitiveData = "Credit card: 4111-1111-1111-1111";
            
            // ok: weak-cipher-algorithm
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                
                byte[] dataBytes = Encoding.UTF8.GetBytes(sensitiveData);
                byte[] encryptedData;
                
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(dataBytes, 0, dataBytes.Length);
                    cs.FlushFinalBlock();
                    encryptedData = ms.ToArray();
                }
                
                // Store encrypted data and IV
                File.WriteAllBytes("encrypted_card.dat", encryptedData);
                File.WriteAllBytes("card.iv", iv);
            }
        }
// {/fact}
        
        private byte[] GetKeyFromSecureStorage()
        {
            // Simulated secure key retrieval
            // In a real application, this would retrieve a key from a secure key vault
            return new byte[32]; // Return a 256-bit key
        }
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public void good_case_11()
        {
            // Using AES with secure random key generation
            byte[] plaintext = Encoding.UTF8.GetBytes("Sensitive information to protect");
            byte[] ciphertext;
            byte[] key;
            byte[] iv;
            
            // ok: weak-cipher-algorithm
            using (Aes aes = Aes.Create())
            {
                aes.GenerateKey(); // Securely generate a random key
                aes.GenerateIV();  // Securely generate a random IV
                
                key = aes.Key;
                iv = aes.IV;
                
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
                }
            }
            
            // Store or transmit ciphertext, key, and IV securely
            Console.WriteLine($"Key length: {key.Length * 8} bits");
            Console.WriteLine($"IV length: {iv.Length * 8} bits");
            Console.WriteLine($"Ciphertext length: {ciphertext.Length} bytes");
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public void good_case_12()
        {
            // Using AES for secure communication
            byte[] key = new byte[32]; // 256-bit key
            byte[] iv = new byte[16];  // 128-bit IV
            string message = "This is a secure message";
            
            // ok: weak-cipher-algorithm
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                byte[] encryptedMessage;
                
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    encryptedMessage = encryptor.TransformFinalBlock(messageBytes, 0, messageBytes.Length);
                }
                
                // Simulate sending the encrypted message
                SendSecureMessage(encryptedMessage, iv);
            }
        }
// {/fact}
        
        private void SendSecureMessage(byte[] encryptedData, byte[] iv)
        {
            // Simulated secure message transmission
            Console.WriteLine($"Sending {encryptedData.Length} bytes of encrypted data");
            Console.WriteLine($"IV: {Convert.ToBase64String(iv)}");
        }
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public void good_case_13()
        {
            // Using AES for database field encryption
            string sensitiveField = "SSN: 123-45-6789";
            byte[] key = new byte[32]; // 256-bit key
            byte[] iv = new byte[16];  // 128-bit IV
            
            // ok: weak-cipher-algorithm
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                
                byte[] fieldBytes = Encoding.UTF8.GetBytes(sensitiveField);
                byte[] encryptedField;
                
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    encryptedField = encryptor.TransformFinalBlock(fieldBytes, 0, fieldBytes.Length);
                }
                
                // Store in database (simulated)
                string base64EncryptedField = Convert.ToBase64String(encryptedField);
                string base64IV = Convert.ToBase64String(iv);
                
                Console.WriteLine($"Storing encrypted field in database: {base64EncryptedField}");
                Console.WriteLine($"IV: {base64IV}");
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public void good_case_14()
        {
            // Using AES with a key derived from a password using modern parameters
            string password = "StrongUserPassword123!";
            byte[] salt = new byte[16];
            new Random().NextBytes(salt);
            
            // ok: weak-cipher-algorithm
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, 310000)) // Modern iteration count
            {
                byte[] key = pbkdf2.GetBytes(32); // 256-bit key
                byte[] iv = pbkdf2.GetBytes(16);  // 128-bit IV
                
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    
                    string plainText = "Very sensitive information";
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    byte[] cipherText;
                    
                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    {
                        cipherText = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                    }
                    
                    // Store salt, IV, and ciphertext
                    Console.WriteLine($"Salt: {Convert.ToBase64String(salt)}");
                    Console.WriteLine($"IV: {Convert.ToBase64String(iv)}");
                    Console.WriteLine($"Ciphertext: {Convert.ToBase64String(cipherText)}");
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public void good_case_15()
        {
            // Using AES-GCM with additional authenticated data (requires .NET 6.0+)
            byte[] key = new byte[32]; // 256-bit key
            byte[] nonce = new byte[12]; // 96-bit nonce
            string plainText = "Sensitive data with metadata";
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherText = new byte[plainBytes.Length];
            byte[] tag = new byte[16]; // 128-bit authentication tag
            
            // Additional data that will be authenticated but not encrypted
            byte[] metadata = Encoding.UTF8.GetBytes("User ID: 12345, Timestamp: 2023-05-15T14:30:00Z");
            
            // ok: weak-cipher-algorithm
            using (AesGcm aesGcm = new AesGcm(key))
            {
                aesGcm.Encrypt(nonce, plainBytes, cipherText, tag, metadata);
                
                // Store or transmit cipherText, tag, nonce, and metadata
                Console.WriteLine($"Ciphertext: {Convert.ToBase64String(cipherText)}");
                Console.WriteLine($"Auth Tag: {Convert.ToBase64String(tag)}");
                Console.WriteLine($"Metadata (authenticated): {Encoding.UTF8.GetString(metadata)}");
            }
        }
// {/fact}
    }
}