using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace RSAPaddingExamples
{
    class Program
    {
        static void Main(string[] args)
        {
            // This file contains examples of secure and insecure RSA padding usage
        }
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=1}

        // True Positive Examples (Vulnerable Code)

        public static void bad_case_1()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Sensitive data");
                
                // ruleid: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, false); // false means PKCS#1 v1.5 padding
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=1}

        public static void bad_case_2()
        {
            string sensitiveData = "Secret message";
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes(sensitiveData);
            
            using (RSA rsa = RSA.Create())
            {
                // ruleid: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.Pkcs1);
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=1}

        public static void bad_case_3()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Confidential information");
            RSAEncryptionPadding paddingMode = RSAEncryptionPadding.Pkcs1;
            
            using (RSA rsa = RSA.Create())
            {
                // ruleid: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, paddingMode);
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=1}

        public static void bad_case_4()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                byte[] dataToEncrypt = Encoding.UTF8.GetBytes("API key: 12345");
                bool useOaepPadding = false; // Using PKCS#1 v1.5 padding
                
                // ruleid: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, useOaepPadding);
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=1}

        public static void bad_case_5()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Password123");
            
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(GetPublicKey());
                
                // ruleid: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, false);
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=1}

        public static void bad_case_6()
        {
            string message = "Top secret information";
            byte[] data = Encoding.UTF8.GetBytes(message);
            
            using (RSA rsa = RSA.Create())
            {
                RSAEncryptionPadding padding = RSAEncryptionPadding.Pkcs1;
                
                // ruleid: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encrypted = rsa.Encrypt(data, padding);
                File.WriteAllBytes("encrypted.bin", encrypted);
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=1}

        public static void bad_case_7()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Credit card: 1234-5678-9012-3456");
                
                if (IsHighSecurityMode())
                {
                    // ruleid: use-weak-rsa-encryption-padding-csharp-rule
                    return rsa.Encrypt(dataToEncrypt, false);
                }
                else
                {
                    // ruleid: use-weak-rsa-encryption-padding-csharp-rule
                    return rsa.Encrypt(dataToEncrypt, false);
                }
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=1}

        public static void bad_case_8()
        {
            EncryptionService service = new EncryptionService();
            byte[] data = Encoding.UTF8.GetBytes("Sensitive customer data");
            
            // ruleid: use-weak-rsa-encryption-padding-csharp-rule
            byte[] encrypted = service.EncryptWithPkcs1(data);
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=1}

        public static void bad_case_9()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Internal document");
            
            using (RSA rsa = RSA.Create())
            {
                rsa.KeySize = 2048;
                
                try
                {
                    // ruleid: use-weak-rsa-encryption-padding-csharp-rule
                    byte[] encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.Pkcs1);
                }
                catch (CryptographicException ex)
                {
                    Console.WriteLine("Encryption failed: " + ex.Message);
                }
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=1}

        public static void bad_case_10()
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                byte[] dataToEncrypt = Encoding.UTF8.GetBytes("SSN: 123-45-6789");
                bool useLegacyPadding = true;
                
                // ruleid: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, !useLegacyPadding);
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=1}

        public static void bad_case_11()
        {
            RSAEncryptionPadding[] paddingOptions = new RSAEncryptionPadding[] 
            {
                RSAEncryptionPadding.Pkcs1,
                RSAEncryptionPadding.OaepSHA1,
                RSAEncryptionPadding.OaepSHA256
            };
            
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Confidential report");
            
            using (RSA rsa = RSA.Create())
            {
                // ruleid: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, paddingOptions[0]); // Using PKCS#1
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=1}

        public static void bad_case_12()
        {
            string configSetting = GetConfigSetting("padding");
            RSAEncryptionPadding padding;
            
            if (configSetting == "oaep")
            {
                padding = RSAEncryptionPadding.OaepSHA256;
            }
            else
            {
                padding = RSAEncryptionPadding.Pkcs1; // Default to PKCS#1
            }
            
            using (RSA rsa = RSA.Create())
            {
                byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Proprietary algorithm details");
                
                // ruleid: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, padding);
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=1}

        public static void bad_case_13()
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Database connection string");
                
                for (int i = 0; i < 3; i++)
                {
                    // ruleid: use-weak-rsa-encryption-padding-csharp-rule
                    byte[] encryptedData = rsa.Encrypt(dataToEncrypt, false);
                    SaveToFile($"encrypted_{i}.bin", encryptedData);
                }
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=1}

        public static void bad_case_14()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Authentication token");
            
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportFromPem(File.ReadAllText("public_key.pem"));
                
                switch (GetEncryptionLevel())
                {
                    case EncryptionLevel.Low:
                    case EncryptionLevel.Medium:
                        // ruleid: use-weak-rsa-encryption-padding-csharp-rule
                        return rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.Pkcs1);
                    case EncryptionLevel.High:
                        return rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
                }
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=1}

        public static void bad_case_15()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Private key material");
            RSAEncryptionPadding[] paddings = GetAvailablePaddings();
            
            using (RSA rsa = RSA.Create())
            {
                // ruleid: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.Pkcs1);
                
                if (IsDebugMode())
                {
                    Console.WriteLine("Using PKCS#1 v1.5 padding");
                }
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        public static void good_case_1()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Sensitive data");
                
                // ok: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, true); // true means OAEP padding
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=0}

        public static void good_case_2()
        {
            string sensitiveData = "Secret message";
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes(sensitiveData);
            
            using (RSA rsa = RSA.Create())
            {
                // ok: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=0}

        public static void good_case_3()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Confidential information");
            RSAEncryptionPadding paddingMode = RSAEncryptionPadding.OaepSHA1;
            
            using (RSA rsa = RSA.Create())
            {
                // ok: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, paddingMode);
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=0}

        public static void good_case_4()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                byte[] dataToEncrypt = Encoding.UTF8.GetBytes("API key: 12345");
                bool useOaepPadding = true; // Using OAEP padding
                
                // ok: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, useOaepPadding);
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=0}

        public static void good_case_5()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Password123");
            
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(GetPublicKey());
                
                // ok: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, true); // Using OAEP padding
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=0}

        public static void good_case_6()
        {
            string message = "Top secret information";
            byte[] data = Encoding.UTF8.GetBytes(message);
            
            using (RSA rsa = RSA.Create())
            {
                // ok: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA512);
                File.WriteAllBytes("encrypted.bin", encrypted);
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=0}

        public static void good_case_7()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Credit card: 1234-5678-9012-3456");
                
                if (IsHighSecurityMode())
                {
                    // ok: use-weak-rsa-encryption-padding-csharp-rule
                    return rsa.Encrypt(dataToEncrypt, true); // OAEP padding
                }
                else
                {
                    // ok: use-weak-rsa-encryption-padding-csharp-rule
                    return rsa.Encrypt(dataToEncrypt, true); // OAEP padding
                }
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=0}

        public static void good_case_8()
        {
            EncryptionService service = new EncryptionService();
            byte[] data = Encoding.UTF8.GetBytes("Sensitive customer data");
            
            // ok: use-weak-rsa-encryption-padding-csharp-rule
            byte[] encrypted = service.EncryptWithOaep(data);
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=0}

        public static void good_case_9()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Internal document");
            
            using (RSA rsa = RSA.Create())
            {
                rsa.KeySize = 2048;
                
                try
                {
                    // ok: use-weak-rsa-encryption-padding-csharp-rule
                    byte[] encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
                }
                catch (CryptographicException ex)
                {
                    Console.WriteLine("Encryption failed: " + ex.Message);
                }
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=0}

        public static void good_case_10()
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                byte[] dataToEncrypt = Encoding.UTF8.GetBytes("SSN: 123-45-6789");
                
                // ok: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, true); // Using OAEP padding
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=0}

        public static void good_case_11()
        {
            RSAEncryptionPadding[] paddingOptions = new RSAEncryptionPadding[] 
            {
                RSAEncryptionPadding.Pkcs1,
                RSAEncryptionPadding.OaepSHA1,
                RSAEncryptionPadding.OaepSHA256
            };
            
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Confidential report");
            
            using (RSA rsa = RSA.Create())
            {
                // ok: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, paddingOptions[2]); // Using OAEP with SHA-256
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=0}

        public static void good_case_12()
        {
            string configSetting = GetConfigSetting("padding");
            RSAEncryptionPadding padding;
            
            if (configSetting == "sha1")
            {
                padding = RSAEncryptionPadding.OaepSHA1;
            }
            else
            {
                padding = RSAEncryptionPadding.OaepSHA256; // Default to OAEP with SHA-256
            }
            
            using (RSA rsa = RSA.Create())
            {
                byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Proprietary algorithm details");
                
                // ok: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, padding);
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=0}

        public static void good_case_13()
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Database connection string");
                
                for (int i = 0; i < 3; i++)
                {
                    // ok: use-weak-rsa-encryption-padding-csharp-rule
                    byte[] encryptedData = rsa.Encrypt(dataToEncrypt, true); // Using OAEP padding
                    SaveToFile($"encrypted_{i}.bin", encryptedData);
                }
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=0}

        public static void good_case_14()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Authentication token");
            
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportFromPem(File.ReadAllText("public_key.pem"));
                
                switch (GetEncryptionLevel())
                {
                    case EncryptionLevel.Low:
                        // ok: use-weak-rsa-encryption-padding-csharp-rule
                        return rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA1);
                    case EncryptionLevel.Medium:
                    case EncryptionLevel.High:
                        // ok: use-weak-rsa-encryption-padding-csharp-rule
                        return rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
                }
            }
        }
// {/fact}
// {fact rule=use-of-rsa-algorithm-without-oaep@v1.0 defects=0}

        public static void good_case_15()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Private key material");
            
            using (RSA rsa = RSA.Create())
            {
                // ok: use-weak-rsa-encryption-padding-csharp-rule
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA512);
                
                if (IsDebugMode())
                {
                    Console.WriteLine("Using OAEP padding with SHA-512");
                }
            }
        }
// {/fact}

        // Helper methods (implementations not shown for brevity)
        private static RSAParameters GetPublicKey() { return new RSAParameters(); }
        private static bool IsHighSecurityMode() { return true; }
        private static void SaveToFile(string filename, byte[] data) { }
        private static string GetConfigSetting(string key) { return ""; }
        private static EncryptionLevel GetEncryptionLevel() { return EncryptionLevel.High; }
        private static bool IsDebugMode() { return false; }
        private static RSAEncryptionPadding[] GetAvailablePaddings() { return new RSAEncryptionPadding[] { }; }
    }

    // Helper classes
    public enum EncryptionLevel { Low, Medium, High }

    public class EncryptionService
    {
        public byte[] EncryptWithPkcs1(byte[] data)
        {
            using (RSA rsa = RSA.Create())
            {
                return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            }
        }

        public byte[] EncryptWithOaep(byte[] data)
        {
            using (RSA rsa = RSA.Create())
            {
                return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            }
        }
    }
}