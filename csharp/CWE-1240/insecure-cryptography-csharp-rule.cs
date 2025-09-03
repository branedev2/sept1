using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Net.Http;
using System.Threading.Tasks;

namespace InsecureCryptographyExamples
{
    public class CryptographyExamples
    {
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
        // True Positives (Vulnerable Code)

        public static string bad_case_1()
        {
            string password = "sensitive_password";
            
            // ruleid: insecure-cryptography-csharp-rule
            MD5 md5 = MD5.Create();
            byte[] inputBytes = Encoding.ASCII.GetBytes(password);
            byte[] hashBytes = md5.ComputeHash(inputBytes);
            
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashBytes.Length; i++)
            {
                sb.Append(hashBytes[i].ToString("X2"));
            }
            return sb.ToString();
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public static string bad_case_2()
        {
            string data = "sensitive_data";
            
            // ruleid: insecure-cryptography-csharp-rule
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] hashBytes = sha1.ComputeHash(Encoding.UTF8.GetBytes(data));
                return BitConverter.ToString(hashBytes).Replace("-", "");
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public static string bad_case_3()
        {
            string userInput = "user_provided_data";
            
            // ruleid: insecure-cryptography-csharp-rule
            using (var md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(userInput));
                return Convert.ToBase64String(hash);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public static async Task<string> bad_case_4()
        {
            using (var client = new HttpClient())
            {
                var response = await client.GetStringAsync("https://example.com/data");
                
                // ruleid: insecure-cryptography-csharp-rule
                using (var sha1 = SHA1.Create())
                {
                    byte[] hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(response));
                    return Convert.ToBase64String(hash);
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public static string bad_case_5()
        {
            string apiKey = "api_key_value";
            
            // ruleid: insecure-cryptography-csharp-rule
            using (HMACMD5 hmac = new HMACMD5(Encoding.UTF8.GetBytes("secret_key")))
            {
                byte[] hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(apiKey));
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public static string bad_case_6(string fileName)
        {
            byte[] fileData = File.ReadAllBytes(fileName);
            
            // ruleid: insecure-cryptography-csharp-rule
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] hashValue = sha1.ComputeHash(fileData);
                return Convert.ToBase64String(hashValue);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public static string bad_case_7()
        {
            string password = "user_password";
            string salt = "random_salt";
            
            // ruleid: insecure-cryptography-csharp-rule
            using (var md5 = MD5.Create())
            {
                byte[] combined = Encoding.UTF8.GetBytes(password + salt);
                byte[] hash = md5.ComputeHash(combined);
                return Convert.ToBase64String(hash);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public static string bad_case_8()
        {
            // ruleid: insecure-cryptography-csharp-rule
            using (var provider = new MD5CryptoServiceProvider())
            {
                byte[] hashBytes = provider.ComputeHash(Encoding.UTF8.GetBytes("sensitive_data"));
                return BitConverter.ToString(hashBytes).Replace("-", "");
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public static string bad_case_9()
        {
            // ruleid: insecure-cryptography-csharp-rule
            using (var provider = new SHA1CryptoServiceProvider())
            {
                byte[] hashBytes = provider.ComputeHash(Encoding.UTF8.GetBytes("sensitive_data"));
                return BitConverter.ToString(hashBytes).Replace("-", "");
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public static string bad_case_10()
        {
            string message = "message_to_sign";
            byte[] key = Encoding.UTF8.GetBytes("secret_key");
            
            // ruleid: insecure-cryptography-csharp-rule
            using (var hmacsha1 = new HMACSHA1(key))
            {
                byte[] hashBytes = hmacsha1.ComputeHash(Encoding.UTF8.GetBytes(message));
                return Convert.ToBase64String(hashBytes);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public static string bad_case_11()
        {
            // ruleid: insecure-cryptography-csharp-rule
            using (var ripemd160 = RIPEMD160.Create())
            {
                byte[] hashBytes = ripemd160.ComputeHash(Encoding.UTF8.GetBytes("sensitive_data"));
                return BitConverter.ToString(hashBytes).Replace("-", "");
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public static string bad_case_12()
        {
            string data = "sensitive_data";
            
            // ruleid: insecure-cryptography-csharp-rule
            using (var provider = new RIPEMD160Managed())
            {
                byte[] hashBytes = provider.ComputeHash(Encoding.UTF8.GetBytes(data));
                return BitConverter.ToString(hashBytes).Replace("-", "");
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public static byte[] bad_case_13(byte[] data, byte[] key)
        {
            // ruleid: insecure-cryptography-csharp-rule
            using (var des = new DESCryptoServiceProvider())
            {
                des.Key = key;
                des.IV = new byte[8];
                
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public static byte[] bad_case_14(byte[] data)
        {
            // ruleid: insecure-cryptography-csharp-rule
            using (var rc2 = new RC2CryptoServiceProvider())
            {
                rc2.Key = new byte[8] { 1, 2, 3, 4, 5, 6, 7, 8 };
                rc2.IV = new byte[8] { 8, 7, 6, 5, 4, 3, 2, 1 };
                
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, rc2.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

        public static string bad_case_15()
        {
            // ruleid: insecure-cryptography-csharp-rule
            using (var md5 = MD5.Create())
            using (var sha1 = SHA1.Create())
            {
                byte[] data = Encoding.UTF8.GetBytes("sensitive_data");
                byte[] md5Hash = md5.ComputeHash(data);
                byte[] sha1Hash = sha1.ComputeHash(md5Hash);
                return Convert.ToBase64String(sha1Hash);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        // True Negatives (Secure Code)

        public static string good_case_1()
        {
            string password = "sensitive_password";
            
            // ok: insecure-cryptography-csharp-rule
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return BitConverter.ToString(hashBytes).Replace("-", "");
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public static string good_case_2()
        {
            string data = "sensitive_data";
            
            // ok: insecure-cryptography-csharp-rule
            using (SHA512 sha512 = SHA512.Create())
            {
                byte[] hashBytes = sha512.ComputeHash(Encoding.UTF8.GetBytes(data));
                return Convert.ToBase64String(hashBytes);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public static string good_case_3()
        {
            string userInput = "user_provided_data";
            
            // ok: insecure-cryptography-csharp-rule
            using (var sha384 = SHA384.Create())
            {
                byte[] hash = sha384.ComputeHash(Encoding.UTF8.GetBytes(userInput));
                return Convert.ToBase64String(hash);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public static async Task<string> good_case_4()
        {
            using (var client = new HttpClient())
            {
                var response = await client.GetStringAsync("https://example.com/data");
                
                // ok: insecure-cryptography-csharp-rule
                using (var sha256 = SHA256.Create())
                {
                    byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(response));
                    return Convert.ToBase64String(hash);
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public static string good_case_5()
        {
            string apiKey = "api_key_value";
            
            // ok: insecure-cryptography-csharp-rule
            using (HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes("secret_key")))
            {
                byte[] hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(apiKey));
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public static string good_case_6(string fileName)
        {
            byte[] fileData = File.ReadAllBytes(fileName);
            
            // ok: insecure-cryptography-csharp-rule
            using (SHA512 sha512 = SHA512.Create())
            {
                byte[] hashValue = sha512.ComputeHash(fileData);
                return Convert.ToBase64String(hashValue);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public static string good_case_7()
        {
            string password = "user_password";
            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            
            // ok: insecure-cryptography-csharp-rule
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256))
            {
                byte[] hash = pbkdf2.GetBytes(32);
                return Convert.ToBase64String(hash);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public static string good_case_8()
        {
            // ok: insecure-cryptography-csharp-rule
            using (var sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes("sensitive_data"));
                return BitConverter.ToString(hashBytes).Replace("-", "");
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public static string good_case_9()
        {
            // ok: insecure-cryptography-csharp-rule
            using (var sha512 = SHA512.Create())
            {
                byte[] hashBytes = sha512.ComputeHash(Encoding.UTF8.GetBytes("sensitive_data"));
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashBytes)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public static string good_case_10()
        {
            string message = "message_to_sign";
            byte[] key = Encoding.UTF8.GetBytes("secret_key");
            
            // ok: insecure-cryptography-csharp-rule
            using (var hmacsha512 = new HMACSHA512(key))
            {
                byte[] hashBytes = hmacsha512.ComputeHash(Encoding.UTF8.GetBytes(message));
                return Convert.ToBase64String(hashBytes);
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public static string good_case_11()
        {
            // ok: insecure-cryptography-csharp-rule
            using (var sha3 = SHA3_256.Create())
            {
                byte[] hashBytes = sha3.ComputeHash(Encoding.UTF8.GetBytes("sensitive_data"));
                return BitConverter.ToString(hashBytes).Replace("-", "");
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public static string good_case_12()
        {
            string data = "sensitive_data";
            
            // ok: insecure-cryptography-csharp-rule
            using (var sha3 = SHA3_512.Create())
            {
                byte[] hashBytes = sha3.ComputeHash(Encoding.UTF8.GetBytes(data));
                return BitConverter.ToString(hashBytes).Replace("-", "");
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public static byte[] good_case_13(byte[] data, byte[] key)
        {
            // ok: insecure-cryptography-csharp-rule
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();
                
                using (var ms = new MemoryStream())
                {
                    ms.Write(aes.IV, 0, aes.IV.Length);
                    
                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public static byte[] good_case_14(byte[] data)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] key = new byte[32];
                byte[] iv = new byte[16];
                rng.GetBytes(key);
                rng.GetBytes(iv);
                
                // ok: insecure-cryptography-csharp-rule
                using (var aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    
                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock();
                            return ms.ToArray();
                        }
                    }
                }
            }
        }
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

        public static string good_case_15()
        {
            // ok: insecure-cryptography-csharp-rule
            using (var hmacsha384 = new HMACSHA384(Encoding.UTF8.GetBytes("secret_key")))
            {
                byte[] data = Encoding.UTF8.GetBytes("sensitive_data");
                byte[] hashBytes = hmacsha384.ComputeHash(data);
                return Convert.ToBase64String(hashBytes);
            }
        }
// {/fact}
    }
}