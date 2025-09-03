using System;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Collections.Generic;
using System.IO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

namespace WeakRandomNumberGenerationExamples
{
    public class WeakRandomNumberGenerationController
    {
// {fact rule=weak-random-number-generation@v1.0 defects=1}
        // TRUE POSITIVES (Vulnerable Code)

        public void bad_case_1()
        {
            // Using standard Random class for generating a token
            // ruleid: weak-random-number-generation-csharp-rule
            Random random = new Random();
            string token = random.Next().ToString();
            Console.WriteLine($"Generated token: {token}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

        public void bad_case_2()
        {
            // Using Random class for password generation
            // ruleid: weak-random-number-generation-csharp-rule
            Random rnd = new Random();
            string password = "";
            for (int i = 0; i < 10; i++)
            {
                password += (char)rnd.Next(33, 126);
            }
            Console.WriteLine($"Generated password: {password}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

        public void bad_case_3()
        {
            // Using Random for session ID
            // ruleid: weak-random-number-generation-csharp-rule
            var rand = new Random();
            string sessionId = rand.Next(100000, 999999).ToString();
            Console.WriteLine($"Session ID: {sessionId}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

        public void bad_case_4()
        {
            // Using Random for cryptographic key
            // ruleid: weak-random-number-generation-csharp-rule
            Random random = new Random();
            byte[] key = new byte[32];
            random.NextBytes(key);
            Console.WriteLine($"Key generated with length: {key.Length}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

        public void bad_case_5()
        {
            // Using Random for 2FA code
            // ruleid: weak-random-number-generation-csharp-rule
            Random r = new Random();
            int twoFactorCode = r.Next(100000, 999999);
            Console.WriteLine($"2FA Code: {twoFactorCode}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

        public void bad_case_6()
        {
            // Using Random for salt generation
            // ruleid: weak-random-number-generation-csharp-rule
            Random rng = new Random();
            byte[] salt = new byte[16];
            rng.NextBytes(salt);
            Console.WriteLine($"Salt generated with length: {salt.Length}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

        public void bad_case_7()
        {
            // Using Random with seed for IV generation
            // ruleid: weak-random-number-generation-csharp-rule
            Random random = new Random(42); // Using a fixed seed makes it even worse
            byte[] iv = new byte[16];
            random.NextBytes(iv);
            Console.WriteLine($"IV generated with length: {iv.Length}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

        [HttpPost]
        public ActionResult bad_case_8(string username)
        {
            // Using Random for reset token in web application
            // ruleid: weak-random-number-generation-csharp-rule
            Random random = new Random();
            string resetToken = random.Next(1000000, 9999999).ToString();
            // Store token for user
            return Content($"Reset token generated for {username}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

        public void bad_case_9()
        {
            // Using Random for UUID generation
            // ruleid: weak-random-number-generation-csharp-rule
            Random rnd = new Random();
            byte[] buffer = new byte[16];
            rnd.NextBytes(buffer);
            Guid customGuid = new Guid(buffer);
            Console.WriteLine($"Custom GUID: {customGuid}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

        public void bad_case_10()
        {
            // Using Random for lottery number generation
            // ruleid: weak-random-number-generation-csharp-rule
            Random random = new Random();
            List<int> lotteryNumbers = new List<int>();
            for (int i = 0; i < 6; i++)
            {
                lotteryNumbers.Add(random.Next(1, 50));
            }
            Console.WriteLine($"Lottery numbers: {string.Join(", ", lotteryNumbers)}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

        public void bad_case_11()
        {
            // Using Random for API key generation
            // ruleid: weak-random-number-generation-csharp-rule
            Random rand = new Random();
            string apiKey = "";
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            for (int i = 0; i < 32; i++)
            {
                apiKey += chars[rand.Next(chars.Length)];
            }
            Console.WriteLine($"API Key: {apiKey}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

        public void bad_case_12()
        {
            // Using Random for nonce generation
            // ruleid: weak-random-number-generation-csharp-rule
            Random random = new Random();
            int nonce = random.Next();
            Console.WriteLine($"Nonce: {nonce}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

        public void bad_case_13()
        {
            // Using Random for encryption key
            // ruleid: weak-random-number-generation-csharp-rule
            Random rng = new Random();
            byte[] encryptionKey = new byte[32];
            rng.NextBytes(encryptionKey);
            string keyBase64 = Convert.ToBase64String(encryptionKey);
            Console.WriteLine($"Encryption key: {keyBase64}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

        public void bad_case_14()
        {
            // Using Random for CSRF token
            // ruleid: weak-random-number-generation-csharp-rule
            Random random = new Random();
            StringBuilder tokenBuilder = new StringBuilder();
            for (int i = 0; i < 20; i++)
            {
                tokenBuilder.Append(random.Next(0, 10));
            }
            string csrfToken = tokenBuilder.ToString();
            Console.WriteLine($"CSRF Token: {csrfToken}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

        public void bad_case_15()
        {
            // Using Random for file name generation
            // ruleid: weak-random-number-generation-csharp-rule
            Random rand = new Random();
            string fileName = $"file_{rand.Next(1000, 9999)}_{DateTime.Now.Ticks}.tmp";
            Console.WriteLine($"Generated filename: {fileName}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

        // TRUE NEGATIVES (Secure Code)

        public void good_case_1()
        {
            // Using RandomNumberGenerator for token generation
            // ok: weak-random-number-generation-csharp-rule
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                byte[] tokenData = new byte[32];
                rng.GetBytes(tokenData);
                string token = Convert.ToBase64String(tokenData);
                Console.WriteLine($"Generated secure token: {token}");
            }
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

        public void good_case_2()
        {
            // Using RandomNumberGenerator for password generation
            // ok: weak-random-number-generation-csharp-rule
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] data = new byte[10];
                rng.GetBytes(data);
                string password = Convert.ToBase64String(data);
                Console.WriteLine($"Generated secure password: {password}");
            }
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

        public void good_case_3()
        {
            // Using RandomNumberGenerator for session ID
            // ok: weak-random-number-generation-csharp-rule
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] data = new byte[16];
                rng.GetBytes(data);
                string sessionId = BitConverter.ToString(data).Replace("-", "");
                Console.WriteLine($"Secure Session ID: {sessionId}");
            }
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

        public void good_case_4()
        {
            // Using RandomNumberGenerator for cryptographic key
            // ok: weak-random-number-generation-csharp-rule
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] key = new byte[32];
                rng.GetBytes(key);
                Console.WriteLine($"Secure key generated with length: {key.Length}");
            }
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

        public void good_case_5()
        {
            // Using RandomNumberGenerator for 2FA code
            // ok: weak-random-number-generation-csharp-rule
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] data = new byte[4];
                rng.GetBytes(data);
                int value = BitConverter.ToInt32(data, 0);
                int twoFactorCode = Math.Abs(value) % 900000 + 100000; // Ensure 6 digits
                Console.WriteLine($"Secure 2FA Code: {twoFactorCode}");
            }
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

        public void good_case_6()
        {
            // Using RandomNumberGenerator for salt generation
            // ok: weak-random-number-generation-csharp-rule
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] salt = new byte[16];
                rng.GetBytes(salt);
                Console.WriteLine($"Secure salt generated with length: {salt.Length}");
            }
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

        public void good_case_7()
        {
            // Using RandomNumberGenerator for IV generation
            // ok: weak-random-number-generation-csharp-rule
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] iv = new byte[16];
                rng.GetBytes(iv);
                Console.WriteLine($"Secure IV generated with length: {iv.Length}");
            }
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

        [HttpPost]
        public ActionResult good_case_8(string username)
        {
            // Using RandomNumberGenerator for reset token in web application
            // ok: weak-random-number-generation-csharp-rule
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] tokenData = new byte[32];
                rng.GetBytes(tokenData);
                string resetToken = Convert.ToBase64String(tokenData);
                // Store token for user
                return Content($"Secure reset token generated for {username}");
            }
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

        public void good_case_9()
        {
            // Using Guid.NewGuid() for UUID generation (internally uses cryptographically secure RNG)
            // ok: weak-random-number-generation-csharp-rule
            Guid guid = Guid.NewGuid();
            Console.WriteLine($"Secure GUID: {guid}");
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

        public void good_case_10()
        {
            // Using RandomNumberGenerator for lottery number generation
            // ok: weak-random-number-generation-csharp-rule
            using (var rng = RandomNumberGenerator.Create())
            {
                List<int> lotteryNumbers = new List<int>();
                for (int i = 0; i < 6; i++)
                {
                    byte[] data = new byte[4];
                    rng.GetBytes(data);
                    int value = BitConverter.ToInt32(data, 0);
                    int number = Math.Abs(value) % 49 + 1; // 1-49
                    lotteryNumbers.Add(number);
                }
                Console.WriteLine($"Secure lottery numbers: {string.Join(", ", lotteryNumbers)}");
            }
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

        public void good_case_11()
        {
            // Using RandomNumberGenerator for API key generation
            // ok: weak-random-number-generation-csharp-rule
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] data = new byte[32];
                rng.GetBytes(data);
                string apiKey = Convert.ToBase64String(data);
                Console.WriteLine($"Secure API Key: {apiKey}");
            }
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

        public void good_case_12()
        {
            // Using RandomNumberGenerator for nonce generation
            // ok: weak-random-number-generation-csharp-rule
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] nonceBytes = new byte[8];
                rng.GetBytes(nonceBytes);
                string nonce = Convert.ToBase64String(nonceBytes);
                Console.WriteLine($"Secure Nonce: {nonce}");
            }
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

        public void good_case_13()
        {
            // Using RandomNumberGenerator for encryption key
            // ok: weak-random-number-generation-csharp-rule
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] encryptionKey = new byte[32];
                rng.GetBytes(encryptionKey);
                string keyBase64 = Convert.ToBase64String(encryptionKey);
                Console.WriteLine($"Secure encryption key: {keyBase64}");
            }
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

        public void good_case_14()
        {
            // Using RandomNumberGenerator for CSRF token
            // ok: weak-random-number-generation-csharp-rule
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] tokenData = new byte[32];
                rng.GetBytes(tokenData);
                string csrfToken = Convert.ToBase64String(tokenData);
                Console.WriteLine($"Secure CSRF Token: {csrfToken}");
            }
        }
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

        public void good_case_15()
        {
            // Using RandomNumberGenerator for file name generation
            // ok: weak-random-number-generation-csharp-rule
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] data = new byte[8];
                rng.GetBytes(data);
                string randomPart = BitConverter.ToString(data).Replace("-", "");
                string fileName = $"file_{randomPart}_{DateTime.Now.Ticks}.tmp";
                Console.WriteLine($"Generated secure filename: {fileName}");
            }
        }
// {/fact}
    }
}