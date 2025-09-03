using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace X509CertificateExamples
{
    public class CertificateOperations : Controller
    {
// {fact rule=aws-kms-reencryption@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public void bad_case_1()
        {
            // Loading certificate from file
            X509Certificate2 cert = new X509Certificate2("mycert.pfx", "password");
            
            // ruleid: X509Certificate2-private-key-csharp-rule
            AsymmetricAlgorithm privateKey = cert.PrivateKey;
            
            // Use the private key for signing
            if (privateKey is RSACryptoServiceProvider rsaKey)
            {
                byte[] data = Encoding.UTF8.GetBytes("Data to sign");
                byte[] signature = rsaKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public void bad_case_2()
        {
            // Loading certificate from store
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySubjectName, "MyCert", false);
            
            if (certs.Count > 0)
            {
                X509Certificate2 cert = certs[0];
                // ruleid: X509Certificate2-private-key-csharp-rule
                var privateKey = cert.PrivateKey;
                
                // Log the key type
                Console.WriteLine($"Private key type: {privateKey.GetType().Name}");
            }
            store.Close();
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public void bad_case_3()
        {
            try
            {
                // Create a self-signed certificate
                using (RSA rsa = RSA.Create(2048))
                {
                    var request = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    var cert = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
                    
                    // ruleid: X509Certificate2-private-key-csharp-rule
                    if (cert.PrivateKey != null)
                    {
                        Console.WriteLine("Certificate has a private key");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public void bad_case_4(string certificatePath, string password)
        {
            // Load certificate and check its algorithm
            X509Certificate2 cert = new X509Certificate2(certificatePath, password);
            
            // ruleid: X509Certificate2-private-key-csharp-rule
            AsymmetricAlgorithm key = cert.PrivateKey;
            
            if (key is DSACryptoServiceProvider)
            {
                Console.WriteLine("DSA algorithm detected");
            }
            else if (key is RSACryptoServiceProvider)
            {
                Console.WriteLine("RSA algorithm detected");
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public void bad_case_5()
        {
            // Certificate chain validation with private key check
            X509Chain chain = new X509Chain();
            X509Certificate2 cert = new X509Certificate2("server.pfx", "password");
            
            bool isValid = chain.Build(cert);
            
            if (isValid)
            {
                // ruleid: X509Certificate2-private-key-csharp-rule
                bool hasPrivateKey = (cert.PrivateKey != null);
                Console.WriteLine($"Certificate is valid and has private key: {hasPrivateKey}");
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        [HttpPost]
        public IActionResult bad_case_6([FromForm] IFormFile certificateFile, [FromForm] string password)
        {
            try
            {
                // Load certificate from uploaded file
                using (var ms = new MemoryStream())
                {
                    certificateFile.CopyTo(ms);
                    byte[] certBytes = ms.ToArray();
                    
                    X509Certificate2 cert = new X509Certificate2(certBytes, password);
                    
                    // ruleid: X509Certificate2-private-key-csharp-rule
                    var privateKey = cert.PrivateKey;
                    
                    return Ok(new { HasPrivateKey = (privateKey != null) });
                }
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public void bad_case_7()
        {
            // Certificate export with private key check
            X509Certificate2 cert = new X509Certificate2("mycert.pfx", "password");
            
            // ruleid: X509Certificate2-private-key-csharp-rule
            bool canExportPrivateKey = (cert.PrivateKey != null && 
                cert.PrivateKey is RSACryptoServiceProvider rsa && 
                rsa.CspKeyContainerInfo.Exportable);
            
            if (canExportPrivateKey)
            {
                byte[] pfxData = cert.Export(X509ContentType.Pfx, "newpassword");
                File.WriteAllBytes("exported.pfx", pfxData);
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public void bad_case_8()
        {
            // Certificate key size determination
            X509Certificate2 cert = new X509Certificate2("mycert.pfx", "password");
            
            int keySize = 0;
            // ruleid: X509Certificate2-private-key-csharp-rule
            if (cert.PrivateKey is RSACryptoServiceProvider rsaKey)
            {
                keySize = rsaKey.KeySize;
            }
            else if (cert.PrivateKey is DSACryptoServiceProvider dsaKey)
            {
                keySize = dsaKey.KeySize;
            }
            
            Console.WriteLine($"Certificate key size: {keySize} bits");
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public void bad_case_9()
        {
            // Certificate with conditional private key usage
            X509Certificate2 cert = new X509Certificate2("mycert.pfx", "password");
            
            byte[] dataToSign = Encoding.UTF8.GetBytes("Sign this data");
            byte[] signature = null;
            
            // ruleid: X509Certificate2-private-key-csharp-rule
            if (cert.PrivateKey is RSACryptoServiceProvider rsa)
            {
                signature = rsa.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            else
            {
                throw new InvalidOperationException("Certificate does not contain an RSA private key");
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public void bad_case_10()
        {
            // Certificate private key extraction for custom operation
            X509Certificate2 cert = new X509Certificate2("mycert.pfx", "password");
            
            // ruleid: X509Certificate2-private-key-csharp-rule
            AsymmetricAlgorithm privateKey = cert.PrivateKey;
            
            // Custom key handling
            if (privateKey != null)
            {
                Type keyType = privateKey.GetType();
                int keySize = privateKey.KeySize;
                
                Console.WriteLine($"Key type: {keyType.Name}, Key size: {keySize}");
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public void bad_case_11()
        {
            // Certificate private key for TLS client authentication
            using (TcpClient client = new TcpClient("example.com", 443))
            using (SslStream sslStream = new SslStream(client.GetStream(), false))
            {
                X509Certificate2 clientCert = new X509Certificate2("client.pfx", "password");
                
                // Check if certificate has private key before using for authentication
                // ruleid: X509Certificate2-private-key-csharp-rule
                if (clientCert.PrivateKey == null)
                {
                    throw new InvalidOperationException("Client certificate must have a private key");
                }
                
                sslStream.AuthenticateAsClient("example.com", new X509CertificateCollection { clientCert }, 
                    System.Security.Authentication.SslProtocols.Tls12, false);
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public void bad_case_12()
        {
            // Certificate key algorithm check
            X509Certificate2 cert = new X509Certificate2("mycert.pfx", "password");
            
            // ruleid: X509Certificate2-private-key-csharp-rule
            string keyAlgorithm = cert.PrivateKey?.GetType().Name ?? "No private key";
            
            if (keyAlgorithm.Contains("RSA"))
            {
                Console.WriteLine("Certificate uses RSA algorithm");
            }
            else if (keyAlgorithm.Contains("DSA"))
            {
                Console.WriteLine("Certificate uses DSA algorithm");
            }
            else if (keyAlgorithm.Contains("ECDsa"))
            {
                Console.WriteLine("Certificate uses ECDSA algorithm");
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public void bad_case_13()
        {
            // Certificate key usage in a custom encryption operation
            X509Certificate2 cert = new X509Certificate2("mycert.pfx", "password");
            
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Secret data");
            byte[] encryptedData = null;
            
            // ruleid: X509Certificate2-private-key-csharp-rule
            if (cert.PrivateKey is RSACryptoServiceProvider rsa)
            {
                // Using private key for encryption (typically you'd use the public key)
                encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public void bad_case_14()
        {
            // Certificate key property access in error handling
            try
            {
                X509Certificate2 cert = new X509Certificate2("mycert.pfx", "wrongpassword");
            }
            catch (CryptographicException ex)
            {
                // Attempt with a different password
                try
                {
                    X509Certificate2 cert = new X509Certificate2("mycert.pfx", "correctpassword");
                    
                    // ruleid: X509Certificate2-private-key-csharp-rule
                    if (cert.PrivateKey == null)
                    {
                        Console.WriteLine("Certificate loaded but without private key");
                    }
                    else
                    {
                        Console.WriteLine("Certificate loaded with private key");
                    }
                }
                catch (Exception innerEx)
                {
                    Console.WriteLine($"Failed to load certificate: {innerEx.Message}");
                }
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=1}

        public void bad_case_15()
        {
            // Certificate key usage with multiple certificates
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            
            foreach (X509Certificate2 cert in store.Certificates)
            {
                if (cert.Subject.Contains("CN=MyService"))
                {
                    // ruleid: X509Certificate2-private-key-csharp-rule
                    bool hasPrivateKey = (cert.PrivateKey != null);
                    
                    if (hasPrivateKey)
                    {
                        Console.WriteLine($"Found service certificate with private key: {cert.Thumbprint}");
                        break;
                    }
                }
            }
            
            store.Close();
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        public void good_case_1()
        {
            // Loading certificate from file and using GetRSAPrivateKey
            X509Certificate2 cert = new X509Certificate2("mycert.pfx", "password");
            
            // ok: X509Certificate2-private-key-csharp-rule
            RSA privateKey = cert.GetRSAPrivateKey();
            
            if (privateKey != null)
            {
                byte[] data = Encoding.UTF8.GetBytes("Data to sign");
                byte[] signature = privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public void good_case_2()
        {
            // Loading certificate from store and using GetRSAPrivateKey
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySubjectName, "MyCert", false);
            
            if (certs.Count > 0)
            {
                X509Certificate2 cert = certs[0];
                
                // ok: X509Certificate2-private-key-csharp-rule
                var rsaPrivateKey = cert.GetRSAPrivateKey();
                
                if (rsaPrivateKey != null)
                {
                    Console.WriteLine($"RSA private key size: {rsaPrivateKey.KeySize}");
                }
            }
            store.Close();
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public void good_case_3()
        {
            try
            {
                // Create a self-signed certificate
                using (RSA rsa = RSA.Create(2048))
                {
                    var request = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    var cert = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
                    
                    // ok: X509Certificate2-private-key-csharp-rule
                    if (cert.HasPrivateKey)
                    {
                        Console.WriteLine("Certificate has a private key");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public void good_case_4(string certificatePath, string password)
        {
            // Load certificate and check its algorithm using modern methods
            X509Certificate2 cert = new X509Certificate2(certificatePath, password);
            
            // ok: X509Certificate2-private-key-csharp-rule
            RSA rsaKey = cert.GetRSAPrivateKey();
            DSA dsaKey = cert.GetDSAPrivateKey();
            ECDsa ecdsaKey = cert.GetECDsaPrivateKey();
            
            if (rsaKey != null)
            {
                Console.WriteLine($"RSA algorithm detected, key size: {rsaKey.KeySize}");
            }
            else if (dsaKey != null)
            {
                Console.WriteLine($"DSA algorithm detected, key size: {dsaKey.KeySize}");
            }
            else if (ecdsaKey != null)
            {
                Console.WriteLine($"ECDSA algorithm detected, key size: {ecdsaKey.KeySize}");
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public void good_case_5()
        {
            // Certificate chain validation with private key check
            X509Chain chain = new X509Chain();
            X509Certificate2 cert = new X509Certificate2("server.pfx", "password");
            
            bool isValid = chain.Build(cert);
            
            if (isValid)
            {
                // ok: X509Certificate2-private-key-csharp-rule
                bool hasPrivateKey = cert.HasPrivateKey;
                Console.WriteLine($"Certificate is valid and has private key: {hasPrivateKey}");
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        [HttpPost]
        public IActionResult good_case_6([FromForm] IFormFile certificateFile, [FromForm] string password)
        {
            try
            {
                // Load certificate from uploaded file
                using (var ms = new MemoryStream())
                {
                    certificateFile.CopyTo(ms);
                    byte[] certBytes = ms.ToArray();
                    
                    X509Certificate2 cert = new X509Certificate2(certBytes, password);
                    
                    // ok: X509Certificate2-private-key-csharp-rule
                    bool hasPrivateKey = cert.HasPrivateKey;
                    RSA rsaKey = cert.GetRSAPrivateKey();
                    
                    return Ok(new { 
                        HasPrivateKey = hasPrivateKey,
                        KeyType = rsaKey != null ? "RSA" : "Other or None"
                    });
                }
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public void good_case_7()
        {
            // Certificate export with private key check
            X509Certificate2 cert = new X509Certificate2("mycert.pfx", "password");
            
            // ok: X509Certificate2-private-key-csharp-rule
            RSA rsaKey = cert.GetRSAPrivateKey();
            bool canExportPrivateKey = (rsaKey != null);
            
            if (canExportPrivateKey)
            {
                byte[] pfxData = cert.Export(X509ContentType.Pfx, "newpassword");
                File.WriteAllBytes("exported.pfx", pfxData);
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public void good_case_8()
        {
            // Certificate key size determination using modern methods
            X509Certificate2 cert = new X509Certificate2("mycert.pfx", "password");
            
            int keySize = 0;
            
            // ok: X509Certificate2-private-key-csharp-rule
            RSA rsaKey = cert.GetRSAPrivateKey();
            if (rsaKey != null)
            {
                keySize = rsaKey.KeySize;
            }
            else
            {
                DSA dsaKey = cert.GetDSAPrivateKey();
                if (dsaKey != null)
                {
                    keySize = dsaKey.KeySize;
                }
                else
                {
                    ECDsa ecdsaKey = cert.GetECDsaPrivateKey();
                    if (ecdsaKey != null)
                    {
                        keySize = ecdsaKey.KeySize;
                    }
                }
            }
            
            Console.WriteLine($"Certificate key size: {keySize} bits");
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public void good_case_9()
        {
            // Certificate with conditional private key usage using modern methods
            X509Certificate2 cert = new X509Certificate2("mycert.pfx", "password");
            
            byte[] dataToSign = Encoding.UTF8.GetBytes("Sign this data");
            byte[] signature = null;
            
            // ok: X509Certificate2-private-key-csharp-rule
            RSA rsaKey = cert.GetRSAPrivateKey();
            if (rsaKey != null)
            {
                signature = rsaKey.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            else
            {
                throw new InvalidOperationException("Certificate does not contain an RSA private key");
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public void good_case_10()
        {
            // Certificate private key extraction for custom operation using modern methods
            X509Certificate2 cert = new X509Certificate2("mycert.pfx", "password");
            
            // ok: X509Certificate2-private-key-csharp-rule
            RSA rsaKey = cert.GetRSAPrivateKey();
            ECDsa ecdsaKey = cert.GetECDsaPrivateKey();
            DSA dsaKey = cert.GetDSAPrivateKey();
            
            // Custom key handling
            if (rsaKey != null)
            {
                Console.WriteLine($"Key type: RSA, Key size: {rsaKey.KeySize}");
            }
            else if (ecdsaKey != null)
            {
                Console.WriteLine($"Key type: ECDSA, Key size: {ecdsaKey.KeySize}");
            }
            else if (dsaKey != null)
            {
                Console.WriteLine($"Key type: DSA, Key size: {dsaKey.KeySize}");
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public void good_case_11()
        {
            // Certificate private key for TLS client authentication using modern property
            using (TcpClient client = new TcpClient("example.com", 443))
            using (SslStream sslStream = new SslStream(client.GetStream(), false))
            {
                X509Certificate2 clientCert = new X509Certificate2("client.pfx", "password");
                
                // Check if certificate has private key before using for authentication
                // ok: X509Certificate2-private-key-csharp-rule
                if (!clientCert.HasPrivateKey)
                {
                    throw new InvalidOperationException("Client certificate must have a private key");
                }
                
                sslStream.AuthenticateAsClient("example.com", new X509CertificateCollection { clientCert }, 
                    System.Security.Authentication.SslProtocols.Tls12, false);
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public void good_case_12()
        {
            // Certificate key algorithm check using modern methods
            X509Certificate2 cert = new X509Certificate2("mycert.pfx", "password");
            
            string keyAlgorithm = "No private key";
            
            // ok: X509Certificate2-private-key-csharp-rule
            if (cert.GetRSAPrivateKey() != null)
            {
                keyAlgorithm = "RSA";
            }
            else if (cert.GetDSAPrivateKey() != null)
            {
                keyAlgorithm = "DSA";
            }
            else if (cert.GetECDsaPrivateKey() != null)
            {
                keyAlgorithm = "ECDSA";
            }
            
            Console.WriteLine($"Certificate uses {keyAlgorithm} algorithm");
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public void good_case_13()
        {
            // Certificate key usage in a custom encryption operation using modern methods
            X509Certificate2 cert = new X509Certificate2("mycert.pfx", "password");
            
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Secret data");
            byte[] encryptedData = null;
            
            // ok: X509Certificate2-private-key-csharp-rule
            RSA rsaKey = cert.GetRSAPrivateKey();
            if (rsaKey != null)
            {
                // Using RSA key for encryption
                encryptedData = rsaKey.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public void good_case_14()
        {
            // Using CopyWithPrivateKey to create a new certificate instance with private key
            X509Certificate2 certWithoutKey = new X509Certificate2("public.cer");
            
            // Create a new RSA key
            using (RSA rsa = RSA.Create(2048))
            {
                // ok: X509Certificate2-private-key-csharp-rule
                X509Certificate2 certWithKey = certWithoutKey.CopyWithPrivateKey(rsa);
                
                // Verify the certificate now has a private key
                if (certWithKey.HasPrivateKey)
                {
                    Console.WriteLine("Successfully added private key to certificate");
                    
                    // Use the private key for signing
                    RSA rsaPrivateKey = certWithKey.GetRSAPrivateKey();
                    byte[] data = Encoding.UTF8.GetBytes("Data to sign");
                    byte[] signature = rsaPrivateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
        }
// {/fact}
// {fact rule=aws-kms-reencryption@v1.0 defects=0}

        public void good_case_15()
        {
            // Certificate key usage with multiple certificates using modern methods
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            
            foreach (X509Certificate2 cert in store.Certificates)
            {
                if (cert.Subject.Contains("CN=MyService"))
                {
                    // ok: X509Certificate2-private-key-csharp-rule
                    bool hasPrivateKey = cert.HasPrivateKey;
                    RSA rsaKey = cert.GetRSAPrivateKey();
                    
                    if (hasPrivateKey && rsaKey != null)
                    {
                        Console.WriteLine($"Found service certificate with RSA private key: {cert.Thumbprint}");
                        break;
                    }
                }
            }
            
            store.Close();
        }
// {/fact}
    }
}