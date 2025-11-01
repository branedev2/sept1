using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.Security.Authentication;

namespace CertificateValidationExamples
{
    public class CertificateValidationController : Controller
    {
// {fact rule=improper-certificate-validation@v1.0 defects=1}
        // True Positive Examples (Vulnerable)

        public void bad_case_1()
        {
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
            {
                X509Certificate2 cert = new X509Certificate2(certificate);
                // ruleid: X509-subject-name-validation-csharp-rule
                return cert.Subject.Contains("CN=example.com");
            };

            using (HttpClient client = new HttpClient())
            {
                var response = client.GetAsync("https://example.com").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

        public void bad_case_2()
        {
            using (HttpClient client = new HttpClient(new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
                {
                    // ruleid: X509-subject-name-validation-csharp-rule
                    return cert.Subject == "CN=example.org, O=Example Inc, C=US";
                }
            }))
            {
                var response = client.GetAsync("https://example.org").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

        public void bad_case_3()
        {
            var handler = new WebRequestHandler();
            handler.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
            {
                // ruleid: X509-subject-name-validation-csharp-rule
                if (certificate.Subject.Contains("CN=trusted-server"))
                {
                    return true;
                }
                return false;
            };

            using (var client = new HttpClient(handler))
            {
                var response = client.GetAsync("https://trusted-server.com").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

        public void bad_case_4()
        {
            ServicePointManager.ServerCertificateValidationCallback = delegate (object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            {
                X509Certificate2 cert = new X509Certificate2(certificate);
                // ruleid: X509-subject-name-validation-csharp-rule
                if (cert.GetNameInfo(X509NameType.SimpleName, false) == "example.com")
                {
                    return true;
                }
                return false;
            };

            using (WebClient client = new WebClient())
            {
                string result = client.DownloadString("https://example.com");
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

        public void bad_case_5()
        {
            bool ValidateCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            {
                // ruleid: X509-subject-name-validation-csharp-rule
                return certificate.Subject.EndsWith("OU=IT Department, O=Company Ltd, C=US");
            }

            ServicePointManager.ServerCertificateValidationCallback = ValidateCertificate;
            
            using (var client = new WebClient())
            {
                string data = client.DownloadString("https://internal-server.company.com");
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

        public void bad_case_6()
        {
            SslStream sslStream = new SslStream(
                new NetworkStream(new System.Net.Sockets.TcpClient("example.com", 443).Client),
                false,
                (sender, certificate, chain, sslPolicyErrors) =>
                {
                    // ruleid: X509-subject-name-validation-csharp-rule
                    return certificate.Subject.Contains("CN=example.com");
                }
            );

            sslStream.AuthenticateAsClient("example.com");
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

        public void bad_case_7()
        {
            using (var client = new HttpClient(new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
                {
                    // ruleid: X509-subject-name-validation-csharp-rule
                    var subjectName = cert.GetNameInfo(X509NameType.DnsName, false);
                    return subjectName == "api.example.com" || subjectName == "backup-api.example.com";
                }
            }))
            {
                var response = client.GetAsync("https://api.example.com/data").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

        public void bad_case_8()
        {
            X509Certificate2 serverCert = new X509Certificate2("server.pfx", "password");
            
            bool ValidateClientCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            {
                // ruleid: X509-subject-name-validation-csharp-rule
                return certificate.Subject.Contains("O=Client Organization");
            }

            var listener = new HttpListener();
            listener.Prefixes.Add("https://localhost:8443/");
            listener.Start();
            
            while (true)
            {
                var context = listener.GetContext();
                // Process request...
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

        public void bad_case_9()
        {
            var handler = new HttpClientHandler();
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
            {
                // ruleid: X509-subject-name-validation-csharp-rule
                var expectedSubject = "CN=api.payment-processor.com, O=Payment Processor Inc, C=US";
                return cert.Subject.Equals(expectedSubject, StringComparison.OrdinalIgnoreCase);
            };

            using (var client = new HttpClient(handler))
            {
                var response = client.GetAsync("https://api.payment-processor.com").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

        public void bad_case_10()
        {
            using (var tcpClient = new System.Net.Sockets.TcpClient("secure-service.com", 443))
            {
                using (var sslStream = new SslStream(
                    tcpClient.GetStream(),
                    false,
                    (sender, certificate, chain, sslPolicyErrors) =>
                    {
                        // ruleid: X509-subject-name-validation-csharp-rule
                        var certSubject = certificate.Subject;
                        var isValidSubject = certSubject.Contains("CN=secure-service.com");
                        return isValidSubject;
                    }))
                {
                    sslStream.AuthenticateAsClient("secure-service.com");
                    // Use the stream...
                }
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

        public void bad_case_11()
        {
            var certificateValidator = new CertificateValidator();
            
            using (var client = new HttpClient(new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
                {
                    // ruleid: X509-subject-name-validation-csharp-rule
                    return certificateValidator.ValidateSubjectOnly(cert);
                }
            }))
            {
                var response = client.GetAsync("https://api.example.com").Result;
            }
        }
// {/fact}

        private class CertificateValidator
        {
            public bool ValidateSubjectOnly(X509Certificate cert)
            {
                return cert.Subject.Contains("CN=api.example.com");
            }
        }
// {fact rule=improper-certificate-validation@v1.0 defects=1}

        public void bad_case_12()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
            {
                // ruleid: X509-subject-name-validation-csharp-rule
                var cert = new X509Certificate2(certificate);
                var subjectName = cert.GetNameInfo(X509NameType.SimpleName, false);
                var issuerName = cert.GetNameInfo(X509NameType.SimpleName, true);
                
                return subjectName == "secure-api.com" && issuerName == "TrustedCA";
            };

            using (var client = new WebClient())
            {
                var data = client.DownloadString("https://secure-api.com/data");
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

        public void bad_case_13()
        {
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
            {
                // ruleid: X509-subject-name-validation-csharp-rule
                if (sslPolicyErrors == SslPolicyErrors.None)
                {
                    return true;
                }
                
                // Fallback to just checking the subject
                return cert.Subject.Contains("CN=fallback-server.com");
            };

            using (var client = new HttpClient(handler))
            {
                var response = client.GetAsync("https://fallback-server.com").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

        public void bad_case_14()
        {
            X509Certificate2 LoadCertificate()
            {
                return new X509Certificate2("client.pfx", "password");
            }

            bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            {
                // ruleid: X509-subject-name-validation-csharp-rule
                var serverCert = new X509Certificate2(certificate);
                var domainName = serverCert.GetNameInfo(X509NameType.DnsName, false);
                return domainName.EndsWith(".trusted-domain.com");
            }

            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(LoadCertificate());
            handler.ServerCertificateCustomValidationCallback = ValidateServerCertificate;

            using (var client = new HttpClient(handler))
            {
                var response = client.GetAsync("https://api.trusted-domain.com").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

        public void bad_case_15()
        {
            using (var client = new HttpClient(new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
                {
                    // ruleid: X509-subject-name-validation-csharp-rule
                    var serverCert = new X509Certificate2(cert);
                    var subjectAlternativeNames = serverCert.Extensions["2.5.29.17"];
                    
                    // Just check if the subject contains our domain
                    return serverCert.Subject.Contains("example.net");
                }
            }))
            {
                var response = client.GetAsync("https://example.net/api/data").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

        // True Negative Examples (Secure)

        public void good_case_1()
        {
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
            {
                X509Certificate2 cert = new X509Certificate2(certificate);
                // ok: X509-subject-name-validation-csharp-rule
                return cert.Verify();
            };

            using (HttpClient client = new HttpClient())
            {
                var response = client.GetAsync("https://example.com").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

        public void good_case_2()
        {
            using (HttpClient client = new HttpClient(new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
                {
                    // ok: X509-subject-name-validation-csharp-rule
                    X509Certificate2 certificate = new X509Certificate2(cert);
                    return certificate.Verify() && sslPolicyErrors == SslPolicyErrors.None;
                }
            }))
            {
                var response = client.GetAsync("https://example.org").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

        public void good_case_3()
        {
            // Using default certificate validation (no custom callback)
            // ok: X509-subject-name-validation-csharp-rule
            using (HttpClient client = new HttpClient())
            {
                var response = client.GetAsync("https://example.com").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

        public void good_case_4()
        {
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
            {
                if (sslPolicyErrors != SslPolicyErrors.None)
                    return false;
                
                X509Certificate2 certificate = new X509Certificate2(cert);
                // ok: X509-subject-name-validation-csharp-rule
                return certificate.Verify() && certificate.Subject.Contains("CN=example.com");
            };

            using (var client = new HttpClient(handler))
            {
                var response = client.GetAsync("https://example.com").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

        public void good_case_5()
        {
            bool ValidateCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            {
                // ok: X509-subject-name-validation-csharp-rule
                X509Chain validationChain = new X509Chain();
                validationChain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                validationChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                
                X509Certificate2 cert = new X509Certificate2(certificate);
                return validationChain.Build(cert);
            }

            ServicePointManager.ServerCertificateValidationCallback = ValidateCertificate;
            
            using (var client = new WebClient())
            {
                string data = client.DownloadString("https://internal-server.company.com");
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

        public void good_case_6()
        {
            SslStream sslStream = new SslStream(
                new NetworkStream(new System.Net.Sockets.TcpClient("example.com", 443).Client),
                false,
                (sender, certificate, chain, sslPolicyErrors) =>
                {
                    // ok: X509-subject-name-validation-csharp-rule
                    return sslPolicyErrors == SslPolicyErrors.None;
                }
            );

            sslStream.AuthenticateAsClient("example.com");
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

        public void good_case_7()
        {
            using (var client = new HttpClient(new HttpClientHandler
            {
                // ok: X509-subject-name-validation-csharp-rule
                CheckCertificateRevocationList = true,
                // Using default certificate validation
            }))
            {
                var response = client.GetAsync("https://api.example.com/data").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

        public void good_case_8()
        {
            X509Certificate2 serverCert = new X509Certificate2("server.pfx", "password");
            
            bool ValidateClientCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            {
                X509Certificate2 cert = new X509Certificate2(certificate);
                // ok: X509-subject-name-validation-csharp-rule
                X509Chain validationChain = new X509Chain();
                validationChain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                validationChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                validationChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                
                return validationChain.Build(cert);
            }

            var listener = new HttpListener();
            listener.Prefixes.Add("https://localhost:8443/");
            listener.Start();
            
            while (true)
            {
                var context = listener.GetContext();
                // Process request...
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

        public void good_case_9()
        {
            var handler = new HttpClientHandler();
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
            {
                if (sslPolicyErrors != SslPolicyErrors.None)
                    return false;
                
                X509Certificate2 certificate = new X509Certificate2(cert);
                // ok: X509-subject-name-validation-csharp-rule
                return certificate.Verify();
            };

            using (var client = new HttpClient(handler))
            {
                var response = client.GetAsync("https://api.payment-processor.com").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

        public void good_case_10()
        {
            using (var tcpClient = new System.Net.Sockets.TcpClient("secure-service.com", 443))
            {
                using (var sslStream = new SslStream(
                    tcpClient.GetStream(),
                    false))
                {
                    // ok: X509-subject-name-validation-csharp-rule
                    // Using default certificate validation
                    sslStream.AuthenticateAsClient("secure-service.com");
                    // Use the stream...
                }
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

        public void good_case_11()
        {
            var certificateValidator = new SecureCertificateValidator();
            
            using (var client = new HttpClient(new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
                {
                    // ok: X509-subject-name-validation-csharp-rule
                    return certificateValidator.ValidateCompletely(cert, chain, sslPolicyErrors);
                }
            }))
            {
                var response = client.GetAsync("https://api.example.com").Result;
            }
        }
// {/fact}

        private class SecureCertificateValidator
        {
            public bool ValidateCompletely(X509Certificate cert, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            {
                if (sslPolicyErrors != SslPolicyErrors.None)
                    return false;
                
                X509Certificate2 certificate = new X509Certificate2(cert);
                return certificate.Verify();
            }
        }

        public void good_case_12()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            // ok: X509-subject-name-validation-csharp-rule
            // Using default certificate validation (no custom callback)
            
            using (var client = new WebClient())
            {
                var data = client.DownloadString("https://secure-api.com/data");
            }
        }
// {fact rule=improper-certificate-validation@v1.0 defects=0}

        public void good_case_13()
        {
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
            {
                // ok: X509-subject-name-validation-csharp-rule
                if (sslPolicyErrors != SslPolicyErrors.None)
                    return false;
                
                X509Certificate2 certificate = new X509Certificate2(cert);
                X509Chain validationChain = new X509Chain();
                validationChain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                
                return validationChain.Build(certificate);
            };

            using (var client = new HttpClient(handler))
            {
                var response = client.GetAsync("https://fallback-server.com").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

        public void good_case_14()
        {
            X509Certificate2 LoadCertificate()
            {
                return new X509Certificate2("client.pfx", "password");
            }

            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(LoadCertificate());
            // ok: X509-subject-name-validation-csharp-rule
            // Using default certificate validation (no custom callback)

            using (var client = new HttpClient(handler))
            {
                var response = client.GetAsync("https://api.trusted-domain.com").Result;
            }
        }
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

        public void good_case_15()
        {
            using (var client = new HttpClient(new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
                {
                    if (sslPolicyErrors != SslPolicyErrors.None)
                        return false;
                    
                    var serverCert = new X509Certificate2(cert);
                    // ok: X509-subject-name-validation-csharp-rule
                    return serverCert.Verify() && chain.ChainStatus.Length == 0;
                }
            }))
            {
                var response = client.GetAsync("https://example.net/api/data").Result;
            }
        }
// {/fact}
    }
}