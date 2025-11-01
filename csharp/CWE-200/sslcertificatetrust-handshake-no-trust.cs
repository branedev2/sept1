using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http;
using System.Threading.Tasks;
using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Net.Sockets;

namespace SSLCertificateTrustHandshakeExamples
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Main method for running the examples
            Console.WriteLine("SSL Certificate Trust Handshake Examples");
        }
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        // True Positive Examples (Vulnerable Code)

        public static void bad_case_1()
        {
            var sslOptions = new SslClientAuthenticationOptions
            {
                // ruleid: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = true,
                TargetHost = "example.com"
            };

            using (var client = new TcpClient("example.com", 443))
            using (var sslStream = new SslStream(client.GetStream()))
            {
                sslStream.AuthenticateAsClient("example.com", null, System.Security.Authentication.SslProtocols.Tls12, false);
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public static void bad_case_2()
        {
            var handler = new HttpClientHandler();
            var sslOptions = new SslClientAuthenticationOptions();
            // ruleid: sslcertificatetrust-handshake-no-trust
            sslOptions.SendTrustInHandshake = true;
            sslOptions.TargetHost = "api.example.org";

            using (var client = new HttpClient(handler))
            {
                var response = client.GetAsync("https://api.example.org").Result;
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public static void bad_case_3()
        {
            var clientCertificates = new X509CertificateCollection();
            clientCertificates.Add(new X509Certificate2("client.pfx", "password"));
            
            var sslOptions = new SslClientAuthenticationOptions
            {
                ClientCertificates = clientCertificates,
                // ruleid: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = true
            };
            
            using (var client = new TcpClient("secure.example.com", 443))
            using (var sslStream = new SslStream(client.GetStream(), false))
            {
                sslStream.AuthenticateAsClient("secure.example.com", clientCertificates, System.Security.Authentication.SslProtocols.Tls12, false);
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public static async Task bad_case_4()
        {
            using (var client = new TcpClient())
            {
                await client.ConnectAsync("api.service.com", 443);
                using (var sslStream = new SslStream(client.GetStream(), false))
                {
                    var options = new SslClientAuthenticationOptions
                    {
                        TargetHost = "api.service.com",
                        EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12,
                        // ruleid: sslcertificatetrust-handshake-no-trust
                        SendTrustInHandshake = true
                    };
                    
                    await sslStream.AuthenticateAsClientAsync(options);
                }
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public static void bad_case_5()
        {
            var handler = new SocketsHttpHandler();
            var sslOptions = new SslClientAuthenticationOptions
            {
                // ruleid: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = true
            };
            
            handler.SslOptions = sslOptions;
            
            using (var client = new HttpClient(handler))
            {
                var response = client.GetAsync("https://example.com").Result;
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public static void bad_case_6()
        {
            var options = new SslClientAuthenticationOptions();
            options.TargetHost = "secure.api.com";
            options.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12;
            // ruleid: sslcertificatetrust-handshake-no-trust
            options.SendTrustInHandshake = true;
            
            using (var client = new TcpClient("secure.api.com", 443))
            using (var sslStream = new SslStream(client.GetStream()))
            {
                sslStream.AuthenticateAsClientAsync(options).Wait();
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public static async Task bad_case_7()
        {
            var handler = new HttpClientHandler();
            var socketHandler = new SocketsHttpHandler();
            
            socketHandler.SslOptions = new SslClientAuthenticationOptions
            {
                // ruleid: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = true,
                CertificateRevocationCheckMode = X509RevocationMode.Online
            };
            
            using (var client = new HttpClient(socketHandler))
            {
                await client.GetAsync("https://api.example.com");
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public static void bad_case_8()
        {
            bool isSecure = true;
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = "payment.example.com",
                // ruleid: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = isSecure // Still true, just using a variable
            };
            
            using (var tcpClient = new TcpClient("payment.example.com", 443))
            using (var sslStream = new SslStream(tcpClient.GetStream()))
            {
                sslStream.AuthenticateAsClientAsync(options).Wait();
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public static void bad_case_9()
        {
            var config = new
            {
                Host = "api.example.com",
                Port = 443,
                SendTrust = true
            };
            
            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = config.Host,
                // ruleid: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = config.SendTrust
            };
            
            using (var client = new TcpClient(config.Host, config.Port))
            using (var sslStream = new SslStream(client.GetStream()))
            {
                sslStream.AuthenticateAsClientAsync(sslOptions).Wait();
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public static void bad_case_10()
        {
            var handler = new SocketsHttpHandler();
            
            // Configure SSL options with insecure settings
            var sslOptions = new SslClientAuthenticationOptions();
            sslOptions.TargetHost = "example.com";
            // ruleid: sslcertificatetrust-handshake-no-trust
            sslOptions.SendTrustInHandshake = true;
            
            handler.SslOptions = sslOptions;
            
            using (var client = new HttpClient(handler))
            {
                var response = client.GetStringAsync("https://example.com").Result;
                Console.WriteLine(response);
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public static void bad_case_11()
        {
            using (var tcpClient = new TcpClient())
            {
                tcpClient.Connect("secure.example.org", 443);
                using (var sslStream = new SslStream(tcpClient.GetStream(), false))
                {
                    var options = new SslClientAuthenticationOptions
                    {
                        TargetHost = "secure.example.org",
                        // ruleid: sslcertificatetrust-handshake-no-trust
                        SendTrustInHandshake = true,
                        RemoteCertificateValidationCallback = (sender, certificate, chain, errors) => true // Also insecure, but not the focus of this rule
                    };
                    
                    sslStream.AuthenticateAsClientAsync(options).Wait();
                }
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public static void bad_case_12()
        {
            var socketHandler = new SocketsHttpHandler();
            
            // Create options with insecure settings
            var options = new SslClientAuthenticationOptions
            {
                // ruleid: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = true,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12
            };
            
            socketHandler.SslOptions = options;
            
            using (var client = new HttpClient(socketHandler))
            {
                var response = client.GetAsync("https://api.example.com").Result;
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public static async Task bad_case_13()
        {
            var clientCertificate = new X509Certificate2("client.pfx", "password");
            var clientCertificates = new X509CertificateCollection { clientCertificate };
            
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = "api.service.com",
                ClientCertificates = clientCertificates,
                // ruleid: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = true
            };
            
            using (var client = new TcpClient())
            {
                await client.ConnectAsync("api.service.com", 443);
                using (var sslStream = new SslStream(client.GetStream()))
                {
                    await sslStream.AuthenticateAsClientAsync(options);
                }
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public static void bad_case_14()
        {
            var handler = new HttpClientHandler();
            var socketHandler = new SocketsHttpHandler();
            
            // Set insecure SSL options
            socketHandler.SslOptions = new SslClientAuthenticationOptions
            {
                // ruleid: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = true
            };
            
            // Create a client with the handler
            using (var client = new HttpClient(socketHandler))
            {
                try
                {
                    var response = client.GetAsync("https://api.example.com").Result;
                    Console.WriteLine($"Status: {response.StatusCode}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public static void bad_case_15()
        {
            // Create a function that configures SSL options
            SslClientAuthenticationOptions ConfigureSslOptions()
            {
                return new SslClientAuthenticationOptions
                {
                    TargetHost = "example.com",
                    // ruleid: sslcertificatetrust-handshake-no-trust
                    SendTrustInHandshake = true,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12
                };
            }
            
            var options = ConfigureSslOptions();
            
            using (var client = new TcpClient("example.com", 443))
            using (var sslStream = new SslStream(client.GetStream()))
            {
                sslStream.AuthenticateAsClientAsync(options).Wait();
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        public static void good_case_1()
        {
            var sslOptions = new SslClientAuthenticationOptions
            {
                // ok: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = false,
                TargetHost = "example.com"
            };

            using (var client = new TcpClient("example.com", 443))
            using (var sslStream = new SslStream(client.GetStream()))
            {
                sslStream.AuthenticateAsClient("example.com", null, System.Security.Authentication.SslProtocols.Tls12, false);
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public static void good_case_2()
        {
            var handler = new HttpClientHandler();
            var sslOptions = new SslClientAuthenticationOptions();
            // ok: sslcertificatetrust-handshake-no-trust
            sslOptions.SendTrustInHandshake = false;
            sslOptions.TargetHost = "api.example.org";

            using (var client = new HttpClient(handler))
            {
                var response = client.GetAsync("https://api.example.org").Result;
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public static void good_case_3()
        {
            var clientCertificates = new X509CertificateCollection();
            clientCertificates.Add(new X509Certificate2("client.pfx", "password"));
            
            var sslOptions = new SslClientAuthenticationOptions
            {
                ClientCertificates = clientCertificates,
                // ok: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = false
            };
            
            using (var client = new TcpClient("secure.example.com", 443))
            using (var sslStream = new SslStream(client.GetStream(), false))
            {
                sslStream.AuthenticateAsClient("secure.example.com", clientCertificates, System.Security.Authentication.SslProtocols.Tls12, false);
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public static async Task good_case_4()
        {
            using (var client = new TcpClient())
            {
                await client.ConnectAsync("api.service.com", 443);
                using (var sslStream = new SslStream(client.GetStream(), false))
                {
                    var options = new SslClientAuthenticationOptions
                    {
                        TargetHost = "api.service.com",
                        EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12,
                        // ok: sslcertificatetrust-handshake-no-trust
                        SendTrustInHandshake = false
                    };
                    
                    await sslStream.AuthenticateAsClientAsync(options);
                }
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public static void good_case_5()
        {
            var handler = new SocketsHttpHandler();
            var sslOptions = new SslClientAuthenticationOptions
            {
                // ok: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = false
            };
            
            handler.SslOptions = sslOptions;
            
            using (var client = new HttpClient(handler))
            {
                var response = client.GetAsync("https://example.com").Result;
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public static void good_case_6()
        {
            // Using the default value (which is false)
            var options = new SslClientAuthenticationOptions();
            options.TargetHost = "secure.api.com";
            options.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12;
            // ok: sslcertificatetrust-handshake-no-trust
            // Not setting SendTrustInHandshake explicitly uses the default value of false
            
            using (var client = new TcpClient("secure.api.com", 443))
            using (var sslStream = new SslStream(client.GetStream()))
            {
                sslStream.AuthenticateAsClientAsync(options).Wait();
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public static async Task good_case_7()
        {
            var handler = new HttpClientHandler();
            var socketHandler = new SocketsHttpHandler();
            
            socketHandler.SslOptions = new SslClientAuthenticationOptions
            {
                // ok: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = false,
                CertificateRevocationCheckMode = X509RevocationMode.Online
            };
            
            using (var client = new HttpClient(socketHandler))
            {
                await client.GetAsync("https://api.example.com");
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public static void good_case_8()
        {
            bool isSecure = false;
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = "payment.example.com",
                // ok: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = isSecure
            };
            
            using (var tcpClient = new TcpClient("payment.example.com", 443))
            using (var sslStream = new SslStream(tcpClient.GetStream()))
            {
                sslStream.AuthenticateAsClientAsync(options).Wait();
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public static void good_case_9()
        {
            var config = new
            {
                Host = "api.example.com",
                Port = 443,
                SendTrust = false
            };
            
            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = config.Host,
                // ok: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = config.SendTrust
            };
            
            using (var client = new TcpClient(config.Host, config.Port))
            using (var sslStream = new SslStream(client.GetStream()))
            {
                sslStream.AuthenticateAsClientAsync(sslOptions).Wait();
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public static void good_case_10()
        {
            var handler = new SocketsHttpHandler();
            
            // Configure SSL options with secure settings
            var sslOptions = new SslClientAuthenticationOptions();
            sslOptions.TargetHost = "example.com";
            // ok: sslcertificatetrust-handshake-no-trust
            sslOptions.SendTrustInHandshake = false;
            
            handler.SslOptions = sslOptions;
            
            using (var client = new HttpClient(handler))
            {
                var response = client.GetStringAsync("https://example.com").Result;
                Console.WriteLine(response);
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public static void good_case_11()
        {
            using (var tcpClient = new TcpClient())
            {
                tcpClient.Connect("secure.example.org", 443);
                using (var sslStream = new SslStream(tcpClient.GetStream(), false))
                {
                    var options = new SslClientAuthenticationOptions
                    {
                        TargetHost = "secure.example.org",
                        // ok: sslcertificatetrust-handshake-no-trust
                        SendTrustInHandshake = false,
                        RemoteCertificateValidationCallback = (sender, certificate, chain, errors) => 
                        {
                            // Proper certificate validation logic
                            return errors == SslPolicyErrors.None;
                        }
                    };
                    
                    sslStream.AuthenticateAsClientAsync(options).Wait();
                }
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public static void good_case_12()
        {
            var socketHandler = new SocketsHttpHandler();
            
            // Create options with secure settings
            var options = new SslClientAuthenticationOptions
            {
                // ok: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = false,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12
            };
            
            socketHandler.SslOptions = options;
            
            using (var client = new HttpClient(socketHandler))
            {
                var response = client.GetAsync("https://api.example.com").Result;
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public static async Task good_case_13()
        {
            var clientCertificate = new X509Certificate2("client.pfx", "password");
            var clientCertificates = new X509CertificateCollection { clientCertificate };
            
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = "api.service.com",
                ClientCertificates = clientCertificates,
                // ok: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = false
            };
            
            using (var client = new TcpClient())
            {
                await client.ConnectAsync("api.service.com", 443);
                using (var sslStream = new SslStream(client.GetStream()))
                {
                    await sslStream.AuthenticateAsClientAsync(options);
                }
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public static void good_case_14()
        {
            var handler = new HttpClientHandler();
            var socketHandler = new SocketsHttpHandler();
            
            // Set secure SSL options
            socketHandler.SslOptions = new SslClientAuthenticationOptions
            {
                // ok: sslcertificatetrust-handshake-no-trust
                SendTrustInHandshake = false
            };
            
            // Create a client with the handler
            using (var client = new HttpClient(socketHandler))
            {
                try
                {
                    var response = client.GetAsync("https://api.example.com").Result;
                    Console.WriteLine($"Status: {response.StatusCode}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public static void good_case_15()
        {
            // Create a function that configures SSL options
            SslClientAuthenticationOptions ConfigureSslOptions()
            {
                return new SslClientAuthenticationOptions
                {
                    TargetHost = "example.com",
                    // ok: sslcertificatetrust-handshake-no-trust
                    SendTrustInHandshake = false,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12
                };
            }
            
            var options = ConfigureSslOptions();
            
            using (var client = new TcpClient("example.com", 443))
            using (var sslStream = new SslStream(client.GetStream()))
            {
                sslStream.AuthenticateAsClientAsync(options).Wait();
            }
        }
// {/fact}
    }
}