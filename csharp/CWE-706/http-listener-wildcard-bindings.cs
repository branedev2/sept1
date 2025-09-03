using System;
using System.Net;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;

namespace HttpListenerExamples
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Examples can be called here
        }
// {fact rule=module-injection@v1.0 defects=1}

        // True Positive Examples (Vulnerable)

        public static void bad_case_1()
        {
            HttpListener listener = new HttpListener();
            // ruleid: http-listener-wildcard-bindings
            listener.Prefixes.Add("http://*:8080/");
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=1}

        public static void bad_case_2()
        {
            HttpListener listener = new HttpListener();
            // ruleid: http-listener-wildcard-bindings
            listener.Prefixes.Add("http://+:9090/api/");
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=1}

        public static void bad_case_3()
        {
            string prefix = "http://*:7070/";
            HttpListener listener = new HttpListener();
            // ruleid: http-listener-wildcard-bindings
            listener.Prefixes.Add(prefix);
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=1}

        public static void bad_case_4()
        {
            var prefixes = new List<string> { "http://+:8000/", "https://+:8001/" };
            HttpListener listener = new HttpListener();
            
            foreach (var prefix in prefixes)
            {
                // ruleid: http-listener-wildcard-bindings
                listener.Prefixes.Add(prefix);
            }
            
            listener.Start();
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=1}

        public static void bad_case_5()
        {
            HttpListener listener = new HttpListener();
            string port = "5000";
            // ruleid: http-listener-wildcard-bindings
            listener.Prefixes.Add($"http://*:{port}/");
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=1}

        public static async Task bad_case_6()
        {
            HttpListener listener = new HttpListener();
            // ruleid: http-listener-wildcard-bindings
            listener.Prefixes.Add("https://+:443/secure/");
            listener.Start();
            
            while (true)
            {
                var context = await listener.GetContextAsync();
                // Process request
            }
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=1}

        public static void bad_case_7()
        {
            var listener = new HttpListener();
            int port = 8888;
            // ruleid: http-listener-wildcard-bindings
            listener.Prefixes.Add(string.Format("http://*:{0}/", port));
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=1}

        public static void bad_case_8()
        {
            HttpListener listener = new HttpListener();
            // ruleid: http-listener-wildcard-bindings
            listener.Prefixes.Add("http://+:80/");
            // ruleid: http-listener-wildcard-bindings
            listener.Prefixes.Add("https://+:443/");
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=1}

        public static void bad_case_9()
        {
            var config = new Dictionary<string, string>
            {
                { "prefix", "http://*:3000/" }
            };
            
            HttpListener listener = new HttpListener();
            // ruleid: http-listener-wildcard-bindings
            listener.Prefixes.Add(config["prefix"]);
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=1}

        public static void bad_case_10()
        {
            HttpListener listener = new HttpListener();
            string wildcard = "*";
            // ruleid: http-listener-wildcard-bindings
            listener.Prefixes.Add($"http://{wildcard}:8080/api/");
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=1}

        public static void bad_case_11()
        {
            var ports = new[] { 8080, 8081, 8082 };
            HttpListener listener = new HttpListener();
            
            foreach (var port in ports)
            {
                // ruleid: http-listener-wildcard-bindings
                listener.Prefixes.Add($"http://+:{port}/");
            }
            
            listener.Start();
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=1}

        public static void bad_case_12()
        {
            string protocol = "http";
            string wildcard = "+";
            string port = "9000";
            
            HttpListener listener = new HttpListener();
            // ruleid: http-listener-wildcard-bindings
            listener.Prefixes.Add($"{protocol}://{wildcard}:{port}/");
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=1}

        public static void bad_case_13()
        {
            HttpListener listener = new HttpListener();
            bool useWildcard = true;
            string host = useWildcard ? "*" : "localhost";
            
            // ruleid: http-listener-wildcard-bindings
            listener.Prefixes.Add($"http://{host}:8080/");
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=1}

        public static void bad_case_14()
        {
            var builder = new WebHostBuilder()
                // ruleid: http-listener-wildcard-bindings
                .UseUrls("http://*:5000", "https://*:5001")
                .UseKestrel()
                .Configure(app => app.Run(async context => 
                {
                    await context.Response.WriteAsync("Hello World!");
                }));
            
            var host = builder.Build();
            host.Run();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=1}

        public static void bad_case_15()
        {
            string[] args = { "--urls", "http://+:5000" };
            
            // ruleid: http-listener-wildcard-bindings
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                })
                .Build()
                .Run();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=0}

        // True Negative Examples (Secure)

        public static void good_case_1()
        {
            HttpListener listener = new HttpListener();
            // ok: http-listener-wildcard-bindings
            listener.Prefixes.Add("http://localhost:8080/");
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=0}

        public static void good_case_2()
        {
            HttpListener listener = new HttpListener();
            // ok: http-listener-wildcard-bindings
            listener.Prefixes.Add("http://127.0.0.1:9090/api/");
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=0}

        public static void good_case_3()
        {
            string prefix = "http://example.com:7070/";
            HttpListener listener = new HttpListener();
            // ok: http-listener-wildcard-bindings
            listener.Prefixes.Add(prefix);
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=0}

        public static void good_case_4()
        {
            var prefixes = new List<string> { "http://api.example.com:8000/", "https://api.example.com:8001/" };
            HttpListener listener = new HttpListener();
            
            foreach (var prefix in prefixes)
            {
                // ok: http-listener-wildcard-bindings
                listener.Prefixes.Add(prefix);
            }
            
            listener.Start();
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=0}

        public static void good_case_5()
        {
            HttpListener listener = new HttpListener();
            string domain = "myapp.example.com";
            string port = "5000";
            // ok: http-listener-wildcard-bindings
            listener.Prefixes.Add($"http://{domain}:{port}/");
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=0}

        public static async Task good_case_6()
        {
            HttpListener listener = new HttpListener();
            // ok: http-listener-wildcard-bindings
            listener.Prefixes.Add("https://secure.example.com:443/secure/");
            listener.Start();
            
            while (true)
            {
                var context = await listener.GetContextAsync();
                // Process request
            }
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=0}

        public static void good_case_7()
        {
            var listener = new HttpListener();
            int port = 8888;
            // ok: http-listener-wildcard-bindings
            listener.Prefixes.Add(string.Format("http://localhost:{0}/", port));
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=0}

        public static void good_case_8()
        {
            HttpListener listener = new HttpListener();
            // ok: http-listener-wildcard-bindings
            listener.Prefixes.Add("http://api.internal.example.com:80/");
            // ok: http-listener-wildcard-bindings
            listener.Prefixes.Add("https://api.internal.example.com:443/");
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=0}

        public static void good_case_9()
        {
            var config = new Dictionary<string, string>
            {
                { "prefix", "http://localhost:3000/" }
            };
            
            HttpListener listener = new HttpListener();
            // ok: http-listener-wildcard-bindings
            listener.Prefixes.Add(config["prefix"]);
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=0}

        public static void good_case_10()
        {
            HttpListener listener = new HttpListener();
            // ok: http-listener-wildcard-bindings
            listener.Prefixes.Add("http://192.168.1.100:8080/api/");
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=0}

        public static void good_case_11()
        {
            // Subdomain wildcard is safe if you control the entire parent domain
            HttpListener listener = new HttpListener();
            // ok: http-listener-wildcard-bindings
            listener.Prefixes.Add("http://*.example.com:8080/");
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=0}

        public static void good_case_12()
        {
            string protocol = "http";
            string domain = "api.example.com";
            string port = "9000";
            
            HttpListener listener = new HttpListener();
            // ok: http-listener-wildcard-bindings
            listener.Prefixes.Add($"{protocol}://{domain}:{port}/");
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=0}

        public static void good_case_13()
        {
            HttpListener listener = new HttpListener();
            bool useLocalhost = true;
            string host = useLocalhost ? "localhost" : "api.example.com";
            
            // ok: http-listener-wildcard-bindings
            listener.Prefixes.Add($"http://{host}:8080/");
            listener.Start();
            
            // Process requests
            listener.Stop();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=0}

        public static void good_case_14()
        {
            var builder = new WebHostBuilder()
                // ok: http-listener-wildcard-bindings
                .UseUrls("http://localhost:5000", "https://localhost:5001")
                .UseKestrel()
                .Configure(app => app.Run(async context => 
                {
                    await context.Response.WriteAsync("Hello World!");
                }));
            
            var host = builder.Build();
            host.Run();
        }
// {/fact}
// {fact rule=module-injection@v1.0 defects=0}

        public static void good_case_15()
        {
            string[] args = { "--urls", "http://localhost:5000" };
            
            // ok: http-listener-wildcard-bindings
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                })
                .Build()
                .Run();
        }
// {/fact}
    }

    public class Startup
    {
        public void Configure(IApplicationBuilder app)
        {
            app.Run(async context =>
            {
                await context.Response.WriteAsync("Hello World!");
            });
        }
    }
}