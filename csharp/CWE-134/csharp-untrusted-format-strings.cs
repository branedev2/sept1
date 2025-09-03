using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

namespace FormatStringVulnerabilityExamples
{
    public class FormatStringExamples
    {
// {fact rule=untrusted-format-strings@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public void bad_case_1(HttpRequest request)
        {
            string userInput = request.Query["format"].ToString();
            
            // ruleid: csharp-untrusted-format-strings
            string result = string.Format(userInput, "sensitive data", 42, DateTime.Now);
            Console.WriteLine(result);
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

        public void bad_case_2(HttpContext context)
        {
            string formatString = context.Request.Headers["X-Format-Template"].ToString();
            
            // ruleid: csharp-untrusted-format-strings
            Console.WriteLine(string.Format(formatString, Environment.UserName, Environment.MachineName));
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

        public void bad_case_3()
        {
            using (var client = new WebClient())
            {
                string formatTemplate = client.DownloadString("http://example.com/format-template.txt");
                
                // ruleid: csharp-untrusted-format-strings
                string formattedOutput = string.Format(formatTemplate, "confidential", 12345, true);
                Console.WriteLine(formattedOutput);
            }
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

        public async Task bad_case_4()
        {
            using (var httpClient = new HttpClient())
            {
                string formatPattern = await httpClient.GetStringAsync("https://example.com/api/formats");
                
                // ruleid: csharp-untrusted-format-strings
                string result = string.Format(formatPattern, "secret", 987654);
                Console.WriteLine(result);
            }
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

        public void bad_case_5()
        {
            string formatString = File.ReadAllText("user_format.txt");
            
            // ruleid: csharp-untrusted-format-strings
            string output = string.Format(formatString, Environment.GetEnvironmentVariable("API_KEY"), 
                                         Environment.GetEnvironmentVariable("DB_PASSWORD"));
            Console.WriteLine(output);
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

        public void bad_case_6(HttpRequest request)
        {
            string userFormat = request.Form["customFormat"];
            object[] args = { "sensitive", 42, DateTime.Now };
            
            // ruleid: csharp-untrusted-format-strings
            Console.WriteLine(string.Format(userFormat, args));
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

        public void bad_case_7()
        {
            using (var reader = new StreamReader("network_data.txt"))
            {
                string formatTemplate = reader.ReadLine();
                
                // ruleid: csharp-untrusted-format-strings
                string message = string.Format(formatTemplate, "username", "password", 123);
                Console.WriteLine(message);
            }
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

        public void bad_case_8(HttpContext context)
        {
            var formatCookie = context.Request.Cookies["format-preference"];
            
            // ruleid: csharp-untrusted-format-strings
            string formatted = string.Format(formatCookie, 
                                           Environment.GetEnvironmentVariable("SECRET_KEY"),
                                           DateTime.Now);
            context.Response.WriteAsync(formatted);
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

        public void bad_case_9()
        {
            TcpListener server = new TcpListener(IPAddress.Any, 8080);
            server.Start();
            
            TcpClient client = server.AcceptTcpClient();
            NetworkStream stream = client.GetStream();
            
            byte[] bytes = new byte[1024];
            stream.Read(bytes, 0, bytes.Length);
            string formatString = Encoding.UTF8.GetString(bytes);
            
            // ruleid: csharp-untrusted-format-strings
            string result = string.Format(formatString, "internal", 42, "data");
            
            byte[] response = Encoding.UTF8.GetBytes(result);
            stream.Write(response, 0, response.Length);
            
            client.Close();
            server.Stop();
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

        public void bad_case_10(HttpRequest request)
        {
            string userInput = request.Query["template"].ToString();
            var data = new { Name = "John", Password = "secret123", Id = 42 };
            
            // ruleid: csharp-untrusted-format-strings
            string.Format(userInput, data.Name, data.Password, data.Id);
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

        public void bad_case_11()
        {
            using (var client = new WebClient())
            {
                string formatTemplate = client.DownloadString("http://example.com/template.txt");
                var sensitiveData = new { ApiKey = "ak_12345", Token = "t_67890" };
                
                // ruleid: csharp-untrusted-format-strings
                string output = string.Format(formatTemplate, sensitiveData.ApiKey, sensitiveData.Token);
                File.WriteAllText("output.log", output);
            }
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

        public async Task bad_case_12(HttpContext context)
        {
            string body;
            using (var reader = new StreamReader(context.Request.Body))
            {
                body = await reader.ReadToEndAsync();
            }
            
            // ruleid: csharp-untrusted-format-strings
            string formatted = string.Format(body, DateTime.Now, Environment.UserName, 
                                           Environment.GetEnvironmentVariable("DB_CONNECTION"));
            await context.Response.WriteAsync(formatted);
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

        public void bad_case_13()
        {
            string formatPattern = "";
            using (var fileStream = new FileStream("user_input.txt", FileMode.Open))
            using (var streamReader = new StreamReader(fileStream))
            {
                formatPattern = streamReader.ReadToEnd();
            }
            
            // ruleid: csharp-untrusted-format-strings
            Console.WriteLine(string.Format(formatPattern, "admin", "password123", 42));
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

        public void bad_case_14(HttpRequest request)
        {
            string formatString = request.Headers["X-Format"].ToString();
            StringBuilder sb = new StringBuilder();
            
            // ruleid: csharp-untrusted-format-strings
            sb.AppendFormat(formatString, "confidential", 12345, DateTime.Now);
            Console.WriteLine(sb.ToString());
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

        public void bad_case_15()
        {
            using (var client = new WebClient())
            {
                string formatTemplate = client.DownloadString("http://example.com/formats/complex.txt");
                object[] args = { "secret", 42, true, DateTime.Now };
                
                // ruleid: csharp-untrusted-format-strings
                TextWriter writer = Console.Out;
                writer.Write(string.Format(formatTemplate, args));
            }
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

        // True Negative Examples (Safe Code)

        public void good_case_1(HttpRequest request)
        {
            string userInput = request.Query["data"].ToString();
            
            // ok: csharp-untrusted-format-strings
            string result = string.Format("User input: {0}", userInput);
            Console.WriteLine(result);
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

        public void good_case_2(HttpContext context)
        {
            string userName = context.Request.Headers["X-User-Name"].ToString();
            
            // ok: csharp-untrusted-format-strings
            Console.WriteLine($"Welcome, {userName}!");
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

        public void good_case_3()
        {
            using (var client = new WebClient())
            {
                string data = client.DownloadString("http://example.com/data.txt");
                
                // ok: csharp-untrusted-format-strings
                string formattedOutput = string.Format("Downloaded data: {0}", data);
                Console.WriteLine(formattedOutput);
            }
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

        public async Task good_case_4()
        {
            using (var httpClient = new HttpClient())
            {
                string apiResponse = await httpClient.GetStringAsync("https://example.com/api/data");
                
                // ok: csharp-untrusted-format-strings
                string result = $"API response: {apiResponse}";
                Console.WriteLine(result);
            }
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

        public void good_case_5()
        {
            string userData = File.ReadAllText("user_data.txt");
            
            // ok: csharp-untrusted-format-strings
            string output = string.Format("User data: {0}", userData);
            Console.WriteLine(output);
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

        public void good_case_6(HttpRequest request)
        {
            string userInput = request.Form["input"];
            
            // ok: csharp-untrusted-format-strings
            Console.WriteLine("You entered: {0}", userInput);
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

        public void good_case_7()
        {
            using (var reader = new StreamReader("network_data.txt"))
            {
                string data = reader.ReadLine();
                
                // ok: csharp-untrusted-format-strings
                string message = $"Received data: {data}";
                Console.WriteLine(message);
            }
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

        public void good_case_8(HttpContext context)
        {
            var userPreference = context.Request.Cookies["user-preference"];
            
            // ok: csharp-untrusted-format-strings
            string formatted = string.Format("Your preference is: {0}", userPreference);
            context.Response.WriteAsync(formatted);
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

        public void good_case_9()
        {
            TcpListener server = new TcpListener(IPAddress.Any, 8080);
            server.Start();
            
            TcpClient client = server.AcceptTcpClient();
            NetworkStream stream = client.GetStream();
            
            byte[] bytes = new byte[1024];
            stream.Read(bytes, 0, bytes.Length);
            string receivedData = Encoding.UTF8.GetString(bytes);
            
            // ok: csharp-untrusted-format-strings
            string result = string.Format("Server received: {0}", receivedData);
            
            byte[] response = Encoding.UTF8.GetBytes(result);
            stream.Write(response, 0, response.Length);
            
            client.Close();
            server.Stop();
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

        public void good_case_10(HttpRequest request)
        {
            string userInput = request.Query["input"].ToString();
            var data = new { Name = "John", Id = 42 };
            
            // ok: csharp-untrusted-format-strings
            string output = $"User input: {userInput}, Name: {data.Name}, ID: {data.Id}";
            Console.WriteLine(output);
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

        public void good_case_11()
        {
            using (var client = new WebClient())
            {
                string downloadedData = client.DownloadString("http://example.com/data.txt");
                
                // ok: csharp-untrusted-format-strings
                string output = string.Format("Downloaded content length: {0}", downloadedData.Length);
                File.WriteAllText("output.log", output);
            }
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

        public async Task good_case_12(HttpContext context)
        {
            string body;
            using (var reader = new StreamReader(context.Request.Body))
            {
                body = await reader.ReadToEndAsync();
            }
            
            // ok: csharp-untrusted-format-strings
            string formatted = $"Received body: {body}";
            await context.Response.WriteAsync(formatted);
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

        public void good_case_13()
        {
            string userData = "";
            using (var fileStream = new FileStream("user_input.txt", FileMode.Open))
            using (var streamReader = new StreamReader(fileStream))
            {
                userData = streamReader.ReadToEnd();
            }
            
            // ok: csharp-untrusted-format-strings
            Console.WriteLine("User data from file: {0}", userData);
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

        public void good_case_14(HttpRequest request)
        {
            string headerValue = request.Headers["X-Custom"].ToString();
            StringBuilder sb = new StringBuilder();
            
            // ok: csharp-untrusted-format-strings
            sb.AppendFormat("Header value: {0}", headerValue);
            Console.WriteLine(sb.ToString());
        }
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

        public void good_case_15()
        {
            using (var client = new WebClient())
            {
                string downloadedContent = client.DownloadString("http://example.com/content.txt");
                
                // ok: csharp-untrusted-format-strings
                string safeFormat = "Downloaded content: {0}";
                TextWriter writer = Console.Out;
                writer.Write(string.Format(safeFormat, downloadedContent));
            }
        }
// {/fact}
    }
}