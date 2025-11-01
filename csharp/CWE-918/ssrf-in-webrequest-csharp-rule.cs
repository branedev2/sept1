using System;
using System.IO;
using System.Net;
using System.Web;
using System.Text;
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Hosting;

namespace SSRFTestCases
{
    public class SSRFExamples : Controller
    {
// {fact rule=server-side-request-forgery@v1.0 defects=1}
        // TRUE POSITIVES (Vulnerable Code)

        public IActionResult bad_case_1()
        {
            // Taking URL directly from query parameter
            string url = Request.Query["url"];
            
            // ruleid: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(url);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                string responseText = reader.ReadToEnd();
                return Content(responseText);
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_2()
        {
            // Taking URL from form data
            string url = Request.Form["target_url"];
            
            try
            {
                // ruleid: ssrf-in-webrequest-csharp-rule
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.Method = "GET";
                
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                {
                    return Content(reader.ReadToEnd());
                }
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_3()
        {
            // URL from header
            string apiEndpoint = Request.Headers["X-Api-Endpoint"];
            string finalUrl = "https://" + apiEndpoint + "/api/data";
            
            // ruleid: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(finalUrl);
            request.Method = "POST";
            
            using (var streamWriter = new StreamWriter(request.GetRequestStream()))
            {
                streamWriter.Write("{}");
            }
            
            WebResponse response = request.GetResponse();
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_4()
        {
            // URL from cookie
            string serviceUrl = Request.Cookies["preferred_service"];
            
            // Basic string manipulation but still vulnerable
            string processedUrl = serviceUrl.Trim().ToLower();
            
            // ruleid: ssrf-in-webrequest-csharp-rule
            FtpWebRequest request = (FtpWebRequest)WebRequest.Create(processedUrl);
            request.Method = WebRequestMethods.Ftp.DownloadFile;
            
            using (FtpWebResponse response = (FtpWebResponse)request.GetResponse())
            using (Stream responseStream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(responseStream))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_5()
        {
            // URL from route parameter
            string id = RouteData.Values["id"].ToString();
            string apiUrl = $"https://api.example.com/users/{id}/profile";
            
            // Concatenation with user input is still vulnerable
            if (Request.Query.ContainsKey("format"))
            {
                apiUrl += "?format=" + Request.Query["format"];
            }
            
            // ruleid: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(apiUrl);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_6()
        {
            // URL from JSON body
            var body = new StreamReader(Request.Body).ReadToEndAsync().Result;
            dynamic data = Newtonsoft.Json.JsonConvert.DeserializeObject(body);
            string serviceEndpoint = data.service_endpoint;
            
            // ruleid: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(serviceEndpoint);
            request.ContentType = "application/json";
            
            WebResponse response = request.GetResponse();
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_7()
        {
            // URL from multiple parameters
            string host = Request.Query["host"];
            string path = Request.Query["path"];
            string protocol = Request.Query["protocol"] ?? "https";
            
            string url = $"{protocol}://{host}/{path}";
            
            // ruleid: ssrf-in-webrequest-csharp-rule
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            
            using (WebResponse response = request.GetResponse())
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_8()
        {
            // URL with conditional logic but still vulnerable
            string baseUrl = "https://api.example.com";
            string endpoint;
            
            if (Request.Query.ContainsKey("endpoint"))
            {
                endpoint = Request.Query["endpoint"];
            }
            else
            {
                endpoint = "default";
            }
            
            string finalUrl = $"{baseUrl}/{endpoint}";
            
            // ruleid: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(finalUrl);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_9()
        {
            // URL from encoded parameter
            string encodedUrl = Request.Query["data"];
            string decodedUrl = HttpUtility.UrlDecode(encodedUrl);
            
            // ruleid: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(decodedUrl);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_10()
        {
            // URL with some basic validation that's insufficient
            string url = Request.Query["url"];
            
            if (!url.StartsWith("http"))
            {
                url = "https://" + url;
            }
            
            // ruleid: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(url);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_11()
        {
            // URL with string replacement but still vulnerable
            string template = "https://api.{0}.example.com/v1/data";
            string tenant = Request.Query["tenant"];
            string url = string.Format(template, tenant);
            
            // ruleid: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(url);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_12()
        {
            // URL from header with some processing
            string callbackUrl = Request.Headers["X-Callback-URL"];
            
            if (string.IsNullOrEmpty(callbackUrl))
            {
                callbackUrl = "https://default-api.example.com";
            }
            
            // ruleid: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(callbackUrl);
            request.Method = "POST";
            
            using (var streamWriter = new StreamWriter(request.GetRequestStream()))
            {
                streamWriter.Write("{\"status\":\"complete\"}");
            }
            
            WebResponse response = request.GetResponse();
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_13()
        {
            // URL with path traversal attempt blocked but still SSRF vulnerable
            string path = Request.Query["path"];
            
            // Block path traversal attempts
            path = path.Replace("..", "");
            
            string url = "https://api.example.com/" + path;
            
            // ruleid: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(url);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_14()
        {
            // URL from multiple sources
            string service = Request.Query["service"] ?? "users";
            string action = Request.Form["action"] ?? "get";
            string id = RouteData.Values["id"]?.ToString() ?? "1";
            
            string url = $"https://api.example.com/{service}/{action}/{id}";
            
            // ruleid: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(url);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_15()
        {
            // URL with attempted sanitization that's insufficient
            string url = Request.Query["url"];
            
            // Attempt to limit to specific domain but still vulnerable
            if (!url.Contains("example.com"))
            {
                url = "https://example.com/api/proxy?target=" + url;
            }
            
            // ruleid: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(url);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        // TRUE NEGATIVES (Safe Code)

        public IActionResult good_case_1()
        {
            // Using a hardcoded URL
            string url = "https://api.example.com/data";
            
            // ok: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(url);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                string responseText = reader.ReadToEnd();
                return Content(responseText);
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_2()
        {
            // Using a whitelist of allowed domains
            string requestedDomain = Request.Query["domain"];
            
            List<string> allowedDomains = new List<string> 
            { 
                "api.example.com", 
                "cdn.example.com", 
                "static.example.com" 
            };
            
            if (!allowedDomains.Contains(requestedDomain))
            {
                return BadRequest("Domain not allowed");
            }
            
            string url = $"https://{requestedDomain}/api/data";
            
            // ok: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(url);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_3()
        {
            // Using regex pattern matching for URL validation
            string path = Request.Query["path"];
            
            // Validate path format strictly
            if (!Regex.IsMatch(path, @"^[a-zA-Z0-9\-_/]+$"))
            {
                return BadRequest("Invalid path format");
            }
            
            string url = $"https://api.example.com/{path}";
            
            // ok: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(url);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_4()
        {
            // Using URI validation
            string inputUrl = Request.Query["url"];
            
            if (!Uri.TryCreate(inputUrl, UriKind.Absolute, out Uri uri))
            {
                return BadRequest("Invalid URL");
            }
            
            // Validate host is allowed
            if (uri.Host != "api.example.com" && !uri.Host.EndsWith(".example.com"))
            {
                return BadRequest("Host not allowed");
            }
            
            // ok: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(uri);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_5()
        {
            // Using a predefined set of endpoints
            string endpoint = Request.Query["endpoint"];
            
            Dictionary<string, string> allowedEndpoints = new Dictionary<string, string>
            {
                { "users", "https://api.example.com/users" },
                { "products", "https://api.example.com/products" },
                { "orders", "https://api.example.com/orders" }
            };
            
            if (!allowedEndpoints.TryGetValue(endpoint, out string url))
            {
                return BadRequest("Endpoint not allowed");
            }
            
            // ok: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(url);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_6()
        {
            // Using configuration for allowed URLs
            IConfiguration configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .Build();
            
            string serviceName = Request.Query["service"];
            string serviceUrl = configuration[$"Services:{serviceName}:Url"];
            
            if (string.IsNullOrEmpty(serviceUrl))
            {
                return NotFound("Service not configured");
            }
            
            // ok: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(serviceUrl);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_7()
        {
            // Using IP address validation
            string server = Request.Query["server"];
            
            if (!Uri.TryCreate($"https://{server}", UriKind.Absolute, out Uri uri))
            {
                return BadRequest("Invalid server");
            }
            
            // Resolve hostname to check if it's internal
            IPAddress[] addresses = Dns.GetHostAddresses(uri.Host);
            
            foreach (IPAddress address in addresses)
            {
                // Check if IP is internal/private
                if (IsPrivateIpAddress(address))
                {
                    return BadRequest("Cannot access internal servers");
                }
            }
            
            // ok: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(uri);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
        
        private bool IsPrivateIpAddress(IPAddress address)
        {
            byte[] bytes = address.GetAddressBytes();
            
            // Check for private IP ranges
            return (bytes[0] == 10) || 
                   (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) || 
                   (bytes[0] == 192 && bytes[1] == 168) ||
                   (bytes[0] == 127);
        }
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_8()
        {
            // Using a URL builder with validation
            string resourceId = Request.Query["id"];
            
            if (!Regex.IsMatch(resourceId, @"^\d+$"))
            {
                return BadRequest("Invalid resource ID");
            }
            
            // Build URL with validated components
            UriBuilder uriBuilder = new UriBuilder
            {
                Scheme = "https",
                Host = "api.example.com",
                Path = $"/resources/{resourceId}"
            };
            
            // ok: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(uriBuilder.Uri);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_9()
        {
            // Using a proxy service pattern
            string targetResource = Request.Query["resource"];
            
            // Validate resource name format
            if (!Regex.IsMatch(targetResource, @"^[a-zA-Z0-9\-_]+$"))
            {
                return BadRequest("Invalid resource name");
            }
            
            // Use the resource name as a path component in a fixed domain
            string url = $"https://api.example.com/proxy/{targetResource}";
            
            // ok: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(url);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_10()
        {
            // Using a service locator pattern
            string serviceType = Request.Query["service"];
            
            // Map service type to specific endpoints
            Dictionary<string, Func<string>> serviceLocator = new Dictionary<string, Func<string>>
            {
                { "users", () => "https://users.example.com/api" },
                { "billing", () => "https://billing.example.com/api" },
                { "inventory", () => "https://inventory.example.com/api" }
            };
            
            if (!serviceLocator.TryGetValue(serviceType, out Func<string> urlProvider))
            {
                return BadRequest("Unknown service");
            }
            
            string url = urlProvider();
            
            // ok: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(url);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_11()
        {
            // Using URL signing for validation
            string requestedUrl = Request.Query["url"];
            string signature = Request.Query["signature"];
            string secret = Environment.GetEnvironmentVariable("URL_SIGNING_SECRET");
            
            // Validate signature
            string expectedSignature = ComputeHmacSha256(requestedUrl, secret);
            
            if (signature != expectedSignature)
            {
                return BadRequest("Invalid URL signature");
            }
            
            // Parse and validate URL
            if (!Uri.TryCreate(requestedUrl, UriKind.Absolute, out Uri uri) || 
                uri.Host != "api.example.com")
            {
                return BadRequest("Invalid or disallowed URL");
            }
            
            // ok: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(uri);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
        
        private string ComputeHmacSha256(string data, string key)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA256(Encoding.UTF8.GetBytes(key)))
            {
                byte[] hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_12()
        {
            // Using a dedicated HTTP client with preconfigured base address
            HttpClient client = new HttpClient
            {
                BaseAddress = new Uri("https://api.example.com/")
            };
            
            string resourcePath = Request.Query["resource"];
            
            // Validate resource path
            if (!Regex.IsMatch(resourcePath, @"^[a-zA-Z0-9\-_/]+$"))
            {
                return BadRequest("Invalid resource path");
            }
            
            // ok: ssrf-in-webrequest-csharp-rule
            // Using HttpClient instead of WebRequest with validated path
            HttpResponseMessage response = client.GetAsync(resourcePath).Result;
            string content = response.Content.ReadAsStringAsync().Result;
            
            return Content(content);
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_13()
        {
            // Using domain validation with DNS lookup
            string subdomain = Request.Query["subdomain"];
            
            // Validate subdomain format
            if (!Regex.IsMatch(subdomain, @"^[a-zA-Z0-9\-]+$"))
            {
                return BadRequest("Invalid subdomain format");
            }
            
            string hostname = $"{subdomain}.example.com";
            
            try
            {
                // Verify the hostname exists in DNS
                IPHostEntry hostEntry = Dns.GetHostEntry(hostname);
                
                string url = $"https://{hostname}/api/data";
                
                // ok: ssrf-in-webrequest-csharp-rule
                WebRequest request = WebRequest.Create(url);
                WebResponse response = request.GetResponse();
                
                using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                {
                    return Content(reader.ReadToEnd());
                }
            }
            catch (Exception)
            {
                return BadRequest("Invalid or non-existent hostname");
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_14()
        {
            // Using a URL parser and validator
            string inputUrl = Request.Query["url"];
            
            if (!Uri.TryCreate(inputUrl, UriKind.Absolute, out Uri parsedUri))
            {
                return BadRequest("Invalid URL format");
            }
            
            // Check scheme
            if (parsedUri.Scheme != "https")
            {
                return BadRequest("Only HTTPS URLs are allowed");
            }
            
            // Check hostname against allowed patterns
            if (!parsedUri.Host.EndsWith(".example.com") && parsedUri.Host != "example.com")
            {
                return BadRequest("Domain not allowed");
            }
            
            // Check for suspicious port numbers
            if (parsedUri.Port != 443 && parsedUri.Port != 80 && parsedUri.Port != -1)
            {
                return BadRequest("Port not allowed");
            }
            
            // ok: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(parsedUri);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_15()
        {
            // Using environment-specific configuration
            string environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            string apiId = Request.Query["api"];
            
            // Validate API ID format
            if (!Regex.IsMatch(apiId, @"^[a-zA-Z0-9\-]+$"))
            {
                return BadRequest("Invalid API identifier");
            }
            
            // Get URL from configuration based on environment
            Dictionary<string, Dictionary<string, string>> apiEndpoints = new Dictionary<string, Dictionary<string, string>>
            {
                { "Development", new Dictionary<string, string> {
                    { "users", "https://dev-api.example.com/users" },
                    { "products", "https://dev-api.example.com/products" }
                }},
                { "Production", new Dictionary<string, string> {
                    { "users", "https://api.example.com/users" },
                    { "products", "https://api.example.com/products" }
                }}
            };
            
            if (!apiEndpoints.TryGetValue(environment, out var endpoints) || 
                !endpoints.TryGetValue(apiId, out string url))
            {
                return BadRequest("API endpoint not configured");
            }
            
            // ok: ssrf-in-webrequest-csharp-rule
            WebRequest request = WebRequest.Create(url);
            WebResponse response = request.GetResponse();
            
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }
// {/fact}
    }
}