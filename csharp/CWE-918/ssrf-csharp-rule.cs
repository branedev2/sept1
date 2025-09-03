using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.IO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Configuration;
using Microsoft.Extensions.Configuration;
using RestSharp;

namespace SSRFTestCases
{
    public class SSRFExamples : Controller
    {
// {fact rule=server-side-request-forgery@v1.0 defects=1}
        // TRUE POSITIVES (Vulnerable Code)

        public async Task<IActionResult> bad_case_1()
        {
            // Taking user input directly from query parameter
            string url = Request.Query["url"];
            
            using (HttpClient client = new HttpClient())
            {
                // ruleid: ssrf-csharp-rule
                var response = await client.GetAsync(url);
                return Content(await response.Content.ReadAsStringAsync());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public async Task<IActionResult> bad_case_2()
        {
            // Taking user input from form data
            string apiEndpoint = Request.Form["endpoint"];
            string fullUrl = "https://api.example.com" + apiEndpoint;
            
            using (HttpClient client = new HttpClient())
            {
                // ruleid: ssrf-csharp-rule
                var response = await client.GetStringAsync(fullUrl);
                return Content(response);
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_3()
        {
            // Taking user input from route parameter
            string server = RouteData.Values["server"] as string;
            string url = $"http://{server}/api/data";
            
            using (WebClient client = new WebClient())
            {
                // ruleid: ssrf-csharp-rule
                string result = client.DownloadString(url);
                return Content(result);
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public async Task<IActionResult> bad_case_4()
        {
            // Taking user input from header
            string targetHost = Request.Headers["X-Target-Host"];
            string apiPath = "/api/v1/users";
            string fullUrl = $"https://{targetHost}{apiPath}";
            
            using (HttpClient client = new HttpClient())
            {
                // ruleid: ssrf-csharp-rule
                HttpResponseMessage response = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, fullUrl));
                return Content(await response.Content.ReadAsStringAsync());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_5()
        {
            // Taking user input from cookie
            string serviceUrl = Request.Cookies["preferred_service"];
            
            var client = new RestClient();
            var request = new RestRequest(serviceUrl, Method.GET);
            
            // ruleid: ssrf-csharp-rule
            var response = client.Execute(request);
            return Content(response.Content);
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public async Task<IActionResult> bad_case_6()
        {
            // Taking user input with minimal processing
            string baseUrl = "https://api.example.com";
            string endpoint = Request.Query["endpoint"];
            string fullUrl = baseUrl + "/" + endpoint.Trim();
            
            using (HttpClient client = new HttpClient())
            {
                // ruleid: ssrf-csharp-rule
                var response = await client.GetAsync(fullUrl);
                return Content(await response.Content.ReadAsStringAsync());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public async Task<IActionResult> bad_case_7()
        {
            // Taking user input with string concatenation
            string protocol = Request.Query["protocol"];
            string domain = Request.Query["domain"];
            string url = protocol + "://" + domain;
            
            using (HttpClient client = new HttpClient())
            {
                // ruleid: ssrf-csharp-rule
                var response = await client.GetAsync(url);
                return Content(await response.Content.ReadAsStringAsync());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_8()
        {
            // Taking user input with conditional logic
            string targetSystem = Request.Query["system"];
            string url;
            
            if (targetSystem == "internal")
            {
                url = "https://internal.example.com/api";
            }
            else
            {
                url = Request.Query["url"];
            }
            
            using (WebClient client = new WebClient())
            {
                // ruleid: ssrf-csharp-rule
                string result = client.DownloadString(url);
                return Content(result);
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public async Task<IActionResult> bad_case_9()
        {
            // Taking user input from JSON body
            string requestBody = new StreamReader(Request.Body).ReadToEndAsync().Result;
            dynamic data = Newtonsoft.Json.JsonConvert.DeserializeObject(requestBody);
            string serviceUrl = data.serviceUrl;
            
            using (HttpClient client = new HttpClient())
            {
                // ruleid: ssrf-csharp-rule
                var response = await client.GetAsync(serviceUrl);
                return Content(await response.Content.ReadAsStringAsync());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_10()
        {
            // Taking user input with string formatting
            string host = Request.Query["host"];
            int port = int.Parse(Request.Query["port"]);
            string path = Request.Query["path"];
            
            string url = string.Format("http://{0}:{1}/{2}", host, port, path);
            
            using (WebClient client = new WebClient())
            {
                // ruleid: ssrf-csharp-rule
                string result = client.DownloadString(url);
                return Content(result);
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public async Task<IActionResult> bad_case_11()
        {
            // Taking user input with string interpolation
            string subdomain = Request.Query["subdomain"];
            string url = $"https://{subdomain}.example.com/api/data";
            
            using (HttpClient client = new HttpClient())
            {
                // ruleid: ssrf-csharp-rule
                var response = await client.GetAsync(url);
                return Content(await response.Content.ReadAsStringAsync());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_12()
        {
            // Taking user input with loop processing
            string[] servers = Request.Query["servers"].ToString().Split(',');
            string result = "";
            
            using (WebClient client = new WebClient())
            {
                foreach (string server in servers)
                {
                    string url = $"http://{server}/status";
                    // ruleid: ssrf-csharp-rule
                    result += client.DownloadString(url) + "\n";
                }
            }
            
            return Content(result);
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public async Task<IActionResult> bad_case_13()
        {
            // Taking user input with try-catch
            string url = Request.Query["url"];
            
            try
            {
                using (HttpClient client = new HttpClient())
                {
                    // ruleid: ssrf-csharp-rule
                    var response = await client.GetAsync(url);
                    return Content(await response.Content.ReadAsStringAsync());
                }
            }
            catch (Exception ex)
            {
                return BadRequest("Error: " + ex.Message);
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public IActionResult bad_case_14()
        {
            // Taking user input with switch statement
            string serviceType = Request.Query["service"];
            string serviceUrl;
            
            switch (serviceType)
            {
                case "weather":
                    serviceUrl = "https://weather.example.com";
                    break;
                case "news":
                    serviceUrl = "https://news.example.com";
                    break;
                default:
                    serviceUrl = Request.Query["custom_url"];
                    break;
            }
            
            using (WebClient client = new WebClient())
            {
                // ruleid: ssrf-csharp-rule
                string result = client.DownloadString(serviceUrl);
                return Content(result);
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

        public async Task<IActionResult> bad_case_15()
        {
            // Taking user input with dictionary lookup
            var services = new Dictionary<string, string>
            {
                { "service1", "https://service1.example.com" },
                { "service2", "https://service2.example.com" }
            };
            
            string serviceKey = Request.Query["service"];
            string url;
            
            if (services.ContainsKey(serviceKey))
            {
                url = services[serviceKey];
            }
            else
            {
                url = Request.Query["fallback_url"];
            }
            
            using (HttpClient client = new HttpClient())
            {
                // ruleid: ssrf-csharp-rule
                var response = await client.GetAsync(url);
                return Content(await response.Content.ReadAsStringAsync());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        // TRUE NEGATIVES (Safe Code)

        public async Task<IActionResult> good_case_1()
        {
            // Using a hardcoded URL
            string url = "https://api.example.com/data";
            
            using (HttpClient client = new HttpClient())
            {
                // ok: ssrf-csharp-rule
                var response = await client.GetAsync(url);
                return Content(await response.Content.ReadAsStringAsync());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public async Task<IActionResult> good_case_2()
        {
            // Using a whitelist for user input
            string serviceId = Request.Query["service"];
            Dictionary<string, string> allowedServices = new Dictionary<string, string>
            {
                { "weather", "https://weather-api.example.com" },
                { "news", "https://news-api.example.com" },
                { "sports", "https://sports-api.example.com" }
            };
            
            if (!allowedServices.ContainsKey(serviceId))
            {
                return BadRequest("Invalid service");
            }
            
            string url = allowedServices[serviceId];
            
            using (HttpClient client = new HttpClient())
            {
                // ok: ssrf-csharp-rule
                var response = await client.GetAsync(url);
                return Content(await response.Content.ReadAsStringAsync());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_3()
        {
            // Using configuration for URLs instead of user input
            IConfiguration configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .Build();
            
            string apiUrl = configuration["ApiEndpoints:UserService"];
            
            using (WebClient client = new WebClient())
            {
                // ok: ssrf-csharp-rule
                string result = client.DownloadString(apiUrl);
                return Content(result);
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public async Task<IActionResult> good_case_4()
        {
            // Validating URL against allowed domains
            string requestedUrl = Request.Query["url"];
            Uri uri;
            
            if (!Uri.TryCreate(requestedUrl, UriKind.Absolute, out uri))
            {
                return BadRequest("Invalid URL format");
            }
            
            string[] allowedDomains = { "api.example.com", "data.example.com" };
            bool isAllowed = false;
            
            foreach (var domain in allowedDomains)
            {
                if (uri.Host.Equals(domain, StringComparison.OrdinalIgnoreCase))
                {
                    isAllowed = true;
                    break;
                }
            }
            
            if (!isAllowed)
            {
                return BadRequest("Domain not allowed");
            }
            
            using (HttpClient client = new HttpClient())
            {
                // ok: ssrf-csharp-rule
                var response = await client.GetAsync(uri);
                return Content(await response.Content.ReadAsStringAsync());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_5()
        {
            // Using a fixed base URL with validated path
            string path = Request.Query["path"];
            
            // Validate path to prevent directory traversal
            if (path.Contains("..") || path.Contains("//") || !path.StartsWith("/api/"))
            {
                return BadRequest("Invalid path");
            }
            
            string baseUrl = "https://api.example.com";
            string fullUrl = baseUrl + path;
            
            using (WebClient client = new WebClient())
            {
                // ok: ssrf-csharp-rule
                string result = client.DownloadString(fullUrl);
                return Content(result);
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public async Task<IActionResult> good_case_6()
        {
            // Using URL builder with validation
            string resourceId = Request.Query["id"];
            
            // Validate resource ID format
            if (!System.Text.RegularExpressions.Regex.IsMatch(resourceId, "^[a-zA-Z0-9]+$"))
            {
                return BadRequest("Invalid resource ID");
            }
            
            var uriBuilder = new UriBuilder
            {
                Scheme = "https",
                Host = "api.example.com",
                Path = $"/resources/{resourceId}"
            };
            
            using (HttpClient client = new HttpClient())
            {
                // ok: ssrf-csharp-rule
                var response = await client.GetAsync(uriBuilder.Uri);
                return Content(await response.Content.ReadAsStringAsync());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_7()
        {
            // Using enum for predefined services
            string serviceParam = Request.Query["service"];
            
            if (!Enum.TryParse<ServiceType>(serviceParam, true, out ServiceType service))
            {
                return BadRequest("Invalid service type");
            }
            
            string serviceUrl;
            switch (service)
            {
                case ServiceType.Weather:
                    serviceUrl = "https://weather.example.com/api";
                    break;
                case ServiceType.News:
                    serviceUrl = "https://news.example.com/api";
                    break;
                case ServiceType.Sports:
                    serviceUrl = "https://sports.example.com/api";
                    break;
                default:
                    return BadRequest("Service not supported");
            }
            
            using (WebClient client = new WebClient())
            {
                // ok: ssrf-csharp-rule
                string result = client.DownloadString(serviceUrl);
                return Content(result);
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public async Task<IActionResult> good_case_8()
        {
            // Using a service locator pattern
            string serviceName = Request.Query["service"];
            
            var serviceRegistry = new ServiceRegistry();
            string serviceUrl = serviceRegistry.GetServiceUrl(serviceName);
            
            if (string.IsNullOrEmpty(serviceUrl))
            {
                return BadRequest("Unknown service");
            }
            
            using (HttpClient client = new HttpClient())
            {
                // ok: ssrf-csharp-rule
                var response = await client.GetAsync(serviceUrl);
                return Content(await response.Content.ReadAsStringAsync());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_9()
        {
            // Using a numeric ID to construct URL
            string idParam = Request.Query["id"];
            
            if (!int.TryParse(idParam, out int id) || id <= 0)
            {
                return BadRequest("Invalid ID");
            }
            
            string url = $"https://api.example.com/resources/{id}";
            
            using (WebClient client = new WebClient())
            {
                // ok: ssrf-csharp-rule
                string result = client.DownloadString(url);
                return Content(result);
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public async Task<IActionResult> good_case_10()
        {
            // Using URL validation with custom validator
            string url = Request.Query["url"];
            
            var validator = new UrlValidator();
            if (!validator.IsValid(url))
            {
                return BadRequest("Invalid or disallowed URL");
            }
            
            using (HttpClient client = new HttpClient())
            {
                // ok: ssrf-csharp-rule
                var response = await client.GetAsync(url);
                return Content(await response.Content.ReadAsStringAsync());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_11()
        {
            // Using path parameters with fixed domain
            string category = Request.Query["category"];
            string id = Request.Query["id"];
            
            // Validate parameters
            if (string.IsNullOrEmpty(category) || !System.Text.RegularExpressions.Regex.IsMatch(category, "^[a-z]+$"))
            {
                return BadRequest("Invalid category");
            }
            
            if (string.IsNullOrEmpty(id) || !System.Text.RegularExpressions.Regex.IsMatch(id, "^[0-9]+$"))
            {
                return BadRequest("Invalid ID");
            }
            
            string url = $"https://api.example.com/{category}/{id}";
            
            using (WebClient client = new WebClient())
            {
                // ok: ssrf-csharp-rule
                string result = client.DownloadString(url);
                return Content(result);
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public async Task<IActionResult> good_case_12()
        {
            // Using environment-specific configuration
            string environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            string apiBaseUrl;
            
            if (environment == "Production")
            {
                apiBaseUrl = "https://api.example.com";
            }
            else if (environment == "Staging")
            {
                apiBaseUrl = "https://staging-api.example.com";
            }
            else
            {
                apiBaseUrl = "https://dev-api.example.com";
            }
            
            string endpoint = "/users/current";
            string url = apiBaseUrl + endpoint;
            
            using (HttpClient client = new HttpClient())
            {
                // ok: ssrf-csharp-rule
                var response = await client.GetAsync(url);
                return Content(await response.Content.ReadAsStringAsync());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_13()
        {
            // Using a service client with predefined endpoints
            string operation = Request.Query["operation"];
            
            var serviceClient = new ExampleServiceClient();
            string result;
            
            try
            {
                // ok: ssrf-csharp-rule
                result = serviceClient.ExecuteOperation(operation);
                return Content(result);
            }
            catch (ArgumentException)
            {
                return BadRequest("Invalid operation");
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public async Task<IActionResult> good_case_14()
        {
            // Using a factory pattern for creating URLs
            string resourceType = Request.Query["type"];
            string resourceId = Request.Query["id"];
            
            var urlFactory = new ResourceUrlFactory();
            string url = urlFactory.CreateUrl(resourceType, resourceId);
            
            if (string.IsNullOrEmpty(url))
            {
                return BadRequest("Invalid resource type or ID");
            }
            
            using (HttpClient client = new HttpClient())
            {
                // ok: ssrf-csharp-rule
                var response = await client.GetAsync(url);
                return Content(await response.Content.ReadAsStringAsync());
            }
        }
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

        public IActionResult good_case_15()
        {
            // Using a configuration file with allowed endpoints
            string endpoint = Request.Query["endpoint"];
            
            IConfiguration configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .Build();
            
            var allowedEndpoints = configuration.GetSection("AllowedEndpoints")
                .Get<List<string>>();
            
            if (!allowedEndpoints.Contains(endpoint))
            {
                return BadRequest("Endpoint not allowed");
            }
            
            string baseUrl = configuration["ApiSettings:BaseUrl"];
            string url = baseUrl + endpoint;
            
            using (WebClient client = new WebClient())
            {
                // ok: ssrf-csharp-rule
                string result = client.DownloadString(url);
                return Content(result);
            }
        }
// {/fact}
    }

    // Helper classes for the examples
    public enum ServiceType
    {
        Weather,
        News,
        Sports
    }

    public class ServiceRegistry
    {
        private readonly Dictionary<string, string> _services = new Dictionary<string, string>
        {
            { "weather", "https://weather.example.com/api" },
            { "news", "https://news.example.com/api" },
            { "sports", "https://sports.example.com/api" }
        };

        public string GetServiceUrl(string serviceName)
        {
            if (_services.ContainsKey(serviceName))
            {
                return _services[serviceName];
            }
            return null;
        }
    }

    public class UrlValidator
    {
        private readonly string[] _allowedDomains = { "api.example.com", "data.example.com", "services.example.com" };

        public bool IsValid(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return false;
            }

            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uri))
            {
                return false;
            }

            if (uri.Scheme != "https")
            {
                return false;
            }

            foreach (var domain in _allowedDomains)
            {
                if (uri.Host.Equals(domain, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
    }

    public class ExampleServiceClient
    {
        private readonly Dictionary<string, string> _operationEndpoints = new Dictionary<string, string>
        {
            { "getUserProfile", "https://api.example.com/users/profile" },
            { "getProductList", "https://api.example.com/products" },
            { "getOrderStatus", "https://api.example.com/orders/status" }
        };

        public string ExecuteOperation(string operation)
        {
            if (!_operationEndpoints.ContainsKey(operation))
            {
                throw new ArgumentException("Unknown operation");
            }

            string url = _operationEndpoints[operation];
            using (WebClient client = new WebClient())
            {
                return client.DownloadString(url);
            }
        }
    }

    public class ResourceUrlFactory
    {
        public string CreateUrl(string resourceType, string resourceId)
        {
            if (string.IsNullOrEmpty(resourceType) || string.IsNullOrEmpty(resourceId))
            {
                return null;
            }

            if (!System.Text.RegularExpressions.Regex.IsMatch(resourceType, "^[a-z]+$") ||
                !System.Text.RegularExpressions.Regex.IsMatch(resourceId, "^[0-9]+$"))
            {
                return null;
            }

            return $"https://api.example.com/{resourceType}/{resourceId}";
        }
    }
}