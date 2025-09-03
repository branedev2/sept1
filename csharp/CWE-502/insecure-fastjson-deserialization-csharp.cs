using System;
using System.IO;
using System.Net;
using System.Web;
using System.Web.Mvc;
using System.Collections.Generic;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System.Threading.Tasks;
using System.Net.Http;

namespace InsecureFastJsonDeserializationExamples
{
    public class User
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public List<string> Roles { get; set; }
    }

    public class Product
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public decimal Price { get; set; }
    }

    public class ApiController : Controller
    {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public void bad_case_1()
        {
            var httpRequest = HttpContext.Request;
            string jsonData = new StreamReader(httpRequest.Body).ReadToEnd();
            
            var settings = new JsonSerializerSettings();
            // ruleid: insecure-fastjson-deserialization-csharp
            settings.TypeNameHandling = TypeNameHandling.All;
            settings.BadListTypeChecking = false;
            
            var user = JsonConvert.DeserializeObject<User>(jsonData, settings);
            ProcessUser(user);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_2(HttpRequest request)
        {
            string jsonData = request.Form["userData"];
            
            var settings = new JsonSerializerSettings
            {
                // ruleid: insecure-fastjson-deserialization-csharp
                BadListTypeChecking = false,
                TypeNameHandling = TypeNameHandling.Objects
            };
            
            var product = JsonConvert.DeserializeObject<Product>(jsonData, settings);
            SaveProduct(product);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        [HttpPost]
        public IActionResult bad_case_3([FromBody] string jsonData)
        {
            var settings = new JsonSerializerSettings();
            settings.TypeNameHandling = TypeNameHandling.Auto;
            // ruleid: insecure-fastjson-deserialization-csharp
            settings.BadListTypeChecking = false;
            
            var userData = JsonConvert.DeserializeObject(jsonData, settings);
            return Json(userData);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_4()
        {
            var client = new HttpClient();
            var response = client.GetAsync("https://external-api.com/data").Result;
            string jsonData = response.Content.ReadAsStringAsync().Result;
            
            // ruleid: insecure-fastjson-deserialization-csharp
            var settings = new JsonSerializerSettings { BadListTypeChecking = false };
            var data = JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonData, settings);
            ProcessData(data);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        [HttpPost("api/import")]
        public async Task<IActionResult> bad_case_5()
        {
            using (var reader = new StreamReader(Request.Body))
            {
                string jsonData = await reader.ReadToEndAsync();
                
                var settings = new JsonSerializerSettings();
                // ruleid: insecure-fastjson-deserialization-csharp
                settings.BadListTypeChecking = false;
                
                var importData = JsonConvert.DeserializeObject(jsonData, settings);
                return Ok(importData);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public IActionResult bad_case_6()
        {
            string jsonData = Request.Headers["X-Custom-Data"];
            
            var settings = new JsonSerializerSettings();
            settings.TypeNameHandling = TypeNameHandling.All;
            // ruleid: insecure-fastjson-deserialization-csharp
            settings.BadListTypeChecking = false;
            
            var result = JsonConvert.DeserializeObject(jsonData, typeof(object), settings);
            return Ok(result);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        [HttpPost]
        public void bad_case_7(IFormFile file)
        {
            if (file != null)
            {
                using (var reader = new StreamReader(file.OpenReadStream()))
                {
                    string jsonData = reader.ReadToEnd();
                    
                    // ruleid: insecure-fastjson-deserialization-csharp
                    var settings = new JsonSerializerSettings { BadListTypeChecking = false };
                    var userData = JsonConvert.DeserializeObject<List<User>>(jsonData, settings);
                    ProcessUsers(userData);
                }
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_8()
        {
            string jsonData = Request.Cookies["userData"];
            if (!string.IsNullOrEmpty(jsonData))
            {
                var settings = new JsonSerializerSettings();
                // ruleid: insecure-fastjson-deserialization-csharp
                settings.BadListTypeChecking = false;
                settings.TypeNameHandling = TypeNameHandling.Objects;
                
                var user = JsonConvert.DeserializeObject<User>(jsonData, settings);
                UpdateUserProfile(user);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public IActionResult bad_case_9(string id)
        {
            var apiClient = new HttpClient();
            var response = apiClient.GetAsync($"https://api.example.com/users/{id}").Result;
            string jsonData = response.Content.ReadAsStringAsync().Result;
            
            var settings = new JsonSerializerSettings();
            // ruleid: insecure-fastjson-deserialization-csharp
            settings.BadListTypeChecking = false;
            
            var user = JsonConvert.DeserializeObject<User>(jsonData, settings);
            return View(user);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        [HttpPost]
        public void bad_case_10()
        {
            var formData = Request.Form;
            string jsonData = formData["config"];
            
            var settings = new JsonSerializerSettings
            {
                // ruleid: insecure-fastjson-deserialization-csharp
                BadListTypeChecking = false,
                TypeNameHandling = TypeNameHandling.Arrays
            };
            
            var config = JsonConvert.DeserializeObject(jsonData, settings);
            ApplyConfiguration(config);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_11(HttpContext context)
        {
            string jsonData = context.Request.Query["data"];
            
            var settings = new JsonSerializerSettings();
            // ruleid: insecure-fastjson-deserialization-csharp
            settings.BadListTypeChecking = false;
            
            dynamic result = JsonConvert.DeserializeObject(jsonData, settings);
            ProcessDynamicData(result);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        [HttpPost("api/webhook")]
        public async Task<IActionResult> bad_case_12()
        {
            using (var reader = new StreamReader(Request.Body))
            {
                string payload = await reader.ReadToEndAsync();
                
                var settings = new JsonSerializerSettings();
                settings.TypeNameHandling = TypeNameHandling.All;
                // ruleid: insecure-fastjson-deserialization-csharp
                settings.BadListTypeChecking = false;
                
                var webhookData = JsonConvert.DeserializeObject(payload, settings);
                ProcessWebhook(webhookData);
                return Ok();
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_13()
        {
            WebClient client = new WebClient();
            string jsonData = client.DownloadString("https://external-service.com/api/data");
            
            // ruleid: insecure-fastjson-deserialization-csharp
            var settings = new JsonSerializerSettings { BadListTypeChecking = false };
            var data = JsonConvert.DeserializeObject(jsonData, settings);
            
            ProcessExternalData(data);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        [HttpGet]
        public IActionResult bad_case_14(string configJson)
        {
            if (!string.IsNullOrEmpty(configJson))
            {
                var settings = new JsonSerializerSettings();
                // ruleid: insecure-fastjson-deserialization-csharp
                settings.BadListTypeChecking = false;
                
                var config = JsonConvert.DeserializeObject(configJson, settings);
                return Json(new { success = true, config });
            }
            return BadRequest();
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_15()
        {
            string jsonData = Request.Headers["Authorization"].ToString().Split(' ')[1]; // Bearer token
            
            var settings = new JsonSerializerSettings
            {
                // ruleid: insecure-fastjson-deserialization-csharp
                BadListTypeChecking = false,
                TypeNameHandling = TypeNameHandling.Objects
            };
            
            var tokenData = JsonConvert.DeserializeObject(jsonData, settings);
            ValidateToken(tokenData);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        public void good_case_1()
        {
            var httpRequest = HttpContext.Request;
            string jsonData = new StreamReader(httpRequest.Body).ReadToEnd();
            
            var settings = new JsonSerializerSettings();
            // ok: insecure-fastjson-deserialization-csharp
            settings.BadListTypeChecking = true;
            
            var user = JsonConvert.DeserializeObject<User>(jsonData, settings);
            ProcessUser(user);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_2(HttpRequest request)
        {
            string jsonData = request.Form["userData"];
            
            // ok: insecure-fastjson-deserialization-csharp
            var settings = new JsonSerializerSettings { BadListTypeChecking = true };
            var product = JsonConvert.DeserializeObject<Product>(jsonData, settings);
            SaveProduct(product);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        [HttpPost]
        public IActionResult good_case_3([FromBody] string jsonData)
        {
            // Using default settings which has BadListTypeChecking = true by default
            // ok: insecure-fastjson-deserialization-csharp
            var userData = JsonConvert.DeserializeObject(jsonData);
            return Json(userData);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_4()
        {
            var client = new HttpClient();
            var response = client.GetAsync("https://trusted-internal-api.com/data").Result;
            string jsonData = response.Content.ReadAsStringAsync().Result;
            
            // Even with BadListTypeChecking = false, this is safe because we're using a trusted source
            // ok: insecure-fastjson-deserialization-csharp
            var settings = new JsonSerializerSettings { BadListTypeChecking = false };
            var data = JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonData, settings);
            ProcessData(data);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        [HttpPost("api/import")]
        public async Task<IActionResult> good_case_5()
        {
            using (var reader = new StreamReader(Request.Body))
            {
                string jsonData = await reader.ReadToEndAsync();
                
                // ok: insecure-fastjson-deserialization-csharp
                var settings = new JsonSerializerSettings { BadListTypeChecking = true };
                var importData = JsonConvert.DeserializeObject(jsonData, settings);
                return Ok(importData);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public IActionResult good_case_6()
        {
            string jsonData = Request.Headers["X-Custom-Data"];
            
            // ok: insecure-fastjson-deserialization-csharp
            var settings = new JsonSerializerSettings { BadListTypeChecking = true };
            var result = JsonConvert.DeserializeObject(jsonData, typeof(object), settings);
            return Ok(result);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        [HttpPost]
        public void good_case_7(IFormFile file)
        {
            if (file != null)
            {
                using (var reader = new StreamReader(file.OpenReadStream()))
                {
                    string jsonData = reader.ReadToEnd();
                    
                    // Using default settings (BadListTypeChecking = true)
                    // ok: insecure-fastjson-deserialization-csharp
                    var userData = JsonConvert.DeserializeObject<List<User>>(jsonData);
                    ProcessUsers(userData);
                }
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_8()
        {
            string jsonData = Request.Cookies["userData"];
            if (!string.IsNullOrEmpty(jsonData))
            {
                var settings = new JsonSerializerSettings();
                // ok: insecure-fastjson-deserialization-csharp
                settings.BadListTypeChecking = true;
                
                var user = JsonConvert.DeserializeObject<User>(jsonData, settings);
                UpdateUserProfile(user);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public IActionResult good_case_9(string id)
        {
            // Validate and sanitize the ID parameter
            if (!int.TryParse(id, out int userId) || userId <= 0)
            {
                return BadRequest("Invalid user ID");
            }
            
            var apiClient = new HttpClient();
            var response = apiClient.GetAsync($"https://api.example.com/users/{userId}").Result;
            string jsonData = response.Content.ReadAsStringAsync().Result;
            
            // ok: insecure-fastjson-deserialization-csharp
            var settings = new JsonSerializerSettings { BadListTypeChecking = true };
            var user = JsonConvert.DeserializeObject<User>(jsonData, settings);
            return View(user);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        [HttpPost]
        public void good_case_10()
        {
            var formData = Request.Form;
            string jsonData = formData["config"];
            
            // ok: insecure-fastjson-deserialization-csharp
            var settings = new JsonSerializerSettings { BadListTypeChecking = true };
            var config = JsonConvert.DeserializeObject(jsonData, settings);
            ApplyConfiguration(config);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_11(HttpContext context)
        {
            string jsonData = context.Request.Query["data"];
            
            // Using default settings (BadListTypeChecking = true)
            // ok: insecure-fastjson-deserialization-csharp
            dynamic result = JsonConvert.DeserializeObject(jsonData);
            ProcessDynamicData(result);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        [HttpPost("api/webhook")]
        public async Task<IActionResult> good_case_12()
        {
            using (var reader = new StreamReader(Request.Body))
            {
                string payload = await reader.ReadToEndAsync();
                
                var settings = new JsonSerializerSettings();
                // ok: insecure-fastjson-deserialization-csharp
                settings.BadListTypeChecking = true;
                
                var webhookData = JsonConvert.DeserializeObject(payload, settings);
                ProcessWebhook(webhookData);
                return Ok();
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_13()
        {
            WebClient client = new WebClient();
            string jsonData = client.DownloadString("https://external-service.com/api/data");
            
            // Validate the JSON structure before deserializing
            if (IsValidJsonStructure(jsonData))
            {
                // ok: insecure-fastjson-deserialization-csharp
                var settings = new JsonSerializerSettings { BadListTypeChecking = true };
                var data = JsonConvert.DeserializeObject(jsonData, settings);
                ProcessExternalData(data);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        [HttpGet]
        public IActionResult good_case_14(string configJson)
        {
            if (!string.IsNullOrEmpty(configJson))
            {
                // ok: insecure-fastjson-deserialization-csharp
                var settings = new JsonSerializerSettings { BadListTypeChecking = true };
                var config = JsonConvert.DeserializeObject(configJson, settings);
                return Json(new { success = true, config });
            }
            return BadRequest();
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_15()
        {
            string jsonData = Request.Headers["Authorization"].ToString().Split(' ')[1]; // Bearer token
            
            // ok: insecure-fastjson-deserialization-csharp
            var settings = new JsonSerializerSettings { BadListTypeChecking = true };
            var tokenData = JsonConvert.DeserializeObject(jsonData, settings);
            ValidateToken(tokenData);
        }
// {/fact}

        // Helper methods
        private void ProcessUser(User user) { /* Implementation */ }
        private void SaveProduct(Product product) { /* Implementation */ }
        private void ProcessData(Dictionary<string, object> data) { /* Implementation */ }
        private void ProcessUsers(List<User> users) { /* Implementation */ }
        private void UpdateUserProfile(User user) { /* Implementation */ }
        private void ApplyConfiguration(object config) { /* Implementation */ }
        private void ProcessDynamicData(dynamic data) { /* Implementation */ }
        private void ProcessWebhook(object webhookData) { /* Implementation */ }
        private void ProcessExternalData(object data) { /* Implementation */ }
        private void ValidateToken(object tokenData) { /* Implementation */ }
        private bool IsValidJsonStructure(string json) { return true; /* Implementation */ }
    }
}