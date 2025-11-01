using System;
using System.IO;
using System.Net;
using System.Web;
using System.Web.Mvc;
using System.Web.Http;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Xml.Serialization;
using System.Text.Json;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using System.Net.Http;

namespace DeserializationExamples
{
    public class SerializationExamples
    {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public void bad_case_1(HttpRequest request)
        {
            // Using BinaryFormatter to deserialize user input from a request parameter
            string base64Data = request.QueryString["data"];
            byte[] bytes = Convert.FromBase64String(base64Data);
            
            using (MemoryStream ms = new MemoryStream(bytes))
            {
                // ruleid: untrusted-deserialization-csharp-rule
                BinaryFormatter formatter = new BinaryFormatter();
                object obj = formatter.Deserialize(ms);
                // Use the deserialized object
                Console.WriteLine(obj.ToString());
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        [HttpPost]
        public ActionResult bad_case_2()
        {
            // Using BinaryFormatter to deserialize user input from a request body
            HttpRequest request = System.Web.HttpContext.Current.Request;
            Stream inputStream = request.InputStream;
            inputStream.Position = 0;
            
            // ruleid: untrusted-deserialization-csharp-rule
            BinaryFormatter formatter = new BinaryFormatter();
            object deserializedObject = formatter.Deserialize(inputStream);
            
            return new ContentResult { Content = "Processed: " + deserializedObject.ToString() };
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        [System.Web.Http.HttpGet]
        public IHttpActionResult bad_case_3(string id)
        {
            // Using BinaryFormatter with data from a cookie
            HttpCookie cookie = HttpContext.Current.Request.Cookies["userdata"];
            if (cookie != null)
            {
                byte[] bytes = Convert.FromBase64String(cookie.Value);
                using (MemoryStream ms = new MemoryStream(bytes))
                {
                    // ruleid: untrusted-deserialization-csharp-rule
                    BinaryFormatter formatter = new BinaryFormatter();
                    object obj = formatter.Deserialize(ms);
                    return Ok("Data processed: " + obj.ToString());
                }
            }
            return BadRequest("No cookie found");
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        [Microsoft.AspNetCore.Mvc.HttpPost]
        public async Task<IActionResult> bad_case_4()
        {
            // Using BinaryFormatter with data from request body in ASP.NET Core
            using (MemoryStream ms = new MemoryStream())
            {
                await HttpContext.Request.Body.CopyToAsync(ms);
                ms.Position = 0;
                
                // ruleid: untrusted-deserialization-csharp-rule
                BinaryFormatter formatter = new BinaryFormatter();
                object result = formatter.Deserialize(ms);
                
                return Ok(new { success = true, data = result.ToString() });
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_5(HttpRequest request)
        {
            // Using NetDataContractSerializer with untrusted data
            string data = request.Form["serializedData"];
            byte[] bytes = Convert.FromBase64String(data);
            
            using (MemoryStream ms = new MemoryStream(bytes))
            {
                // ruleid: untrusted-deserialization-csharp-rule
                NetDataContractSerializer serializer = new NetDataContractSerializer();
                object obj = serializer.Deserialize(ms);
                ProcessObject(obj);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        [HttpGet]
        public string bad_case_6()
        {
            // Using LosFormatter with data from query string
            string data = HttpContext.Current.Request.QueryString["data"];
            
            // ruleid: untrusted-deserialization-csharp-rule
            System.Web.UI.LosFormatter formatter = new System.Web.UI.LosFormatter();
            object result = formatter.Deserialize(data);
            
            return "Processed: " + result.ToString();
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_7(HttpListenerContext context)
        {
            // Using BinaryFormatter with data from HTTP listener
            HttpListenerRequest request = context.Request;
            Stream body = request.InputStream;
            
            // ruleid: untrusted-deserialization-csharp-rule
            BinaryFormatter formatter = new BinaryFormatter();
            object obj = formatter.Deserialize(body);
            
            context.Response.StatusCode = 200;
            context.Response.Close();
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        [Microsoft.AspNetCore.Mvc.HttpPost("api/data")]
        public IActionResult bad_case_8([FromBody] string base64Data)
        {
            // Using ObjectStateFormatter with untrusted input
            try
            {
                byte[] bytes = Convert.FromBase64String(base64Data);
                using (MemoryStream ms = new MemoryStream(bytes))
                {
                    // ruleid: untrusted-deserialization-csharp-rule
                    System.Web.UI.ObjectStateFormatter formatter = new System.Web.UI.ObjectStateFormatter();
                    object result = formatter.Deserialize(ms);
                    return Ok(result);
                }
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_9(HttpRequest request)
        {
            // Using SoapFormatter with untrusted data
            string data = request.Headers["X-Serialized-Data"];
            byte[] bytes = Convert.FromBase64String(data);
            
            using (MemoryStream ms = new MemoryStream(bytes))
            {
                // ruleid: untrusted-deserialization-csharp-rule
                System.Runtime.Serialization.Formatters.Soap.SoapFormatter formatter = 
                    new System.Runtime.Serialization.Formatters.Soap.SoapFormatter();
                object obj = formatter.Deserialize(ms);
                Console.WriteLine(obj.ToString());
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        [HttpPost]
        public async Task<ActionResult> bad_case_10()
        {
            // Using BinaryFormatter with a custom wrapper class
            using (StreamReader reader = new StreamReader(HttpContext.Current.Request.InputStream))
            {
                string requestData = await reader.ReadToEndAsync();
                byte[] bytes = Convert.FromBase64String(requestData);
                
                using (MemoryStream ms = new MemoryStream(bytes))
                {
                    // ruleid: untrusted-deserialization-csharp-rule
                    BinaryFormatter formatter = new BinaryFormatter();
                    CustomDataWrapper wrapper = (CustomDataWrapper)formatter.Deserialize(ms);
                    return new JsonResult { Data = wrapper.Data, JsonRequestBehavior = JsonRequestBehavior.AllowGet };
                }
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        [Microsoft.AspNetCore.Mvc.HttpPost]
        public IActionResult bad_case_11([FromForm] IFormFile file)
        {
            // Using BinaryFormatter with uploaded file
            if (file != null && file.Length > 0)
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    file.CopyTo(ms);
                    ms.Position = 0;
                    
                    // ruleid: untrusted-deserialization-csharp-rule
                    BinaryFormatter formatter = new BinaryFormatter();
                    object result = formatter.Deserialize(ms);
                    
                    return Ok(result);
                }
            }
            return BadRequest("No file uploaded");
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_12(HttpRequest request)
        {
            // Using DataContractSerializer with untrusted data
            string xml = request.Form["xmlData"];
            using (MemoryStream ms = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(xml)))
            {
                // ruleid: untrusted-deserialization-csharp-rule
                DataContractSerializer serializer = new DataContractSerializer(typeof(UserData));
                UserData userData = (UserData)serializer.ReadObject(ms);
                ProcessUserData(userData);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        [HttpGet]
        public ActionResult bad_case_13(string id)
        {
            // Using BinaryFormatter with data from a database that originally came from user input
            byte[] serializedData = GetSerializedDataFromDatabase(id); // Assume this gets previously stored user data
            
            using (MemoryStream ms = new MemoryStream(serializedData))
            {
                // ruleid: untrusted-deserialization-csharp-rule
                BinaryFormatter formatter = new BinaryFormatter();
                object obj = formatter.Deserialize(ms);
                return View("Details", obj);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public async Task<string> bad_case_14()
        {
            // Using BinaryFormatter with data from an external API that might be compromised
            using (HttpClient client = new HttpClient())
            {
                byte[] response = await client.GetByteArrayAsync("https://external-api.com/data");
                
                using (MemoryStream ms = new MemoryStream(response))
                {
                    // ruleid: untrusted-deserialization-csharp-rule
                    BinaryFormatter formatter = new BinaryFormatter();
                    object result = formatter.Deserialize(ms);
                    return result.ToString();
                }
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        [Microsoft.AspNetCore.Mvc.HttpPost]
        public IActionResult bad_case_15([FromBody] SerializedDataWrapper wrapper)
        {
            // Using BinaryFormatter with data wrapped in JSON
            if (wrapper != null && !string.IsNullOrEmpty(wrapper.Base64Data))
            {
                byte[] bytes = Convert.FromBase64String(wrapper.Base64Data);
                using (MemoryStream ms = new MemoryStream(bytes))
                {
                    // ruleid: untrusted-deserialization-csharp-rule
                    BinaryFormatter formatter = new BinaryFormatter();
                    object result = formatter.Deserialize(ms);
                    return Ok(new { success = true, data = result });
                }
            }
            return BadRequest("Invalid data");
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        public void good_case_1(HttpRequest request)
        {
            // Using JSON deserialization with type restrictions instead of BinaryFormatter
            string jsonData = request.QueryString["data"];
            
            // ok: untrusted-deserialization-csharp-rule
            UserData userData = System.Text.Json.JsonSerializer.Deserialize<UserData>(
                jsonData, 
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            );
            
            Console.WriteLine(userData.Username);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        [HttpPost]
        public ActionResult good_case_2()
        {
            // Using XML serializer with a specific type instead of BinaryFormatter
            HttpRequest request = System.Web.HttpContext.Current.Request;
            Stream inputStream = request.InputStream;
            inputStream.Position = 0;
            
            // ok: untrusted-deserialization-csharp-rule
            XmlSerializer serializer = new XmlSerializer(typeof(UserData));
            UserData userData = (UserData)serializer.Deserialize(inputStream);
            
            return new ContentResult { Content = "Processed: " + userData.Username };
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        [System.Web.Http.HttpGet]
        public IHttpActionResult good_case_3(string id)
        {
            // Using JSON.NET with type restrictions instead of BinaryFormatter
            HttpCookie cookie = HttpContext.Current.Request.Cookies["userdata"];
            if (cookie != null)
            {
                // ok: untrusted-deserialization-csharp-rule
                UserData userData = JsonConvert.DeserializeObject<UserData>(
                    cookie.Value, 
                    new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None }
                );
                return Ok("Data processed: " + userData.Username);
            }
            return BadRequest("No cookie found");
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        [Microsoft.AspNetCore.Mvc.HttpPost]
        public async Task<IActionResult> good_case_4()
        {
            // Using System.Text.Json with ASP.NET Core
            using (StreamReader reader = new StreamReader(HttpContext.Request.Body))
            {
                string json = await reader.ReadToEndAsync();
                
                // ok: untrusted-deserialization-csharp-rule
                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    AllowTrailingCommas = true
                };
                UserData userData = System.Text.Json.JsonSerializer.Deserialize<UserData>(json, options);
                
                return Ok(new { success = true, username = userData.Username });
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_5(HttpRequest request)
        {
            // Manual parsing of data instead of using deserialization
            string username = request.Form["username"];
            string email = request.Form["email"];
            int age;
            
            // ok: untrusted-deserialization-csharp-rule
            if (int.TryParse(request.Form["age"], out age))
            {
                UserData userData = new UserData
                {
                    Username = username,
                    Email = email,
                    Age = age
                };
                ProcessUserData(userData);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        [HttpGet]
        public string good_case_6()
        {
            // Using a custom parser for specific data format instead of deserialization
            string data = HttpContext.Current.Request.QueryString["data"];
            
            // ok: untrusted-deserialization-csharp-rule
            string[] parts = data.Split(',');
            if (parts.Length >= 3)
            {
                UserData userData = new UserData
                {
                    Username = parts[0],
                    Email = parts[1],
                    Age = int.Parse(parts[2])
                };
                return "Processed: " + userData.Username;
            }
            return "Invalid data format";
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_7(HttpListenerContext context)
        {
            // Using JSON deserialization with type restrictions
            HttpListenerRequest request = context.Request;
            
            using (StreamReader reader = new StreamReader(request.InputStream))
            {
                string json = reader.ReadToEnd();
                
                // ok: untrusted-deserialization-csharp-rule
                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };
                UserData userData = System.Text.Json.JsonSerializer.Deserialize<UserData>(json, options);
                
                context.Response.StatusCode = 200;
                context.Response.Close();
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        [Microsoft.AspNetCore.Mvc.HttpPost("api/data")]
        public IActionResult good_case_8([FromBody] UserDataDto dto)
        {
            // Using model binding and validation instead of deserialization
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            
            // ok: untrusted-deserialization-csharp-rule
            UserData userData = new UserData
            {
                Username = dto.Username,
                Email = dto.Email,
                Age = dto.Age
            };
            
            return Ok(userData);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_9(HttpRequest request)
        {
            // Using DataContractJsonSerializer with known types
            string json = request.Headers["X-User-Data"];
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(json);
            
            using (MemoryStream ms = new MemoryStream(bytes))
            {
                // ok: untrusted-deserialization-csharp-rule
                System.Runtime.Serialization.Json.DataContractJsonSerializer serializer = 
                    new System.Runtime.Serialization.Json.DataContractJsonSerializer(typeof(UserData));
                UserData userData = (UserData)serializer.ReadObject(ms);
                Console.WriteLine(userData.Username);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        [HttpPost]
        public async Task<ActionResult> good_case_10()
        {
            // Using JSON.NET with secure settings
            using (StreamReader reader = new StreamReader(HttpContext.Current.Request.InputStream))
            {
                string json = await reader.ReadToEndAsync();
                
                // ok: untrusted-deserialization-csharp-rule
                JsonSerializerSettings settings = new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.None,
                    MaxDepth = 10
                };
                UserData userData = JsonConvert.DeserializeObject<UserData>(json, settings);
                
                return new JsonResult { Data = userData, JsonRequestBehavior = JsonRequestBehavior.AllowGet };
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        [Microsoft.AspNetCore.Mvc.HttpPost]
        public async Task<IActionResult> good_case_11([FromForm] IFormFile file)
        {
            // Parsing CSV file instead of deserializing binary data
            if (file != null && file.Length > 0)
            {
                using (StreamReader reader = new StreamReader(file.OpenReadStream()))
                {
                    string content = await reader.ReadToEndAsync();
                    
                    // ok: untrusted-deserialization-csharp-rule
                    List<UserData> users = ParseCsvToUserData(content);
                    return Ok(users);
                }
            }
            return BadRequest("No file uploaded");
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_12(HttpRequest request)
        {
            // Using XmlSerializer with specific type and validation
            string xml = request.Form["xmlData"];
            
            // Validate XML against schema first
            if (ValidateXmlAgainstSchema(xml))
            {
                using (StringReader reader = new StringReader(xml))
                {
                    // ok: untrusted-deserialization-csharp-rule
                    XmlSerializer serializer = new XmlSerializer(typeof(UserData));
                    UserData userData = (UserData)serializer.Deserialize(reader);
                    ProcessUserData(userData);
                }
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        [HttpGet]
        public ActionResult good_case_13(string id)
        {
            // Using a data access layer to retrieve data instead of deserializing
            // ok: untrusted-deserialization-csharp-rule
            UserData userData = UserDataRepository.GetById(id);
            if (userData != null)
            {
                return View("Details", userData);
            }
            return NotFound();
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public async Task<string> good_case_14()
        {
            // Using strongly typed HTTP client to get data
            using (HttpClient client = new HttpClient())
            {
                string json = await client.GetStringAsync("https://external-api.com/data");
                
                // ok: untrusted-deserialization-csharp-rule
                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };
                ApiResponse response = System.Text.Json.JsonSerializer.Deserialize<ApiResponse>(json, options);
                return response.Message;
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        [Microsoft.AspNetCore.Mvc.HttpPost]
        public IActionResult good_case_15([FromBody] UserDataDto dto)
        {
            // Using a mapper to convert DTO to domain object
            if (dto == null)
            {
                return BadRequest("Invalid data");
            }
            
            // ok: untrusted-deserialization-csharp-rule
            UserData userData = new UserData
            {
                Username = SanitizeInput(dto.Username),
                Email = ValidateEmail(dto.Email),
                Age = Math.Max(0, Math.Min(120, dto.Age)) // Constrain age to reasonable values
            };
            
            return Ok(new { success = true, data = userData });
        }
// {/fact}

        // Helper methods and classes
        private void ProcessObject(object obj)
        {
            // Process the object
        }

        private void ProcessUserData(UserData userData)
        {
            // Process user data
        }

        private byte[] GetSerializedDataFromDatabase(string id)
        {
            // Simulate getting data from database
            return new byte[0];
        }

        private List<UserData> ParseCsvToUserData(string csvContent)
        {
            // Parse CSV to user data
            return new List<UserData>();
        }

        private bool ValidateXmlAgainstSchema(string xml)
        {
            // Validate XML against schema
            return true;
        }

        private string SanitizeInput(string input)
        {
            // Sanitize input
            return input?.Trim();
        }

        private string ValidateEmail(string email)
        {
            // Validate email
            return email;
        }
    }

    [Serializable]
    public class UserData
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public int Age { get; set; }
    }

    public class UserDataDto
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public int Age { get; set; }
    }

    [Serializable]
    public class CustomDataWrapper
    {
        public object Data { get; set; }
    }

    public class SerializedDataWrapper
    {
        public string Base64Data { get; set; }
    }

    public class ApiResponse
    {
        public string Message { get; set; }
    }

    public static class UserDataRepository
    {
        public static UserData GetById(string id)
        {
            // Get user data by ID
            return new UserData();
        }
    }
}