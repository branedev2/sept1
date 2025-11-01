using System;
using System.IO;
using System.Net;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace InsecureDeserializationExamples
{
    public class Program
    {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public void bad_case_1(HttpContext context)
        {
            string jsonData = new StreamReader(context.Request.Body).ReadToEnd();
            
            // ruleid: insecure-newtonsoft-deserialization
            JsonSerializerSettings settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            };
            
            var obj = JsonConvert.DeserializeObject(jsonData, settings);
            Console.WriteLine($"Deserialized object: {obj}");
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_2(HttpRequest request)
        {
            string jsonInput = request.Form["data"];
            
            // ruleid: insecure-newtonsoft-deserialization
            var settings = new JsonSerializerSettings();
            settings.TypeNameHandling = TypeNameHandling.Objects;
            
            dynamic deserializedObject = JsonConvert.DeserializeObject(jsonInput, settings);
            ProcessObject(deserializedObject);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_3([FromBody] string jsonPayload)
        {
            // ruleid: insecure-newtonsoft-deserialization
            var jsonSettings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Auto,
                NullValueHandling = NullValueHandling.Ignore
            };
            
            var result = JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonPayload, jsonSettings);
            foreach (var item in result)
            {
                Console.WriteLine($"{item.Key}: {item.Value}");
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public async Task bad_case_4()
        {
            HttpClient client = new HttpClient();
            string jsonData = await client.GetStringAsync("https://example.com/api/data");
            
            // ruleid: insecure-newtonsoft-deserialization
            JsonSerializerSettings settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Arrays,
                Formatting = Formatting.Indented
            };
            
            var parsedData = JsonConvert.DeserializeObject<List<object>>(jsonData, settings);
            ProcessList(parsedData);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_5(HttpContext httpContext)
        {
            string json = httpContext.Request.Query["jsonData"];
            
            // ruleid: insecure-newtonsoft-deserialization
            var deserializer = JsonSerializer.Create(new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All,
                TypeNameAssemblyFormatHandling = TypeNameAssemblyFormatHandling.Full
            });
            
            using (var reader = new StringReader(json))
            using (var jsonReader = new JsonTextReader(reader))
            {
                var obj = deserializer.Deserialize(jsonReader);
                ProcessObject(obj);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_6(HttpRequestMessage request)
        {
            string jsonContent = request.Content.ReadAsStringAsync().Result;
            
            // ruleid: insecure-newtonsoft-deserialization
            var settings = new JsonSerializerSettings();
            settings.TypeNameHandling = TypeNameHandling.Objects;
            settings.MetadataPropertyHandling = MetadataPropertyHandling.ReadAhead;
            
            var data = JsonConvert.DeserializeObject(jsonContent, typeof(object), settings);
            SaveToDatabase(data);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_7(HttpRequest request)
        {
            var jsonData = request.Headers["X-Json-Data"].ToString();
            
            // ruleid: insecure-newtonsoft-deserialization
            var serializerSettings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Auto,
                ContractResolver = new Newtonsoft.Json.Serialization.CamelCasePropertyNamesContractResolver()
            };
            
            dynamic result = JsonConvert.DeserializeObject(jsonData, serializerSettings);
            ProcessDynamicObject(result);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_8(string jsonFromApi)
        {
            using (var client = new WebClient())
            {
                jsonFromApi = client.DownloadString("https://external-api.com/data");
                
                // ruleid: insecure-newtonsoft-deserialization
                var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.All,
                    PreserveReferencesHandling = PreserveReferencesHandling.Objects
                };
                
                var obj = JsonConvert.DeserializeObject(jsonFromApi, settings);
                ProcessApiResponse(obj);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_9(HttpContext context)
        {
            var cookieValue = context.Request.Cookies["userData"];
            if (cookieValue != null)
            {
                // ruleid: insecure-newtonsoft-deserialization
                JsonSerializerSettings settings = new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.Objects,
                    DateFormatHandling = DateFormatHandling.IsoDateFormat
                };
                
                var userData = JsonConvert.DeserializeObject(cookieValue, settings);
                UpdateUserProfile(userData);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_10([FromQuery] string serializedData)
        {
            if (!string.IsNullOrEmpty(serializedData))
            {
                // ruleid: insecure-newtonsoft-deserialization
                var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.Arrays,
                    ReferenceLoopHandling = ReferenceLoopHandling.Ignore
                };
                
                var items = JsonConvert.DeserializeObject<object[]>(serializedData, settings);
                ProcessItems(items);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_11(HttpRequest request)
        {
            var jsonFile = request.Form.Files.GetFile("jsonFile");
            string jsonContent;
            
            using (var reader = new StreamReader(jsonFile.OpenReadStream()))
            {
                jsonContent = reader.ReadToEnd();
            }
            
            // ruleid: insecure-newtonsoft-deserialization
            var serializerSettings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All,
                MissingMemberHandling = MissingMemberHandling.Ignore
            };
            
            var deserializedData = JsonConvert.DeserializeObject(jsonContent, serializerSettings);
            ProcessUploadedData(deserializedData);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_12(HttpContext context)
        {
            string base64Json = context.Request.Query["encodedJson"];
            string jsonData = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(base64Json));
            
            // ruleid: insecure-newtonsoft-deserialization
            var settings = new JsonSerializerSettings();
            settings.TypeNameHandling = TypeNameHandling.Auto;
            settings.Converters.Add(new CustomJsonConverter());
            
            var result = JsonConvert.DeserializeObject(jsonData, settings);
            ProcessConvertedData(result);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_13(HttpRequestMessage request)
        {
            string jsonPayload = request.Content.ReadAsStringAsync().Result;
            JObject jsonObject = JObject.Parse(jsonPayload);
            string nestedJson = jsonObject["data"].ToString();
            
            // ruleid: insecure-newtonsoft-deserialization
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Objects,
                ObjectCreationHandling = ObjectCreationHandling.Replace
            };
            
            var nestedObject = JsonConvert.DeserializeObject(nestedJson, settings);
            ProcessNestedData(nestedObject);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_14(HttpRequest request)
        {
            var configJson = request.Form["configuration"];
            
            // ruleid: insecure-newtonsoft-deserialization
            JsonSerializerSettings settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All,
                ConstructorHandling = ConstructorHandling.AllowNonPublicDefaultConstructor
            };
            
            var config = JsonConvert.DeserializeObject<Dictionary<string, object>>(configJson, settings);
            ApplyConfiguration(config);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_15(HttpContext context)
        {
            string jsonInput = new StreamReader(context.Request.Body).ReadToEnd();
            
            // Create a factory that produces settings with insecure TypeNameHandling
            var settingsFactory = new SettingsFactory();
            
            // ruleid: insecure-newtonsoft-deserialization
            var settings = settingsFactory.CreateSettings();
            settings.TypeNameHandling = TypeNameHandling.Auto;
            
            var result = JsonConvert.DeserializeObject(jsonInput, settings);
            ProcessFactoryCreatedObject(result);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        public void good_case_1(HttpContext context)
        {
            string jsonData = new StreamReader(context.Request.Body).ReadToEnd();
            
            // ok: insecure-newtonsoft-deserialization
            JsonSerializerSettings settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.None
            };
            
            var obj = JsonConvert.DeserializeObject(jsonData, settings);
            Console.WriteLine($"Deserialized object: {obj}");
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_2(HttpRequest request)
        {
            string jsonInput = request.Form["data"];
            
            // ok: insecure-newtonsoft-deserialization
            var settings = new JsonSerializerSettings();
            // Default TypeNameHandling is None, which is secure
            
            dynamic deserializedObject = JsonConvert.DeserializeObject(jsonInput, settings);
            ProcessObject(deserializedObject);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_3([FromBody] string jsonPayload)
        {
            // ok: insecure-newtonsoft-deserialization
            // No TypeNameHandling specified, so it defaults to None
            var result = JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonPayload);
            
            foreach (var item in result)
            {
                Console.WriteLine($"{item.Key}: {item.Value}");
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public async Task good_case_4()
        {
            HttpClient client = new HttpClient();
            string jsonData = await client.GetStringAsync("https://example.com/api/data");
            
            // ok: insecure-newtonsoft-deserialization
            // Using explicit type for deserialization instead of TypeNameHandling
            var parsedData = JsonConvert.DeserializeObject<List<CustomDataType>>(jsonData);
            ProcessTypedList(parsedData);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_5(HttpContext httpContext)
        {
            string json = httpContext.Request.Query["jsonData"];
            
            // ok: insecure-newtonsoft-deserialization
            var deserializer = JsonSerializer.Create(new JsonSerializerSettings
            {
                // TypeNameHandling is None by default
                Formatting = Formatting.Indented
            });
            
            using (var reader = new StringReader(json))
            using (var jsonReader = new JsonTextReader(reader))
            {
                var obj = deserializer.Deserialize<SafeDataType>(jsonReader);
                ProcessSafeObject(obj);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_6(HttpRequestMessage request)
        {
            string jsonContent = request.Content.ReadAsStringAsync().Result;
            
            // ok: insecure-newtonsoft-deserialization
            // Using a known type for deserialization
            var data = JsonConvert.DeserializeObject<SafeDataModel>(jsonContent);
            SaveToDatabase(data);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_7(HttpRequest request)
        {
            var jsonData = request.Headers["X-Json-Data"].ToString();
            
            // ok: insecure-newtonsoft-deserialization
            var serializerSettings = new JsonSerializerSettings
            {
                // TypeNameHandling.None is the secure option
                TypeNameHandling = TypeNameHandling.None,
                ContractResolver = new Newtonsoft.Json.Serialization.CamelCasePropertyNamesContractResolver()
            };
            
            var result = JsonConvert.DeserializeObject<SafeDataType>(jsonData, serializerSettings);
            ProcessSafeObject(result);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_8(string jsonFromApi)
        {
            using (var client = new WebClient())
            {
                jsonFromApi = client.DownloadString("https://external-api.com/data");
                
                // ok: insecure-newtonsoft-deserialization
                // Using a specific type rather than relying on type information in the JSON
                var obj = JsonConvert.DeserializeObject<ApiResponse>(jsonFromApi);
                ProcessApiResponse(obj);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_9(HttpContext context)
        {
            var cookieValue = context.Request.Cookies["userData"];
            if (cookieValue != null)
            {
                // ok: insecure-newtonsoft-deserialization
                // Not specifying TypeNameHandling, so it defaults to None
                var userData = JsonConvert.DeserializeObject<UserProfile>(cookieValue);
                UpdateUserProfile(userData);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_10([FromQuery] string serializedData)
        {
            if (!string.IsNullOrEmpty(serializedData))
            {
                // ok: insecure-newtonsoft-deserialization
                var settings = new JsonSerializerSettings
                {
                    // Explicitly set to None for security
                    TypeNameHandling = TypeNameHandling.None,
                    ReferenceLoopHandling = ReferenceLoopHandling.Ignore
                };
                
                var items = JsonConvert.DeserializeObject<List<Item>>(serializedData, settings);
                ProcessItems(items.ToArray());
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_11(HttpRequest request)
        {
            var jsonFile = request.Form.Files.GetFile("jsonFile");
            string jsonContent;
            
            using (var reader = new StreamReader(jsonFile.OpenReadStream()))
            {
                jsonContent = reader.ReadToEnd();
            }
            
            // ok: insecure-newtonsoft-deserialization
            // Using a specific known type for deserialization
            var deserializedData = JsonConvert.DeserializeObject<UploadedDataModel>(jsonContent);
            ProcessUploadedData(deserializedData);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_12(HttpContext context)
        {
            string base64Json = context.Request.Query["encodedJson"];
            string jsonData = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(base64Json));
            
            // ok: insecure-newtonsoft-deserialization
            // Using custom converter but with TypeNameHandling.None
            var settings = new JsonSerializerSettings();
            settings.TypeNameHandling = TypeNameHandling.None;
            settings.Converters.Add(new CustomJsonConverter());
            
            var result = JsonConvert.DeserializeObject<SafeDataType>(jsonData, settings);
            ProcessConvertedData(result);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_13(HttpRequestMessage request)
        {
            string jsonPayload = request.Content.ReadAsStringAsync().Result;
            JObject jsonObject = JObject.Parse(jsonPayload);
            string nestedJson = jsonObject["data"].ToString();
            
            // ok: insecure-newtonsoft-deserialization
            // Using a specific type for deserialization
            var nestedObject = JsonConvert.DeserializeObject<NestedData>(nestedJson);
            ProcessNestedData(nestedObject);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_14(HttpRequest request)
        {
            var configJson = request.Form["configuration"];
            
            // ok: insecure-newtonsoft-deserialization
            // Using a specific type and not specifying TypeNameHandling
            var config = JsonConvert.DeserializeObject<Dictionary<string, string>>(configJson);
            ApplyConfiguration(config);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_15(HttpContext context)
        {
            string jsonInput = new StreamReader(context.Request.Body).ReadToEnd();
            
            // Create a factory that produces settings with secure TypeNameHandling
            var settingsFactory = new SecureSettingsFactory();
            
            // ok: insecure-newtonsoft-deserialization
            var settings = settingsFactory.CreateSettings();
            // Factory ensures TypeNameHandling is None
            
            var result = JsonConvert.DeserializeObject<SafeDataType>(jsonInput, settings);
            ProcessFactoryCreatedObject(result);
        }
// {/fact}

        // Helper methods and classes
        private void ProcessObject(dynamic obj) { }
        private void ProcessList<T>(List<T> list) { }
        private void SaveToDatabase(object data) { }
        private void ProcessDynamicObject(dynamic obj) { }
        private void ProcessApiResponse(object response) { }
        private void UpdateUserProfile(object userData) { }
        private void ProcessItems(object[] items) { }
        private void ProcessUploadedData(object data) { }
        private void ProcessConvertedData(object data) { }
        private void ProcessNestedData(object data) { }
        private void ApplyConfiguration<T>(Dictionary<string, T> config) { }
        private void ProcessFactoryCreatedObject(object obj) { }
        private void ProcessTypedList<T>(List<T> list) { }
        private void ProcessSafeObject(object obj) { }

        private class CustomJsonConverter : JsonConverter
        {
            public override bool CanConvert(Type objectType) => true;
            public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer) => null;
            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer) { }
        }

        private class SettingsFactory
        {
            public JsonSerializerSettings CreateSettings() => new JsonSerializerSettings();
        }

        private class SecureSettingsFactory
        {
            public JsonSerializerSettings CreateSettings() => new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
        }

        private class CustomDataType { }
        private class SafeDataType { }
        private class SafeDataModel { }
        private class ApiResponse { }
        private class UserProfile { }
        private class Item { }
        private class UploadedDataModel { }
        private class NestedData { }
    }
}