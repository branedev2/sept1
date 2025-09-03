using System;
using System.IO;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Text.Json;
using System.Web;
using System.Xml;
using System.Xml.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace InsecureDeserializationExamples
{
    public class DeserializationExamples
    {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public void bad_case_1(HttpContext context)
        {
            // Using BinaryFormatter to deserialize data from a request
            byte[] serializedData = Convert.FromBase64String(context.Request.Query["data"]);
            
            BinaryFormatter formatter = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream(serializedData))
            {
                // ruleid: insecure-deserialization-formats
                object obj = formatter.Deserialize(ms);
                Console.WriteLine($"Deserialized object: {obj}");
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_2([FromBody] byte[] requestData)
        {
            // Using BinaryFormatter with a memory stream
            using (MemoryStream memStream = new MemoryStream(requestData))
            {
                BinaryFormatter binaryFormatter = new BinaryFormatter();
                try
                {
                    // ruleid: insecure-deserialization-formats
                    object deserializedObject = binaryFormatter.Deserialize(memStream);
                    ProcessObject(deserializedObject);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_3(HttpContext context)
        {
            // Using BinaryFormatter with a file stream from user input
            string filePath = context.Request.Query["filePath"];
            
            using (FileStream fs = new FileStream(filePath, FileMode.Open))
            {
                BinaryFormatter formatter = new BinaryFormatter();
                // ruleid: insecure-deserialization-formats
                object obj = formatter.Deserialize(fs);
                Console.WriteLine($"Loaded object from file: {obj}");
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_4(HttpContext context)
        {
            // Using BinaryFormatter indirectly through a helper method
            byte[] data = Convert.FromBase64String(context.Request.Form["serializedData"]);
            object result = DeserializeWithBinaryFormatter(data);
            Console.WriteLine($"Result: {result}");
        }
// {/fact}

        private object DeserializeWithBinaryFormatter(byte[] data)
        {
            using (MemoryStream ms = new MemoryStream(data))
            {
                BinaryFormatter formatter = new BinaryFormatter();
                // ruleid: insecure-deserialization-formats
                return formatter.Deserialize(ms);
            }
        }
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_5(HttpContext context)
        {
            // Using BinaryFormatter with conditional logic
            string format = context.Request.Query["format"];
            byte[] data = Convert.FromBase64String(context.Request.Query["data"]);
            
            object result = null;
            if (format == "binary")
            {
                using (MemoryStream ms = new MemoryStream(data))
                {
                    BinaryFormatter formatter = new BinaryFormatter();
                    // ruleid: insecure-deserialization-formats
                    result = formatter.Deserialize(ms);
                }
            }
            else
            {
                // Some other format handling
                result = System.Text.Json.JsonSerializer.Deserialize<object>(Encoding.UTF8.GetString(data));
            }
            
            Console.WriteLine($"Deserialized: {result}");
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_6(HttpContext context)
        {
            // Using BinaryFormatter in a try-catch block
            byte[] data = Convert.FromBase64String(context.Request.Headers["X-Serialized-Data"]);
            
            try
            {
                using (MemoryStream ms = new MemoryStream(data))
                {
                    BinaryFormatter formatter = new BinaryFormatter();
                    // ruleid: insecure-deserialization-formats
                    object obj = formatter.Deserialize(ms);
                    ProcessObject(obj);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Deserialization failed: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_7(HttpContext context)
        {
            // Using BinaryFormatter with a loop
            string[] dataItems = context.Request.Form["items"].ToString().Split(',');
            
            foreach (string item in dataItems)
            {
                byte[] data = Convert.FromBase64String(item);
                using (MemoryStream ms = new MemoryStream(data))
                {
                    BinaryFormatter formatter = new BinaryFormatter();
                    // ruleid: insecure-deserialization-formats
                    object obj = formatter.Deserialize(ms);
                    ProcessObject(obj);
                }
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_8(HttpContext context)
        {
            // Using SoapFormatter (another insecure formatter)
            byte[] data = Convert.FromBase64String(context.Request.Query["soapData"]);
            
            using (MemoryStream ms = new MemoryStream(data))
            {
                SoapFormatter formatter = new SoapFormatter();
                // ruleid: insecure-deserialization-formats
                object obj = formatter.Deserialize(ms);
                Console.WriteLine($"Deserialized SOAP object: {obj}");
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_9(HttpContext context)
        {
            // Using BinaryFormatter with a switch statement
            string action = context.Request.Query["action"];
            byte[] data = Convert.FromBase64String(context.Request.Query["data"]);
            
            switch (action)
            {
                case "load":
                    using (MemoryStream ms = new MemoryStream(data))
                    {
                        BinaryFormatter formatter = new BinaryFormatter();
                        // ruleid: insecure-deserialization-formats
                        object obj = formatter.Deserialize(ms);
                        ProcessObject(obj);
                    }
                    break;
                case "save":
                    // Save logic
                    break;
                default:
                    Console.WriteLine("Unknown action");
                    break;
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_10(HttpContext context)
        {
            // Using BinaryFormatter with a delegate
            byte[] data = Convert.FromBase64String(context.Request.Query["data"]);
            
            Func<byte[], object> deserializer = (bytes) =>
            {
                using (MemoryStream ms = new MemoryStream(bytes))
                {
                    BinaryFormatter formatter = new BinaryFormatter();
                    // ruleid: insecure-deserialization-formats
                    return formatter.Deserialize(ms);
                }
            };
            
            object result = deserializer(data);
            Console.WriteLine($"Deserialized: {result}");
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_11(HttpContext context)
        {
            // Using BinaryFormatter with a custom wrapper class
            byte[] data = Convert.FromBase64String(context.Request.Form["objectData"]);
            
            var deserializer = new BinaryDeserializer();
            object obj = deserializer.DeserializeObject(data);
            ProcessObject(obj);
        }
// {/fact}

        private class BinaryDeserializer
        {
            public object DeserializeObject(byte[] data)
            {
                using (MemoryStream ms = new MemoryStream(data))
                {
                    BinaryFormatter formatter = new BinaryFormatter();
                    // ruleid: insecure-deserialization-formats
                    return formatter.Deserialize(ms);
                }
            }
        }
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_12(HttpContext context)
        {
            // Using BinaryFormatter with a generic method
            string dataType = context.Request.Query["type"];
            byte[] data = Convert.FromBase64String(context.Request.Query["data"]);
            
            if (dataType == "user")
            {
                var user = DeserializeData<User>(data);
                Console.WriteLine($"User: {user.Name}");
            }
            else if (dataType == "product")
            {
                var product = DeserializeData<Product>(data);
                Console.WriteLine($"Product: {product.Name}");
            }
        }
// {/fact}

        private T DeserializeData<T>(byte[] data)
        {
            using (MemoryStream ms = new MemoryStream(data))
            {
                BinaryFormatter formatter = new BinaryFormatter();
                // ruleid: insecure-deserialization-formats
                return (T)formatter.Deserialize(ms);
            }
        }
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_13(HttpContext context)
        {
            // Using BinaryFormatter with async pattern (though BinaryFormatter itself is not async)
            byte[] data = Convert.FromBase64String(context.Request.Query["data"]);
            
            // This is still synchronous but wrapped in an async pattern
            var task = System.Threading.Tasks.Task.Run(() =>
            {
                using (MemoryStream ms = new MemoryStream(data))
                {
                    BinaryFormatter formatter = new BinaryFormatter();
                    // ruleid: insecure-deserialization-formats
                    return formatter.Deserialize(ms);
                }
            });
            
            object result = task.Result;
            ProcessObject(result);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_14(HttpContext context)
        {
            // Using BinaryFormatter with a factory pattern
            string format = context.Request.Query["format"];
            byte[] data = Convert.FromBase64String(context.Request.Query["data"]);
            
            IFormatter formatter = GetFormatter(format);
            using (MemoryStream ms = new MemoryStream(data))
            {
                // ruleid: insecure-deserialization-formats
                object obj = formatter.Deserialize(ms);
                ProcessObject(obj);
            }
        }
// {/fact}

        private IFormatter GetFormatter(string format)
        {
            if (format == "soap")
            {
                return new SoapFormatter();
            }
            else
            {
                return new BinaryFormatter();
            }
        }
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

        public void bad_case_15(HttpContext context)
        {
            // Using BinaryFormatter with a custom stream
            byte[] data = Convert.FromBase64String(context.Request.Query["data"]);
            
            using (CustomMemoryStream ms = new CustomMemoryStream(data))
            {
                BinaryFormatter formatter = new BinaryFormatter();
                // ruleid: insecure-deserialization-formats
                object obj = formatter.Deserialize(ms);
                ProcessObject(obj);
            }
        }
// {/fact}

        private class CustomMemoryStream : MemoryStream
        {
            public CustomMemoryStream(byte[] buffer) : base(buffer) { }
        }
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        // True Negative Examples (Safe Code)

        public void good_case_1(HttpContext context)
        {
            // Using System.Text.Json for safe deserialization
            string jsonData = context.Request.Query["data"];
            
            // ok: insecure-deserialization-formats
            var options = new System.Text.Json.JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };
            User user = System.Text.Json.JsonSerializer.Deserialize<User>(jsonData, options);
            
            Console.WriteLine($"User: {user.Name}");
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_2(HttpContext context)
        {
            // Using Newtonsoft.Json for safe deserialization
            string jsonData = context.Request.Form["jsonData"];
            
            // ok: insecure-deserialization-formats
            User user = Newtonsoft.Json.JsonConvert.DeserializeObject<User>(jsonData);
            
            Console.WriteLine($"User: {user.Name}");
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_3(HttpContext context)
        {
            // Using XmlSerializer for safe deserialization
            string xmlData = context.Request.Query["xmlData"];
            
            XmlSerializer serializer = new XmlSerializer(typeof(User));
            using (StringReader reader = new StringReader(xmlData))
            {
                // ok: insecure-deserialization-formats
                User user = (User)serializer.Deserialize(reader);
                Console.WriteLine($"User: {user.Name}");
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_4(HttpContext context)
        {
            // Using DataContractJsonSerializer for safe deserialization
            byte[] data = Convert.FromBase64String(context.Request.Query["data"]);
            
            using (MemoryStream ms = new MemoryStream(data))
            {
                DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(User));
                // ok: insecure-deserialization-formats
                User user = (User)serializer.ReadObject(ms);
                Console.WriteLine($"User: {user.Name}");
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_5(HttpContext context)
        {
            // Using custom JSON deserialization with validation
            string jsonData = context.Request.Query["data"];
            
            // ok: insecure-deserialization-formats
            User user = System.Text.Json.JsonSerializer.Deserialize<User>(jsonData);
            
            // Validate the deserialized object
            if (IsValidUser(user))
            {
                ProcessUser(user);
            }
            else
            {
                Console.WriteLine("Invalid user data");
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_6(HttpContext context)
        {
            // Using Newtonsoft.Json with settings for safe deserialization
            string jsonData = context.Request.Form["data"];
            
            var settings = new Newtonsoft.Json.JsonSerializerSettings
            {
                TypeNameHandling = Newtonsoft.Json.TypeNameHandling.None,
                MaxDepth = 10
            };
            
            // ok: insecure-deserialization-formats
            User user = Newtonsoft.Json.JsonConvert.DeserializeObject<User>(jsonData, settings);
            
            Console.WriteLine($"User: {user.Name}");
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_7(HttpContext context)
        {
            // Using System.Text.Json with a custom converter
            string jsonData = context.Request.Query["data"];
            
            var options = new System.Text.Json.JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                Converters = { new DateTimeConverter() }
            };
            
            // ok: insecure-deserialization-formats
            User user = System.Text.Json.JsonSerializer.Deserialize<User>(jsonData, options);
            
            Console.WriteLine($"User: {user.Name}, Registered: {user.RegisteredDate}");
        }
// {/fact}

        private class DateTimeConverter : System.Text.Json.Serialization.JsonConverter<DateTime>
        {
            public override DateTime Read(ref System.Text.Json.Utf8JsonReader reader, Type typeToConvert, System.Text.Json.JsonSerializerOptions options)
            {
                return DateTime.Parse(reader.GetString());
            }

            public override void Write(System.Text.Json.Utf8JsonWriter writer, DateTime value, System.Text.Json.JsonSerializerOptions options)
            {
                writer.WriteStringValue(value.ToString("yyyy-MM-dd"));
            }
        }
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_8(HttpContext context)
        {
            // Using XmlSerializer with validation
            string xmlData = context.Request.Query["xmlData"];
            
            XmlReaderSettings settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                ValidationType = ValidationType.None,
                XmlResolver = null
            };
            
            using (StringReader stringReader = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(stringReader, settings))
            {
                XmlSerializer serializer = new XmlSerializer(typeof(User));
                // ok: insecure-deserialization-formats
                User user = (User)serializer.Deserialize(reader);
                Console.WriteLine($"User: {user.Name}");
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_9(HttpContext context)
        {
            // Using custom JSON parsing for specific properties
            string jsonData = context.Request.Form["data"];
            
            // ok: insecure-deserialization-formats
            using (JsonDocument doc = JsonDocument.Parse(jsonData))
            {
                JsonElement root = doc.RootElement;
                
                string name = root.GetProperty("name").GetString();
                int age = root.GetProperty("age").GetInt32();
                
                User user = new User
                {
                    Name = name,
                    Age = age
                };
                
                ProcessUser(user);
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_10(HttpContext context)
        {
            // Using DataContractSerializer for safe XML deserialization
            string xmlData = context.Request.Query["xmlData"];
            
            using (StringReader stringReader = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(stringReader))
            {
                DataContractSerializer serializer = new DataContractSerializer(typeof(User));
                // ok: insecure-deserialization-formats
                User user = (User)serializer.ReadObject(reader);
                Console.WriteLine($"User: {user.Name}");
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_11(HttpContext context)
        {
            // Using System.Text.Json with custom options and error handling
            string jsonData = context.Request.Query["data"];
            
            try
            {
                var options = new System.Text.Json.JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    AllowTrailingCommas = true,
                    ReadCommentHandling = System.Text.Json.JsonCommentHandling.Skip
                };
                
                // ok: insecure-deserialization-formats
                User user = System.Text.Json.JsonSerializer.Deserialize<User>(jsonData, options);
                ProcessUser(user);
            }
            catch (System.Text.Json.JsonException ex)
            {
                Console.WriteLine($"JSON parsing error: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_12(HttpContext context)
        {
            // Using Newtonsoft.Json with JObject for flexible parsing
            string jsonData = context.Request.Form["data"];
            
            // ok: insecure-deserialization-formats
            Newtonsoft.Json.Linq.JObject jObject = Newtonsoft.Json.Linq.JObject.Parse(jsonData);
            
            string name = jObject["name"]?.ToString();
            int age = jObject["age"]?.Value<int>() ?? 0;
            
            User user = new User
            {
                Name = name,
                Age = age
            };
            
            ProcessUser(user);
        }
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_13(HttpContext context)
        {
            // Using a custom safe deserialization method
            string data = context.Request.Query["data"];
            string format = context.Request.Query["format"];
            
            // ok: insecure-deserialization-formats
            User user = SafeDeserialize<User>(data, format);
            
            if (user != null)
            {
                ProcessUser(user);
            }
        }
// {/fact}

        private T SafeDeserialize<T>(string data, string format) where T : class, new()
        {
            if (format == "json")
            {
                return System.Text.Json.JsonSerializer.Deserialize<T>(data);
            }
            else if (format == "xml")
            {
                XmlSerializer serializer = new XmlSerializer(typeof(T));
                using (StringReader reader = new StringReader(data))
                {
                    return (T)serializer.Deserialize(reader);
                }
            }
            
            return new T();
        }

        public void good_case_14(HttpContext context)
        {
            // Using System.Text.Json with a stream
            byte[] data = Convert.FromBase64String(context.Request.Query["data"]);
            
            using (MemoryStream ms = new MemoryStream(data))
            {
                // ok: insecure-deserialization-formats
                User user = System.Text.Json.JsonSerializer.DeserializeAsync<User>(ms).Result;
                ProcessUser(user);
            }
        }
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

        public void good_case_15(HttpContext context)
        {
            // Using a factory pattern with safe serializers
            string format = context.Request.Query["format"];
            string data = context.Request.Query["data"];
            
            ICustomSerializer serializer = GetSafeSerializer(format);
            // ok: insecure-deserialization-formats
            User user = serializer.Deserialize<User>(data);
            
            ProcessUser(user);
        }
// {/fact}

        private ICustomSerializer GetSafeSerializer(string format)
        {
            if (format == "xml")
            {
                return new XmlSafeSerializer();
            }
            else
            {
                return new JsonSafeSerializer();
            }
        }

        private interface ICustomSerializer
        {
            T Deserialize<T>(string data) where T : class, new();
        }

        private class JsonSafeSerializer : ICustomSerializer
        {
            public T Deserialize<T>(string data) where T : class, new()
            {
                return System.Text.Json.JsonSerializer.Deserialize<T>(data);
            }
        }

        private class XmlSafeSerializer : ICustomSerializer
        {
            public T Deserialize<T>(string data) where T : class, new()
            {
                XmlSerializer serializer = new XmlSerializer(typeof(T));
                using (StringReader reader = new StringReader(data))
                {
                    return (T)serializer.Deserialize(reader);
                }
            }
        }

        // Helper methods and classes
        private void ProcessObject(object obj)
        {
            Console.WriteLine($"Processing object: {obj}");
        }

        private void ProcessUser(User user)
        {
            Console.WriteLine($"Processing user: {user.Name}");
        }

        private bool IsValidUser(User user)
        {
            return user != null && !string.IsNullOrEmpty(user.Name) && user.Age > 0;
        }

        [Serializable]
        public class User
        {
            public string Name { get; set; }
            public int Age { get; set; }
            public DateTime RegisteredDate { get; set; }
        }

        [Serializable]
        public class Product
        {
            public string Name { get; set; }
            public decimal Price { get; set; }
        }
    }
}