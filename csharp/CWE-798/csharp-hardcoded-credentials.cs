using System;
using System.Data.SqlClient;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net;
using System.IO;
using Microsoft.Azure.Storage;
using Microsoft.Azure.Storage.Blob;
using Amazon.S3;
using Amazon.Runtime;
using System.Net.Mail;
using Renci.SshNet;
using Microsoft.Extensions.Configuration;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace HardcodedCredentialsExamples
{
    public class Examples
    {
// {fact rule=hardcoded-credentials@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public void bad_case_1()
        {
            // Database connection with hardcoded credentials
            string connectionString = "Server=myserver;Database=mydb;User Id=admin;Password=Password123!;";
            // ruleid: csharp-hardcoded-credentials
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();
                // Database operations
                SqlCommand command = new SqlCommand("SELECT * FROM Users", connection);
                SqlDataReader reader = command.ExecuteReader();
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_2()
        {
            // REST API authentication with hardcoded API key
            using (HttpClient client = new HttpClient())
            {
                // ruleid: csharp-hardcoded-credentials
                client.DefaultRequestHeaders.Add("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U");
                HttpResponseMessage response = client.GetAsync("https://api.example.com/data").Result;
                string content = response.Content.ReadAsStringAsync().Result;
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_3()
        {
            // Azure Storage connection with hardcoded account key
            string storageAccount = "mystorageaccount";
            string storageKey = "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6==;EndpointSuffix=core.windows.net";
            
            // ruleid: csharp-hardcoded-credentials
            CloudStorageAccount account = CloudStorageAccount.Parse(storageKey);
            CloudBlobClient client = account.CreateCloudBlobClient();
            CloudBlobContainer container = client.GetContainerReference("mycontainer");
            container.CreateIfNotExists();
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_4()
        {
            // SMTP configuration with hardcoded password
            SmtpClient smtpClient = new SmtpClient("smtp.example.com")
            {
                Port = 587,
                EnableSsl = true,
                // ruleid: csharp-hardcoded-credentials
                Credentials = new NetworkCredential("admin@example.com", "SuperSecretPassword123!")
            };
            
            MailMessage message = new MailMessage("sender@example.com", "recipient@example.com", "Subject", "Body");
            smtpClient.Send(message);
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_5()
        {
            // SSH connection with hardcoded credentials
            string host = "example.com";
            string username = "admin";
            string password = "AdminPass123!";
            
            // ruleid: csharp-hardcoded-credentials
            using (var client = new SshClient(host, username, password))
            {
                client.Connect();
                var result = client.RunCommand("ls -la");
                client.Disconnect();
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_6()
        {
            // AWS S3 client with hardcoded access keys
            string accessKey = "AKIAIOSFODNN7EXAMPLE";
            string secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
            
            // ruleid: csharp-hardcoded-credentials
            var credentials = new BasicAWSCredentials(accessKey, secretKey);
            var s3Client = new AmazonS3Client(credentials, Amazon.RegionEndpoint.USEast1);
            var response = s3Client.ListBucketsAsync().Result;
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_7()
        {
            // FTP client with hardcoded credentials
            string ftpUrl = "ftp://example.com/files/";
            string username = "ftpuser";
            string password = "ftpP@ssw0rd";
            
            // ruleid: csharp-hardcoded-credentials
            FtpWebRequest request = (FtpWebRequest)WebRequest.Create(ftpUrl);
            request.Method = WebRequestMethods.Ftp.ListDirectory;
            request.Credentials = new NetworkCredential(username, password);
            
            using (FtpWebResponse response = (FtpWebResponse)request.GetResponse())
            using (Stream responseStream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(responseStream))
            {
                string listings = reader.ReadToEnd();
                Console.WriteLine(listings);
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_8()
        {
            // MongoDB connection string with hardcoded credentials
            string connectionString = "mongodb://dbadmin:mongo123@localhost:27017/admin";
            
            // ruleid: csharp-hardcoded-credentials
            var client = new MongoDB.Driver.MongoClient(connectionString);
            var database = client.GetDatabase("mydb");
            var collection = database.GetCollection<MongoDB.Bson.BsonDocument>("mycollection");
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_9()
        {
            // OAuth2 client with hardcoded client secret
            string clientId = "my-client-id";
            string clientSecret = "my-super-secret-oauth2-key";
            
            // ruleid: csharp-hardcoded-credentials
            using (HttpClient client = new HttpClient())
            {
                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("client_secret", clientSecret)
                });
                
                HttpResponseMessage response = client.PostAsync("https://auth.example.com/oauth/token", content).Result;
                string tokenResponse = response.Content.ReadAsStringAsync().Result;
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_10()
        {
            // Redis connection with hardcoded password
            string redisConnectionString = "redis.example.com:6379,password=RedisPassword123!,ssl=true";
            
            // ruleid: csharp-hardcoded-credentials
            var redis = StackExchange.Redis.ConnectionMultiplexer.Connect(redisConnectionString);
            var db = redis.GetDatabase();
            db.StringSet("key", "value");
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_11()
        {
            // Encryption key hardcoded
            byte[] key = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            byte[] iv = new byte[] { 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32 };
            
            // ruleid: csharp-hardcoded-credentials
            using (var aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                
                // Encryption operations
                using (var encryptor = aes.CreateEncryptor())
                {
                    byte[] dataToEncrypt = System.Text.Encoding.UTF8.GetBytes("Secret data");
                    byte[] encryptedData = encryptor.TransformFinalBlock(dataToEncrypt, 0, dataToEncrypt.Length);
                }
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_12()
        {
            // Basic authentication in HTTP request
            using (HttpClient client = new HttpClient())
            {
                string credentials = Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes("username:p@ssw0rd"));
                
                // ruleid: csharp-hardcoded-credentials
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);
                HttpResponseMessage response = client.GetAsync("https://api.example.com/protected").Result;
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_13()
        {
            // Hardcoded connection string in configuration
            var config = new Dictionary<string, string>
            {
                // ruleid: csharp-hardcoded-credentials
                ["ConnectionStrings:DefaultConnection"] = "Server=myserver;Database=mydb;User Id=sa;Password=SqlServerP@ss;"
            };
            
            var builder = new ConfigurationBuilder();
            builder.AddInMemoryCollection(config);
            var configuration = builder.Build();
            
            string connectionString = configuration.GetConnectionString("DefaultConnection");
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_14()
        {
            // Hardcoded API key in query string
            string apiKey = "sk_test_abcdefghijklmnopqrstuvwxyz123456";
            
            // ruleid: csharp-hardcoded-credentials
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = client.GetAsync($"https://api.stripe.com/v1/charges?api_key={apiKey}").Result;
                string responseContent = response.Content.ReadAsStringAsync().Result;
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_15()
        {
            // Hardcoded certificate password
            string certPath = "mycert.pfx";
            string certPassword = "Cert!f!c@teP@ssw0rd";
            
            // ruleid: csharp-hardcoded-credentials
            var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(certPath, certPassword);
            
            using (HttpClient client = new HttpClient())
            {
                var handler = new HttpClientHandler();
                handler.ClientCertificates.Add(cert);
                client = new HttpClient(handler);
                
                HttpResponseMessage response = client.GetAsync("https://api.example.com/secure").Result;
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        public void good_case_1()
        {
            // Database connection with credentials from environment variables
            string server = Environment.GetEnvironmentVariable("DB_SERVER");
            string database = Environment.GetEnvironmentVariable("DB_NAME");
            string userId = Environment.GetEnvironmentVariable("DB_USER");
            string password = Environment.GetEnvironmentVariable("DB_PASSWORD");
            
            string connectionString = $"Server={server};Database={database};User Id={userId};Password={password};";
            
            // ok: csharp-hardcoded-credentials
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();
                // Database operations
                SqlCommand command = new SqlCommand("SELECT * FROM Users", connection);
                SqlDataReader reader = command.ExecuteReader();
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_2()
        {
            // REST API authentication with API key from configuration
            IConfiguration configuration = new ConfigurationBuilder()
                .AddEnvironmentVariables()
                .Build();
                
            string apiKey = configuration["API_KEY"];
            
            using (HttpClient client = new HttpClient())
            {
                // ok: csharp-hardcoded-credentials
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}");
                HttpResponseMessage response = client.GetAsync("https://api.example.com/data").Result;
                string content = response.Content.ReadAsStringAsync().Result;
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_3()
        {
            // Azure Storage connection with account key from Azure Key Vault
            string keyVaultUrl = "https://myvault.vault.azure.net/";
            string secretName = "StorageConnectionString";
            
            var client = new SecretClient(new Uri(keyVaultUrl), new DefaultAzureCredential());
            KeyVaultSecret secret = client.GetSecret(secretName);
            string storageConnectionString = secret.Value;
            
            // ok: csharp-hardcoded-credentials
            CloudStorageAccount account = CloudStorageAccount.Parse(storageConnectionString);
            CloudBlobClient blobClient = account.CreateCloudBlobClient();
            CloudBlobContainer container = blobClient.GetContainerReference("mycontainer");
            container.CreateIfNotExists();
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_4()
        {
            // SMTP configuration with password from configuration file
            IConfiguration configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .Build();
                
            string smtpServer = configuration["Smtp:Server"];
            int smtpPort = int.Parse(configuration["Smtp:Port"]);
            string smtpUsername = configuration["Smtp:Username"];
            string smtpPassword = configuration["Smtp:Password"];
            
            SmtpClient smtpClient = new SmtpClient(smtpServer)
            {
                Port = smtpPort,
                EnableSsl = true,
                // ok: csharp-hardcoded-credentials
                Credentials = new NetworkCredential(smtpUsername, smtpPassword)
            };
            
            MailMessage message = new MailMessage("sender@example.com", "recipient@example.com", "Subject", "Body");
            smtpClient.Send(message);
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_5()
        {
            // SSH connection with credentials from secure storage
            IConfiguration configuration = new ConfigurationBuilder()
                .AddUserSecrets<Examples>()
                .Build();
                
            string host = configuration["Ssh:Host"];
            string username = configuration["Ssh:Username"];
            string password = configuration["Ssh:Password"];
            
            // ok: csharp-hardcoded-credentials
            using (var client = new SshClient(host, username, password))
            {
                client.Connect();
                var result = client.RunCommand("ls -la");
                client.Disconnect();
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_6()
        {
            // AWS S3 client with access keys from environment variables
            string accessKey = Environment.GetEnvironmentVariable("AWS_ACCESS_KEY");
            string secretKey = Environment.GetEnvironmentVariable("AWS_SECRET_KEY");
            
            // ok: csharp-hardcoded-credentials
            var credentials = new BasicAWSCredentials(accessKey, secretKey);
            var s3Client = new AmazonS3Client(credentials, Amazon.RegionEndpoint.USEast1);
            var response = s3Client.ListBucketsAsync().Result;
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_7()
        {
            // FTP client with credentials from configuration
            IConfiguration configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .Build();
                
            string ftpUrl = configuration["Ftp:Url"];
            string username = configuration["Ftp:Username"];
            string password = configuration["Ftp:Password"];
            
            // ok: csharp-hardcoded-credentials
            FtpWebRequest request = (FtpWebRequest)WebRequest.Create(ftpUrl);
            request.Method = WebRequestMethods.Ftp.ListDirectory;
            request.Credentials = new NetworkCredential(username, password);
            
            using (FtpWebResponse response = (FtpWebResponse)request.GetResponse())
            using (Stream responseStream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(responseStream))
            {
                string listings = reader.ReadToEnd();
                Console.WriteLine(listings);
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_8()
        {
            // MongoDB connection string from environment variable
            string connectionString = Environment.GetEnvironmentVariable("MONGODB_CONNECTION_STRING");
            
            // ok: csharp-hardcoded-credentials
            var client = new MongoDB.Driver.MongoClient(connectionString);
            var database = client.GetDatabase("mydb");
            var collection = database.GetCollection<MongoDB.Bson.BsonDocument>("mycollection");
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_9()
        {
            // OAuth2 client with client secret from secure storage
            var secretProvider = new SecretClient(
                new Uri("https://myvault.vault.azure.net/"), 
                new DefaultAzureCredential());
                
            string clientId = secretProvider.GetSecret("oauth-client-id").Value.Value;
            string clientSecret = secretProvider.GetSecret("oauth-client-secret").Value.Value;
            
            // ok: csharp-hardcoded-credentials
            using (HttpClient client = new HttpClient())
            {
                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("client_secret", clientSecret)
                });
                
                HttpResponseMessage response = client.PostAsync("https://auth.example.com/oauth/token", content).Result;
                string tokenResponse = response.Content.ReadAsStringAsync().Result;
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_10()
        {
            // Redis connection with password from configuration
            IConfiguration configuration = new ConfigurationBuilder()
                .AddEnvironmentVariables()
                .Build();
                
            string redisHost = configuration["Redis:Host"];
            string redisPort = configuration["Redis:Port"];
            string redisPassword = configuration["Redis:Password"];
            
            string redisConnectionString = $"{redisHost}:{redisPort},password={redisPassword},ssl=true";
            
            // ok: csharp-hardcoded-credentials
            var redis = StackExchange.Redis.ConnectionMultiplexer.Connect(redisConnectionString);
            var db = redis.GetDatabase();
            db.StringSet("key", "value");
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_11()
        {
            // Encryption key from secure storage
            IConfiguration configuration = new ConfigurationBuilder()
                .AddUserSecrets<Examples>()
                .Build();
                
            string base64Key = configuration["Encryption:Key"];
            string base64Iv = configuration["Encryption:IV"];
            
            byte[] key = Convert.FromBase64String(base64Key);
            byte[] iv = Convert.FromBase64String(base64Iv);
            
            // ok: csharp-hardcoded-credentials
            using (var aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                
                // Encryption operations
                using (var encryptor = aes.CreateEncryptor())
                {
                    byte[] dataToEncrypt = System.Text.Encoding.UTF8.GetBytes("Secret data");
                    byte[] encryptedData = encryptor.TransformFinalBlock(dataToEncrypt, 0, dataToEncrypt.Length);
                }
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_12()
        {
            // Basic authentication with credentials from environment variables
            string username = Environment.GetEnvironmentVariable("API_USERNAME");
            string password = Environment.GetEnvironmentVariable("API_PASSWORD");
            
            using (HttpClient client = new HttpClient())
            {
                string credentials = Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes($"{username}:{password}"));
                
                // ok: csharp-hardcoded-credentials
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);
                HttpResponseMessage response = client.GetAsync("https://api.example.com/protected").Result;
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_13()
        {
            // Connection string from configuration provider
            var configBuilder = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddEnvironmentVariables()
                .AddUserSecrets<Examples>();
                
            IConfiguration configuration = configBuilder.Build();
            
            // ok: csharp-hardcoded-credentials
            string connectionString = configuration.GetConnectionString("DefaultConnection");
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();
                // Database operations
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_14()
        {
            // API key from secure storage in query string
            var secretClient = new SecretClient(
                new Uri("https://myvault.vault.azure.net/"), 
                new DefaultAzureCredential());
                
            string apiKey = secretClient.GetSecret("stripe-api-key").Value.Value;
            
            // ok: csharp-hardcoded-credentials
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = client.GetAsync($"https://api.stripe.com/v1/charges?api_key={apiKey}").Result;
                string responseContent = response.Content.ReadAsStringAsync().Result;
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_15()
        {
            // Certificate password from secure storage
            IConfiguration configuration = new ConfigurationBuilder()
                .AddUserSecrets<Examples>()
                .Build();
                
            string certPath = configuration["Certificate:Path"];
            string certPassword = configuration["Certificate:Password"];
            
            // ok: csharp-hardcoded-credentials
            var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(certPath, certPassword);
            
            using (HttpClient client = new HttpClient())
            {
                var handler = new HttpClientHandler();
                handler.ClientCertificates.Add(cert);
                client = new HttpClient(handler);
                
                HttpResponseMessage response = client.GetAsync("https://api.example.com/secure").Result;
            }
        }
// {/fact}
    }
}