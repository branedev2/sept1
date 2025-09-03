using System;
using System.IO;
using System.Net;
using System.Text;
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SensitiveInformationLeakExamples
{
    public class SensitiveInformationLeakController : Controller
    {
        private readonly ILogger<SensitiveInformationLeakController> _logger;
        private readonly IConfiguration _configuration;

        public SensitiveInformationLeakController(ILogger<SensitiveInformationLeakController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        // True Positive Examples (Vulnerable Code)

        public void bad_case_1()
        {
            try
            {
                string creditCardNumber = Request.Form["creditCard"];
                string ssn = Request.Form["ssn"];
                
                // ruleid: sensitive-information-leak-csharp-rule
                _logger.LogInformation($"Processing payment with credit card: {creditCardNumber} and SSN: {ssn}");
                
                // Process payment logic
            }
            catch (Exception ex)
            {
                // ruleid: sensitive-information-leak-csharp-rule
                _logger.LogError($"Error processing payment: {ex}");
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public void bad_case_2()
        {
            string password = Request.Form["password"];
            string username = Request.Form["username"];
            
            // ruleid: sensitive-information-leak-csharp-rule
            Console.WriteLine($"User {username} attempted login with password: {password}");
            
            // Authentication logic
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public void bad_case_3()
        {
            try
            {
                string apiKey = Request.Headers["X-API-Key"];
                
                // ruleid: sensitive-information-leak-csharp-rule
                _logger.LogDebug($"API request received with key: {apiKey}");
                
                // API processing logic
            }
            catch (Exception ex)
            {
                // ruleid: sensitive-information-leak-csharp-rule
                _logger.LogError(ex.ToString());
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public void bad_case_4()
        {
            string connectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";
            
            try
            {
                using (SqlConnection connection = new SqlConnection(connectionString))
                {
                    connection.Open();
                    // Database operations
                }
            }
            catch (Exception ex)
            {
                // ruleid: sensitive-information-leak-csharp-rule
                _logger.LogError($"Failed to connect with connection string: {connectionString}. Error: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public void bad_case_5()
        {
            string token = Request.Cookies["auth_token"];
            
            // ruleid: sensitive-information-leak-csharp-rule
            _logger.LogInformation($"User authenticated with token: {token}");
            
            // Authentication verification logic
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public void bad_case_6()
        {
            try
            {
                string privateKey = System.IO.File.ReadAllText("private_key.pem");
                
                // Some encryption logic
                
                // ruleid: sensitive-information-leak-csharp-rule
                _logger.LogInformation($"Encryption completed with key: {privateKey}");
            }
            catch (Exception ex)
            {
                // ruleid: sensitive-information-leak-csharp-rule
                Console.WriteLine($"Exception details: {ex}");
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public void bad_case_7()
        {
            Dictionary<string, string> userCredentials = new Dictionary<string, string>
            {
                { "username", Request.Form["username"] },
                { "password", Request.Form["password"] }
            };
            
            // ruleid: sensitive-information-leak-csharp-rule
            foreach (var credential in userCredentials)
            {
                _logger.LogInformation($"{credential.Key}: {credential.Value}");
            }
            
            // Authentication logic
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public void bad_case_8()
        {
            try
            {
                string accountNumber = Request.Query["accountNumber"];
                decimal amount = decimal.Parse(Request.Query["amount"]);
                
                // Transaction logic
                
                // ruleid: sensitive-information-leak-csharp-rule
                _logger.LogInformation($"Transaction completed for account {accountNumber} with amount {amount}");
            }
            catch (Exception ex)
            {
                // ruleid: sensitive-information-leak-csharp-rule
                _logger.LogError($"Transaction failed with details: {ex}");
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public void bad_case_9()
        {
            string healthData = Request.Form["healthData"];
            string patientId = Request.Form["patientId"];
            
            // ruleid: sensitive-information-leak-csharp-rule
            using (StreamWriter writer = new StreamWriter("health_records.log", true))
            {
                writer.WriteLine($"Patient {patientId} data: {healthData}");
            }
            
            // Health record processing
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public void bad_case_10()
        {
            try
            {
                string encryptionKey = _configuration["EncryptionKey"];
                
                // Encryption logic
                
                // ruleid: sensitive-information-leak-csharp-rule
                _logger.LogInformation($"Data encrypted with key: {encryptionKey}");
            }
            catch (Exception ex)
            {
                // ruleid: sensitive-information-leak-csharp-rule
                _logger.LogError(ex.StackTrace);
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public void bad_case_11()
        {
            string socialSecurityNumber = Request.Form["ssn"];
            
            try
            {
                // Process SSN
                if (string.IsNullOrEmpty(socialSecurityNumber))
                {
                    throw new ArgumentException("SSN is required");
                }
                
                // More processing
            }
            catch (Exception ex)
            {
                // ruleid: sensitive-information-leak-csharp-rule
                _logger.LogError($"Error processing SSN {socialSecurityNumber}: {ex}");
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public void bad_case_12()
        {
            string databasePassword = "SecretDbPassword123!";
            
            try
            {
                // Database connection logic
            }
            catch (Exception ex)
            {
                // ruleid: sensitive-information-leak-csharp-rule
                _logger.LogError($"Failed to connect to database with password {databasePassword}. Error: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public void bad_case_13()
        {
            try
            {
                string userInput = Request.Query["input"];
                
                // Process user input
                if (userInput.Length < 5)
                {
                    throw new ArgumentException("Input too short");
                }
                
                // More processing
            }
            catch (Exception ex)
            {
                // ruleid: sensitive-information-leak-csharp-rule
                Response.WriteAsync($"Error details: {ex}");
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public void bad_case_14()
        {
            string creditCardCVV = Request.Form["cvv"];
            string cardNumber = Request.Form["cardNumber"];
            
            // ruleid: sensitive-information-leak-csharp-rule
            _logger.LogWarning($"Payment processing started for card ending in {cardNumber.Substring(cardNumber.Length - 4)} with CVV {creditCardCVV}");
            
            // Payment processing logic
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

        public void bad_case_15()
        {
            try
            {
                byte[] keyData = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(keyData);
                }
                
                // Encryption logic
                
                // ruleid: sensitive-information-leak-csharp-rule
                _logger.LogInformation($"Generated encryption key: {Convert.ToBase64String(keyData)}");
            }
            catch (Exception ex)
            {
                // ruleid: sensitive-information-leak-csharp-rule
                _logger.LogError($"Encryption failed: {ex}");
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        public void good_case_1()
        {
            try
            {
                string creditCardNumber = Request.Form["creditCard"];
                string ssn = Request.Form["ssn"];
                
                // ok: sensitive-information-leak-csharp-rule
                _logger.LogInformation($"Processing payment with credit card: XXXX-XXXX-XXXX-{creditCardNumber.Substring(creditCardNumber.Length - 4)} and SSN: XXX-XX-{ssn.Substring(ssn.Length - 4)}");
                
                // Process payment logic
            }
            catch (Exception ex)
            {
                // ok: sensitive-information-leak-csharp-rule
                _logger.LogError("Error processing payment. See logs for details.");
                _logger.LogDebug($"Error details: {ex}"); // Only in debug mode
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public void good_case_2()
        {
            string password = Request.Form["password"];
            string username = Request.Form["username"];
            
            // ok: sensitive-information-leak-csharp-rule
            Console.WriteLine($"User {username} attempted login");
            
            // Authentication logic
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public void good_case_3()
        {
            try
            {
                string apiKey = Request.Headers["X-API-Key"];
                
                // ok: sensitive-information-leak-csharp-rule
                _logger.LogDebug("API request received with valid key");
                
                // API processing logic
            }
            catch (Exception ex)
            {
                // ok: sensitive-information-leak-csharp-rule
                _logger.LogError("API request processing failed");
                
                #if DEBUG
                _logger.LogDebug($"Debug details: {ex}");
                #endif
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public void good_case_4()
        {
            string connectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";
            
            try
            {
                using (SqlConnection connection = new SqlConnection(connectionString))
                {
                    connection.Open();
                    // Database operations
                }
            }
            catch (Exception ex)
            {
                // ok: sensitive-information-leak-csharp-rule
                _logger.LogError("Database connection failed. Check server status.");
                
                // Log exception details only in development environment
                if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
                {
                    _logger.LogDebug($"Connection error details: {ex.Message}");
                }
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public void good_case_5()
        {
            string token = Request.Cookies["auth_token"];
            
            // ok: sensitive-information-leak-csharp-rule
            _logger.LogInformation("User authentication attempt processed");
            
            // Authentication verification logic
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public void good_case_6()
        {
            try
            {
                string privateKey = System.IO.File.ReadAllText("private_key.pem");
                
                // Some encryption logic
                
                // ok: sensitive-information-leak-csharp-rule
                _logger.LogInformation("Encryption completed successfully");
            }
            catch (Exception ex)
            {
                // ok: sensitive-information-leak-csharp-rule
                Console.WriteLine("Encryption failed. Check key file.");
                
                // Log to secure channel for administrators only
                _logger.LogDebug($"Encryption error: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public void good_case_7()
        {
            Dictionary<string, string> userCredentials = new Dictionary<string, string>
            {
                { "username", Request.Form["username"] },
                { "password", Request.Form["password"] }
            };
            
            // ok: sensitive-information-leak-csharp-rule
            _logger.LogInformation($"Authentication attempt for user: {userCredentials["username"]}");
            
            // Authentication logic
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public void good_case_8()
        {
            try
            {
                string accountNumber = Request.Query["accountNumber"];
                decimal amount = decimal.Parse(Request.Query["amount"]);
                
                // Transaction logic
                
                // ok: sensitive-information-leak-csharp-rule
                _logger.LogInformation($"Transaction completed for account ending in {accountNumber.Substring(accountNumber.Length - 4)}");
            }
            catch (Exception ex)
            {
                // ok: sensitive-information-leak-csharp-rule
                _logger.LogError("Transaction failed");
                
                // Only log technical details in development
                if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
                {
                    _logger.LogDebug($"Error details: {ex.Message}");
                }
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public void good_case_9()
        {
            string healthData = Request.Form["healthData"];
            string patientId = Request.Form["patientId"];
            
            // ok: sensitive-information-leak-csharp-rule
            using (StreamWriter writer = new StreamWriter("health_records.log", true))
            {
                writer.WriteLine($"Patient ID: {patientId} - Data processed at {DateTime.Now}");
            }
            
            // Health record processing
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public void good_case_10()
        {
            try
            {
                string encryptionKey = _configuration["EncryptionKey"];
                
                // Encryption logic
                
                // ok: sensitive-information-leak-csharp-rule
                _logger.LogInformation("Data encrypted successfully");
            }
            catch (Exception ex)
            {
                // ok: sensitive-information-leak-csharp-rule
                _logger.LogError("Encryption failed");
                
                // Log detailed error only in secure channel
                _logger.LogDebug($"Error message: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public void good_case_11()
        {
            string socialSecurityNumber = Request.Form["ssn"];
            
            try
            {
                // Process SSN
                if (string.IsNullOrEmpty(socialSecurityNumber))
                {
                    throw new ArgumentException("SSN is required");
                }
                
                // More processing
            }
            catch (Exception ex)
            {
                // ok: sensitive-information-leak-csharp-rule
                _logger.LogError("Error processing personal identification information");
                
                // Log masked version of the data
                if (!string.IsNullOrEmpty(socialSecurityNumber) && socialSecurityNumber.Length >= 4)
                {
                    _logger.LogDebug($"Error for SSN ending in {socialSecurityNumber.Substring(socialSecurityNumber.Length - 4)}");
                }
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public void good_case_12()
        {
            string databasePassword = "SecretDbPassword123!";
            
            try
            {
                // Database connection logic
            }
            catch (Exception ex)
            {
                // ok: sensitive-information-leak-csharp-rule
                _logger.LogError("Failed to connect to database");
                
                // Log only in secure environments
                if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
                {
                    _logger.LogDebug($"Connection error: {ex.Message}");
                }
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public void good_case_13()
        {
            try
            {
                string userInput = Request.Query["input"];
                
                // Process user input
                if (userInput.Length < 5)
                {
                    throw new ArgumentException("Input too short");
                }
                
                // More processing
            }
            catch (Exception ex)
            {
                // ok: sensitive-information-leak-csharp-rule
                Response.WriteAsync("An error occurred while processing your request");
                
                // Log the actual error internally
                _logger.LogError($"Input validation error: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public void good_case_14()
        {
            string creditCardCVV = Request.Form["cvv"];
            string cardNumber = Request.Form["cardNumber"];
            
            // ok: sensitive-information-leak-csharp-rule
            _logger.LogInformation($"Payment processing started for card ending in {cardNumber.Substring(cardNumber.Length - 4)}");
            
            // Payment processing logic
        }
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

        public void good_case_15()
        {
            try
            {
                byte[] keyData = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(keyData);
                }
                
                // Encryption logic
                
                // ok: sensitive-information-leak-csharp-rule
                _logger.LogInformation("Encryption key generated successfully");
                
                // Store key securely, not in logs
            }
            catch (Exception ex)
            {
                // ok: sensitive-information-leak-csharp-rule
                _logger.LogError("Key generation failed");
                
                // Log only in development environment
                if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
                {
                    _logger.LogDebug($"Error details: {ex.Message}");
                }
            }
        }
// {/fact}
    }
}