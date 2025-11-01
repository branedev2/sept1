using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using NLog;
using Serilog;
using Microsoft.AspNetCore.Http;
using System.Net.Http;
using System.Threading.Tasks;

namespace StructuredLoggingExamples
{
    public class LoggingExamples
    {
// {fact rule=ldap-injection@v1.0 defects=1}
        // True Positive Examples (Bad Cases)

        public void bad_case_1(ILogger<LoggingExamples> logger, string username)
        {
            try
            {
                // Some operation
                // ruleid: structured-logging-csharp-rule
                logger.LogInformation($"User {username} logged in successfully");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Login failed");
            }
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_2(ILogger<LoggingExamples> logger, string orderId, decimal amount)
        {
            // ruleid: structured-logging-csharp-rule
            logger.LogWarning($"Order {orderId} with amount {amount:C} is pending approval");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_3()
        {
            var logger = LogManager.GetCurrentClassLogger();
            var userId = "user123";
            var action = "delete";
            
            // ruleid: structured-logging-csharp-rule
            logger.Info($"User {userId} performed {action} operation");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_4(ILogger<LoggingExamples> logger)
        {
            var requestId = Guid.NewGuid().ToString();
            var endpoint = "/api/users";
            
            // ruleid: structured-logging-csharp-rule
            logger.LogDebug($"Processing request {requestId} to endpoint {endpoint}");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_5(ILogger<LoggingExamples> logger, HttpContext context)
        {
            var ip = context.Connection.RemoteIpAddress;
            var path = context.Request.Path;
            
            // ruleid: structured-logging-csharp-rule
            logger.LogInformation($"Request from IP {ip} to path {path}");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_6()
        {
            var log = new LoggerConfiguration()
                .WriteTo.Console()
                .CreateLogger();
                
            var username = "john.doe";
            var loginAttempts = 3;
            
            // ruleid: structured-logging-csharp-rule
            log.Information($"User {username} has made {loginAttempts} failed login attempts");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_7(ILogger<LoggingExamples> logger, string filename, long filesize)
        {
            // ruleid: structured-logging-csharp-rule
            logger.LogInformation($"File {filename} with size {filesize} bytes was uploaded");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_8(ILogger<LoggingExamples> logger)
        {
            var startTime = DateTime.Now;
            var operation = "database backup";
            
            // Some operation
            var endTime = DateTime.Now;
            var duration = (endTime - startTime).TotalSeconds;
            
            // ruleid: structured-logging-csharp-rule
            logger.LogInformation($"Operation {operation} completed in {duration} seconds");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_9(ILogger<LoggingExamples> logger, string productId, int quantity)
        {
            // ruleid: structured-logging-csharp-rule
            logger.LogWarning($"Low stock alert: Product {productId} has only {quantity} items remaining");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_10()
        {
            var logger = LogManager.GetCurrentClassLogger();
            var errorCode = "E404";
            var errorMessage = "Resource not found";
            
            // ruleid: structured-logging-csharp-rule
            logger.Error($"Error occurred: {errorCode} - {errorMessage}");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_11(ILogger<LoggingExamples> logger, string transactionId, string status)
        {
            // ruleid: structured-logging-csharp-rule
            logger.LogInformation($"Transaction {transactionId} status changed to {status}");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_12(ILogger<LoggingExamples> logger)
        {
            var configName = "app.config";
            var settingsCount = 42;
            
            // ruleid: structured-logging-csharp-rule
            logger.LogDebug($"Loaded {settingsCount} settings from {configName}");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_13(ILogger<LoggingExamples> logger, HttpContext context)
        {
            var userAgent = context.Request.Headers["User-Agent"].ToString();
            var method = context.Request.Method;
            
            // ruleid: structured-logging-csharp-rule
            logger.LogInformation($"Request with method {method} from user agent {userAgent}");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_14()
        {
            var log = new LoggerConfiguration()
                .WriteTo.Console()
                .CreateLogger();
                
            var apiName = "PaymentAPI";
            var responseTime = 1500;
            
            // ruleid: structured-logging-csharp-rule
            log.Warning($"API {apiName} response time ({responseTime}ms) exceeds threshold");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_15(ILogger<LoggingExamples> logger, string username, string role)
        {
            // ruleid: structured-logging-csharp-rule
            logger.LogInformation($"User {username} was assigned role {role}");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        // True Negative Examples (Good Cases)

        public void good_case_1(ILogger<LoggingExamples> logger, string username)
        {
            try
            {
                // Some operation
                // ok: structured-logging-csharp-rule
                logger.LogInformation("User {Username} logged in successfully", username);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Login failed");
            }
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_2(ILogger<LoggingExamples> logger, string orderId, decimal amount)
        {
            // ok: structured-logging-csharp-rule
            logger.LogWarning("Order {OrderId} with amount {Amount} is pending approval", orderId, amount);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_3()
        {
            var logger = LogManager.GetCurrentClassLogger();
            var userId = "user123";
            var action = "delete";
            
            // ok: structured-logging-csharp-rule
            logger.Info("User {UserId} performed {Action} operation", userId, action);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_4(ILogger<LoggingExamples> logger)
        {
            var requestId = Guid.NewGuid().ToString();
            var endpoint = "/api/users";
            
            // ok: structured-logging-csharp-rule
            logger.LogDebug("Processing request {RequestId} to endpoint {Endpoint}", requestId, endpoint);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_5(ILogger<LoggingExamples> logger, HttpContext context)
        {
            var ip = context.Connection.RemoteIpAddress;
            var path = context.Request.Path;
            
            // ok: structured-logging-csharp-rule
            logger.LogInformation("Request from IP {IpAddress} to path {Path}", ip, path);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_6()
        {
            var log = new LoggerConfiguration()
                .WriteTo.Console()
                .CreateLogger();
                
            var username = "john.doe";
            var loginAttempts = 3;
            
            // ok: structured-logging-csharp-rule
            log.Information("User {Username} has made {LoginAttempts} failed login attempts", username, loginAttempts);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_7(ILogger<LoggingExamples> logger, string filename, long filesize)
        {
            // ok: structured-logging-csharp-rule
            logger.LogInformation("File {Filename} with size {Filesize} bytes was uploaded", filename, filesize);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_8(ILogger<LoggingExamples> logger)
        {
            var startTime = DateTime.Now;
            var operation = "database backup";
            
            // Some operation
            var endTime = DateTime.Now;
            var duration = (endTime - startTime).TotalSeconds;
            
            // ok: structured-logging-csharp-rule
            logger.LogInformation("Operation {Operation} completed in {Duration} seconds", operation, duration);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_9(ILogger<LoggingExamples> logger, string productId, int quantity)
        {
            // ok: structured-logging-csharp-rule
            logger.LogWarning("Low stock alert: Product {ProductId} has only {Quantity} items remaining", productId, quantity);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_10()
        {
            var logger = LogManager.GetCurrentClassLogger();
            var errorCode = "E404";
            var errorMessage = "Resource not found";
            
            // ok: structured-logging-csharp-rule
            logger.Error("Error occurred: {ErrorCode} - {ErrorMessage}", errorCode, errorMessage);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_11(ILogger<LoggingExamples> logger, string transactionId, string status)
        {
            var logData = new Dictionary<string, object>
            {
                ["TransactionId"] = transactionId,
                ["Status"] = status
            };
            
            // ok: structured-logging-csharp-rule
            using (logger.BeginScope(logData))
            {
                logger.LogInformation("Transaction status changed");
            }
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_12(ILogger<LoggingExamples> logger)
        {
            var configName = "app.config";
            var settingsCount = 42;
            
            // ok: structured-logging-csharp-rule
            logger.LogDebug("Loaded {SettingsCount} settings from {ConfigName}", settingsCount, configName);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_13(ILogger<LoggingExamples> logger, HttpContext context)
        {
            var userAgent = context.Request.Headers["User-Agent"].ToString();
            var method = context.Request.Method;
            
            // ok: structured-logging-csharp-rule
            logger.LogInformation("Request with method {Method} from user agent {UserAgent}", method, userAgent);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_14()
        {
            var log = new LoggerConfiguration()
                .WriteTo.Console()
                .CreateLogger();
                
            var apiName = "PaymentAPI";
            var responseTime = 1500;
            
            // ok: structured-logging-csharp-rule
            log.Warning("API {ApiName} response time ({ResponseTime}ms) exceeds threshold", apiName, responseTime);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public async Task good_case_15(ILogger<LoggingExamples> logger)
        {
            var client = new HttpClient();
            var url = "https://api.example.com/data";
            
            try
            {
                var response = await client.GetAsync(url);
                var statusCode = (int)response.StatusCode;
                
                // ok: structured-logging-csharp-rule
                logger.LogInformation("API call to {Url} returned status code {StatusCode}", url, statusCode);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "API call to {Url} failed", url);
            }
        }
// {/fact}
    }

    [ApiController]
    [Route("api/[controller]")]
    public class LoggingController : ControllerBase
    {
        private readonly ILogger<LoggingController> _logger;

        public LoggingController(ILogger<LoggingController> logger)
        {
            _logger = logger;
        }

        [HttpGet("{id}")]
        public IActionResult Get(string id)
        {
            // This would be flagged by the rule
            _logger.LogInformation($"Retrieving item with ID {id}");
            
            // This is the correct way
            _logger.LogInformation("Retrieving item with ID {ItemId}", id);
            
            return Ok(new { Id = id });
        }
    }
}