using System;
using System.Web;
using System.Web.Mvc;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Serilog;
using NLog;
using log4net;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace LogInjectionExamples
{
    public class LogInjectionController : Controller
    {
        private static readonly ILogger<LogInjectionController> _logger = null;
        private static readonly NLog.Logger _nlogger = LogManager.GetCurrentClassLogger();
        private static readonly ILog _log4netLogger = LogManager.GetLogger(typeof(LogInjectionController));
        private static readonly Serilog.ILogger _serilogger = Serilog.Log.ForContext<LogInjectionController>();
// {fact rule=ldap-injection@v1.0 defects=1}

        // True Positive Examples (Vulnerable Code)

        public void bad_case_1()
        {
            string username = Request.QueryString["username"];
            // ruleid: csharp-log-injection-ide
            Console.WriteLine("User login attempt: " + username);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_2()
        {
            string userInput = Request.Form["message"];
            // ruleid: csharp-log-injection-ide
            _logger.LogInformation("Received message: " + userInput);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_3()
        {
            string ipAddress = Request.Headers["X-Forwarded-For"];
            // ruleid: csharp-log-injection-ide
            _nlogger.Info($"Request from IP: {ipAddress}");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_4()
        {
            string searchQuery = Request.QueryString["q"];
            // ruleid: csharp-log-injection-ide
            _log4netLogger.Info("Search query executed: " + searchQuery);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_5()
        {
            string userAgent = Request.Headers["User-Agent"];
            // ruleid: csharp-log-injection-ide
            Debug.WriteLine("User agent: " + userAgent);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_6()
        {
            string referrer = Request.Headers["Referer"];
            // ruleid: csharp-log-injection-ide
            _serilogger.Information("User came from: {Referrer}", referrer);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_7(HttpRequest request)
        {
            string email = request.Form["email"];
            // ruleid: csharp-log-injection-ide
            Trace.TraceInformation("Registration attempt with email: " + email);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_8(HttpContext context)
        {
            string authHeader = context.Request.Headers["Authorization"];
            // ruleid: csharp-log-injection-ide
            _logger.LogWarning($"Authentication attempt with token: {authHeader}");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_9()
        {
            string errorMessage = Request.QueryString["error"];
            if (!string.IsNullOrEmpty(errorMessage))
            {
                // ruleid: csharp-log-injection-ide
                _nlogger.Error("Client reported error: " + errorMessage);
            }
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_10(HttpContext httpContext)
        {
            string requestBody = new StreamReader(httpContext.Request.Body).ReadToEndAsync().Result;
            // ruleid: csharp-log-injection-ide
            _log4netLogger.Debug("Request body: " + requestBody);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_11()
        {
            var cookies = Request.Cookies;
            string sessionId = cookies["SessionId"];
            // ruleid: csharp-log-injection-ide
            Console.WriteLine($"Session ID from cookie: {sessionId}");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_12()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"]; // Should never log passwords!
            
            // ruleid: csharp-log-injection-ide
            _logger.LogInformation("Login attempt - Username: " + username + ", Password length: " + password.Length);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_13(HttpRequest request)
        {
            string contentType = request.ContentType;
            // ruleid: csharp-log-injection-ide
            _serilogger.Debug("Content type of request: " + contentType);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_14()
        {
            string queryParams = Request.QueryString.ToString();
            // ruleid: csharp-log-injection-ide
            _nlogger.Info("Query parameters: " + queryParams);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_15(HttpContext context)
        {
            string path = context.Request.Path;
            string method = context.Request.Method;
            
            // ruleid: csharp-log-injection-ide
            _logger.LogInformation($"Request {method} {path} received at {DateTime.Now}");
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        // True Negative Examples (Safe Code)

        public void good_case_1()
        {
            string username = Request.QueryString["username"];
            // ok: csharp-log-injection-ide
            Console.WriteLine("User login attempt: {0}", HttpUtility.HtmlEncode(username));
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_2()
        {
            string userInput = Request.Form["message"];
            // ok: csharp-log-injection-ide
            _logger.LogInformation("Received message: {Message}", HttpUtility.HtmlEncode(userInput));
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_3()
        {
            string ipAddress = Request.Headers["X-Forwarded-For"];
            string sanitizedIp = Regex.Replace(ipAddress, @"[^\d\.]", "");
            // ok: csharp-log-injection-ide
            _nlogger.Info("Request from IP: {0}", sanitizedIp);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_4()
        {
            string searchQuery = Request.QueryString["q"];
            // ok: csharp-log-injection-ide
            _log4netLogger.Info(string.Format("Search query executed: {0}", WebUtility.HtmlEncode(searchQuery)));
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_5()
        {
            string userAgent = Request.Headers["User-Agent"];
            // ok: csharp-log-injection-ide
            Debug.WriteLine("User agent: {0}", HttpUtility.HtmlEncode(userAgent));
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_6()
        {
            string referrer = Request.Headers["Referer"];
            // Serilog's templated logging is safe when using positional parameters
            // ok: csharp-log-injection-ide
            _serilogger.Information("User came from: {@Referrer}", HttpUtility.HtmlEncode(referrer));
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_7(HttpRequest request)
        {
            string email = request.Form["email"];
            // Using a sanitization method
            string sanitizedEmail = SanitizeForLog(email);
            // ok: csharp-log-injection-ide
            Trace.TraceInformation("Registration attempt with email: {0}", sanitizedEmail);
        }
// {/fact}

        private string SanitizeForLog(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;
                
            // Remove control characters and normalize line breaks
            return HttpUtility.HtmlEncode(Regex.Replace(input, @"[\r\n\t]", " "));
        }
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_8(HttpContext context)
        {
            string authHeader = context.Request.Headers["Authorization"];
            // Mask sensitive information before logging
            string maskedAuth = MaskAuthToken(authHeader);
            // ok: csharp-log-injection-ide
            _logger.LogWarning("Authentication attempt with token: {Token}", maskedAuth);
        }
// {/fact}

        private string MaskAuthToken(string token)
        {
            if (string.IsNullOrEmpty(token))
                return string.Empty;
                
            if (token.Length <= 8)
                return "***";
                
            return token.Substring(0, 4) + "..." + token.Substring(token.Length - 4);
        }
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_9()
        {
            string errorMessage = Request.QueryString["error"];
            if (!string.IsNullOrEmpty(errorMessage))
            {
                // ok: csharp-log-injection-ide
                _nlogger.Error("Client reported error: {0}", HttpUtility.HtmlEncode(errorMessage));
            }
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_10(HttpContext httpContext)
        {
            string requestBody = new StreamReader(httpContext.Request.Body).ReadToEndAsync().Result;
            // ok: csharp-log-injection-ide
            _log4netLogger.Debug("Request body: {0}", HttpUtility.HtmlEncode(requestBody));
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_11()
        {
            var cookies = Request.Cookies;
            string sessionId = cookies["SessionId"];
            // Mask most of the session ID for security
            string maskedSessionId = sessionId.Length > 8 
                ? sessionId.Substring(0, 4) + "..." + sessionId.Substring(sessionId.Length - 4) 
                : "***";
            // ok: csharp-log-injection-ide
            Console.WriteLine("Session ID from cookie: {0}", maskedSessionId);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_12()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"]; // Should never log passwords!
            
            // ok: csharp-log-injection-ide
            _logger.LogInformation("Login attempt - Username: {Username}, Password length: {PasswordLength}", 
                HttpUtility.HtmlEncode(username), password.Length);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_13(HttpRequest request)
        {
            string contentType = request.ContentType;
            // Using a whitelist approach for content types
            string safeContentType = ValidateContentType(contentType);
            // ok: csharp-log-injection-ide
            _serilogger.Debug("Content type of request: {ContentType}", safeContentType);
        }
// {/fact}

        private string ValidateContentType(string contentType)
        {
            string[] allowedTypes = new[] { "application/json", "application/xml", "text/plain", "text/html" };
            return allowedTypes.Contains(contentType) ? contentType : "invalid-content-type";
        }
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_14()
        {
            string queryParams = Request.QueryString.ToString();
            // Create a dictionary of sanitized parameters instead of logging raw string
            var sanitizedParams = new Dictionary<string, string>();
            foreach (string key in Request.QueryString.Keys)
            {
                sanitizedParams[HttpUtility.HtmlEncode(key)] = HttpUtility.HtmlEncode(Request.QueryString[key]);
            }
            // ok: csharp-log-injection-ide
            _nlogger.Info("Query parameters: {@QueryParams}", sanitizedParams);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

        public void good_case_15(HttpContext context)
        {
            string path = context.Request.Path;
            string method = context.Request.Method;
            
            // Validate HTTP method against known values
            if (!new[] { "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS" }.Contains(method))
            {
                method = "INVALID";
            }
            
            // Sanitize path
            string sanitizedPath = HttpUtility.HtmlEncode(path);
            
            // ok: csharp-log-injection-ide
            _logger.LogInformation("Request {Method} {Path} received at {Timestamp}", 
                method, sanitizedPath, DateTime.Now);
        }
// {/fact}
    }
}