using System;
using System.Web;
using System.Web.Mvc;
using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace StackTraceExposureExamples
{
    public class StackTraceExposureController : Controller
    {
        private readonly ILogger<StackTraceExposureController> _logger;
        
        public StackTraceExposureController(ILogger<StackTraceExposureController> logger)
        {
            _logger = logger;
        }
// {fact rule=stack-trace-exposure@v1.0 defects=1}

        // True Positive Examples (Vulnerable Code)

        public ActionResult bad_case_1()
        {
            try
            {
                int zero = 0;
                int result = 10 / zero; // This will cause a division by zero exception
                return Content("Result: " + result);
            }
            catch (Exception ex)
            {
                // ruleid: stack-trace-exposure
                return Content("An error occurred: " + ex.ToString());
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=1}

        public ActionResult bad_case_2()
        {
            try
            {
                string filePath = Request.QueryString["file"];
                var fileContent = System.IO.File.ReadAllText(filePath);
                return Content(fileContent);
            }
            catch (Exception ex)
            {
                // ruleid: stack-trace-exposure
                Response.Write("Error details: " + ex.StackTrace);
                return new EmptyResult();
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=1}

        public JsonResult bad_case_3()
        {
            try
            {
                string[] data = null;
                var item = data[0]; // Will throw NullReferenceException
                return Json(new { success = true, data = item });
            }
            catch (Exception ex)
            {
                // ruleid: stack-trace-exposure
                return Json(new { success = false, error = ex.ToString(), stackTrace = ex.StackTrace });
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=1}

        public ActionResult bad_case_4()
        {
            Exception error = null;
            try
            {
                var invalidData = Convert.ToInt32("not_a_number");
            }
            catch (Exception ex)
            {
                error = ex;
            }

            if (error != null)
            {
                // ruleid: stack-trace-exposure
                ViewBag.ErrorDetails = error.StackTrace;
                return View("Error");
            }
            
            return View();
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=1}

        [HttpPost]
        public IActionResult bad_case_5([FromBody] dynamic data)
        {
            try
            {
                if (data == null)
                {
                    throw new ArgumentNullException("data");
                }
                
                // Process data
                return Ok("Data processed successfully");
            }
            catch (Exception ex)
            {
                // ruleid: stack-trace-exposure
                return StatusCode(500, "Server error details: " + ex.Message + "\n" + ex.StackTrace);
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=1}

        public async Task<IActionResult> bad_case_6()
        {
            try
            {
                using (HttpClient client = new HttpClient())
                {
                    var response = await client.GetAsync("https://nonexistent-domain-12345.com");
                    response.EnsureSuccessStatusCode();
                    return Ok(await response.Content.ReadAsStringAsync());
                }
            }
            catch (Exception ex)
            {
                // ruleid: stack-trace-exposure
                return BadRequest(new { message = "Failed to fetch data", details = ex.ToString() });
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=1}

        public IActionResult bad_case_7()
        {
            try
            {
                var dbConnection = new System.Data.SqlClient.SqlConnection("invalid_connection_string");
                dbConnection.Open(); // This will throw an exception
                return Ok("Connected to database");
            }
            catch (Exception ex)
            {
                // ruleid: stack-trace-exposure
                HttpContext.Response.WriteAsync($"Database error: {ex.Message}\nStack: {ex.StackTrace}");
                return new EmptyResult();
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=1}

        public ContentResult bad_case_8()
        {
            try
            {
                string input = Request.Form["input"];
                if (string.IsNullOrEmpty(input))
                {
                    throw new ArgumentException("Input cannot be empty");
                }
                return Content("Input processed: " + input);
            }
            catch (Exception ex)
            {
                // ruleid: stack-trace-exposure
                return Content($"<html><body><h1>Error</h1><pre>{ex.ToString()}</pre></body></html>", "text/html");
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=1}

        public IActionResult bad_case_9()
        {
            var env = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            try
            {
                int.Parse(Request.Query["id"]);
                return Ok("ID processed");
            }
            catch (Exception ex)
            {
                // Even though we check for environment, we're still exposing the stack trace in production
                if (env != "Development")
                {
                    // ruleid: stack-trace-exposure
                    return StatusCode(500, $"Error processing ID: {ex.StackTrace}");
                }
                return StatusCode(500, "An error occurred");
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=1}

        public IActionResult bad_case_10()
        {
            Exception capturedEx = null;
            try
            {
                var path = Path.Combine(Request.Query["directory"], "file.txt");
                var content = File.ReadAllText(path);
                return Ok(content);
            }
            catch (Exception ex)
            {
                capturedEx = ex;
                _logger.LogError(ex, "Error reading file");
            }

            // ruleid: stack-trace-exposure
            return View("ErrorView", capturedEx);
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=1}

        public IActionResult bad_case_11()
        {
            try
            {
                throw new NotImplementedException("This feature is not implemented yet");
            }
            catch (Exception ex)
            {
                var errorModel = new ErrorViewModel
                {
                    RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
                    // ruleid: stack-trace-exposure
                    StackTrace = ex.StackTrace,
                    ErrorMessage = ex.Message
                };
                
                return View("Error", errorModel);
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=1}

        [HttpGet]
        public string bad_case_12(string filename)
        {
            try
            {
                if (string.IsNullOrEmpty(filename))
                {
                    throw new ArgumentNullException(nameof(filename));
                }
                
                var content = File.ReadAllText(filename);
                return content;
            }
            catch (Exception ex)
            {
                // ruleid: stack-trace-exposure
                return $"Error processing file: {ex.GetType().Name}\n{ex.Message}\n{ex.StackTrace}";
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=1}

        public IActionResult bad_case_13()
        {
            StringBuilder errorInfo = new StringBuilder();
            
            try
            {
                var result = ProcessComplexOperation();
                return Ok(result);
            }
            catch (Exception ex)
            {
                errorInfo.AppendLine("Error Type: " + ex.GetType().Name);
                errorInfo.AppendLine("Message: " + ex.Message);
                // ruleid: stack-trace-exposure
                errorInfo.AppendLine("Stack Trace: " + ex.StackTrace);
                
                return Content(errorInfo.ToString(), "text/plain");
            }
        }
// {/fact}

        private string ProcessComplexOperation()
        {
            throw new NotImplementedException();
        }

        public IActionResult bad_case_14()
        {
            var errorDetails = string.Empty;
            
            try
            {
                var userId = int.Parse(Request.Query["userId"]);
                // Do something with userId
                return Ok($"User ID: {userId}");
            }
            catch (Exception ex)
            {
                errorDetails = $"Exception: {ex.Message}\n";
                // ruleid: stack-trace-exposure
                errorDetails += $"Stack: {ex.StackTrace}";
            }
            
            return BadRequest(errorDetails);
        }
// {fact rule=stack-trace-exposure@v1.0 defects=1}

        public IActionResult bad_case_15()
        {
            try
            {
                // Simulate database operation
                throw new System.Data.SqlClient.SqlException("Database connection failed");
            }
            catch (Exception ex)
            {
                // Creating a custom error object but still exposing stack trace
                var errorResponse = new
                {
                    Success = false,
                    ErrorCode = 500,
                    Message = "Database operation failed",
                    // ruleid: stack-trace-exposure
                    TechnicalDetails = ex.ToString()
                };
                
                return Json(errorResponse);
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=0}

        // True Negative Examples (Safe Code)

        public ActionResult good_case_1()
        {
            try
            {
                int zero = 0;
                int result = 10 / zero; // This will cause a division by zero exception
                return Content("Result: " + result);
            }
            catch (Exception ex)
            {
                // ok: stack-trace-exposure
                _logger.LogError(ex, "Division by zero error");
                return Content("An error occurred. Please contact support.");
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=0}

        public ActionResult good_case_2()
        {
            try
            {
                string filePath = Request.QueryString["file"];
                var fileContent = System.IO.File.ReadAllText(filePath);
                return Content(fileContent);
            }
            catch (Exception ex)
            {
                // ok: stack-trace-exposure
                _logger.LogError(ex, "Error reading file: {FilePath}", filePath);
                return Content("Unable to read the requested file. Please verify the file path.");
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=0}

        public JsonResult good_case_3()
        {
            try
            {
                string[] data = null;
                var item = data[0]; // Will throw NullReferenceException
                return Json(new { success = true, data = item });
            }
            catch (Exception ex)
            {
                // Log the full exception for debugging
                _logger.LogError(ex, "Null reference exception occurred");
                
                // ok: stack-trace-exposure
                return Json(new { success = false, error = "An internal error occurred" });
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=0}

        public ActionResult good_case_4()
        {
            Exception error = null;
            try
            {
                var invalidData = Convert.ToInt32("not_a_number");
            }
            catch (Exception ex)
            {
                error = ex;
                _logger.LogError(ex, "Format exception occurred");
            }

            if (error != null)
            {
                // ok: stack-trace-exposure
                ViewBag.ErrorMessage = "Invalid input format. Please provide a valid number.";
                return View("Error");
            }
            
            return View();
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=0}

        [HttpPost]
        public IActionResult good_case_5([FromBody] dynamic data)
        {
            try
            {
                if (data == null)
                {
                    throw new ArgumentNullException("data");
                }
                
                // Process data
                return Ok("Data processed successfully");
            }
            catch (Exception ex)
            {
                // ok: stack-trace-exposure
                _logger.LogError(ex, "Error processing data");
                return StatusCode(500, "An error occurred while processing your request.");
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=0}

        public async Task<IActionResult> good_case_6()
        {
            try
            {
                using (HttpClient client = new HttpClient())
                {
                    var response = await client.GetAsync("https://nonexistent-domain-12345.com");
                    response.EnsureSuccessStatusCode();
                    return Ok(await response.Content.ReadAsStringAsync());
                }
            }
            catch (Exception ex)
            {
                // Log the exception with full details for debugging
                _logger.LogError(ex, "Failed to fetch data from external API");
                
                // ok: stack-trace-exposure
                return BadRequest(new { message = "Failed to fetch data from external service" });
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=0}

        public IActionResult good_case_7()
        {
            try
            {
                var dbConnection = new System.Data.SqlClient.SqlConnection("invalid_connection_string");
                dbConnection.Open(); // This will throw an exception
                return Ok("Connected to database");
            }
            catch (Exception ex)
            {
                // Log the exception with full details
                _logger.LogError(ex, "Database connection error");
                
                // ok: stack-trace-exposure
                return StatusCode(500, "Unable to connect to the database. Please try again later.");
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=0}

        public ContentResult good_case_8()
        {
            try
            {
                string input = Request.Form["input"];
                if (string.IsNullOrEmpty(input))
                {
                    throw new ArgumentException("Input cannot be empty");
                }
                return Content("Input processed: " + input);
            }
            catch (ArgumentException ex)
            {
                // ok: stack-trace-exposure
                return Content($"<html><body><h1>Error</h1><p>Please provide a valid input.</p></body></html>", "text/html");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error processing input");
                return Content($"<html><body><h1>Error</h1><p>An unexpected error occurred.</p></body></html>", "text/html");
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=0}

        public IActionResult good_case_9()
        {
            var env = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            try
            {
                int.Parse(Request.Query["id"]);
                return Ok("ID processed");
            }
            catch (Exception ex)
            {
                // Log the full exception
                _logger.LogError(ex, "Error parsing ID");
                
                // Only show detailed errors in development
                if (env == "Development")
                {
                    // ok: stack-trace-exposure
                    return StatusCode(500, $"Error processing ID: {ex.Message} - {ex.StackTrace}");
                }
                
                return StatusCode(500, "An error occurred processing your request");
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=0}

        public IActionResult good_case_10()
        {
            try
            {
                var path = Path.Combine(Request.Query["directory"], "file.txt");
                var content = File.ReadAllText(path);
                return Ok(content);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error reading file");
                
                // ok: stack-trace-exposure
                return View("ErrorView", new ErrorViewModel 
                { 
                    RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
                    ErrorMessage = "Could not read the requested file"
                });
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=0}

        public IActionResult good_case_11()
        {
            try
            {
                throw new NotImplementedException("This feature is not implemented yet");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Feature not implemented");
                
                var errorModel = new ErrorViewModel
                {
                    RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
                    // ok: stack-trace-exposure
                    ErrorMessage = "This feature is currently unavailable"
                };
                
                return View("Error", errorModel);
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=0}

        [HttpGet]
        public string good_case_12(string filename)
        {
            try
            {
                if (string.IsNullOrEmpty(filename))
                {
                    throw new ArgumentNullException(nameof(filename));
                }
                
                var content = File.ReadAllText(filename);
                return content;
            }
            catch (FileNotFoundException)
            {
                // ok: stack-trace-exposure
                return "The requested file could not be found.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing file: {Filename}", filename);
                return "An error occurred while processing your file request.";
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=0}

        public IActionResult good_case_13()
        {
            try
            {
                var result = ProcessComplexOperation();
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in complex operation");
                
                // ok: stack-trace-exposure
                return StatusCode(500, "The operation could not be completed due to a server error.");
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=0}

        public IActionResult good_case_14()
        {
            try
            {
                var userId = int.Parse(Request.Query["userId"]);
                // Do something with userId
                return Ok($"User ID: {userId}");
            }
            catch (FormatException)
            {
                // ok: stack-trace-exposure
                return BadRequest("User ID must be a valid number");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing user ID");
                return StatusCode(500, "An unexpected error occurred");
            }
        }
// {/fact}
// {fact rule=stack-trace-exposure@v1.0 defects=0}

        public IActionResult good_case_15()
        {
            try
            {
                // Simulate database operation
                throw new System.Data.SqlClient.SqlException("Database connection failed");
            }
            catch (System.Data.SqlClient.SqlException ex)
            {
                _logger.LogError(ex, "Database operation failed");
                
                // Creating a custom error object without exposing stack trace
                var errorResponse = new
                {
                    Success = false,
                    ErrorCode = 500,
                    // ok: stack-trace-exposure
                    Message = "Database operation failed. Please try again later."
                };
                
                return Json(errorResponse);
            }
        }
// {/fact}
    }

    public class ErrorViewModel
    {
        public string RequestId { get; set; }
        public string ErrorMessage { get; set; }
        public string StackTrace { get; set; }
    }
}