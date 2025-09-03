using System;
using System.Text.RegularExpressions;
using System.Web;
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Threading;
using System.Threading.Tasks;

namespace RegexDosExamples
{
    public class RegexDosController : Controller
    {
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        [HttpGet]
        public IActionResult bad_case_1()
        {
            // Getting user input from query parameter
            string userInput = Request.Query["input"];
            
            // Complex regex pattern that could be vulnerable to ReDoS
            string pattern = @"^(([a-z])+.)+[A-Z]([a-z])+$";
            
            // ruleid: regular-expression-dos-infinite-timeout
            bool isMatch = Regex.IsMatch(userInput, pattern);
            
            return Content($"Match result: {isMatch}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=1}

        [HttpPost]
        public IActionResult bad_case_2()
        {
            // Getting user input from form data
            string userInput = Request.Form["email"];
            
            // Email validation regex that could be exploited
            string emailPattern = @"^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$";
            
            // ruleid: regular-expression-dos-infinite-timeout
            var matches = Regex.Matches(userInput, emailPattern);
            
            return Content($"Found {matches.Count} matches");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=1}

        [HttpGet]
        public IActionResult bad_case_3()
        {
            // Getting user input from header
            string userAgent = Request.Headers["User-Agent"].ToString();
            
            // Complex pattern to identify browser type
            string pattern = @"^Mozilla\/\d\.\d\s\(.*?(?:Windows|Macintosh|Linux|iPhone|Android).*?\)\s(?:.*?\s)?(?:Chrome|Firefox|Safari|Edge|MSIE)\/[\d\.]+.*$";
            
            // ruleid: regular-expression-dos-infinite-timeout
            string result = Regex.Replace(userAgent, pattern, "Detected: $0");
            
            return Content(result);
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=1}

        [HttpPost]
        public IActionResult bad_case_4()
        {
            // Getting user input from cookie
            string cookieValue = Request.Cookies["userPreference"];
            
            // Pattern with nested quantifiers - vulnerable to ReDoS
            string pattern = @"^(a+)+b$";
            
            // ruleid: regular-expression-dos-infinite-timeout
            Regex regex = new Regex(pattern);
            bool isMatch = regex.IsMatch(cookieValue);
            
            return Content($"Match result: {isMatch}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=1}

        [HttpGet]
        public IActionResult bad_case_5()
        {
            // Getting user input from query string
            string htmlContent = Request.Query["content"];
            
            // HTML tag matching regex - can be exploited with deeply nested tags
            string pattern = @"<([a-z]+)([^<]+)*(?:>(.*?)</\1>|\s+/>)";
            
            // ruleid: regular-expression-dos-infinite-timeout
            var matches = Regex.Matches(htmlContent, pattern, RegexOptions.Singleline);
            
            return Content($"Found {matches.Count} HTML tags");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=1}

        [HttpPost]
        public async Task<IActionResult> bad_case_6()
        {
            // Reading body content
            using var reader = new System.IO.StreamReader(Request.Body);
            string requestBody = await reader.ReadToEndAsync();
            
            // JSON property validation regex - can be exploited
            string pattern = @"""([^""\\]|\\.)*""\s*:\s*""([^""\\]|\\.)*""";
            
            // ruleid: regular-expression-dos-infinite-timeout
            var regex = new Regex(pattern, RegexOptions.Multiline);
            var matches = regex.Matches(requestBody);
            
            return Json(new { matchCount = matches.Count });
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=1}

        [HttpGet]
        public IActionResult bad_case_7()
        {
            // Getting URL from query parameter
            string url = Request.Query["url"];
            
            // URL validation regex with potential for catastrophic backtracking
            string pattern = @"^(https?|ftp)://[^\s/$.?#].[^\s]*$";
            
            // ruleid: regular-expression-dos-infinite-timeout
            if (Regex.IsMatch(url, pattern))
            {
                return Content("Valid URL");
            }
            
            return Content("Invalid URL");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=1}

        [HttpPost]
        public IActionResult bad_case_8()
        {
            // Getting XML from form
            string xml = Request.Form["xml"];
            
            // XML tag validation - vulnerable to ReDoS
            string pattern = @"<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>(.*?)</\1>";
            
            // ruleid: regular-expression-dos-infinite-timeout
            var regex = new Regex(pattern, RegexOptions.Singleline);
            string sanitizedXml = regex.Replace(xml, "<sanitized>$2</sanitized>");
            
            return Content(sanitizedXml);
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=1}

        [HttpGet]
        public IActionResult bad_case_9()
        {
            // Getting search term from query
            string searchTerm = Request.Query["q"];
            
            // Complex word boundary pattern
            string pattern = @"\b([\w-]+(?:\.[\w-]+)*@(?:[\w-]+\.)+[a-zA-Z]{2,7})\b";
            
            // ruleid: regular-expression-dos-infinite-timeout
            var regex = new Regex(pattern, RegexOptions.IgnoreCase);
            bool containsEmail = regex.IsMatch(searchTerm);
            
            return Content($"Contains email: {containsEmail}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=1}

        [HttpPost]
        public IActionResult bad_case_10()
        {
            // Getting date from form
            string dateInput = Request.Form["date"];
            
            // Date validation regex with multiple formats
            string pattern = @"^(?:(?:31(\/|-|\.)(?:0?[13578]|1[02]))\1|(?:(?:29|30)(\/|-|\.)(?:0?[13-9]|1[0-2])\2))(?:(?:1[6-9]|[2-9]\d)?\d{2})$|^(?:29(\/|-|\.)0?2\3(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1-9]|1\d|2[0-8])(\/|-|\.)(?:(?:0?[1-9])|(?:1[0-2]))\4(?:(?:1[6-9]|[2-9]\d)?\d{2})$";
            
            // ruleid: regular-expression-dos-infinite-timeout
            bool isValidDate = Regex.IsMatch(dateInput, pattern);
            
            return Content($"Valid date: {isValidDate}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=1}

        [HttpGet]
        public IActionResult bad_case_11()
        {
            // Getting password from query (bad practice but for example)
            string password = Request.Query["password"];
            
            // Password strength checker with complex regex
            string pattern = @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$";
            
            // ruleid: regular-expression-dos-infinite-timeout
            var regex = new Regex(pattern);
            bool isStrongPassword = regex.IsMatch(password);
            
            return Content($"Strong password: {isStrongPassword}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=1}

        [HttpPost]
        public IActionResult bad_case_12()
        {
            // Getting markdown content from form
            string markdown = Request.Form["markdown"];
            
            // Markdown link finder regex
            string pattern = @"\[([^\[]+)\](\(.*\))";
            
            // ruleid: regular-expression-dos-infinite-timeout
            var regex = new Regex(pattern);
            string processedMarkdown = regex.Replace(markdown, "<a href=\"$2\">$1</a>");
            
            return Content(processedMarkdown);
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=1}

        [HttpGet]
        public IActionResult bad_case_13()
        {
            // Getting phone number from query
            string phoneNumber = Request.Query["phone"];
            
            // International phone number validation
            string pattern = @"^\+(?:[0-9] ?){6,14}[0-9]$";
            
            // ruleid: regular-expression-dos-infinite-timeout
            var matches = Regex.Matches(phoneNumber, pattern);
            
            return Content($"Valid phone numbers found: {matches.Count}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=1}

        [HttpPost]
        public IActionResult bad_case_14()
        {
            // Getting CSV data from form
            string csvData = Request.Form["csv"];
            
            // CSV parser regex with quoted fields support
            string pattern = @"(?:^|,)(?=[^""]|(""|^))(""(?:(?:""""|[^""])+)""|[^,]*)";
            
            // ruleid: regular-expression-dos-infinite-timeout
            var matches = Regex.Matches(csvData, pattern);
            
            return Content($"CSV fields found: {matches.Count}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=1}

        [HttpGet]
        public IActionResult bad_case_15()
        {
            // Getting IP address from query
            string ipAddress = Request.Query["ip"];
            
            // IPv4 and IPv6 validation regex
            string pattern = @"((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))";
            
            // ruleid: regular-expression-dos-infinite-timeout
            bool isValidIp = Regex.IsMatch(ipAddress, pattern);
            
            return Content($"Valid IP: {isValidIp}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=0}

        // True Negative Examples (Safe Code)

        [HttpGet]
        public IActionResult good_case_1()
        {
            // Getting user input from query parameter
            string userInput = Request.Query["input"];
            
            // Complex regex pattern with timeout
            string pattern = @"^(([a-z])+.)+[A-Z]([a-z])+$";
            
            // ok: regular-expression-dos-infinite-timeout
            bool isMatch = Regex.IsMatch(userInput, pattern, RegexOptions.None, TimeSpan.FromSeconds(2));
            
            return Content($"Match result: {isMatch}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=0}

        [HttpPost]
        public IActionResult good_case_2()
        {
            // Getting user input from form data
            string userInput = Request.Form["email"];
            
            // Email validation regex with timeout
            string emailPattern = @"^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$";
            
            // ok: regular-expression-dos-infinite-timeout
            var regex = new Regex(emailPattern, RegexOptions.None, TimeSpan.FromSeconds(1));
            var matches = regex.Matches(userInput);
            
            return Content($"Found {matches.Count} matches");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=0}

        [HttpGet]
        public IActionResult good_case_3()
        {
            // Getting user input from header
            string userAgent = Request.Headers["User-Agent"].ToString();
            
            // Complex pattern to identify browser type with timeout
            string pattern = @"^Mozilla\/\d\.\d\s\(.*?(?:Windows|Macintosh|Linux|iPhone|Android).*?\)\s(?:.*?\s)?(?:Chrome|Firefox|Safari|Edge|MSIE)\/[\d\.]+.*$";
            
            // ok: regular-expression-dos-infinite-timeout
            var regex = new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(500));
            string result = regex.Replace(userAgent, "Detected: $0");
            
            return Content(result);
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=0}

        [HttpPost]
        public IActionResult good_case_4()
        {
            // Getting user input from cookie
            string cookieValue = Request.Cookies["userPreference"];
            
            // Using a safer regex pattern (avoiding nested quantifiers)
            string pattern = @"^a*b$";  // Safer alternative to (a+)+b
            
            // ok: regular-expression-dos-infinite-timeout
            bool isMatch = Regex.IsMatch(cookieValue, pattern, RegexOptions.None, TimeSpan.FromSeconds(1));
            
            return Content($"Match result: {isMatch}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=0}

        [HttpGet]
        public IActionResult good_case_5()
        {
            // Getting user input from query string
            string htmlContent = Request.Query["content"];
            
            // Using a simpler regex for HTML tags with timeout
            string pattern = @"<[^>]+>";
            
            // ok: regular-expression-dos-infinite-timeout
            var matches = Regex.Matches(htmlContent, pattern, RegexOptions.None, TimeSpan.FromSeconds(3));
            
            return Content($"Found {matches.Count} HTML tags");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=0}

        [HttpPost]
        public async Task<IActionResult> good_case_6()
        {
            // Reading body content
            using var reader = new System.IO.StreamReader(Request.Body);
            string requestBody = await reader.ReadToEndAsync();
            
            // Using a timeout for JSON property validation
            string pattern = @"""([^""\\]|\\.)*""\s*:\s*""([^""\\]|\\.)*""";
            
            // ok: regular-expression-dos-infinite-timeout
            var regex = new Regex(pattern, RegexOptions.Multiline, TimeSpan.FromSeconds(2));
            
            // Using try-catch to handle timeout exceptions
            try
            {
                var matches = regex.Matches(requestBody);
                return Json(new { matchCount = matches.Count });
            }
            catch (RegexMatchTimeoutException)
            {
                return StatusCode(400, "Regex processing timed out");
            }
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=0}

        [HttpGet]
        public IActionResult good_case_7()
        {
            // Getting URL from query parameter
            string url = Request.Query["url"];
            
            // Using Uri class instead of complex regex for URL validation
            bool isValid = Uri.TryCreate(url, UriKind.Absolute, out Uri uriResult) 
                && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);
            
            // ok: regular-expression-dos-infinite-timeout
            return Content($"Valid URL: {isValid}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=0}

        [HttpPost]
        public IActionResult good_case_8()
        {
            // Getting XML from form
            string xml = Request.Form["xml"];
            
            // XML tag validation with timeout
            string pattern = @"<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>(.*?)</\1>";
            
            // ok: regular-expression-dos-infinite-timeout
            var regex = new Regex(pattern, RegexOptions.Singleline, TimeSpan.FromSeconds(1));
            
            try
            {
                string sanitizedXml = regex.Replace(xml, "<sanitized>$2</sanitized>");
                return Content(sanitizedXml);
            }
            catch (RegexMatchTimeoutException)
            {
                return StatusCode(400, "XML processing timed out");
            }
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=0}

        [HttpGet]
        public IActionResult good_case_9()
        {
            // Getting search term from query
            string searchTerm = Request.Query["q"];
            
            // Limiting input size before regex processing
            if (searchTerm.Length > 1000)
            {
                return BadRequest("Search term too long");
            }
            
            string pattern = @"\b[\w-]+(?:\.[\w-]+)*@(?:[\w-]+\.)+[a-zA-Z]{2,7}\b";
            
            // ok: regular-expression-dos-infinite-timeout
            var regex = new Regex(pattern, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
            bool containsEmail = regex.IsMatch(searchTerm);
            
            return Content($"Contains email: {containsEmail}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=0}

        [HttpPost]
        public IActionResult good_case_10()
        {
            // Getting date from form
            string dateInput = Request.Form["date"];
            
            // Using DateTime.TryParse instead of complex regex
            bool isValidDate = DateTime.TryParse(dateInput, out DateTime result);
            
            // ok: regular-expression-dos-infinite-timeout
            return Content($"Valid date: {isValidDate}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=0}

        [HttpGet]
        public IActionResult good_case_11()
        {
            // Getting password from query (bad practice but for example)
            string password = Request.Query["password"];
            
            // Password strength checker with timeout
            string pattern = @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$";
            
            // ok: regular-expression-dos-infinite-timeout
            var regex = new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(500));
            bool isStrongPassword = regex.IsMatch(password);
            
            return Content($"Strong password: {isStrongPassword}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=0}

        [HttpPost]
        public IActionResult good_case_12()
        {
            // Getting markdown content from form
            string markdown = Request.Form["markdown"];
            
            // Limiting input size
            if (markdown.Length > 5000)
            {
                return BadRequest("Markdown content too large");
            }
            
            // Markdown link finder regex with timeout
            string pattern = @"\[([^\[]+)\](\(.*\))";
            
            // ok: regular-expression-dos-infinite-timeout
            var regex = new Regex(pattern, RegexOptions.None, TimeSpan.FromSeconds(2));
            string processedMarkdown = regex.Replace(markdown, "<a href=\"$2\">$1</a>");
            
            return Content(processedMarkdown);
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=0}

        [HttpGet]
        public IActionResult good_case_13()
        {
            // Getting phone number from query
            string phoneNumber = Request.Query["phone"];
            
            // Simplified phone number validation with timeout
            string pattern = @"^\+[0-9]{1,3}[0-9\s]{5,14}$";
            
            // ok: regular-expression-dos-infinite-timeout
            var regex = new Regex(pattern, RegexOptions.None, TimeSpan.FromSeconds(1));
            bool isValid = regex.IsMatch(phoneNumber);
            
            return Content($"Valid phone number: {isValid}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=0}

        [HttpPost]
        public IActionResult good_case_14()
        {
            // Getting CSV data from form
            string csvData = Request.Form["csv"];
            
            // Using a CSV parser library instead of complex regex
            // This is a simplified example - in real code, use a proper CSV parsing library
            string[] lines = csvData.Split('\n');
            int fieldCount = 0;
            
            foreach (var line in lines)
            {
                if (!string.IsNullOrEmpty(line))
                {
                    fieldCount += line.Split(',').Length;
                }
            }
            
            // ok: regular-expression-dos-infinite-timeout
            return Content($"CSV fields found: {fieldCount}");
        }
// {/fact}
// {fact rule=regular-expression-dos-infinite-timeout@v1.0 defects=0}

        [HttpGet]
        public IActionResult good_case_15()
        {
            // Getting IP address from query
            string ipAddress = Request.Query["ip"];
            
            // Using System.Net.IPAddress instead of complex regex
            bool isValidIp = System.Net.IPAddress.TryParse(ipAddress, out _);
            
            // ok: regular-expression-dos-infinite-timeout
            return Content($"Valid IP: {isValidIp}");
        }
// {/fact}
    }
}