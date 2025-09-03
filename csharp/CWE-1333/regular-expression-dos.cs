using System;
using System.Text.RegularExpressions;
using System.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

namespace RegexDoSExamples
{
    public class RegexDoSController : Controller
    {
// {fact rule=regular-expression-dos@v1.0 defects=1}
        // True Positives (Vulnerable Code)

        public IActionResult bad_case_1()
        {
            // Get untrusted input from query parameter
            string userInput = Request.Query["input"];
            
            // Complex regex pattern that could be exploited
            string pattern = @"^(a+)+$";
            
            // ruleid: regular-expression-dos
            bool isMatch = Regex.IsMatch(userInput, pattern);
            
            return Content($"Match result: {isMatch}");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=1}

        public IActionResult bad_case_2()
        {
            // Get untrusted input from form data
            string userInput = Request.Form["data"];
            
            // Another vulnerable pattern
            string pattern = @"^([a-z]+)*$";
            
            // ruleid: regular-expression-dos
            MatchCollection matches = Regex.Matches(userInput, pattern);
            
            return Json(new { matchCount = matches.Count });
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=1}

        public IActionResult bad_case_3()
        {
            // Get untrusted input from request header
            string userAgent = Request.Headers["User-Agent"];
            
            // Vulnerable email validation pattern
            string emailPattern = @"^([a-zA-Z0-9])(([a-zA-Z0-9])*([\._-])?([a-zA-Z0-9]))*@(([a-zA-Z0-9\-])+(\.))+([a-zA-Z]{2,4})+$";
            
            // ruleid: regular-expression-dos
            string sanitized = Regex.Replace(userAgent, emailPattern, "REDACTED");
            
            return Content(sanitized);
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=1}

        public IActionResult bad_case_4()
        {
            // Get untrusted input from cookies
            string cookieValue = Request.Cookies["userPrefs"];
            
            // Vulnerable nested quantifiers
            string pattern = @"(a|aa)+";
            
            // ruleid: regular-expression-dos
            Match match = Regex.Match(cookieValue, pattern);
            
            return Content($"Found match: {match.Success}");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=1}

        public IActionResult bad_case_5()
        {
            // Get untrusted input from route parameter
            string id = RouteData.Values["id"] as string;
            
            // Vulnerable pattern with backreferences
            string pattern = @"(\w+)\1+";
            
            // ruleid: regular-expression-dos
            var regex = new Regex(pattern);
            bool isMatch = regex.IsMatch(id);
            
            return Content($"Pattern matched: {isMatch}");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=1}

        public IActionResult bad_case_6(IFormFile file)
        {
            // Get untrusted input from uploaded file name
            string filename = file.FileName;
            
            // Vulnerable pattern with nested repetition
            string pattern = @"([a-z]+)*([0-9]+)*";
            
            // ruleid: regular-expression-dos
            if (Regex.IsMatch(filename, pattern))
            {
                return Content("Valid filename");
            }
            
            return Content("Invalid filename");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=1}

        public IActionResult bad_case_7()
        {
            // Get untrusted input from JSON body
            string json = new System.IO.StreamReader(Request.Body).ReadToEndAsync().Result;
            
            // Vulnerable pattern with lookaheads
            string pattern = @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$";
            
            // ruleid: regular-expression-dos
            var regex = new Regex(pattern, RegexOptions.Compiled);
            bool isMatch = regex.IsMatch(json);
            
            return Content($"Valid JSON: {isMatch}");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=1}

        public IActionResult bad_case_8()
        {
            // Get untrusted input from query string
            string search = HttpUtility.UrlDecode(Request.QueryString.ToString());
            
            // Vulnerable pattern with alternation and repetition
            string pattern = @"(ab|cd|ef)+";
            
            // ruleid: regular-expression-dos
            string[] results = Regex.Split(search, pattern);
            
            return Json(results);
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=1}

        public IActionResult bad_case_9()
        {
            // Get untrusted input from path
            string path = Request.Path.ToString();
            
            // Vulnerable pattern with nested groups and repetition
            string pattern = @"((a+|b+)c+)+";
            
            // ruleid: regular-expression-dos
            var matches = Regex.Matches(path, pattern, RegexOptions.IgnoreCase);
            
            return Content($"Found {matches.Count} matches");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=1}

        public IActionResult bad_case_10()
        {
            // Get untrusted input from query parameter
            string text = Request.Query["text"];
            
            // Vulnerable pattern for HTML tag matching
            string pattern = @"<([a-z][a-z0-9]*)\b[^>]*>(.*?)</\1>";
            
            // ruleid: regular-expression-dos
            string sanitized = Regex.Replace(text, pattern, string.Empty);
            
            return Content(sanitized);
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=1}

        public IActionResult bad_case_11()
        {
            // Get untrusted input from form
            string comment = Request.Form["comment"];
            
            // Create regex instance with vulnerable pattern
            Regex urlRegex = new Regex(@"((https?|ftp):\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?");
            
            // ruleid: regular-expression-dos
            string linkified = urlRegex.Replace(comment, "<a href=\"$0\">$0</a>");
            
            return Content(linkified, "text/html");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=1}

        public IActionResult bad_case_12()
        {
            // Get untrusted input from request header
            string referer = Request.Headers["Referer"];
            
            // Vulnerable pattern with nested quantifiers
            string pattern = @"^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?";
            
            // ruleid: regular-expression-dos
            if (Regex.IsMatch(referer, pattern))
            {
                return Content("Valid URL format");
            }
            
            return Content("Invalid URL format");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=1}

        public IActionResult bad_case_13()
        {
            // Get untrusted input from query parameter
            string phoneNumber = Request.Query["phone"];
            
            // Vulnerable phone number validation pattern
            string pattern = @"^(?:(?:\(?(?:00|\+)([1-4]\d\d|[1-9]\d?)\)?)?[\-\.\ \\\/]?)?((?:\(?\d{1,}\)?[\-\.\ \\\/]?){0,})(?:[\-\.\ \\\/]?(?:#|ext\.?|extension|x)[\-\.\ \\\/]?(\d+))?$";
            
            // ruleid: regular-expression-dos
            bool isValidPhone = Regex.IsMatch(phoneNumber, pattern);
            
            return Content($"Phone validation: {isValidPhone}");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=1}

        public IActionResult bad_case_14()
        {
            // Get untrusted input from query parameter
            string xml = Request.Query["xml"];
            
            // Vulnerable XML tag pattern
            string pattern = @"<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>(.*?)</\1>";
            
            // ruleid: regular-expression-dos
            var regex = new Regex(pattern, RegexOptions.Singleline);
            var matches = regex.Matches(xml);
            
            return Json(new { tagCount = matches.Count });
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=1}

        public IActionResult bad_case_15()
        {
            // Get untrusted input from form
            string markdown = Request.Form["markdown"];
            
            // Vulnerable markdown link pattern
            string pattern = @"\[((?:\[[^\]]*\]|[^\[\]])*)\]\([ \t]*<?([^<>\s]*)>?(?:[ \t]+['""]([^\n]*)['""])?[ \t]*\)";
            
            // ruleid: regular-expression-dos
            string html = Regex.Replace(markdown, pattern, "<a href=\"$2\" title=\"$3\">$1</a>");
            
            return Content(html, "text/html");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=0}

        // True Negatives (Safe Code)

        public IActionResult good_case_1()
        {
            // Get untrusted input from query parameter
            string userInput = Request.Query["input"];
            
            // Complex regex pattern with timeout
            string pattern = @"^(a+)+$";
            
            // ok: regular-expression-dos
            bool isMatch = Regex.IsMatch(userInput, pattern, RegexOptions.None, TimeSpan.FromSeconds(1));
            
            return Content($"Match result: {isMatch}");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=0}

        public IActionResult good_case_2()
        {
            // Get untrusted input from form data
            string userInput = Request.Form["data"];
            
            // Another pattern with timeout
            string pattern = @"^([a-z]+)*$";
            
            // ok: regular-expression-dos
            MatchCollection matches = Regex.Matches(userInput, pattern, RegexOptions.None, TimeSpan.FromMilliseconds(2000));
            
            return Json(new { matchCount = matches.Count });
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=0}

        public IActionResult good_case_3()
        {
            // Get untrusted input from request header
            string userAgent = Request.Headers["User-Agent"];
            
            // Email validation pattern with timeout
            string emailPattern = @"^([a-zA-Z0-9])(([a-zA-Z0-9])*([\._-])?([a-zA-Z0-9]))*@(([a-zA-Z0-9\-])+(\.))+([a-zA-Z]{2,4})+$";
            
            // ok: regular-expression-dos
            string sanitized = Regex.Replace(userAgent, emailPattern, "REDACTED", RegexOptions.None, TimeSpan.FromSeconds(2));
            
            return Content(sanitized);
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=0}

        public IActionResult good_case_4()
        {
            // Get untrusted input from cookies
            string cookieValue = Request.Cookies["userPrefs"];
            
            // Pattern with nested quantifiers but with timeout
            string pattern = @"(a|aa)+";
            
            // ok: regular-expression-dos
            Match match = Regex.Match(cookieValue, pattern, RegexOptions.None, TimeSpan.FromSeconds(3));
            
            return Content($"Found match: {match.Success}");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=0}

        public IActionResult good_case_5()
        {
            // Get untrusted input from route parameter
            string id = RouteData.Values["id"] as string;
            
            // Pattern with backreferences but with timeout
            string pattern = @"(\w+)\1+";
            
            // Create regex with timeout
            // ok: regular-expression-dos
            var regex = new Regex(pattern, RegexOptions.None, TimeSpan.FromSeconds(1));
            bool isMatch = regex.IsMatch(id);
            
            return Content($"Pattern matched: {isMatch}");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=0}

        public IActionResult good_case_6()
        {
            // Get untrusted input from query parameter
            string userInput = Request.Query["input"];
            
            // Using a non-vulnerable pattern (simple, linear time complexity)
            string pattern = @"^[a-zA-Z0-9]+$";
            
            // ok: regular-expression-dos
            bool isMatch = Regex.IsMatch(userInput, pattern);
            
            return Content($"Match result: {isMatch}");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=0}

        public IActionResult good_case_7()
        {
            // Get untrusted input from form data
            string userInput = Request.Form["data"];
            
            // Limit input length before regex processing
            if (userInput.Length > 100)
            {
                userInput = userInput.Substring(0, 100);
            }
            
            string pattern = @"^([a-z]+)*$";
            
            // ok: regular-expression-dos
            // Safe because input length is limited
            MatchCollection matches = Regex.Matches(userInput, pattern);
            
            return Json(new { matchCount = matches.Count });
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=0}

        public IActionResult good_case_8()
        {
            // Get untrusted input from request header
            string userAgent = Request.Headers["User-Agent"];
            
            // Use a simple, non-vulnerable pattern
            string pattern = @"Mozilla|Chrome|Safari|Edge|MSIE";
            
            // ok: regular-expression-dos
            bool isMatch = Regex.IsMatch(userAgent, pattern);
            
            return Content($"Browser detected: {isMatch}");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=0}

        public IActionResult good_case_9()
        {
            // Get untrusted input from cookies
            string cookieValue = Request.Cookies["userPrefs"];
            
            // Use a fixed-length pattern without backtracking issues
            string pattern = @"\d{3}-\d{2}-\d{4}"; // SSN format
            
            // ok: regular-expression-dos
            bool isMatch = Regex.IsMatch(cookieValue, pattern);
            
            return Content($"Found SSN: {isMatch}");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=0}

        public IActionResult good_case_10()
        {
            // Get untrusted input from route parameter
            string id = RouteData.Values["id"] as string;
            
            // Use a pattern with bounded repetition
            string pattern = @"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"; // UUID format
            
            // ok: regular-expression-dos
            bool isMatch = Regex.IsMatch(id, pattern);
            
            return Content($"Valid UUID: {isMatch}");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=0}

        public IActionResult good_case_11(IFormFile file)
        {
            // Get untrusted input from uploaded file name
            string filename = file.FileName;
            
            // Use regex with timeout
            string pattern = @"([a-z]+)*([0-9]+)*";
            
            // ok: regular-expression-dos
            var regex = new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(500));
            bool isMatch = regex.IsMatch(filename);
            
            return Content($"Valid filename: {isMatch}");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=0}

        public IActionResult good_case_12()
        {
            // Get untrusted input from query string
            string search = HttpUtility.UrlDecode(Request.QueryString.ToString());
            
            // Use alternative approach without regex for simple splitting
            // ok: regular-expression-dos
            string[] results = search.Split('&');
            
            return Json(results);
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=0}

        public IActionResult good_case_13()
        {
            // Get untrusted input from path
            string path = Request.Path.ToString();
            
            // Use regex with timeout for path validation
            string pattern = @"^/api/v\d+/[a-zA-Z0-9\-_/]+$";
            
            // ok: regular-expression-dos
            bool isValidPath = Regex.IsMatch(path, pattern, RegexOptions.None, TimeSpan.FromSeconds(1));
            
            return Content($"Valid API path: {isValidPath}");
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=0}

        public IActionResult good_case_14()
        {
            // Get untrusted input from query parameter
            string text = Request.Query["text"];
            
            // Use a simple character class pattern
            string pattern = @"[<>&]";
            
            // ok: regular-expression-dos
            string sanitized = Regex.Replace(text, pattern, match => {
                switch (match.Value)
                {
                    case "<": return "&lt;";
                    case ">": return "&gt;";
                    case "&": return "&amp;";
                    default: return match.Value;
                }
            });
            
            return Content(sanitized);
        }
// {/fact}
// {fact rule=regular-expression-dos@v1.0 defects=0}

        public IActionResult good_case_15()
        {
            // Get untrusted input from form
            string comment = Request.Form["comment"];
            
            // Create regex instance with timeout for URL detection
            // ok: regular-expression-dos
            Regex urlRegex = new Regex(@"https?://[^\s]+", RegexOptions.None, TimeSpan.FromSeconds(2));
            string linkified = urlRegex.Replace(comment, "<a href=\"$0\">$0</a>");
            
            return Content(linkified, "text/html");
        }
// {/fact}
    }
}