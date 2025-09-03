using System;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Net;
using System.Text.RegularExpressions;

namespace OpenRedirectExamples
{
    // True Positive Examples (Vulnerable Code)
    
    public class BadController1 : Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=1}
        public ActionResult bad_case_1()
        {
            // Direct use of returnUrl parameter without validation
            string returnUrl = Request.QueryString["returnUrl"];
            // ruleid: open-redirect-csharp-rule
            return Redirect(returnUrl);
        }
// {/fact}
    }

    public class BadController2 : Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=1}
        public ActionResult bad_case_2()
        {
            // Using form data for redirection without validation
            string redirectUrl = Request.Form["redirectUrl"];
            // ruleid: open-redirect-csharp-rule
            return RedirectPermanent(redirectUrl);
        }
// {/fact}
    }

    public class BadController3 : Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=1}
        public ActionResult bad_case_3()
        {
            // Using URL from route data without validation
            string url = RouteData.Values["url"] as string;
            // ruleid: open-redirect-csharp-rule
            return Redirect(url);
        }
// {/fact}
    }

    public class BadController4 : Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=1}
        public ActionResult bad_case_4()
        {
            // Using URL from headers without validation
            string referer = Request.Headers["Referer"];
            // ruleid: open-redirect-csharp-rule
            return Redirect(referer);
        }
// {/fact}
    }

    public class BadController5 : Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=1}
        public ActionResult bad_case_5()
        {
            // Basic string manipulation doesn't make it safe
            string url = Request.QueryString["url"];
            string modifiedUrl = url + "?source=myapp";
            // ruleid: open-redirect-csharp-rule
            return Redirect(modifiedUrl);
        }
// {/fact}
    }

    // ASP.NET Core examples
    public class BadCoreController1 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=1}
        public IActionResult bad_case_6()
        {
            // Using URL from query string without validation
            string returnUrl = HttpContext.Request.Query["returnUrl"];
            // ruleid: open-redirect-csharp-rule
            return Redirect(returnUrl);
        }
// {/fact}
    }

    public class BadCoreController2 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=1}
        public IActionResult bad_case_7()
        {
            // Using URL from form without validation
            string redirectUrl = HttpContext.Request.Form["redirectUrl"];
            // ruleid: open-redirect-csharp-rule
            return RedirectPermanent(redirectUrl);
        }
// {/fact}
    }

    public class BadCoreController3 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=1}
        public IActionResult bad_case_8()
        {
            // Using URL from cookies without validation
            string url = HttpContext.Request.Cookies["returnUrl"];
            // ruleid: open-redirect-csharp-rule
            return Redirect(url);
        }
// {/fact}
    }

    public class BadCoreController4 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=1}
        public IActionResult bad_case_9()
        {
            // Conditional logic doesn't make it safe if validation is missing
            string url = HttpContext.Request.Query["url"];
            if (!string.IsNullOrEmpty(url))
            {
                // ruleid: open-redirect-csharp-rule
                return Redirect(url);
            }
            return RedirectToAction("Index");
        }
// {/fact}
    }

    public class BadCoreController5 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=1}
        public IActionResult bad_case_10(string id)
        {
            // Using URL from route parameter without validation
            var returnUrl = RouteData.Values["returnUrl"]?.ToString();
            // ruleid: open-redirect-csharp-rule
            return Redirect(returnUrl);
        }
// {/fact}
    }

    public class BadCoreController6 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=1}
        public IActionResult bad_case_11()
        {
            // Insufficient validation - only checks if URL starts with "http"
            string url = HttpContext.Request.Query["url"];
            if (url.StartsWith("http"))
            {
                // ruleid: open-redirect-csharp-rule
                return Redirect(url);
            }
            return RedirectToAction("Index");
        }
// {/fact}
    }

    public class BadCoreController7 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=1}
        public IActionResult bad_case_12()
        {
            // Using URL from headers without validation
            string referer = HttpContext.Request.Headers["Referer"];
            // ruleid: open-redirect-csharp-rule
            return Redirect(referer);
        }
// {/fact}
    }

    public class BadCoreController8 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=1}
        public IActionResult bad_case_13()
        {
            // Using multiple parameters to construct URL without validation
            string domain = HttpContext.Request.Query["domain"];
            string path = HttpContext.Request.Query["path"];
            string url = $"https://{domain}/{path}";
            // ruleid: open-redirect-csharp-rule
            return Redirect(url);
        }
// {/fact}
    }

    public class BadCoreController9 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=1}
        public IActionResult bad_case_14()
        {
            // Using Response.Redirect instead of return Redirect
            string url = HttpContext.Request.Query["url"];
            // ruleid: open-redirect-csharp-rule
            Response.Redirect(url);
            return new EmptyResult();
        }
// {/fact}
    }

    public class BadCoreController10 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=1}
        public IActionResult bad_case_15()
        {
            // Using LocalRedirect with user input (still vulnerable)
            string returnUrl = HttpContext.Request.Query["returnUrl"];
            // ruleid: open-redirect-csharp-rule
            return LocalRedirect(returnUrl);
        }
// {/fact}
    }

    // True Negative Examples (Safe Code)

    public class GoodController1 : Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=0}
        public ActionResult good_case_1()
        {
            // Using IsLocalUrl to validate URL is local
            string returnUrl = Request.QueryString["returnUrl"];
            // ok: open-redirect-csharp-rule
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }
// {/fact}
    }

    public class GoodController2 : Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=0}
        public ActionResult good_case_2()
        {
            // Using a whitelist of allowed domains
            string url = Request.QueryString["url"];
            string[] allowedDomains = { "example.com", "trusted-site.com" };
            Uri uri;
            if (Uri.TryCreate(url, UriKind.Absolute, out uri) && 
                allowedDomains.Any(domain => uri.Host.EndsWith(domain, StringComparison.OrdinalIgnoreCase)))
            {
                // ok: open-redirect-csharp-rule
                return Redirect(url);
            }
            return RedirectToAction("Index");
        }
// {/fact}
    }

    public class GoodController3 : Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=0}
        public ActionResult good_case_3()
        {
            // Using hardcoded URLs instead of user input
            // ok: open-redirect-csharp-rule
            return Redirect("/home/index");
        }
// {/fact}
    }

    public class GoodController4 : Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=0}
        public ActionResult good_case_4()
        {
            // Using RedirectToAction instead of Redirect
            // ok: open-redirect-csharp-rule
            return RedirectToAction("Index", "Home");
        }
// {/fact}
    }

    public class GoodController5 : Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=0}
        public ActionResult good_case_5()
        {
            // Using RedirectToRoute instead of Redirect
            // ok: open-redirect-csharp-rule
            return RedirectToRoute(new { controller = "Home", action = "Index" });
        }
// {/fact}
    }

    // ASP.NET Core examples
    public class GoodCoreController1 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=0}
        public IActionResult good_case_6()
        {
            // Using IsLocalUrl to validate URL is local
            string returnUrl = HttpContext.Request.Query["returnUrl"];
            // ok: open-redirect-csharp-rule
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }
// {/fact}
    }

    public class GoodCoreController2 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=0}
        public IActionResult good_case_7()
        {
            // Using regex to validate URL against a specific pattern
            string url = HttpContext.Request.Query["url"];
            if (!string.IsNullOrEmpty(url) && 
                Regex.IsMatch(url, @"^(https?:\/\/)?(www\.)?example\.com\/.*$"))
            {
                // ok: open-redirect-csharp-rule
                return Redirect(url);
            }
            return RedirectToAction("Index");
        }
// {/fact}
    }

    public class GoodCoreController3 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=0}
        public IActionResult good_case_8()
        {
            // Using a safe default when URL is not valid
            string returnUrl = HttpContext.Request.Query["returnUrl"];
            if (string.IsNullOrEmpty(returnUrl))
            {
                // ok: open-redirect-csharp-rule
                return RedirectToAction("Index");
            }
            
            Uri uri;
            if (!Uri.TryCreate(returnUrl, UriKind.Absolute, out uri) || 
                !uri.Host.EndsWith("example.com", StringComparison.OrdinalIgnoreCase))
            {
                return RedirectToAction("Index");
            }
            
            return Redirect(returnUrl);
        }
// {/fact}
    }

    public class GoodCoreController4 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=0}
        public IActionResult good_case_9()
        {
            // Using LocalRedirectPermanent with local URL validation
            string returnUrl = HttpContext.Request.Query["returnUrl"];
            
            // ok: open-redirect-csharp-rule
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return LocalRedirectPermanent(returnUrl);
            }
            
            return RedirectToAction("Index");
        }
// {/fact}
    }

    public class GoodCoreController5 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=0}
        public IActionResult good_case_10()
        {
            // Using a path-relative URL
            // ok: open-redirect-csharp-rule
            return Redirect("~/Home/Index");
        }
// {/fact}
    }

    public class GoodCoreController6 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=0}
        public IActionResult good_case_11()
        {
            // Using a safe default and only allowing specific paths
            string path = HttpContext.Request.Query["path"];
            string[] allowedPaths = { "home", "about", "contact" };
            
            if (!string.IsNullOrEmpty(path) && allowedPaths.Contains(path.ToLower()))
            {
                // ok: open-redirect-csharp-rule
                return Redirect($"/{path}");
            }
            
            return RedirectToAction("Index");
        }
// {/fact}
    }

    public class GoodCoreController7 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=0}
        public IActionResult good_case_12()
        {
            // Using URL from query but only taking the path component
            string url = HttpContext.Request.Query["url"];
            Uri uri;
            
            if (Uri.TryCreate(url, UriKind.Absolute, out uri))
            {
                // ok: open-redirect-csharp-rule
                return LocalRedirect(uri.PathAndQuery);
            }
            
            return RedirectToAction("Index");
        }
// {/fact}
    }

    public class GoodCoreController8 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=0}
        public IActionResult good_case_13()
        {
            // Using a URL builder with fixed domain
            string path = HttpContext.Request.Query["path"];
            
            if (!string.IsNullOrEmpty(path))
            {
                UriBuilder builder = new UriBuilder
                {
                    Scheme = "https",
                    Host = "example.com",
                    Path = path
                };
                
                // ok: open-redirect-csharp-rule
                return Redirect(builder.Uri.ToString());
            }
            
            return RedirectToAction("Index");
        }
// {/fact}
    }

    public class GoodCoreController9 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=0}
        public IActionResult good_case_14()
        {
            // Using a custom validation method
            string url = HttpContext.Request.Query["url"];
            
            if (IsValidRedirectUrl(url))
            {
                // ok: open-redirect-csharp-rule
                return Redirect(url);
            }
            
            return RedirectToAction("Index");
        }
// {/fact}
        
        private bool IsValidRedirectUrl(string url)
        {
            if (string.IsNullOrEmpty(url))
                return false;
                
            Uri uri;
            if (!Uri.TryCreate(url, UriKind.Absolute, out uri))
                return false;
                
            return uri.Host.Equals("example.com", StringComparison.OrdinalIgnoreCase);
        }
    }

    public class GoodCoreController10 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=cross-site-scripting@v1.0 defects=0}
        public IActionResult good_case_15()
        {
            // Using a signed URL to prevent tampering
            string signedUrl = HttpContext.Request.Query["signedUrl"];
            
            if (!string.IsNullOrEmpty(signedUrl) && VerifySignedUrl(signedUrl, out string actualUrl))
            {
                // ok: open-redirect-csharp-rule
                return Redirect(actualUrl);
            }
            
            return RedirectToAction("Index");
        }
// {/fact}
        
        private bool VerifySignedUrl(string signedUrl, out string actualUrl)
        {
            // Implementation of URL signature verification
            // In a real app, this would validate a cryptographic signature
            
            // For this example, we'll just check if it starts with a known prefix
            // and extract the actual URL
            string prefix = "SIGNED:";
            actualUrl = null;
            
            if (signedUrl.StartsWith(prefix))
            {
                actualUrl = signedUrl.Substring(prefix.Length);
                return true;
            }
            
            return false;
        }
    }
}