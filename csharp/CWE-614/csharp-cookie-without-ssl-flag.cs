using System;
using System.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

namespace CookieSecurityExamples
{
    public class CookieSecurityController : Controller
    {
// {fact rule=insecure-cookie@v1.0 defects=1}
        // True positive examples (vulnerable code)
        
        public void bad_case_1()
        {
            HttpCookie cookie = new HttpCookie("authToken", "sensitive-value-12345");
            cookie.Expires = DateTime.Now.AddDays(1);
            // ruleid: csharp-cookie-without-ssl-flag
            Response.Cookies.Add(cookie);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}
        
        public void bad_case_2()
        {
            HttpCookie userCookie = new HttpCookie("userData");
            userCookie.Values["username"] = "john_doe";
            userCookie.Values["role"] = "admin";
            userCookie.Expires = DateTime.Now.AddHours(2);
            userCookie.HttpOnly = true; // HttpOnly set but not Secure
            // ruleid: csharp-cookie-without-ssl-flag
            Response.Cookies.Add(userCookie);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}
        
        public void bad_case_3()
        {
            HttpCookie sessionCookie = new HttpCookie("sessionId", Guid.NewGuid().ToString());
            sessionCookie.Expires = DateTime.Now.AddMinutes(30);
            sessionCookie.Secure = false; // Explicitly set to false
            // ruleid: csharp-cookie-without-ssl-flag
            Response.Cookies.Add(sessionCookie);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}
        
        public void bad_case_4(HttpContext context)
        {
            // ASP.NET Core cookie without Secure flag
            CookieOptions options = new CookieOptions
            {
                Expires = DateTimeOffset.Now.AddDays(1),
                HttpOnly = true
                // Secure flag missing
            };
            
            // ruleid: csharp-cookie-without-ssl-flag
            context.Response.Cookies.Append("authToken", "sensitive-value-67890", options);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}
        
        public void bad_case_5(HttpContext context)
        {
            // ASP.NET Core cookie with Secure explicitly set to false
            CookieOptions options = new CookieOptions
            {
                Expires = DateTimeOffset.Now.AddDays(1),
                HttpOnly = true,
                Secure = false
            };
            
            // ruleid: csharp-cookie-without-ssl-flag
            context.Response.Cookies.Append("userPrefs", "theme=dark;sidebar=collapsed", options);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}
        
        public IActionResult bad_case_6()
        {
            // Using Response.Cookies directly in ASP.NET Core MVC
            // ruleid: csharp-cookie-without-ssl-flag
            Response.Cookies.Append("trackingId", Guid.NewGuid().ToString());
            return View();
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}
        
        public void bad_case_7()
        {
            HttpCookie rememberMeCookie = new HttpCookie("rememberMe", "true");
            rememberMeCookie.Expires = DateTime.Now.AddMonths(1);
            if (Request.IsSecureConnection)
            {
                // Only set Secure if the current connection is secure
                // This is still vulnerable because the cookie could be sent over non-HTTPS later
                rememberMeCookie.Secure = true;
            }
            // ruleid: csharp-cookie-without-ssl-flag
            Response.Cookies.Add(rememberMeCookie);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}
        
        public void bad_case_8(HttpContext context)
        {
            string cookieName = "cartItems";
            string cookieValue = "item1=123;item2=456";
            int expiryDays = 7;
            
            CookieOptions options = new CookieOptions
            {
                Expires = DateTimeOffset.Now.AddDays(expiryDays),
                Path = "/"
                // Secure flag missing
            };
            
            // ruleid: csharp-cookie-without-ssl-flag
            context.Response.Cookies.Append(cookieName, cookieValue, options);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}
        
        public void bad_case_9()
        {
            bool isProduction = false; // Simulating development environment
            
            HttpCookie apiCookie = new HttpCookie("apiKey", "secret-api-key-12345");
            apiCookie.Expires = DateTime.Now.AddHours(12);
            
            if (isProduction)
            {
                apiCookie.Secure = true;
            }
            // In development, Secure flag is not set
            // ruleid: csharp-cookie-without-ssl-flag
            Response.Cookies.Add(apiCookie);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}
        
        public void bad_case_10(HttpContext context)
        {
            var cookieOptions = new CookieOptions();
            cookieOptions.Expires = DateTimeOffset.Now.AddDays(30);
            cookieOptions.HttpOnly = true;
            cookieOptions.Path = "/";
            // Secure flag missing
            
            // ruleid: csharp-cookie-without-ssl-flag
            context.Response.Cookies.Append("lastVisit", DateTime.Now.ToString(), cookieOptions);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}
        
        public IActionResult bad_case_11()
        {
            // Using cookie constructor with collection
            HttpCookie cookie = new HttpCookie("userSettings");
            cookie.Values.Add("fontSize", "medium");
            cookie.Values.Add("colorScheme", "light");
            cookie.Expires = DateTime.Now.AddYears(1);
            // ruleid: csharp-cookie-without-ssl-flag
            Response.Cookies.Add(cookie);
            
            return View();
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}
        
        public void bad_case_12(HttpContext context)
        {
            // Using conditional logic but still missing Secure in some cases
            CookieOptions options = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTimeOffset.Now.AddDays(7)
            };
            
            string environment = "development";
            if (environment == "production")
            {
                options.Secure = true;
            }
            
            // ruleid: csharp-cookie-without-ssl-flag
            context.Response.Cookies.Append("environment", environment, options);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}
        
        public void bad_case_13()
        {
            // Setting other properties but forgetting Secure
            HttpCookie analyticsCookie = new HttpCookie("analytics", "user-tracking-id-12345");
            analyticsCookie.Expires = DateTime.Now.AddDays(365);
            analyticsCookie.Path = "/";
            analyticsCookie.Domain = "example.com";
            analyticsCookie.HttpOnly = true;
            
            // ruleid: csharp-cookie-without-ssl-flag
            Response.Cookies.Add(analyticsCookie);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}
        
        public void bad_case_14(HttpContext context)
        {
            // Using a helper method but still missing Secure
            CookieOptions GetStandardCookieOptions()
            {
                return new CookieOptions
                {
                    HttpOnly = true,
                    Expires = DateTimeOffset.Now.AddDays(30),
                    Path = "/"
                    // Missing Secure flag
                };
            }
            
            // ruleid: csharp-cookie-without-ssl-flag
            context.Response.Cookies.Append("preferredLanguage", "en-US", GetStandardCookieOptions());
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}
        
        public void bad_case_15()
        {
            // Using a switch statement but missing Secure in all cases
            string cookieType = "session";
            HttpCookie cookie;
            
            switch (cookieType)
            {
                case "session":
                    cookie = new HttpCookie("sessionData", "session-data-12345");
                    cookie.Expires = DateTime.Now.AddHours(1);
                    break;
                case "persistent":
                    cookie = new HttpCookie("persistentData", "persistent-data-67890");
                    cookie.Expires = DateTime.Now.AddDays(30);
                    break;
                default:
                    cookie = new HttpCookie("defaultData", "default-data-abcde");
                    cookie.Expires = DateTime.Now.AddMinutes(30);
                    break;
            }
            
            // ruleid: csharp-cookie-without-ssl-flag
            Response.Cookies.Add(cookie);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}
        
        // True negative examples (secure code)
        
        public void good_case_1()
        {
            HttpCookie cookie = new HttpCookie("authToken", "sensitive-value-12345");
            cookie.Expires = DateTime.Now.AddDays(1);
            // ok: csharp-cookie-without-ssl-flag
            cookie.Secure = true;
            Response.Cookies.Add(cookie);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}
        
        public void good_case_2()
        {
            HttpCookie userCookie = new HttpCookie("userData");
            userCookie.Values["username"] = "john_doe";
            userCookie.Values["role"] = "admin";
            userCookie.Expires = DateTime.Now.AddHours(2);
            userCookie.HttpOnly = true;
            // ok: csharp-cookie-without-ssl-flag
            userCookie.Secure = true;
            Response.Cookies.Add(userCookie);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}
        
        public void good_case_3(HttpContext context)
        {
            // ASP.NET Core cookie with Secure flag
            CookieOptions options = new CookieOptions
            {
                Expires = DateTimeOffset.Now.AddDays(1),
                HttpOnly = true,
                // ok: csharp-cookie-without-ssl-flag
                Secure = true
            };
            
            context.Response.Cookies.Append("authToken", "sensitive-value-67890", options);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}
        
        public IActionResult good_case_4()
        {
            // Using Response.Cookies directly in ASP.NET Core MVC with Secure flag
            // ok: csharp-cookie-without-ssl-flag
            Response.Cookies.Append("trackingId", Guid.NewGuid().ToString(), new CookieOptions { Secure = true });
            return View();
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}
        
        public void good_case_5()
        {
            HttpCookie sessionCookie = new HttpCookie("sessionId", Guid.NewGuid().ToString())
            {
                Expires = DateTime.Now.AddMinutes(30),
                HttpOnly = true,
                // ok: csharp-cookie-without-ssl-flag
                Secure = true
            };
            Response.Cookies.Add(sessionCookie);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}
        
        public void good_case_6(HttpContext context)
        {
            string cookieName = "cartItems";
            string cookieValue = "item1=123;item2=456";
            int expiryDays = 7;
            
            CookieOptions options = new CookieOptions
            {
                Expires = DateTimeOffset.Now.AddDays(expiryDays),
                Path = "/",
                // ok: csharp-cookie-without-ssl-flag
                Secure = true,
                HttpOnly = true
            };
            
            context.Response.Cookies.Append(cookieName, cookieValue, options);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}
        
        public void good_case_7()
        {
            bool isProduction = false; // Simulating development environment
            
            HttpCookie apiCookie = new HttpCookie("apiKey", "secret-api-key-12345");
            apiCookie.Expires = DateTime.Now.AddHours(12);
            
            // Always set Secure regardless of environment
            // ok: csharp-cookie-without-ssl-flag
            apiCookie.Secure = true;
            
            Response.Cookies.Add(apiCookie);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}
        
        public void good_case_8(HttpContext context)
        {
            var cookieOptions = new CookieOptions
            {
                Expires = DateTimeOffset.Now.AddDays(30),
                HttpOnly = true,
                Path = "/",
                // ok: csharp-cookie-without-ssl-flag
                Secure = true
            };
            
            context.Response.Cookies.Append("lastVisit", DateTime.Now.ToString(), cookieOptions);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}
        
        public IActionResult good_case_9()
        {
            // Using cookie constructor with collection and Secure flag
            HttpCookie cookie = new HttpCookie("userSettings");
            cookie.Values.Add("fontSize", "medium");
            cookie.Values.Add("colorScheme", "light");
            cookie.Expires = DateTime.Now.AddYears(1);
            // ok: csharp-cookie-without-ssl-flag
            cookie.Secure = true;
            Response.Cookies.Add(cookie);
            
            return View();
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}
        
        public void good_case_10(HttpContext context)
        {
            // Using a helper method with Secure flag
            CookieOptions GetSecureCookieOptions()
            {
                return new CookieOptions
                {
                    HttpOnly = true,
                    Expires = DateTimeOffset.Now.AddDays(30),
                    Path = "/",
                    // ok: csharp-cookie-without-ssl-flag
                    Secure = true
                };
            }
            
            context.Response.Cookies.Append("preferredLanguage", "en-US", GetSecureCookieOptions());
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}
        
        public void good_case_11()
        {
            // Using a switch statement with Secure flag in all cases
            string cookieType = "session";
            HttpCookie cookie;
            
            switch (cookieType)
            {
                case "session":
                    cookie = new HttpCookie("sessionData", "session-data-12345");
                    cookie.Expires = DateTime.Now.AddHours(1);
                    break;
                case "persistent":
                    cookie = new HttpCookie("persistentData", "persistent-data-67890");
                    cookie.Expires = DateTime.Now.AddDays(30);
                    break;
                default:
                    cookie = new HttpCookie("defaultData", "default-data-abcde");
                    cookie.Expires = DateTime.Now.AddMinutes(30);
                    break;
            }
            
            // ok: csharp-cookie-without-ssl-flag
            cookie.Secure = true;
            Response.Cookies.Add(cookie);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}
        
        public void good_case_12()
        {
            // Setting all security properties including Secure
            HttpCookie analyticsCookie = new HttpCookie("analytics", "user-tracking-id-12345");
            analyticsCookie.Expires = DateTime.Now.AddDays(365);
            analyticsCookie.Path = "/";
            analyticsCookie.Domain = "example.com";
            analyticsCookie.HttpOnly = true;
            // ok: csharp-cookie-without-ssl-flag
            analyticsCookie.Secure = true;
            
            Response.Cookies.Add(analyticsCookie);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}
        
        public void good_case_13(HttpContext context)
        {
            // Using conditional logic but always ensuring Secure is true
            CookieOptions options = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTimeOffset.Now.AddDays(7),
                // ok: csharp-cookie-without-ssl-flag
                Secure = true
            };
            
            string environment = "development";
            if (environment == "production")
            {
                options.SameSite = SameSiteMode.Strict;
            }
            else
            {
                options.SameSite = SameSiteMode.Lax;
            }
            
            context.Response.Cookies.Append("environment", environment, options);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}
        
        public void good_case_14()
        {
            // Using object initializer syntax with Secure flag
            HttpCookie rememberMeCookie = new HttpCookie("rememberMe", "true")
            {
                Expires = DateTime.Now.AddMonths(1),
                HttpOnly = true,
                Path = "/",
                // ok: csharp-cookie-without-ssl-flag
                Secure = true
            };
            
            Response.Cookies.Add(rememberMeCookie);
        }
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}
        
        public IActionResult good_case_15()
        {
            // Using ASP.NET Core Response.Cookies with all security flags
            var cookieOptions = new CookieOptions
            {
                Expires = DateTime.Now.AddDays(7),
                HttpOnly = true,
                // ok: csharp-cookie-without-ssl-flag
                Secure = true,
                SameSite = SameSiteMode.Strict
            };
            
            Response.Cookies.Append("sessionToken", Guid.NewGuid().ToString(), cookieOptions);
            return View();
        }
// {/fact}
    }
}