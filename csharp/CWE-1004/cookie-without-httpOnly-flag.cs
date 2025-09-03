using System;
using System.Web;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace CookieSecurityExamples
{
    public class CookieSecurityTests
    {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
        // TRUE POSITIVES (Vulnerable Code Examples)

        public void bad_case_1(HttpContext context)
        {
            // Basic cookie creation without HttpOnly flag
            // ruleid: cookie-without-httpOnly-flag
            context.Response.Cookies.Append("sessionId", "abc123", new CookieOptions
            {
                Secure = true,
                Expires = DateTime.Now.AddDays(1)
            });
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

        public void bad_case_2(HttpContext context)
        {
            // Cookie with HttpOnly explicitly set to false
            // ruleid: cookie-without-httpOnly-flag
            context.Response.Cookies.Append("authToken", "xyz789", new CookieOptions
            {
                HttpOnly = false,
                Secure = true,
                SameSite = SameSiteMode.Strict
            });
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

        public void bad_case_3(HttpContext context)
        {
            // Cookie with multiple options but missing HttpOnly
            // ruleid: cookie-without-httpOnly-flag
            var options = new CookieOptions
            {
                Secure = true,
                Expires = DateTime.Now.AddHours(2),
                SameSite = SameSiteMode.Lax,
                Path = "/"
            };
            context.Response.Cookies.Append("userPrefs", "theme=dark", options);
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

        public void bad_case_4()
        {
            // Using HttpCookie class without HttpOnly
            HttpCookie cookie = new HttpCookie("userId", "12345");
            cookie.Secure = true;
            cookie.Expires = DateTime.Now.AddMonths(1);
            
            // ruleid: cookie-without-httpOnly-flag
            HttpContext.Current.Response.Cookies.Add(cookie);
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

        public void bad_case_5()
        {
            // HttpCookie with HttpOnly explicitly set to false
            HttpCookie cookie = new HttpCookie("rememberMe", "true");
            // ruleid: cookie-without-httpOnly-flag
            cookie.HttpOnly = false;
            cookie.Secure = true;
            HttpContext.Current.Response.Cookies.Add(cookie);
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

        [HttpGet]
        public IActionResult bad_case_6()
        {
            // Using MVC CookieOptions without HttpOnly
            var cookieOptions = new CookieOptions
            {
                Expires = DateTime.Now.AddDays(7),
                Secure = true
            };
            
            // ruleid: cookie-without-httpOnly-flag
            Response.Cookies.Append("cartId", Guid.NewGuid().ToString(), cookieOptions);
            return Ok("Cookie set");
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

        public void bad_case_7(HttpContext context)
        {
            // Variable declaration and then setting properties individually without HttpOnly
            CookieOptions options = new CookieOptions();
            options.Secure = true;
            options.Expires = DateTime.Now.AddDays(30);
            options.Path = "/account";
            
            // ruleid: cookie-without-httpOnly-flag
            context.Response.Cookies.Append("lastVisit", DateTime.Now.ToString(), options);
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

        public void bad_case_8()
        {
            // Using HttpCookie with properties set individually, missing HttpOnly
            HttpCookie cookie = new HttpCookie("language");
            cookie.Value = "en-US";
            cookie.Expires = DateTime.Now.AddYears(1);
            cookie.Secure = true;
            
            // ruleid: cookie-without-httpOnly-flag
            HttpContext.Current.Response.Cookies.Add(cookie);
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

        public void bad_case_9(HttpContext context)
        {
            // Conditional cookie setting without HttpOnly
            string userRole = "admin";
            CookieOptions options = new CookieOptions
            {
                Secure = true
            };
            
            if (userRole == "admin")
            {
                options.Expires = DateTime.Now.AddHours(1);
            }
            else
            {
                options.Expires = DateTime.Now.AddDays(1);
            }
            
            // ruleid: cookie-without-httpOnly-flag
            context.Response.Cookies.Append("role", userRole, options);
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

        public void bad_case_10(HttpResponse response)
        {
            // Direct response cookie manipulation without HttpOnly
            // ruleid: cookie-without-httpOnly-flag
            response.Cookies.Append("tracking", "visitor123", new CookieOptions
            {
                Secure = true,
                SameSite = SameSiteMode.None
            });
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

        public void bad_case_11()
        {
            // Setting multiple cookies, all without HttpOnly
            HttpCookie cookie1 = new HttpCookie("preference1", "value1");
            HttpCookie cookie2 = new HttpCookie("preference2", "value2");
            
            // ruleid: cookie-without-httpOnly-flag
            HttpContext.Current.Response.Cookies.Add(cookie1);
            // ruleid: cookie-without-httpOnly-flag
            HttpContext.Current.Response.Cookies.Add(cookie2);
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

        public void bad_case_12(HttpContext context)
        {
            // Using a loop to set multiple cookies without HttpOnly
            string[] cookieNames = { "metric1", "metric2", "metric3" };
            string[] cookieValues = { "value1", "value2", "value3" };
            
            for (int i = 0; i < cookieNames.Length; i++)
            {
                // ruleid: cookie-without-httpOnly-flag
                context.Response.Cookies.Append(cookieNames[i], cookieValues[i], new CookieOptions
                {
                    Secure = true,
                    Expires = DateTime.Now.AddDays(7)
                });
            }
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

        public void bad_case_13(HttpContext context)
        {
            // Using a dictionary to set cookies without HttpOnly
            var cookieData = new Dictionary<string, string>
            {
                { "userId", "12345" },
                { "sessionData", "abcdef" }
            };
            
            foreach (var item in cookieData)
            {
                // ruleid: cookie-without-httpOnly-flag
                context.Response.Cookies.Append(item.Key, item.Value, new CookieOptions
                {
                    Secure = true,
                    SameSite = SameSiteMode.Strict
                });
            }
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

        public void bad_case_14()
        {
            // Using a helper method that doesn't set HttpOnly
            var cookie = CreateCookie("analyticsId", "GA12345");
            // ruleid: cookie-without-httpOnly-flag
            HttpContext.Current.Response.Cookies.Add(cookie);
        }
// {/fact}
        
        private HttpCookie CreateCookie(string name, string value)
        {
            HttpCookie cookie = new HttpCookie(name, value);
            cookie.Secure = true;
            cookie.Expires = DateTime.Now.AddMonths(3);
            return cookie;
        }

        public void bad_case_15(HttpContext context)
        {
            // Setting cookie with dynamic name and value but no HttpOnly
            string cookieName = "user_" + DateTime.Now.Ticks;
            string cookieValue = Guid.NewGuid().ToString();
            
            // ruleid: cookie-without-httpOnly-flag
            context.Response.Cookies.Append(cookieName, cookieValue, new CookieOptions
            {
                Secure = true,
                Expires = DateTime.Now.AddDays(14)
            });
        }
// {fact rule=insecure-file-permissions@v1.0 defects=0}

        // TRUE NEGATIVES (Secure Code Examples)

        public void good_case_1(HttpContext context)
        {
            // Basic cookie creation with HttpOnly flag
            // ok: cookie-without-httpOnly-flag
            context.Response.Cookies.Append("sessionId", "abc123", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                Expires = DateTime.Now.AddDays(1)
            });
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

        public void good_case_2(HttpContext context)
        {
            // Cookie with all security options properly set
            // ok: cookie-without-httpOnly-flag
            context.Response.Cookies.Append("authToken", "xyz789", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict
            });
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

        public void good_case_3(HttpContext context)
        {
            // Cookie with multiple options including HttpOnly
            // ok: cookie-without-httpOnly-flag
            var options = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                Expires = DateTime.Now.AddHours(2),
                SameSite = SameSiteMode.Lax,
                Path = "/"
            };
            context.Response.Cookies.Append("userPrefs", "theme=dark", options);
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

        public void good_case_4()
        {
            // Using HttpCookie class with HttpOnly
            HttpCookie cookie = new HttpCookie("userId", "12345");
            // ok: cookie-without-httpOnly-flag
            cookie.HttpOnly = true;
            cookie.Secure = true;
            cookie.Expires = DateTime.Now.AddMonths(1);
            HttpContext.Current.Response.Cookies.Add(cookie);
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

        public void good_case_5()
        {
            // HttpCookie with all security properties set correctly
            HttpCookie cookie = new HttpCookie("rememberMe", "true");
            // ok: cookie-without-httpOnly-flag
            cookie.HttpOnly = true;
            cookie.Secure = true;
            cookie.SameSite = SameSiteMode.Strict;
            HttpContext.Current.Response.Cookies.Add(cookie);
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

        [HttpGet]
        public IActionResult good_case_6()
        {
            // Using MVC CookieOptions with HttpOnly
            var cookieOptions = new CookieOptions
            {
                // ok: cookie-without-httpOnly-flag
                HttpOnly = true,
                Expires = DateTime.Now.AddDays(7),
                Secure = true
            };
            
            Response.Cookies.Append("cartId", Guid.NewGuid().ToString(), cookieOptions);
            return Ok("Cookie set securely");
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

        public void good_case_7(HttpContext context)
        {
            // Variable declaration and then setting properties individually with HttpOnly
            CookieOptions options = new CookieOptions();
            // ok: cookie-without-httpOnly-flag
            options.HttpOnly = true;
            options.Secure = true;
            options.Expires = DateTime.Now.AddDays(30);
            options.Path = "/account";
            
            context.Response.Cookies.Append("lastVisit", DateTime.Now.ToString(), options);
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

        public void good_case_8()
        {
            // Using HttpCookie with properties set individually, including HttpOnly
            HttpCookie cookie = new HttpCookie("language");
            cookie.Value = "en-US";
            // ok: cookie-without-httpOnly-flag
            cookie.HttpOnly = true;
            cookie.Expires = DateTime.Now.AddYears(1);
            cookie.Secure = true;
            
            HttpContext.Current.Response.Cookies.Add(cookie);
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

        public void good_case_9(HttpContext context)
        {
            // Conditional cookie setting with HttpOnly always set
            string userRole = "admin";
            CookieOptions options = new CookieOptions
            {
                // ok: cookie-without-httpOnly-flag
                HttpOnly = true,
                Secure = true
            };
            
            if (userRole == "admin")
            {
                options.Expires = DateTime.Now.AddHours(1);
            }
            else
            {
                options.Expires = DateTime.Now.AddDays(1);
            }
            
            context.Response.Cookies.Append("role", userRole, options);
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

        public void good_case_10(HttpResponse response)
        {
            // Direct response cookie manipulation with HttpOnly
            // ok: cookie-without-httpOnly-flag
            response.Cookies.Append("tracking", "visitor123", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None
            });
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

        public void good_case_11()
        {
            // Setting multiple cookies, all with HttpOnly
            HttpCookie cookie1 = new HttpCookie("preference1", "value1");
            HttpCookie cookie2 = new HttpCookie("preference2", "value2");
            
            // ok: cookie-without-httpOnly-flag
            cookie1.HttpOnly = true;
            cookie1.Secure = true;
            
            // ok: cookie-without-httpOnly-flag
            cookie2.HttpOnly = true;
            cookie2.Secure = true;
            
            HttpContext.Current.Response.Cookies.Add(cookie1);
            HttpContext.Current.Response.Cookies.Add(cookie2);
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

        public void good_case_12(HttpContext context)
        {
            // Using a loop to set multiple cookies with HttpOnly
            string[] cookieNames = { "metric1", "metric2", "metric3" };
            string[] cookieValues = { "value1", "value2", "value3" };
            
            for (int i = 0; i < cookieNames.Length; i++)
            {
                // ok: cookie-without-httpOnly-flag
                context.Response.Cookies.Append(cookieNames[i], cookieValues[i], new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    Expires = DateTime.Now.AddDays(7)
                });
            }
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

        public void good_case_13(HttpContext context)
        {
            // Using a dictionary to set cookies with HttpOnly
            var cookieData = new Dictionary<string, string>
            {
                { "userId", "12345" },
                { "sessionData", "abcdef" }
            };
            
            foreach (var item in cookieData)
            {
                // ok: cookie-without-httpOnly-flag
                context.Response.Cookies.Append(item.Key, item.Value, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict
                });
            }
        }
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

        public void good_case_14()
        {
            // Using a helper method that sets HttpOnly
            var cookie = CreateSecureCookie("analyticsId", "GA12345");
            HttpContext.Current.Response.Cookies.Add(cookie);
        }
// {/fact}
        
        private HttpCookie CreateSecureCookie(string name, string value)
        {
            HttpCookie cookie = new HttpCookie(name, value);
            // ok: cookie-without-httpOnly-flag
            cookie.HttpOnly = true;
            cookie.Secure = true;
            cookie.Expires = DateTime.Now.AddMonths(3);
            return cookie;
        }

        public void good_case_15(HttpContext context)
        {
            // Setting cookie with dynamic name and value with HttpOnly
            string cookieName = "user_" + DateTime.Now.Ticks;
            string cookieValue = Guid.NewGuid().ToString();
            
            // ok: cookie-without-httpOnly-flag
            context.Response.Cookies.Append(cookieName, cookieValue, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                Expires = DateTime.Now.AddDays(14)
            });
        }
    }
}