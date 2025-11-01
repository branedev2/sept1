using System;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SessionFixationExamples
{
    // True Positive Examples (Vulnerable Code)

    public class BadController : Controller
    {
// {fact rule=session-fixation@v1.0 defects=1}
        // Example 1: Basic login without session cleanup
        public ActionResult bad_case_1()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];

            if (AuthenticateUser(username, password))
            {
                // ruleid: csharp-session-handling-authentication
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("username", username);
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=1}

        // Example 2: Login with role-based authentication but no session cleanup
        public ActionResult bad_case_2()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                string role = GetUserRole(username);
                // ruleid: csharp-session-handling-authentication
                HttpContext.Session.SetString("role", role);
                HttpContext.Session.SetString("authenticated", "true");
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=1}

        // Example 3: Two-factor authentication without session cleanup
        public ActionResult bad_case_3()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            string twoFactorCode = Request.Form["2fa_code"];
            
            if (AuthenticateUser(username, password) && ValidateTwoFactorCode(twoFactorCode))
            {
                // ruleid: csharp-session-handling-authentication
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("2fa_verified", "true");
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=1}

        // Example 4: Social login integration without session cleanup
        public ActionResult bad_case_4()
        {
            string token = Request.Form["social_token"];
            var userInfo = ValidateSocialToken(token);
            
            if (userInfo != null)
            {
                // ruleid: csharp-session-handling-authentication
                HttpContext.Session.SetString("user_id", userInfo.Id);
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("login_method", "social");
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=1}

        // Example 5: Remember me functionality without session cleanup
        public ActionResult bad_case_5()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            bool rememberMe = Convert.ToBoolean(Request.Form["remember_me"]);
            
            if (AuthenticateUser(username, password))
            {
                // ruleid: csharp-session-handling-authentication
                HttpContext.Session.SetString("authenticated", "true");
                
                if (rememberMe)
                {
                    HttpContext.Response.Cookies.Append("remember_token", GenerateRememberToken(username), 
                        new CookieOptions { Expires = DateTime.Now.AddDays(30) });
                }
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=1}

        // Example 6: API token-based authentication without session cleanup
        public ActionResult bad_case_6()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                string apiToken = GenerateApiToken(username);
                // ruleid: csharp-session-handling-authentication
                HttpContext.Session.SetString("api_token", apiToken);
                HttpContext.Session.SetString("authenticated", "true");
                return Json(new { success = true, token = apiToken });
            }
            return Json(new { success = false });
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=1}

        // Example 7: Authentication with permission setting without session cleanup
        public ActionResult bad_case_7()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                var permissions = GetUserPermissions(username);
                // ruleid: csharp-session-handling-authentication
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("permissions", string.Join(",", permissions));
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=1}

        // Example 8: Login with session timeout configuration but no cleanup
        public ActionResult bad_case_8()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                // ruleid: csharp-session-handling-authentication
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("username", username);
                // Set session timeout to 30 minutes
                HttpContext.Session.SetInt32("timeout", 30);
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=1}

        // Example 9: Authentication with user preferences loading without session cleanup
        public ActionResult bad_case_9()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                var preferences = LoadUserPreferences(username);
                // ruleid: csharp-session-handling-authentication
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("theme", preferences.Theme);
                HttpContext.Session.SetString("language", preferences.Language);
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=1}

        // Example 10: Authentication with partial session cleanup (not enough)
        public ActionResult bad_case_10()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                // Only removing one item, not clearing the whole session
                HttpContext.Session.Remove("previous_login_attempt");
                
                // ruleid: csharp-session-handling-authentication
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("username", username);
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=1}

        // Example 11: Authentication with claims-based identity but no session cleanup
        public async Task<IActionResult> bad_case_11()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim(ClaimTypes.Role, GetUserRole(username))
                };
                
                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);
                
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
                
                // ruleid: csharp-session-handling-authentication
                HttpContext.Session.SetString("last_login", DateTime.Now.ToString());
                HttpContext.Session.SetString("user_id", GetUserId(username).ToString());
                
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=1}

        // Example 12: Authentication with IP tracking but no session cleanup
        public ActionResult bad_case_12()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                string ipAddress = HttpContext.Connection.RemoteIpAddress.ToString();
                
                // ruleid: csharp-session-handling-authentication
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("username", username);
                HttpContext.Session.SetString("ip_address", ipAddress);
                
                LogSuccessfulLogin(username, ipAddress);
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=1}

        // Example 13: Authentication with device fingerprinting but no session cleanup
        public ActionResult bad_case_13()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            string deviceFingerprint = Request.Form["device_fingerprint"];
            
            if (AuthenticateUser(username, password))
            {
                // ruleid: csharp-session-handling-authentication
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("username", username);
                HttpContext.Session.SetString("device_id", deviceFingerprint);
                
                RegisterKnownDevice(username, deviceFingerprint);
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=1}

        // Example 14: Authentication with shopping cart preservation but no session cleanup
        public ActionResult bad_case_14()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                var cartItems = HttpContext.Session.GetString("cart_items");
                
                // ruleid: csharp-session-handling-authentication
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("username", username);
                
                // Preserve shopping cart
                if (!string.IsNullOrEmpty(cartItems))
                {
                    SaveCartToDatabase(username, cartItems);
                }
                
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=1}

        // Example 15: Authentication with multiple roles but no session cleanup
        public ActionResult bad_case_15()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                var roles = GetUserRoles(username);
                
                // ruleid: csharp-session-handling-authentication
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("username", username);
                HttpContext.Session.SetString("roles", string.Join(",", roles));
                
                if (roles.Contains("admin"))
                {
                    return RedirectToAction("AdminDashboard");
                }
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        // Example 1: Basic login with proper session cleanup
        public ActionResult good_case_1()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];

            if (AuthenticateUser(username, password))
            {
                // ok: csharp-session-handling-authentication
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("username", username);
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=0}

        // Example 2: Login with role-based authentication and session cleanup
        public ActionResult good_case_2()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                string role = GetUserRole(username);
                // ok: csharp-session-handling-authentication
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("role", role);
                HttpContext.Session.SetString("authenticated", "true");
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=0}

        // Example 3: Two-factor authentication with session cleanup
        public ActionResult good_case_3()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            string twoFactorCode = Request.Form["2fa_code"];
            
            if (AuthenticateUser(username, password) && ValidateTwoFactorCode(twoFactorCode))
            {
                // ok: csharp-session-handling-authentication
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("2fa_verified", "true");
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=0}

        // Example 4: Social login integration with session cleanup
        public ActionResult good_case_4()
        {
            string token = Request.Form["social_token"];
            var userInfo = ValidateSocialToken(token);
            
            if (userInfo != null)
            {
                // ok: csharp-session-handling-authentication
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("user_id", userInfo.Id);
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("login_method", "social");
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=0}

        // Example 5: Remember me functionality with session cleanup
        public ActionResult good_case_5()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            bool rememberMe = Convert.ToBoolean(Request.Form["remember_me"]);
            
            if (AuthenticateUser(username, password))
            {
                // ok: csharp-session-handling-authentication
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("authenticated", "true");
                
                if (rememberMe)
                {
                    HttpContext.Response.Cookies.Append("remember_token", GenerateRememberToken(username), 
                        new CookieOptions { Expires = DateTime.Now.AddDays(30) });
                }
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=0}

        // Example 6: API token-based authentication with session cleanup
        public ActionResult good_case_6()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                string apiToken = GenerateApiToken(username);
                // ok: csharp-session-handling-authentication
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("api_token", apiToken);
                HttpContext.Session.SetString("authenticated", "true");
                return Json(new { success = true, token = apiToken });
            }
            return Json(new { success = false });
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=0}

        // Example 7: Authentication with permission setting and session cleanup
        public ActionResult good_case_7()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                var permissions = GetUserPermissions(username);
                // ok: csharp-session-handling-authentication
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("permissions", string.Join(",", permissions));
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=0}

        // Example 8: Login with session timeout configuration and session cleanup
        public ActionResult good_case_8()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                // ok: csharp-session-handling-authentication
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("username", username);
                // Set session timeout to 30 minutes
                HttpContext.Session.SetInt32("timeout", 30);
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=0}

        // Example 9: Authentication with user preferences loading and session cleanup
        public ActionResult good_case_9()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                var preferences = LoadUserPreferences(username);
                // ok: csharp-session-handling-authentication
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("theme", preferences.Theme);
                HttpContext.Session.SetString("language", preferences.Language);
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=0}

        // Example 10: Authentication with session abandon instead of clear
        public ActionResult good_case_10()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                // ok: csharp-session-handling-authentication
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("username", username);
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=0}

        // Example 11: Authentication with claims-based identity and session cleanup
        public async Task<IActionResult> good_case_11()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim(ClaimTypes.Role, GetUserRole(username))
                };
                
                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);
                
                // ok: csharp-session-handling-authentication
                HttpContext.Session.Clear();
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
                
                HttpContext.Session.SetString("last_login", DateTime.Now.ToString());
                HttpContext.Session.SetString("user_id", GetUserId(username).ToString());
                
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=0}

        // Example 12: Authentication with IP tracking and session cleanup
        public ActionResult good_case_12()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                string ipAddress = HttpContext.Connection.RemoteIpAddress.ToString();
                
                // ok: csharp-session-handling-authentication
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("username", username);
                HttpContext.Session.SetString("ip_address", ipAddress);
                
                LogSuccessfulLogin(username, ipAddress);
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=0}

        // Example 13: Authentication with device fingerprinting and session cleanup
        public ActionResult good_case_13()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            string deviceFingerprint = Request.Form["device_fingerprint"];
            
            if (AuthenticateUser(username, password))
            {
                // ok: csharp-session-handling-authentication
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("username", username);
                HttpContext.Session.SetString("device_id", deviceFingerprint);
                
                RegisterKnownDevice(username, deviceFingerprint);
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=0}

        // Example 14: Authentication with shopping cart preservation and session cleanup
        public ActionResult good_case_14()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                var cartItems = HttpContext.Session.GetString("cart_items");
                
                // ok: csharp-session-handling-authentication
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("username", username);
                
                // Preserve shopping cart after session cleanup
                if (!string.IsNullOrEmpty(cartItems))
                {
                    SaveCartToDatabase(username, cartItems);
                    HttpContext.Session.SetString("cart_items", cartItems);
                }
                
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}
// {fact rule=session-fixation@v1.0 defects=0}

        // Example 15: Authentication with multiple roles and session cleanup
        public ActionResult good_case_15()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            if (AuthenticateUser(username, password))
            {
                var roles = GetUserRoles(username);
                
                // ok: csharp-session-handling-authentication
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("authenticated", "true");
                HttpContext.Session.SetString("username", username);
                HttpContext.Session.SetString("roles", string.Join(",", roles));
                
                if (roles.Contains("admin"))
                {
                    return RedirectToAction("AdminDashboard");
                }
                return RedirectToAction("Dashboard");
            }
            return View("Login");
        }
// {/fact}

        // Helper methods
        private bool AuthenticateUser(string username, string password)
        {
            // Authentication logic
            return !string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password);
        }

        private string GetUserRole(string username)
        {
            // Role retrieval logic
            return "user";
        }

        private List<string> GetUserRoles(string username)
        {
            // Multiple roles retrieval logic
            return new List<string> { "user", "editor" };
        }

        private bool ValidateTwoFactorCode(string code)
        {
            // 2FA validation logic
            return !string.IsNullOrEmpty(code);
        }

        private dynamic ValidateSocialToken(string token)
        {
            // Social token validation logic
            if (!string.IsNullOrEmpty(token))
            {
                return new { Id = "user123" };
            }
            return null;
        }

        private string GenerateRememberToken(string username)
        {
            // Token generation logic
            return Guid.NewGuid().ToString();
        }

        private string GenerateApiToken(string username)
        {
            // API token generation logic
            return Guid.NewGuid().ToString();
        }

        private List<string> GetUserPermissions(string username)
        {
            // Permissions retrieval logic
            return new List<string> { "read", "write" };
        }

        private dynamic LoadUserPreferences(string username)
        {
            // User preferences loading logic
            return new { Theme = "dark", Language = "en" };
        }

        private int GetUserId(string username)
        {
            // User ID retrieval logic
            return 123;
        }

        private void LogSuccessfulLogin(string username, string ipAddress)
        {
            // Login logging logic
        }

        private void RegisterKnownDevice(string username, string deviceFingerprint)
        {
            // Device registration logic
        }

        private void SaveCartToDatabase(string username, string cartItems)
        {
            // Cart saving logic
        }
    }
}