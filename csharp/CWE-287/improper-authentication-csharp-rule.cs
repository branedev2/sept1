using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using System.Net.Http;

namespace JwtAuthenticationExamples
{
    public class JwtAuthenticationController : Controller
    {
        private readonly IConfiguration _configuration;
        
        public JwtAuthenticationController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        // True Positive Examples (Vulnerable Code)

        public void bad_case_1()
        {
            string jwtToken = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            
            var tokenHandler = new JwtSecurityTokenHandler();
            // ruleid: improper-authentication-csharp-rule
            var token = tokenHandler.ReadJwtToken(jwtToken);
            
            // Using the token without validation
            var userId = token.Claims.First(c => c.Type == "sub").Value;
            Console.WriteLine($"User ID: {userId}");
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_2()
        {
            string jwtToken = Request.Cookies["auth_token"];
            
            var handler = new JwtSecurityTokenHandler();
            // ruleid: improper-authentication-csharp-rule
            var jsonToken = handler.ReadToken(jwtToken) as JwtSecurityToken;
            
            if (jsonToken != null)
            {
                var username = jsonToken.Claims.FirstOrDefault(claim => claim.Type == "username")?.Value;
                GrantAccess(username);
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public async Task<IActionResult> bad_case_3()
        {
            string token = Request.Query["token"];
            
            var tokenHandler = new JwtSecurityTokenHandler();
            // ruleid: improper-authentication-csharp-rule
            var jwtToken = tokenHandler.ReadJwtToken(token);
            
            var userRole = jwtToken.Claims.FirstOrDefault(c => c.Type == "role")?.Value;
            
            return Ok(new { Role = userRole });
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public IActionResult bad_case_4()
        {
            var authHeader = Request.Headers["Authorization"].ToString();
            if (authHeader.StartsWith("Bearer "))
            {
                var token = authHeader.Substring(7);
                var handler = new JwtSecurityTokenHandler();
                
                try
                {
                    // ruleid: improper-authentication-csharp-rule
                    var jsonToken = handler.ReadToken(token);
                    var tokenS = jsonToken as JwtSecurityToken;
                    var jti = tokenS.Claims.First(claim => claim.Type == "jti").Value;
                    return Ok(new { TokenId = jti });
                }
                catch
                {
                    return BadRequest("Invalid token");
                }
            }
            
            return Unauthorized();
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_5()
        {
            string tokenString = HttpContext.Session.GetString("JWTToken");
            var tokenHandler = new JwtSecurityTokenHandler();
            
            // ruleid: improper-authentication-csharp-rule
            var securityToken = tokenHandler.ReadToken(tokenString) as JwtSecurityToken;
            
            if (securityToken != null && securityToken.ValidTo > DateTime.UtcNow)
            {
                // Token not expired, proceed
                var userId = securityToken.Claims.FirstOrDefault(c => c.Type == "userId")?.Value;
                Console.WriteLine($"User ID from token: {userId}");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public IActionResult bad_case_6(string returnUrl)
        {
            var token = Request.Form["token"];
            var handler = new JwtSecurityTokenHandler();
            
            try
            {
                // ruleid: improper-authentication-csharp-rule
                var decodedToken = handler.ReadJwtToken(token);
                var email = decodedToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
                
                return Redirect(returnUrl + "?email=" + email);
            }
            catch
            {
                return BadRequest("Invalid token format");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public async Task bad_case_7()
        {
            var client = new HttpClient();
            var response = await client.GetAsync("https://auth-service.example.com/token");
            var tokenString = await response.Content.ReadAsStringAsync();
            
            var handler = new JwtSecurityTokenHandler();
            // ruleid: improper-authentication-csharp-rule
            var jwt = handler.ReadJwtToken(tokenString);
            
            var permissions = jwt.Claims.Where(c => c.Type == "permission")
                                .Select(c => c.Value)
                                .ToList();
                                
            AssignPermissions(permissions);
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public IActionResult bad_case_8()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = Request.Headers["X-API-Token"].ToString();
            
            // ruleid: improper-authentication-csharp-rule
            var token = tokenHandler.ReadJwtToken(jwtToken);
            
            if (token.ValidTo < DateTime.UtcNow)
            {
                return Unauthorized("Token expired");
            }
            
            return Ok(new { Message = "Token accepted" });
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_9()
        {
            string authToken = Request.Cookies["auth"];
            var handler = new JwtSecurityTokenHandler();
            
            try
            {
                // ruleid: improper-authentication-csharp-rule
                var decodedToken = handler.ReadToken(authToken) as JwtSecurityToken;
                var customerId = decodedToken.Claims.FirstOrDefault(c => c.Type == "customer_id")?.Value;
                
                if (!string.IsNullOrEmpty(customerId))
                {
                    LoadCustomerData(customerId);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error decoding token: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public IActionResult bad_case_10()
        {
            var token = Request.Query["access_token"];
            
            if (string.IsNullOrEmpty(token))
            {
                return Unauthorized();
            }
            
            var tokenHandler = new JwtSecurityTokenHandler();
            
            try
            {
                // ruleid: improper-authentication-csharp-rule
                var jwtToken = tokenHandler.ReadJwtToken(token);
                var userId = jwtToken.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
                var tenantId = jwtToken.Claims.FirstOrDefault(c => c.Type == "tenant_id")?.Value;
                
                return Ok(new { UserId = userId, TenantId = tenantId });
            }
            catch
            {
                return BadRequest("Invalid token format");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_11()
        {
            string tokenFromHeader = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            var handler = new JwtSecurityTokenHandler();
            
            if (handler.CanReadToken(tokenFromHeader))
            {
                // ruleid: improper-authentication-csharp-rule
                var token = handler.ReadJwtToken(tokenFromHeader);
                var exp = token.Claims.FirstOrDefault(c => c.Type == "exp")?.Value;
                
                if (exp != null)
                {
                    var expiryTime = DateTimeOffset.FromUnixTimeSeconds(long.Parse(exp)).DateTime;
                    Console.WriteLine($"Token expires at: {expiryTime}");
                }
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public IActionResult bad_case_12()
        {
            var tokenString = Request.Headers["X-Auth-Token"].ToString();
            var handler = new JwtSecurityTokenHandler();
            
            if (!handler.CanReadToken(tokenString))
            {
                return BadRequest("Invalid token format");
            }
            
            // ruleid: improper-authentication-csharp-rule
            var token = handler.ReadToken(tokenString) as JwtSecurityToken;
            var scope = token.Claims.FirstOrDefault(c => c.Type == "scope")?.Value;
            
            if (scope != "admin")
            {
                return Forbid();
            }
            
            return Ok(new { Message = "Admin access granted" });
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public async Task<IActionResult> bad_case_13()
        {
            var client = new HttpClient();
            var response = await client.GetAsync("https://identity-provider.example.com/userinfo");
            var responseContent = await response.Content.ReadAsStringAsync();
            
            // Assume responseContent contains a JWT token
            var handler = new JwtSecurityTokenHandler();
            
            // ruleid: improper-authentication-csharp-rule
            var token = handler.ReadJwtToken(responseContent);
            var name = token.Claims.FirstOrDefault(c => c.Type == "name")?.Value;
            var email = token.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
            
            return Ok(new { Name = name, Email = email });
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public void bad_case_14()
        {
            string tokenFromSession = HttpContext.Session.GetString("UserToken");
            var tokenHandler = new JwtSecurityTokenHandler();
            
            if (string.IsNullOrEmpty(tokenFromSession))
            {
                throw new UnauthorizedAccessException("No token found in session");
            }
            
            // ruleid: improper-authentication-csharp-rule
            var jwt = tokenHandler.ReadJwtToken(tokenFromSession);
            
            foreach (var claim in jwt.Claims)
            {
                Console.WriteLine($"Claim Type: {claim.Type}, Value: {claim.Value}");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

        public IActionResult bad_case_15()
        {
            var authCookie = Request.Cookies["AuthData"];
            
            if (string.IsNullOrEmpty(authCookie))
            {
                return RedirectToAction("Login");
            }
            
            var handler = new JwtSecurityTokenHandler();
            
            try
            {
                // ruleid: improper-authentication-csharp-rule
                var token = handler.ReadToken(authCookie) as JwtSecurityToken;
                var userGroups = token.Claims.Where(c => c.Type == "groups")
                                     .Select(c => c.Value)
                                     .ToList();
                
                ViewBag.UserGroups = userGroups;
                return View();
            }
            catch
            {
                Response.Cookies.Delete("AuthData");
                return RedirectToAction("Login");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        public void good_case_1()
        {
            string jwtToken = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration["Jwt:Key"])),
                ValidateIssuer = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["Jwt:Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
            
            try
            {
                // ok: improper-authentication-csharp-rule
                ClaimsPrincipal claimsPrincipal = tokenHandler.ValidateToken(jwtToken, validationParameters, out SecurityToken validatedToken);
                var userId = claimsPrincipal.Claims.First(c => c.Type == "sub").Value;
                Console.WriteLine($"User ID: {userId}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Token validation failed: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_2()
        {
            string jwtToken = Request.Cookies["auth_token"];
            
            var handler = new JwtSecurityTokenHandler();
            var validationParams = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _configuration["JWT:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["JWT:Audience"],
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = true
            };
            
            try
            {
                // ok: improper-authentication-csharp-rule
                var principal = handler.ValidateToken(jwtToken, validationParams, out var validatedToken);
                var username = principal.Identity.Name;
                GrantAccess(username);
            }
            catch
            {
                // Token validation failed
                Console.WriteLine("Invalid token");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public async Task<IActionResult> good_case_3()
        {
            string token = Request.Query["token"];
            
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:SecretKey"])),
                ValidateIssuer = true,
                ValidIssuer = _configuration["JwtSettings:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["JwtSettings:Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5)
            };
            
            try
            {
                // ok: improper-authentication-csharp-rule
                var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
                var userRole = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
                
                return Ok(new { Role = userRole });
            }
            catch (Exception ex)
            {
                return Unauthorized($"Token validation failed: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public IActionResult good_case_4()
        {
            var authHeader = Request.Headers["Authorization"].ToString();
            if (authHeader.StartsWith("Bearer "))
            {
                var token = authHeader.Substring(7);
                var handler = new JwtSecurityTokenHandler();
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Auth:JwtSecret"])),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };
                
                try
                {
                    // ok: improper-authentication-csharp-rule
                    var principal = handler.ValidateToken(token, validationParameters, out var validatedToken);
                    var jti = principal.Claims.First(claim => claim.Type == "jti").Value;
                    return Ok(new { TokenId = jti });
                }
                catch (Exception ex)
                {
                    return BadRequest($"Invalid token: {ex.Message}");
                }
            }
            
            return Unauthorized();
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_5()
        {
            string tokenString = HttpContext.Session.GetString("JWTToken");
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtConfig:Secret"])),
                ValidateIssuer = true,
                ValidIssuer = _configuration["JwtConfig:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["JwtConfig:Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
            
            try
            {
                // ok: improper-authentication-csharp-rule
                var principal = tokenHandler.ValidateToken(tokenString, validationParameters, out var validatedToken);
                var userId = principal.Claims.FirstOrDefault(c => c.Type == "userId")?.Value;
                Console.WriteLine($"User ID from token: {userId}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Token validation failed: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public IActionResult good_case_6(string returnUrl)
        {
            var token = Request.Form["token"];
            var handler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Authentication:SecretKey"])),
                ValidateIssuer = true,
                ValidIssuer = _configuration["Authentication:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["Authentication:Audience"],
                ValidateLifetime = true
            };
            
            try
            {
                // ok: improper-authentication-csharp-rule
                var principal = handler.ValidateToken(token, validationParameters, out var validatedToken);
                var email = principal.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
                
                return Redirect(returnUrl + "?email=" + email);
            }
            catch (Exception ex)
            {
                return BadRequest($"Invalid token: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public async Task good_case_7()
        {
            var client = new HttpClient();
            var response = await client.GetAsync("https://auth-service.example.com/token");
            var tokenString = await response.Content.ReadAsStringAsync();
            
            var handler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["ExternalAuth:Key"])),
                ValidateIssuer = true,
                ValidIssuer = "https://auth-service.example.com",
                ValidateAudience = true,
                ValidAudience = _configuration["ExternalAuth:Audience"],
                ValidateLifetime = true
            };
            
            try
            {
                // ok: improper-authentication-csharp-rule
                var principal = handler.ValidateToken(tokenString, validationParameters, out var validatedToken);
                var permissions = principal.Claims.Where(c => c.Type == "permission")
                                      .Select(c => c.Value)
                                      .ToList();
                                      
                AssignPermissions(permissions);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Token validation failed: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public IActionResult good_case_8()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = Request.Headers["X-API-Token"].ToString();
            
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["ApiAuth:Secret"])),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
            
            try
            {
                // ok: improper-authentication-csharp-rule
                tokenHandler.ValidateToken(jwtToken, validationParameters, out var validatedToken);
                return Ok(new { Message = "Token accepted" });
            }
            catch (SecurityTokenExpiredException)
            {
                return Unauthorized("Token expired");
            }
            catch (Exception)
            {
                return Unauthorized("Invalid token");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_9()
        {
            string authToken = Request.Cookies["auth"];
            var handler = new JwtSecurityTokenHandler();
            
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Authentication:Key"])),
                ValidateIssuer = true,
                ValidIssuer = _configuration["Authentication:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["Authentication:Audience"],
                ValidateLifetime = true
            };
            
            try
            {
                // ok: improper-authentication-csharp-rule
                var principal = handler.ValidateToken(authToken, validationParameters, out var validatedToken);
                var customerId = principal.Claims.FirstOrDefault(c => c.Type == "customer_id")?.Value;
                
                if (!string.IsNullOrEmpty(customerId))
                {
                    LoadCustomerData(customerId);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error validating token: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public IActionResult good_case_10()
        {
            var token = Request.Query["access_token"];
            
            if (string.IsNullOrEmpty(token))
            {
                return Unauthorized();
            }
            
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["OAuth:Secret"])),
                ValidateIssuer = true,
                ValidIssuer = _configuration["OAuth:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["OAuth:Audience"],
                ValidateLifetime = true
            };
            
            try
            {
                // ok: improper-authentication-csharp-rule
                var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
                var userId = principal.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
                var tenantId = principal.Claims.FirstOrDefault(c => c.Type == "tenant_id")?.Value;
                
                return Ok(new { UserId = userId, TenantId = tenantId });
            }
            catch (Exception ex)
            {
                return BadRequest($"Invalid token: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_11()
        {
            string tokenFromHeader = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            var handler = new JwtSecurityTokenHandler();
            
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])),
                ValidateIssuer = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["Jwt:Audience"],
                ValidateLifetime = true
            };
            
            try
            {
                // ok: improper-authentication-csharp-rule
                var principal = handler.ValidateToken(tokenFromHeader, validationParameters, out var validatedToken);
                var expiryTime = validatedToken.ValidTo;
                Console.WriteLine($"Token expires at: {expiryTime}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Token validation failed: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public IActionResult good_case_12()
        {
            var tokenString = Request.Headers["X-Auth-Token"].ToString();
            var handler = new JwtSecurityTokenHandler();
            
            if (!handler.CanReadToken(tokenString))
            {
                return BadRequest("Invalid token format");
            }
            
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["AdminAuth:Secret"])),
                ValidateIssuer = true,
                ValidIssuer = _configuration["AdminAuth:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["AdminAuth:Audience"],
                ValidateLifetime = true
            };
            
            try
            {
                // ok: improper-authentication-csharp-rule
                var principal = handler.ValidateToken(tokenString, validationParameters, out var validatedToken);
                var scope = principal.Claims.FirstOrDefault(c => c.Type == "scope")?.Value;
                
                if (scope != "admin")
                {
                    return Forbid();
                }
                
                return Ok(new { Message = "Admin access granted" });
            }
            catch (Exception)
            {
                return Unauthorized("Invalid token");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public async Task<IActionResult> good_case_13()
        {
            var client = new HttpClient();
            var response = await client.GetAsync("https://identity-provider.example.com/userinfo");
            var responseContent = await response.Content.ReadAsStringAsync();
            
            // Assume responseContent contains a JWT token
            var handler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["IdentityProvider:Secret"])),
                ValidateIssuer = true,
                ValidIssuer = "https://identity-provider.example.com",
                ValidateAudience = true,
                ValidAudience = _configuration["IdentityProvider:Audience"],
                ValidateLifetime = true
            };
            
            try
            {
                // ok: improper-authentication-csharp-rule
                var principal = handler.ValidateToken(responseContent, validationParameters, out var validatedToken);
                var name = principal.Claims.FirstOrDefault(c => c.Type == "name")?.Value;
                var email = principal.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
                
                return Ok(new { Name = name, Email = email });
            }
            catch (Exception ex)
            {
                return BadRequest($"Invalid token: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public void good_case_14()
        {
            string tokenFromSession = HttpContext.Session.GetString("UserToken");
            var tokenHandler = new JwtSecurityTokenHandler();
            
            if (string.IsNullOrEmpty(tokenFromSession))
            {
                throw new UnauthorizedAccessException("No token found in session");
            }
            
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["SessionAuth:Secret"])),
                ValidateIssuer = true,
                ValidIssuer = _configuration["SessionAuth:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["SessionAuth:Audience"],
                ValidateLifetime = true
            };
            
            try
            {
                // ok: improper-authentication-csharp-rule
                var principal = tokenHandler.ValidateToken(tokenFromSession, validationParameters, out var validatedToken);
                
                foreach (var claim in principal.Claims)
                {
                    Console.WriteLine($"Claim Type: {claim.Type}, Value: {claim.Value}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Token validation failed: {ex.Message}");
            }
        }
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

        public IActionResult good_case_15()
        {
            var authCookie = Request.Cookies["AuthData"];
            
            if (string.IsNullOrEmpty(authCookie))
            {
                return RedirectToAction("Login");
            }
            
            var handler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["CookieAuth:Secret"])),
                ValidateIssuer = true,
                ValidIssuer = _configuration["CookieAuth:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["CookieAuth:Audience"],
                ValidateLifetime = true
            };
            
            try
            {
                // ok: improper-authentication-csharp-rule
                var principal = handler.ValidateToken(authCookie, validationParameters, out var validatedToken);
                var userGroups = principal.Claims.Where(c => c.Type == "groups")
                                      .Select(c => c.Value)
                                      .ToList();
                
                ViewBag.UserGroups = userGroups;
                return View();
            }
            catch
            {
                Response.Cookies.Delete("AuthData");
                return RedirectToAction("Login");
            }
        }
// {/fact}

        // Helper methods
        private void GrantAccess(string username)
        {
            Console.WriteLine($"Access granted to {username}");
        }

        private void LoadCustomerData(string customerId)
        {
            Console.WriteLine($"Loading data for customer {customerId}");
        }

        private void AssignPermissions(List<string> permissions)
        {
            foreach (var permission in permissions)
            {
                Console.WriteLine($"Assigning permission: {permission}");
            }
        }
    }
}