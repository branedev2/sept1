using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace JwtTokenValidationExamples
{
    public class JwtTokenValidationController : Controller
    {
        private readonly IConfiguration _configuration;

        public JwtTokenValidationController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=1}

        // True Positives (Vulnerable Code)

        public void bad_case_1()
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("your-secret-key")),
                ValidateIssuer = true,
                ValidIssuer = "issuer",
                ValidateAudience = true,
                ValidAudience = "audience",
                // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=1}

        public void bad_case_2()
        {
            var validationParams = new TokenValidationParameters();
            validationParams.ValidateIssuerSigningKey = true;
            validationParams.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            validationParams.ValidateIssuer = true;
            validationParams.ValidIssuer = _configuration["Jwt:Issuer"];
            // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
            validationParams.ValidateLifetime = false;
            
            var handler = new JwtSecurityTokenHandler();
            var token = HttpContext.Request.Cookies["auth_token"];
            var principal = handler.ValidateToken(token, validationParams, out var securityToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=1}

        public void bad_case_3()
        {
            bool validateLifetime = false;
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("your-secret-key")),
                ValidateIssuer = true,
                ValidIssuer = "issuer",
                // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                ValidateLifetime = validateLifetime
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = Request.Query["token"];
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=1}

        public void bad_case_4()
        {
            var parameters = new TokenValidationParameters();
            parameters.ValidateIssuerSigningKey = true;
            parameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key"));
            parameters.ValidateIssuer = false;
            parameters.ValidateAudience = false;
            // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
            parameters.RequireExpirationTime = false;
            
            var handler = new JwtSecurityTokenHandler();
            var token = Request.Headers["X-Auth-Token"];
            handler.ValidateToken(token, parameters, out var securityToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=1}

        public void bad_case_5()
        {
            var validationParams = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("my-secret")),
                ValidateIssuer = true,
                ValidIssuer = "example-issuer",
                ValidateAudience = true,
                ValidAudience = "example-audience",
                // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                RequireExpirationTime = false,
                ValidateLifetime = true
            };

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Form["token"];
            var principal = handler.ValidateToken(token, validationParams, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=1}

        public void bad_case_6()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("secret-key")),
                ValidateIssuer = false,
                ValidateAudience = false,
                // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                ValidateLifetime = false,
                // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                RequireExpirationTime = false
            };

            var token = HttpContext.Session.GetString("JwtToken");
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=1}

        public void bad_case_7()
        {
            var tokenValidationParameters = new TokenValidationParameters();
            tokenValidationParameters.ValidateIssuerSigningKey = true;
            tokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret"));
            tokenValidationParameters.ValidateIssuer = true;
            tokenValidationParameters.ValidIssuer = "issuer";
            tokenValidationParameters.ValidateAudience = true;
            tokenValidationParameters.ValidAudience = "audience";
            // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
            tokenValidationParameters.ValidateLifetime = false;
            tokenValidationParameters.ClockSkew = TimeSpan.Zero;

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Cookies["jwt"];
            var principal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=1}

        public void bad_case_8()
        {
            bool shouldValidateLifetime = GetValidationFlag();
            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key")),
                ValidateIssuer = true,
                ValidIssuer = "issuer",
                // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                ValidateLifetime = shouldValidateLifetime // Assume GetValidationFlag returns false
            };

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            var principal = handler.ValidateToken(token, parameters, out var validatedToken);
        }
// {/fact}

        private bool GetValidationFlag()
        {
            return false; // This is for demonstration purposes
        }
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=1}

        public void bad_case_9()
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key")),
                ValidateIssuer = true,
                ValidIssuer = "issuer",
                ValidateAudience = true,
                ValidAudience = "audience",
                // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                RequireExpirationTime = false,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Query["auth_token"];
            var principal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=1}

        public void bad_case_10()
        {
            var parameters = new TokenValidationParameters();
            parameters.ValidateIssuerSigningKey = true;
            parameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key"));
            parameters.ValidateIssuer = true;
            parameters.ValidIssuer = "issuer";
            parameters.ValidateAudience = true;
            parameters.ValidAudience = "audience";
            // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
            parameters.ValidateLifetime = false;
            parameters.RequireExpirationTime = true; // This doesn't help if ValidateLifetime is false

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Headers["X-Token"];
            var principal = handler.ValidateToken(token, parameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=1}

        public void bad_case_11()
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key")),
                ValidateIssuer = false,
                ValidateAudience = false,
                // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                ValidateLifetime = false,
                ClockSkew = TimeSpan.FromMinutes(10)
            };

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Form["access_token"];
            var principal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=1}

        public void bad_case_12()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("your-secret-key");
            
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                RequireExpirationTime = false,
                // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                ValidateLifetime = false
            };

            var token = HttpContext.Request.Cookies["jwt_token"];
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=1}

        public void bad_case_13()
        {
            var validationParams = new TokenValidationParameters();
            validationParams.ValidateIssuerSigningKey = true;
            validationParams.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key"));
            validationParams.ValidateIssuer = true;
            validationParams.ValidIssuer = "issuer";
            validationParams.ValidateAudience = true;
            validationParams.ValidAudience = "audience";
            validationParams.RequireSignedTokens = true;
            // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
            validationParams.ValidateLifetime = false;
            
            var handler = new JwtSecurityTokenHandler();
            var token = Request.Headers["Authorization"].ToString().Split(' ')[1];
            var principal = handler.ValidateToken(token, validationParams, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=1}

        public void bad_case_14()
        {
            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key")),
                ValidateIssuer = true,
                ValidIssuer = "issuer",
                ValidateAudience = true,
                ValidAudience = "audience",
                RequireSignedTokens = true,
                // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                RequireExpirationTime = false
            };

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Query["token"].ToString();
            var principal = handler.ValidateToken(token, parameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=1}

        public void bad_case_15()
        {
            var tokenValidationParameters = new TokenValidationParameters();
            tokenValidationParameters.ValidateIssuerSigningKey = true;
            tokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key"));
            tokenValidationParameters.ValidateIssuer = true;
            tokenValidationParameters.ValidIssuer = "issuer";
            tokenValidationParameters.ValidateAudience = true;
            tokenValidationParameters.ValidAudience = "audience";
            tokenValidationParameters.RequireSignedTokens = true;
            tokenValidationParameters.RequireExpirationTime = true;
            // ruleid: jwt-tokenvalidationparameters-no-expiry-csharp-rule
            tokenValidationParameters.ValidateLifetime = false;

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Headers["X-Auth"].ToString();
            var principal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=0}

        // True Negatives (Secure Code)

        public void good_case_1()
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("your-secret-key")),
                ValidateIssuer = true,
                ValidIssuer = "issuer",
                ValidateAudience = true,
                ValidAudience = "audience",
                // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                ValidateLifetime = true
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=0}

        public void good_case_2()
        {
            var validationParams = new TokenValidationParameters();
            validationParams.ValidateIssuerSigningKey = true;
            validationParams.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            validationParams.ValidateIssuer = true;
            validationParams.ValidIssuer = _configuration["Jwt:Issuer"];
            // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
            validationParams.ValidateLifetime = true;
            
            var handler = new JwtSecurityTokenHandler();
            var token = HttpContext.Request.Cookies["auth_token"];
            var principal = handler.ValidateToken(token, validationParams, out var securityToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=0}

        public void good_case_3()
        {
            bool validateLifetime = true;
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("your-secret-key")),
                ValidateIssuer = true,
                ValidIssuer = "issuer",
                // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                ValidateLifetime = validateLifetime
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = Request.Query["token"];
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=0}

        public void good_case_4()
        {
            var parameters = new TokenValidationParameters();
            parameters.ValidateIssuerSigningKey = true;
            parameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key"));
            parameters.ValidateIssuer = false;
            parameters.ValidateAudience = false;
            // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
            parameters.RequireExpirationTime = true;
            // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
            parameters.ValidateLifetime = true;
            
            var handler = new JwtSecurityTokenHandler();
            var token = Request.Headers["X-Auth-Token"];
            handler.ValidateToken(token, parameters, out var securityToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=0}

        public void good_case_5()
        {
            var validationParams = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("my-secret")),
                ValidateIssuer = true,
                ValidIssuer = "example-issuer",
                ValidateAudience = true,
                ValidAudience = "example-audience",
                // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                RequireExpirationTime = true,
                // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                ValidateLifetime = true
            };

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Form["token"];
            var principal = handler.ValidateToken(token, validationParams, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=0}

        public void good_case_6()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("secret-key")),
                ValidateIssuer = false,
                ValidateAudience = false,
                // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            var token = HttpContext.Session.GetString("JwtToken");
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=0}

        public void good_case_7()
        {
            var tokenValidationParameters = new TokenValidationParameters();
            tokenValidationParameters.ValidateIssuerSigningKey = true;
            tokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret"));
            tokenValidationParameters.ValidateIssuer = true;
            tokenValidationParameters.ValidIssuer = "issuer";
            tokenValidationParameters.ValidateAudience = true;
            tokenValidationParameters.ValidAudience = "audience";
            // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
            tokenValidationParameters.ValidateLifetime = true;
            tokenValidationParameters.ClockSkew = TimeSpan.Zero;

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Cookies["jwt"];
            var principal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=0}

        public void good_case_8()
        {
            bool shouldValidateLifetime = GetSecureValidationFlag();
            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key")),
                ValidateIssuer = true,
                ValidIssuer = "issuer",
                // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                ValidateLifetime = shouldValidateLifetime // Assume GetSecureValidationFlag returns true
            };

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            var principal = handler.ValidateToken(token, parameters, out var validatedToken);
        }
// {/fact}

        private bool GetSecureValidationFlag()
        {
            return true; // This is for demonstration purposes
        }
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=0}

        public void good_case_9()
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key")),
                ValidateIssuer = true,
                ValidIssuer = "issuer",
                ValidateAudience = true,
                ValidAudience = "audience",
                // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                RequireExpirationTime = true,
                // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Query["auth_token"];
            var principal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=0}

        public void good_case_10()
        {
            var parameters = new TokenValidationParameters();
            parameters.ValidateIssuerSigningKey = true;
            parameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key"));
            parameters.ValidateIssuer = true;
            parameters.ValidIssuer = "issuer";
            parameters.ValidateAudience = true;
            parameters.ValidAudience = "audience";
            // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
            parameters.ValidateLifetime = true;
            parameters.RequireExpirationTime = true;

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Headers["X-Token"];
            var principal = handler.ValidateToken(token, parameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=0}

        public void good_case_11()
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key")),
                ValidateIssuer = false,
                ValidateAudience = false,
                // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(10)
            };

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Form["access_token"];
            var principal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=0}

        public void good_case_12()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("your-secret-key");
            
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                RequireExpirationTime = true,
                // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                ValidateLifetime = true
            };

            var token = HttpContext.Request.Cookies["jwt_token"];
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=0}

        public void good_case_13()
        {
            var validationParams = new TokenValidationParameters();
            validationParams.ValidateIssuerSigningKey = true;
            validationParams.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key"));
            validationParams.ValidateIssuer = true;
            validationParams.ValidIssuer = "issuer";
            validationParams.ValidateAudience = true;
            validationParams.ValidAudience = "audience";
            validationParams.RequireSignedTokens = true;
            // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
            validationParams.ValidateLifetime = true;
            
            var handler = new JwtSecurityTokenHandler();
            var token = Request.Headers["Authorization"].ToString().Split(' ')[1];
            var principal = handler.ValidateToken(token, validationParams, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=0}

        public void good_case_14()
        {
            // Default value for ValidateLifetime is true, so not setting it explicitly is also secure
            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key")),
                ValidateIssuer = true,
                ValidIssuer = "issuer",
                ValidateAudience = true,
                ValidAudience = "audience",
                RequireSignedTokens = true,
                // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
                RequireExpirationTime = true
                // ValidateLifetime is true by default
            };

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Query["token"].ToString();
            var principal = handler.ValidateToken(token, parameters, out var validatedToken);
        }
// {/fact}
// {fact rule=jwt-tokenvalidationparameters-no-expiry-validation@v1.0 defects=0}

        public void good_case_15()
        {
            var tokenValidationParameters = new TokenValidationParameters();
            tokenValidationParameters.ValidateIssuerSigningKey = true;
            tokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-key"));
            tokenValidationParameters.ValidateIssuer = true;
            tokenValidationParameters.ValidIssuer = "issuer";
            tokenValidationParameters.ValidateAudience = true;
            tokenValidationParameters.ValidAudience = "audience";
            tokenValidationParameters.RequireSignedTokens = true;
            // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
            tokenValidationParameters.RequireExpirationTime = true;
            // ok: jwt-tokenvalidationparameters-no-expiry-csharp-rule
            tokenValidationParameters.ValidateLifetime = true;

            var handler = new JwtSecurityTokenHandler();
            var token = Request.Headers["X-Auth"].ToString();
            var principal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
// {/fact}
    }
}