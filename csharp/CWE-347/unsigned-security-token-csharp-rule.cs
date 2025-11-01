using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.WsFederation;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace SecurityTokenExamples
{
    public class TokenValidationExamples
    {
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public void bad_case_1()
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                // ruleid: unsigned-security-token-csharp-rule
                RequireSignedTokens = false,
                ValidIssuer = "https://example.com",
                ValidAudience = "myApp"
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.ValidateToken("some-token", tokenValidationParameters, out _);
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}

        public void bad_case_2(IServiceCollection services)
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        // ruleid: unsigned-security-token-csharp-rule
                        RequireSignedTokens = false,
                        ValidIssuer = "https://issuer.example.com",
                        ValidAudience = "api"
                    };
                });
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}

        public void bad_case_3()
        {
            var parameters = new TokenValidationParameters();
            parameters.ValidateIssuer = true;
            parameters.ValidateAudience = true;
            parameters.ValidateLifetime = true;
            // ruleid: unsigned-security-token-csharp-rule
            parameters.RequireSignedTokens = false;
            parameters.ValidIssuer = "https://auth.example.org";
            parameters.ValidAudience = "myService";

            var handler = new JwtSecurityTokenHandler();
            handler.ValidateToken("jwt-token", parameters, out _);
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}

        public void bad_case_4(IServiceCollection services, IConfiguration configuration)
        {
            bool requireSigning = false;
            
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    // ruleid: unsigned-security-token-csharp-rule
                    RequireSignedTokens = requireSigning,
                    ValidateIssuer = true,
                    ValidIssuer = configuration["Jwt:Issuer"],
                    ValidateAudience = true,
                    ValidAudience = configuration["Jwt:Audience"]
                };
            });
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}

        public void bad_case_5()
        {
            var tvp = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                // ruleid: unsigned-security-token-csharp-rule
                RequireSignedTokens = false
            };

            var handler = new JwtSecurityTokenHandler();
            SecurityToken validatedToken;
            handler.ValidateToken("token-string", tvp, out validatedToken);
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}

        public void bad_case_6(IServiceCollection services)
        {
            var tokenParams = new TokenValidationParameters();
            tokenParams.ValidateIssuer = true;
            tokenParams.ValidateAudience = true;
            // ruleid: unsigned-security-token-csharp-rule
            tokenParams.RequireSignedTokens = false;

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = tokenParams;
                });
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}

        public void bad_case_7()
        {
            var config = new SecurityTokenHandlerConfiguration();
            // ruleid: unsigned-security-token-csharp-rule
            config.RequireSignedTokens = false;
            
            var handler = new JwtSecurityTokenHandler();
            handler.Configuration = config;
            handler.ValidateToken("token-value");
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}

        public void bad_case_8(IServiceCollection services)
        {
            services.AddAuthentication(WsFederationDefaults.AuthenticationScheme)
                .AddWsFederation(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        // ruleid: unsigned-security-token-csharp-rule
                        RequireSignedTokens = false,
                        ValidateIssuer = true,
                        ValidIssuer = "https://adfs.example.com"
                    };
                });
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}

        public void bad_case_9(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddOpenIdConnect(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    // ruleid: unsigned-security-token-csharp-rule
                    RequireSignedTokens = false,
                    ValidateIssuer = true
                };
            });
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}

        public void bad_case_10()
        {
            var parameters = new TokenValidationParameters();
            
            if (IsTestEnvironment())
            {
                // ruleid: unsigned-security-token-csharp-rule
                parameters.RequireSignedTokens = false;
            }
            else
            {
                parameters.RequireSignedTokens = true;
            }
            
            var handler = new JwtSecurityTokenHandler();
            handler.ValidateToken("token", parameters, out _);
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}

        public void bad_case_11(IServiceCollection services)
        {
            var tokenValidationParams = GetTokenValidationParameters();
            
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = tokenValidationParams;
                });
        }
// {/fact}
        
        private TokenValidationParameters GetTokenValidationParameters()
        {
            return new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                // ruleid: unsigned-security-token-csharp-rule
                RequireSignedTokens = false,
                ValidIssuer = "https://issuer.example.com"
            };
        }
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}

        public void bad_case_12(IApplicationBuilder app)
        {
            app.UseJwtBearerAuthentication(new JwtBearerOptions
            {
                TokenValidationParameters = new TokenValidationParameters
                {
                    // ruleid: unsigned-security-token-csharp-rule
                    RequireSignedTokens = false,
                    ValidateIssuer = true,
                    ValidateAudience = true
                }
            });
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}

        public void bad_case_13()
        {
            var handler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters();
            
            // Disable signature validation for development
            if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
            {
                // ruleid: unsigned-security-token-csharp-rule
                validationParameters.RequireSignedTokens = false;
            }
            
            handler.ValidateToken("token-string", validationParameters, out _);
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}

        public void bad_case_14(IServiceCollection services)
        {
            bool isProduction = false; // For testing purposes
            
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    var tokenParams = new TokenValidationParameters();
                    
                    if (!isProduction)
                    {
                        // ruleid: unsigned-security-token-csharp-rule
                        tokenParams.RequireSignedTokens = false;
                    }
                    
                    options.TokenValidationParameters = tokenParams;
                });
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}

        public void bad_case_15()
        {
            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = false,
                // ruleid: unsigned-security-token-csharp-rule
                RequireSignedTokens = false
            };
            
            var tokenHandler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal = tokenHandler.ValidateToken("token", parameters, out _);
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        public void good_case_1()
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                // ok: unsigned-security-token-csharp-rule
                RequireSignedTokens = true,
                ValidIssuer = "https://example.com",
                ValidAudience = "myApp"
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.ValidateToken("some-token", tokenValidationParameters, out _);
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}

        public void good_case_2(IServiceCollection services)
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        // ok: unsigned-security-token-csharp-rule
                        RequireSignedTokens = true,
                        ValidIssuer = "https://issuer.example.com",
                        ValidAudience = "api"
                    };
                });
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}

        public void good_case_3()
        {
            var parameters = new TokenValidationParameters();
            parameters.ValidateIssuer = true;
            parameters.ValidateAudience = true;
            parameters.ValidateLifetime = true;
            // ok: unsigned-security-token-csharp-rule
            parameters.RequireSignedTokens = true;
            parameters.ValidIssuer = "https://auth.example.org";
            parameters.ValidAudience = "myService";

            var handler = new JwtSecurityTokenHandler();
            handler.ValidateToken("jwt-token", parameters, out _);
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}

        public void good_case_4(IServiceCollection services, IConfiguration configuration)
        {
            bool requireSigning = true;
            
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    // ok: unsigned-security-token-csharp-rule
                    RequireSignedTokens = requireSigning,
                    ValidateIssuer = true,
                    ValidIssuer = configuration["Jwt:Issuer"],
                    ValidateAudience = true,
                    ValidAudience = configuration["Jwt:Audience"]
                };
            });
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}

        public void good_case_5()
        {
            var tvp = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                // Default value is true, so not setting it explicitly is also secure
                // ok: unsigned-security-token-csharp-rule
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secure-signing-key"))
            };

            var handler = new JwtSecurityTokenHandler();
            SecurityToken validatedToken;
            handler.ValidateToken("token-string", tvp, out validatedToken);
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}

        public void good_case_6(IServiceCollection services)
        {
            var tokenParams = new TokenValidationParameters();
            tokenParams.ValidateIssuer = true;
            tokenParams.ValidateAudience = true;
            // ok: unsigned-security-token-csharp-rule
            tokenParams.RequireSignedTokens = true;

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = tokenParams;
                });
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}

        public void good_case_7()
        {
            var config = new SecurityTokenHandlerConfiguration();
            // ok: unsigned-security-token-csharp-rule
            config.RequireSignedTokens = true;
            
            var handler = new JwtSecurityTokenHandler();
            handler.Configuration = config;
            handler.ValidateToken("token-value");
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}

        public void good_case_8(IServiceCollection services)
        {
            services.AddAuthentication(WsFederationDefaults.AuthenticationScheme)
                .AddWsFederation(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        // ok: unsigned-security-token-csharp-rule
                        RequireSignedTokens = true,
                        ValidateIssuer = true,
                        ValidIssuer = "https://adfs.example.com"
                    };
                });
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}

        public void good_case_9(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddOpenIdConnect(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    // ok: unsigned-security-token-csharp-rule
                    RequireSignedTokens = true,
                    ValidateIssuer = true
                };
            });
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}

        public void good_case_10()
        {
            var parameters = new TokenValidationParameters();
            
            // Always require signed tokens, regardless of environment
            // ok: unsigned-security-token-csharp-rule
            parameters.RequireSignedTokens = true;
            
            var handler = new JwtSecurityTokenHandler();
            handler.ValidateToken("token", parameters, out _);
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}

        public void good_case_11(IServiceCollection services)
        {
            var tokenValidationParams = GetSecureTokenValidationParameters();
            
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = tokenValidationParams;
                });
        }
// {/fact}
        
        private TokenValidationParameters GetSecureTokenValidationParameters()
        {
            return new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                // ok: unsigned-security-token-csharp-rule
                RequireSignedTokens = true,
                ValidIssuer = "https://issuer.example.com"
            };
        }
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}

        public void good_case_12(IApplicationBuilder app)
        {
            app.UseJwtBearerAuthentication(new JwtBearerOptions
            {
                TokenValidationParameters = new TokenValidationParameters
                {
                    // ok: unsigned-security-token-csharp-rule
                    RequireSignedTokens = true,
                    ValidateIssuer = true,
                    ValidateAudience = true
                }
            });
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}

        public void good_case_13()
        {
            var handler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters();
            
            // Always require signed tokens, even in development
            // ok: unsigned-security-token-csharp-rule
            validationParameters.RequireSignedTokens = true;
            
            handler.ValidateToken("token-string", validationParameters, out _);
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}

        public void good_case_14(IServiceCollection services)
        {
            bool isProduction = false; // For testing purposes
            
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    var tokenParams = new TokenValidationParameters();
                    
                    // Always require signed tokens regardless of environment
                    // ok: unsigned-security-token-csharp-rule
                    tokenParams.RequireSignedTokens = true;
                    
                    options.TokenValidationParameters = tokenParams;
                });
        }
// {/fact}
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}

        public void good_case_15()
        {
            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                // ok: unsigned-security-token-csharp-rule
                RequireSignedTokens = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secure-signing-key"))
            };
            
            var tokenHandler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal = tokenHandler.ValidateToken("token", parameters, out _);
        }
// {/fact}

        // Helper method for bad_case_10 and good_case_10
        private bool IsTestEnvironment()
        {
            return true; // Simplified for example purposes
        }
    }
}