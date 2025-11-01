using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace HSTSExamples
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }

    // True Positive Examples (Missing HSTS Header)

    public class bad_case_1
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            // ruleid: missing-hsts-header-csharp-rule
            services.AddMvc();
            // No HSTS configuration
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
            // Missing HSTS configuration
        }
    }

    public class bad_case_2
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: missing-hsts-header-csharp-rule
            services.AddControllersWithViews();
            // No security headers configured
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }

    public class bad_case_3
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: missing-hsts-header-csharp-rule
            services.AddRazorPages();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseStaticFiles();
            app.UseRouting();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
            });
            // HSTS is not configured
        }
    }

    public class bad_case_4
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: missing-hsts-header-csharp-rule
            services.AddMvc(options =>
            {
                options.EnableEndpointRouting = false;
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseAuthentication();
            app.UseMvc();
            // No HSTS middleware
        }
    }

    public class bad_case_5
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: missing-hsts-header-csharp-rule
            services.AddMvc();
            services.AddAuthentication();
            services.AddAuthorization();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
            // Missing HSTS
        }
    }

    public class bad_case_6
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: missing-hsts-header-csharp-rule
            services.AddControllers();
            services.AddCors();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            app.UseCors(policy => policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
            // HSTS not implemented
        }
    }

    public class bad_case_7
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: missing-hsts-header-csharp-rule
            services.AddMvc();
            services.AddHealthChecks();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapHealthChecks("/health");
                endpoints.MapControllers();
            });
            // No HSTS configuration
        }
    }

    public class bad_case_8
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: missing-hsts-header-csharp-rule
            services.AddControllersWithViews();
            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(30);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            app.UseSession();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
            // Missing HSTS header
        }
    }

    public class bad_case_9
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: missing-hsts-header-csharp-rule
            services.AddControllers();
            services.AddResponseCompression();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseResponseCompression();
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
            // HSTS not configured
        }
    }

    public class bad_case_10
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: missing-hsts-header-csharp-rule
            services.AddMvc();
            services.AddResponseCaching();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseResponseCaching();
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
            // No HSTS header configuration
        }
    }

    public class bad_case_11
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: missing-hsts-header-csharp-rule
            services.AddMvc();
            services.AddSignalR();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapHub<ChatHub>("/chatHub");
                endpoints.MapControllers();
            });
            // HSTS not implemented
        }
    }

    public class ChatHub
    {
        // Dummy SignalR hub
    }

    public class bad_case_12
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: missing-hsts-header-csharp-rule
            services.AddControllers();
            // Using custom middleware but no HSTS
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            app.UseMiddleware<CustomSecurityMiddleware>();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
            // Missing HSTS configuration
        }
    }

    public class CustomSecurityMiddleware
    {
        // Dummy middleware
        private readonly RequestDelegate _next;

        public CustomSecurityMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
            context.Response.Headers.Add("X-Frame-Options", "DENY");
            // Missing HSTS header
            await _next(context);
        }
    }

    public class bad_case_13
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: missing-hsts-header-csharp-rule
            services.AddMvc();
            services.Configure<CookiePolicyOptions>(options =>
            {
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.Strict;
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            app.UseCookiePolicy();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
            // No HSTS configuration
        }
    }

    public class bad_case_14
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: missing-hsts-header-csharp-rule
            services.AddMvc();
            // Adding some security headers but not HSTS
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.Use(async (context, next) =>
            {
                context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
                context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
                // Missing HSTS header
                await next();
            });
            
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

    public class bad_case_15
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: missing-hsts-header-csharp-rule
            services.AddMvc();
            services.AddHttpsRedirection(options =>
            {
                options.RedirectStatusCode = StatusCodes.Status307TemporaryRedirect;
                options.HttpsPort = 5001;
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseHttpsRedirection();
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
            // HTTPS redirection is configured but HSTS is missing
        }
    }

    // True Negative Examples (HSTS Header Properly Configured)

    public class good_case_1
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            // ok: missing-hsts-header-csharp-rule
            services.AddHsts(options =>
            {
                options.Preload = true;
                options.IncludeSubDomains = true;
                options.MaxAge = TimeSpan.FromDays(365);
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseHsts();
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

    public class good_case_2
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            // ok: missing-hsts-header-csharp-rule
            services.AddHsts();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (!env.IsDevelopment())
            {
                app.UseHsts();
            }
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }

    public class good_case_3
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddRazorPages();
            // ok: missing-hsts-header-csharp-rule
            services.AddHsts(options =>
            {
                options.MaxAge = TimeSpan.FromDays(180);
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (!env.IsDevelopment())
            {
                app.UseHsts();
            }
            app.UseStaticFiles();
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
            });
        }
    }

    public class good_case_4
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            // ok: missing-hsts-header-csharp-rule
            services.AddHsts(options =>
            {
                options.MaxAge = TimeSpan.FromDays(365);
                options.IncludeSubDomains = true;
                options.ExcludedHosts.Add("example.com");
                options.ExcludedHosts.Add("www.example.com");
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseHsts();
            app.UseHttpsRedirection();
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

    public class good_case_5
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            // ok: missing-hsts-header-csharp-rule
            services.AddHsts(options =>
            {
                options.Preload = true;
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (!env.IsDevelopment())
            {
                app.UseHsts();
                app.UseHttpsRedirection();
            }
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

    public class good_case_6
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            // ok: missing-hsts-header-csharp-rule
            services.AddHsts();
            services.AddCors();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseHsts();
            app.UseRouting();
            app.UseCors(policy => policy.WithOrigins("https://example.com").AllowAnyMethod().AllowAnyHeader());
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

    public class good_case_7
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            // ok: missing-hsts-header-csharp-rule
            services.AddHsts(options =>
            {
                options.MaxAge = TimeSpan.FromDays(730); // 2 years
                options.IncludeSubDomains = true;
                options.Preload = true;
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsProduction())
            {
                app.UseHsts();
            }
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

    public class good_case_8
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            services.AddSession();
            // ok: missing-hsts-header-csharp-rule
            services.AddHsts();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseHsts();
            app.UseHttpsRedirection();
            app.UseSession();
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

    public class good_case_9
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.AddResponseCompression();
            // ok: missing-hsts-header-csharp-rule
            services.AddHsts(options =>
            {
                options.MaxAge = TimeSpan.FromDays(90);
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseResponseCompression();
            app.UseHsts();
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

    public class good_case_10
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            // ok: missing-hsts-header-csharp-rule
            services.AddHsts();
            services.AddResponseCaching();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (!env.IsDevelopment())
            {
                app.UseHsts();
            }
            app.UseResponseCaching();
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

    public class good_case_11
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            services.AddSignalR();
            // ok: missing-hsts-header-csharp-rule
            services.AddHsts(options =>
            {
                options.MaxAge = TimeSpan.FromDays(365);
                options.IncludeSubDomains = true;
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseHsts();
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapHub<SecureChatHub>("/secureChatHub");
                endpoints.MapControllers();
            });
        }
    }

    public class SecureChatHub
    {
        // Dummy SignalR hub
    }

    public class good_case_12
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            // ok: missing-hsts-header-csharp-rule
            services.AddHsts(options =>
            {
                options.MaxAge = TimeSpan.FromDays(365);
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseHsts();
            app.UseRouting();
            app.UseMiddleware<EnhancedSecurityMiddleware>();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

    public class EnhancedSecurityMiddleware
    {
        // Dummy middleware with additional security headers
        private readonly RequestDelegate _next;

        public EnhancedSecurityMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
            context.Response.Headers.Add("X-Frame-Options", "DENY");
            await _next(context);
        }
    }

    public class good_case_13
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            // ok: missing-hsts-header-csharp-rule
            services.AddHsts();
            services.Configure<CookiePolicyOptions>(options =>
            {
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.Strict;
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseHsts();
            app.UseRouting();
            app.UseCookiePolicy();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

    public class good_case_14
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            // ok: missing-hsts-header-csharp-rule
            services.AddHsts(options =>
            {
                options.MaxAge = TimeSpan.FromDays(365);
                options.IncludeSubDomains = true;
                options.Preload = true;
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.Use(async (context, next) =>
            {
                context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
                context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
                await next();
            });
            
            app.UseHsts();
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

    public class good_case_15
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            // ok: missing-hsts-header-csharp-rule
            services.AddHsts(options =>
            {
                options.MaxAge = TimeSpan.FromDays(180);
            });
            services.AddHttpsRedirection(options =>
            {
                options.RedirectStatusCode = StatusCodes.Status307TemporaryRedirect;
                options.HttpsPort = 5001;
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseHsts();
            app.UseHttpsRedirection();
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}