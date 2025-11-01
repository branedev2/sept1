using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Threading.Tasks;

namespace MisconfiguredLockoutOptionExamples
{
    public class ApplicationUser : IdentityUser { }
    
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options) { }
    }

    // True Positive Examples (Vulnerable Code)

    public class BadCase1
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer("connection_string"));

            // ruleid: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.LockoutOnFailure = false;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }

    public class BadCase2
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: misconfigured-lockout-option-csharp-rule
            services.Configure<IdentityOptions>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = false;
            });
        }
    }

    public class BadCase3
    {
        public void ConfigureServices(IServiceCollection services)
        {
            var lockoutTimeSpan = TimeSpan.FromMinutes(10);
            var maxAttempts = 5;
            
            // ruleid: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();
                
            services.Configure<IdentityOptions>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = lockoutTimeSpan;
                options.Lockout.MaxFailedAccessAttempts = maxAttempts;
                options.Lockout.LockoutOnFailure = false;
            });
        }
    }

    public class BadCase4
    {
        public void ConfigureServices(IServiceCollection services, IConfiguration configuration)
        {
            // ruleid: misconfigured-lockout-option-csharp-rule
            var identityBuilder = services.AddIdentityCore<ApplicationUser>(options =>
            {
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 8;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromDays(1);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.LockoutOnFailure = false;
            });
            
            identityBuilder.AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }

    public class BadCase5
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();
                
            services.Configure<IdentityOptions>(options =>
            {
                // Password settings
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 8;
                
                // Lockout settings
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = false;
            });
        }
    }

    public class BadCase6
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: misconfigured-lockout-option-csharp-rule
            var lockoutOptions = new LockoutOptions
            {
                AllowedForNewUsers = true,
                DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10),
                MaxFailedAccessAttempts = 5,
                LockoutOnFailure = false
            };
            
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Lockout = lockoutOptions;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }

    public class BadCase7
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();
                
            var lockoutOnFailure = false;
            
            services.Configure<IdentityOptions>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(20);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = lockoutOnFailure;
            });
        }
    }

    public class BadCase8
    {
        public void ConfigureServices(IServiceCollection services, IConfiguration configuration)
        {
            // ruleid: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                configuration.GetSection("IdentityOptions:Password").Bind(options.Password);
                
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = false;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }

    public class BadCase9
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();
                
            ConfigureLockoutOptions(services);
        }
        
        private void ConfigureLockoutOptions(IServiceCollection services)
        {
            services.Configure<IdentityOptions>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = false;
            });
        }
    }

    public class BadCase10
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: misconfigured-lockout-option-csharp-rule
            services.AddDefaultIdentity<ApplicationUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = true;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = false;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }

    public class BadCase11
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                // Disable lockout for development environment
                if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
                {
                    options.Lockout.LockoutOnFailure = false;
                }
                else
                {
                    options.Lockout.LockoutOnFailure = false; // Still false in production!
                }
                
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }

    public class BadCase12
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();
                
            services.PostConfigure<IdentityOptions>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = false;
            });
        }
    }

    public class BadCase13
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: misconfigured-lockout-option-csharp-rule
            var lockoutOptions = new IdentityOptions();
            lockoutOptions.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
            lockoutOptions.Lockout.MaxFailedAccessAttempts = 5;
            lockoutOptions.Lockout.AllowedForNewUsers = true;
            lockoutOptions.Lockout.LockoutOnFailure = false;
            
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Lockout = lockoutOptions.Lockout;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }

    public class BadCase14
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ruleid: misconfigured-lockout-option-csharp-rule
            bool enableLockout = false;
            
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = enableLockout;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }

    public class BadCase15
    {
        public void ConfigureServices(IServiceCollection services, IConfiguration configuration)
        {
            // ruleid: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();
                
            services.Configure<IdentityOptions>(options =>
            {
                configuration.GetSection("Identity:Password").Bind(options.Password);
                configuration.GetSection("Identity:SignIn").Bind(options.SignIn);
                
                // Manually configure lockout with lockoutOnFailure set to false
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = false;
            });
        }
    }

    // True Negative Examples (Secure Code)

    public class GoodCase1
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer("connection_string"));

            // ok: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.LockoutOnFailure = true;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }

    public class GoodCase2
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ok: misconfigured-lockout-option-csharp-rule
            services.Configure<IdentityOptions>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = true;
            });
        }
    }

    public class GoodCase3
    {
        public void ConfigureServices(IServiceCollection services)
        {
            var lockoutTimeSpan = TimeSpan.FromMinutes(10);
            var maxAttempts = 5;
            
            // ok: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();
                
            services.Configure<IdentityOptions>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = lockoutTimeSpan;
                options.Lockout.MaxFailedAccessAttempts = maxAttempts;
                options.Lockout.LockoutOnFailure = true;
            });
        }
    }

    public class GoodCase4
    {
        public void ConfigureServices(IServiceCollection services, IConfiguration configuration)
        {
            // ok: misconfigured-lockout-option-csharp-rule
            var identityBuilder = services.AddIdentityCore<ApplicationUser>(options =>
            {
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 8;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromDays(1);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.LockoutOnFailure = true;
            });
            
            identityBuilder.AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }

    public class GoodCase5
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ok: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();
                
            services.Configure<IdentityOptions>(options =>
            {
                // Password settings
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 8;
                
                // Lockout settings
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = true;
            });
        }
    }

    public class GoodCase6
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ok: misconfigured-lockout-option-csharp-rule
            var lockoutOptions = new LockoutOptions
            {
                AllowedForNewUsers = true,
                DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10),
                MaxFailedAccessAttempts = 5,
                LockoutOnFailure = true
            };
            
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Lockout = lockoutOptions;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }

    public class GoodCase7
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ok: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();
                
            var lockoutOnFailure = true;
            
            services.Configure<IdentityOptions>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(20);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = lockoutOnFailure;
            });
        }
    }

    public class GoodCase8
    {
        public void ConfigureServices(IServiceCollection services, IConfiguration configuration)
        {
            // ok: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                configuration.GetSection("IdentityOptions:Password").Bind(options.Password);
                
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = true;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }

    public class GoodCase9
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ok: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();
                
            ConfigureLockoutOptions(services);
        }
        
        private void ConfigureLockoutOptions(IServiceCollection services)
        {
            services.Configure<IdentityOptions>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = true;
            });
        }
    }

    public class GoodCase10
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ok: misconfigured-lockout-option-csharp-rule
            services.AddDefaultIdentity<ApplicationUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = true;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = true;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }

    public class GoodCase11
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ok: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                // Enable lockout for all environments
                if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
                {
                    options.Lockout.LockoutOnFailure = true;
                }
                else
                {
                    options.Lockout.LockoutOnFailure = true;
                }
                
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }

    public class GoodCase12
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ok: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();
                
            services.PostConfigure<IdentityOptions>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = true;
            });
        }
    }

    public class GoodCase13
    {
        public void ConfigureServices(IServiceCollection services, IConfiguration configuration)
        {
            // ok: misconfigured-lockout-option-csharp-rule
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();
                
            services.Configure<IdentityOptions>(options =>
            {
                // Load from configuration
                var lockoutSection = configuration.GetSection("Identity:Lockout");
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(lockoutSection.GetValue<int>("LockoutMinutes"));
                options.Lockout.MaxFailedAccessAttempts = lockoutSection.GetValue<int>("MaxAttempts");
                options.Lockout.AllowedForNewUsers = lockoutSection.GetValue<bool>("AllowedForNewUsers");
                options.Lockout.LockoutOnFailure = true; // Explicitly set to true for security
            });
        }
    }

    public class GoodCase14
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ok: misconfigured-lockout-option-csharp-rule
            bool enableLockout = true;
            
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.LockoutOnFailure = enableLockout;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }

    public class GoodCase15
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // ok: misconfigured-lockout-option-csharp-rule
            var lockoutOptions = new IdentityOptions();
            lockoutOptions.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
            lockoutOptions.Lockout.MaxFailedAccessAttempts = 5;
            lockoutOptions.Lockout.AllowedForNewUsers = true;
            lockoutOptions.Lockout.LockoutOnFailure = true;
            
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Lockout = lockoutOptions.Lockout;
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 12;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = true;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();
        }
    }
}