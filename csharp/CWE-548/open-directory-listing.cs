using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using System.IO;

namespace DirectoryListingExamples
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            var app = builder.Build();
            
            // Examples will be in separate methods below
            
            app.Run();
        }
// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
        
        // True Positive Examples (Vulnerable Code)
        
        public static void bad_case_1(WebApplication app)
        {
            // ruleid: open-directory-listing
            app.UseDirectoryBrowser();
            app.UseStaticFiles();
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
        
        public static void bad_case_2(WebApplication app)
        {
            // ruleid: open-directory-listing
            app.UseFileServer(enableDirectoryBrowsing: true);
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
        
        public static void bad_case_3(WebApplication app)
        {
            var options = new FileServerOptions
            {
                EnableDirectoryBrowsing = true
            };
            
            // ruleid: open-directory-listing
            app.UseFileServer(options);
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
        
        public static void bad_case_4(WebApplication app)
        {
            // ruleid: open-directory-listing
            app.UseDirectoryBrowser(new DirectoryBrowserOptions
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "wwwroot")),
                RequestPath = "/files"
            });
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
        
        public static void bad_case_5(WebApplication app)
        {
            var fileServerOptions = new FileServerOptions();
            fileServerOptions.EnableDirectoryBrowsing = true;
            
            // ruleid: open-directory-listing
            app.UseFileServer(fileServerOptions);
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
        
        public static void bad_case_6(WebApplication app)
        {
            // ruleid: open-directory-listing
            app.UseDirectoryBrowser(new DirectoryBrowserOptions
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "sensitive_data")),
                RequestPath = "/browse"
            });
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
        
        public static void bad_case_7(WebApplication app)
        {
            var options = new DirectoryBrowserOptions();
            options.FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "wwwroot"));
            options.RequestPath = "/browse";
            
            // ruleid: open-directory-listing
            app.UseDirectoryBrowser(options);
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
        
        public static void bad_case_8(WebApplication app)
        {
            // ruleid: open-directory-listing
            app.UseFileServer(new FileServerOptions
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "images")),
                RequestPath = "/images",
                EnableDirectoryBrowsing = true
            });
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
        
        public static void bad_case_9(WebApplication app)
        {
            var dirBrowserOptions = new DirectoryBrowserOptions();
            dirBrowserOptions.FileProvider = new PhysicalFileProvider(
                Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "documents"));
            dirBrowserOptions.RequestPath = "/docs";
            
            // ruleid: open-directory-listing
            app.UseDirectoryBrowser(dirBrowserOptions);
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
        
        public static void bad_case_10(WebApplication app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                // ruleid: open-directory-listing
                app.UseDirectoryBrowser();
            }
            
            app.UseStaticFiles();
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
        
        public static void bad_case_11(WebApplication app)
        {
            var enableBrowsing = true;
            
            // ruleid: open-directory-listing
            app.UseFileServer(new FileServerOptions
            {
                EnableDirectoryBrowsing = enableBrowsing
            });
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
        
        public static void bad_case_12(WebApplication app)
        {
            // Multiple directory browsing configurations
            // ruleid: open-directory-listing
            app.UseDirectoryBrowser(new DirectoryBrowserOptions
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "images")),
                RequestPath = "/img"
            });
            
            // ruleid: open-directory-listing
            app.UseDirectoryBrowser(new DirectoryBrowserOptions
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "docs")),
                RequestPath = "/documents"
            });
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
        
        public static void bad_case_13(WebApplication app)
        {
            var options = new FileServerOptions();
            options.FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "wwwroot"));
            options.RequestPath = "/static";
            options.EnableDirectoryBrowsing = true;
            
            // ruleid: open-directory-listing
            app.UseFileServer(options);
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
        
        public static void bad_case_14(WebApplication app)
        {
            // ruleid: open-directory-listing
            app.UseFileServer(new FileServerOptions
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "logs")),
                RequestPath = "/logs",
                EnableDirectoryBrowsing = true
            });
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
        
        public static void bad_case_15(WebApplication app, IWebHostEnvironment env)
        {
            if (!env.IsProduction())
            {
                var options = new FileServerOptions
                {
                    EnableDirectoryBrowsing = true
                };
                
                // ruleid: open-directory-listing
                app.UseFileServer(options);
            }
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
        
        // True Negative Examples (Secure Code)
        
        public static void good_case_1(WebApplication app)
        {
            // ok: open-directory-listing
            app.UseStaticFiles();
            // Directory browsing is not enabled
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
        
        public static void good_case_2(WebApplication app)
        {
            // ok: open-directory-listing
            app.UseFileServer(enableDirectoryBrowsing: false);
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
        
        public static void good_case_3(WebApplication app)
        {
            var options = new FileServerOptions
            {
                EnableDirectoryBrowsing = false
            };
            
            // ok: open-directory-listing
            app.UseFileServer(options);
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
        
        public static void good_case_4(WebApplication app)
        {
            // ok: open-directory-listing
            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "wwwroot")),
                RequestPath = "/files"
            });
            // No directory browsing enabled
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
        
        public static void good_case_5(WebApplication app)
        {
            var fileServerOptions = new FileServerOptions();
            fileServerOptions.EnableDirectoryBrowsing = false;
            
            // ok: open-directory-listing
            app.UseFileServer(fileServerOptions);
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
        
        public static void good_case_6(WebApplication app)
        {
            // ok: open-directory-listing
            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "sensitive_data")),
                RequestPath = "/data"
            });
            // No directory browsing enabled
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
        
        public static void good_case_7(WebApplication app)
        {
            // ok: open-directory-listing
            app.UseFileServer(); // Default is directory browsing disabled
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
        
        public static void good_case_8(WebApplication app)
        {
            // ok: open-directory-listing
            app.UseFileServer(new FileServerOptions
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "images")),
                RequestPath = "/images",
                EnableDirectoryBrowsing = false
            });
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
        
        public static void good_case_9(WebApplication app)
        {
            // Using custom middleware to serve specific files instead of directory browsing
            // ok: open-directory-listing
            app.MapGet("/files", (HttpContext context) => {
                // Custom logic to serve specific files
                return Task.CompletedTask;
            });
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
        
        public static void good_case_10(WebApplication app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                // ok: open-directory-listing
                app.UseStaticFiles(); // No directory browsing
            }
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
        
        public static void good_case_11(WebApplication app)
        {
            // ok: open-directory-listing
            app.UseFileServer(new FileServerOptions
            {
                EnableDirectoryBrowsing = false,
                EnableDefaultFiles = true
            });
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
        
        public static void good_case_12(WebApplication app)
        {
            // ok: open-directory-listing
            app.UseDefaultFiles(); // Serves default files like index.html
            app.UseStaticFiles(); // Serves static files but doesn't enable directory browsing
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
        
        public static void good_case_13(WebApplication app)
        {
            // Explicitly disable directory browsing
            var options = new FileServerOptions
            {
                EnableDirectoryBrowsing = false,
                EnableDefaultFiles = true,
                DefaultFilesOptions = { DefaultFileNames = { "index.html" } }
            };
            
            // ok: open-directory-listing
            app.UseFileServer(options);
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
        
        public static void good_case_14(WebApplication app)
        {
            // ok: open-directory-listing
            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "wwwroot")),
                ServeUnknownFileTypes = false // Don't serve unknown file types
            });
        }
// {/fact}
// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
        
        public static void good_case_15(WebApplication app, IWebHostEnvironment env)
        {
            if (env.IsProduction())
            {
                // ok: open-directory-listing
                app.UseFileServer(new FileServerOptions
                {
                    EnableDirectoryBrowsing = false
                });
            }
            else
            {
                // Development environment with restricted directory browsing
                // ok: open-directory-listing
                app.UseFileServer(new FileServerOptions
                {
                    FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "public")),
                    RequestPath = "/public",
                    EnableDirectoryBrowsing = false
                });
            }
        }
// {/fact}
    }
}