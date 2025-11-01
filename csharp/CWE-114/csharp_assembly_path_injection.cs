using System;
using System.IO;
using System.Reflection;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Net.Http;
using System.Threading.Tasks;

namespace AssemblyPathInjectionExamples
{
    public class AssemblyPathInjectionController : Controller
    {
// {fact rule=assembly-path-injection@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public ActionResult bad_case_1()
        {
            // Get user input directly from query string
            string assemblyPath = Request.QueryString["path"];
            
            // ruleid: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFile(assemblyPath);
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=1}

        public ActionResult bad_case_2()
        {
            // Get user input from form
            string pluginName = Request.Form["plugin"];
            string assemblyPath = $"C:\\plugins\\{pluginName}.dll";
            
            // ruleid: csharp_assembly_path_injection
            Assembly assembly = Assembly.Load(File.ReadAllBytes(assemblyPath));
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=1}

        public ActionResult bad_case_3()
        {
            // Get user input from route parameter
            string moduleName = RouteData.Values["module"] as string;
            string fullPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "modules", moduleName);
            
            // ruleid: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFrom(fullPath);
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=1}

        public ActionResult bad_case_4()
        {
            // Get user input from cookie
            string extensionName = Request.Cookies["preferredExtension"]?.Value;
            string extensionPath = $"/var/extensions/{extensionName}";
            
            try
            {
                // ruleid: csharp_assembly_path_injection
                Assembly assembly = Assembly.UnsafeLoadFrom(extensionPath);
                return View("Result", assembly.GetName().Name);
            }
            catch (Exception ex)
            {
                return View("Error", ex.Message);
            }
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=1}

        public ActionResult bad_case_5()
        {
            // Get user input from header
            string pluginId = Request.Headers["X-Plugin-Id"];
            string pluginPath = Path.Combine(Server.MapPath("~/bin/plugins"), pluginId + ".dll");
            
            // ruleid: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFile(pluginPath);
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=1}

        [Microsoft.AspNetCore.Mvc.HttpPost]
        public IActionResult bad_case_6([FromBody] dynamic payload)
        {
            string modulePath = payload.modulePath;
            
            // ruleid: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFile(modulePath);
            
            return Ok(new { AssemblyName = assembly.GetName().Name });
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=1}

        public ActionResult bad_case_7()
        {
            // Get user input from query string and do minimal transformation
            string assemblyName = Request.QueryString["name"];
            string assemblyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), 
                                              "Plugins", assemblyName);
            
            // ruleid: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFrom(assemblyPath);
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=1}

        public async Task<ActionResult> bad_case_8()
        {
            // Get user input from an API call
            using (var client = new HttpClient())
            {
                string pluginInfo = await client.GetStringAsync("https://example.com/api/plugins");
                dynamic pluginData = Newtonsoft.Json.JsonConvert.DeserializeObject(pluginInfo);
                string pluginPath = pluginData.path;
                
                // ruleid: csharp_assembly_path_injection
                Assembly assembly = Assembly.LoadFile(pluginPath);
                
                return View("Result", assembly.GetName().Name);
            }
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=1}

        public ActionResult bad_case_9()
        {
            // Get user input from multiple sources and concatenate
            string vendor = Request.QueryString["vendor"];
            string version = Request.Form["version"];
            string assemblyPath = $"/opt/modules/{vendor}/{version}/module.dll";
            
            // ruleid: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFrom(assemblyPath);
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=1}

        public ActionResult bad_case_10(IFormCollection form)
        {
            // Get user input from ASP.NET Core form
            string moduleName = form["moduleName"];
            string moduleVersion = form["moduleVersion"];
            string assemblyPath = $"./modules/{moduleName}-{moduleVersion}.dll";
            
            // ruleid: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFile(Path.GetFullPath(assemblyPath));
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=1}

        [Microsoft.AspNetCore.Mvc.HttpGet]
        public IActionResult bad_case_11([FromQuery] string pluginId)
        {
            // Get user input from query parameter in ASP.NET Core
            string pluginPath = Path.Combine(Directory.GetCurrentDirectory(), "plugins", pluginId + ".dll");
            
            // ruleid: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFrom(pluginPath);
            
            return Ok(new { Name = assembly.GetName().Name });
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=1}

        public ActionResult bad_case_12()
        {
            // Get user input from URL fragment
            string fragment = Request.Url.Fragment;
            if (fragment.StartsWith("#"))
            {
                fragment = fragment.Substring(1);
            }
            string assemblyPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, fragment);
            
            // ruleid: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFile(assemblyPath);
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=1}

        public ActionResult bad_case_13()
        {
            // Get user input from query string with some processing
            string assemblyName = Request.QueryString["assembly"];
            string sanitized = assemblyName.Replace("..", ""); // Insufficient sanitization
            string assemblyPath = Path.Combine(Server.MapPath("~/bin"), sanitized);
            
            // ruleid: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFrom(assemblyPath);
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=1}

        public ActionResult bad_case_14()
        {
            // Get user input from session
            string extensionName = Session["preferredExtension"] as string;
            string extensionPath = $"/var/extensions/{extensionName}";
            
            // ruleid: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFile(extensionPath);
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=1}

        public ActionResult bad_case_15()
        {
            // Get user input from multiple query parameters
            string category = Request.QueryString["category"];
            string name = Request.QueryString["name"];
            string version = Request.QueryString["version"];
            
            string assemblyPath = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory, 
                "extensions", 
                category, 
                $"{name}-{version}.dll");
            
            // ruleid: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFile(assemblyPath);
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=0}

        // True Negative Examples (Safe Code)

        public ActionResult good_case_1()
        {
            // Get user input from query string
            string requestedAssembly = Request.QueryString["assembly"];
            
            // Validate against a whitelist of allowed assemblies
            Dictionary<string, string> allowedAssemblies = new Dictionary<string, string>
            {
                { "plugin1", @"C:\plugins\plugin1.dll" },
                { "plugin2", @"C:\plugins\plugin2.dll" },
                { "plugin3", @"C:\plugins\plugin3.dll" }
            };
            
            if (allowedAssemblies.TryGetValue(requestedAssembly, out string assemblyPath))
            {
                // ok: csharp_assembly_path_injection
                Assembly assembly = Assembly.LoadFile(assemblyPath);
                return View("Result", assembly.GetName().Name);
            }
            
            return View("Error", "Invalid assembly requested");
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=0}

        public ActionResult good_case_2()
        {
            // Get user input from form
            string pluginName = Request.Form["plugin"];
            
            // Use a regex pattern to validate the input
            if (!Regex.IsMatch(pluginName, @"^[a-zA-Z0-9_-]+$"))
            {
                return View("Error", "Invalid plugin name");
            }
            
            // Use a fixed base path and validate file exists
            string basePath = @"C:\verified_plugins\";
            string assemblyPath = Path.Combine(basePath, pluginName + ".dll");
            
            if (!File.Exists(assemblyPath))
            {
                return View("Error", "Plugin not found");
            }
            
            // ok: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFrom(assemblyPath);
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=0}

        public ActionResult good_case_3()
        {
            // Get user input from route parameter
            string moduleName = RouteData.Values["module"] as string;
            
            // Validate against a whitelist
            string[] allowedModules = { "core", "admin", "reporting", "analytics" };
            
            if (!allowedModules.Contains(moduleName))
            {
                return View("Error", "Invalid module requested");
            }
            
            string fullPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "verified_modules", moduleName + ".dll");
            
            // Verify file exists and is in the expected directory
            if (!File.Exists(fullPath) || !fullPath.StartsWith(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "verified_modules")))
            {
                return View("Error", "Module not found");
            }
            
            // ok: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFrom(fullPath);
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=0}

        public ActionResult good_case_4()
        {
            // Instead of loading a user-specified assembly, load a predefined one
            string fixedAssemblyPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "bin", "CoreLibrary.dll");
            
            // ok: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFile(fixedAssemblyPath);
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=0}

        public ActionResult good_case_5()
        {
            // Get user input from header
            string pluginId = Request.Headers["X-Plugin-Id"];
            
            // Compute a hash of the plugin ID to prevent path manipulation
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(pluginId));
                string hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                
                // Use the hash to look up the assembly in a secure location
                string pluginCatalogPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "plugin_catalog.json");
                string catalogContent = File.ReadAllText(pluginCatalogPath);
                dynamic catalog = Newtonsoft.Json.JsonConvert.DeserializeObject(catalogContent);
                
                if (catalog.plugins.ContainsKey(hash))
                {
                    string verifiedPath = catalog.plugins[hash].path;
                    
                    // ok: csharp_assembly_path_injection
                    Assembly assembly = Assembly.LoadFile(verifiedPath);
                    return View("Result", assembly.GetName().Name);
                }
            }
            
            return View("Error", "Plugin not found");
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=0}

        [Microsoft.AspNetCore.Mvc.HttpPost]
        public IActionResult good_case_6([FromBody] dynamic payload)
        {
            // Instead of using user input directly, use a configuration system
            var configuration = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .Build();
            
            string moduleName = payload.moduleName;
            
            // Check if the module is configured
            var moduleSection = configuration.GetSection("Modules").GetSection(moduleName);
            if (!moduleSection.Exists())
            {
                return BadRequest("Module not configured");
            }
            
            string assemblyPath = moduleSection["Path"];
            
            // ok: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFile(assemblyPath);
            
            return Ok(new { AssemblyName = assembly.GetName().Name });
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=0}

        public ActionResult good_case_7()
        {
            // Use reflection to load an assembly by its strong name instead of path
            string assemblyName = "System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
            
            // ok: csharp_assembly_path_injection
            Assembly assembly = Assembly.Load(assemblyName);
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=0}

        public async Task<ActionResult> good_case_8()
        {
            // Use a secure service to validate and retrieve assembly path
            using (var client = new HttpClient())
            {
                // Add authentication to the request
                client.DefaultRequestHeaders.Add("Authorization", "Bearer " + GetSecureToken());
                
                // Get plugin info from a trusted API
                string pluginInfo = await client.GetStringAsync("https://internal-api.example.com/verified-plugins");
                dynamic pluginData = Newtonsoft.Json.JsonConvert.DeserializeObject(pluginInfo);
                
                // Verify digital signature of the plugin
                bool isValid = VerifyPluginSignature(pluginData.path, pluginData.signature);
                
                if (isValid)
                {
                    string verifiedPath = pluginData.path;
                    
                    // ok: csharp_assembly_path_injection
                    Assembly assembly = Assembly.LoadFile(verifiedPath);
                    return View("Result", assembly.GetName().Name);
                }
                
                return View("Error", "Invalid plugin signature");
            }
        }
// {/fact}
        
        private string GetSecureToken()
        {
            // Implementation to retrieve a secure token
            return Environment.GetEnvironmentVariable("API_TOKEN");
        }
        
        private bool VerifyPluginSignature(string path, string signature)
        {
            // Implementation to verify digital signature
            return true; // Simplified for example
        }
// {fact rule=assembly-path-injection@v1.0 defects=0}

        public ActionResult good_case_9()
        {
            // Use a factory pattern to create assemblies based on type
            string pluginType = Request.QueryString["type"];
            
            IAssemblyFactory factory = new SafeAssemblyFactory();
            Assembly assembly = factory.CreateAssembly(pluginType);
            
            if (assembly == null)
            {
                return View("Error", "Invalid plugin type");
            }
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
        
        public interface IAssemblyFactory
        {
            Assembly CreateAssembly(string type);
        }
        
        public class SafeAssemblyFactory : IAssemblyFactory
        {
            private readonly Dictionary<string, string> _assemblyPaths = new Dictionary<string, string>
            {
                { "reporting", @"C:\verified_plugins\ReportingPlugin.dll" },
                { "analytics", @"C:\verified_plugins\AnalyticsPlugin.dll" },
                { "dashboard", @"C:\verified_plugins\DashboardPlugin.dll" }
            };
            
            public Assembly CreateAssembly(string type)
            {
                if (_assemblyPaths.TryGetValue(type, out string path))
                {
                    // ok: csharp_assembly_path_injection
                    return Assembly.LoadFile(path);
                }
                
                return null;
            }
        }
// {fact rule=assembly-path-injection@v1.0 defects=0}

        public ActionResult good_case_10(IFormCollection form)
        {
            // Use a secure configuration system to map user input to assembly paths
            string moduleName = form["moduleName"];
            
            // Load configuration from a secure source
            var config = LoadSecureConfiguration();
            
            if (config.Modules.TryGetValue(moduleName, out ModuleConfig moduleConfig))
            {
                string assemblyPath = moduleConfig.Path;
                
                // Verify the path is within allowed directories
                string allowedBasePath = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "verified_modules"));
                string fullPath = Path.GetFullPath(assemblyPath);
                
                if (fullPath.StartsWith(allowedBasePath))
                {
                    // ok: csharp_assembly_path_injection
                    Assembly assembly = Assembly.LoadFile(fullPath);
                    return View("Result", assembly.GetName().Name);
                }
            }
            
            return View("Error", "Invalid module");
        }
// {/fact}
        
        private AppConfig LoadSecureConfiguration()
        {
            // Implementation to load secure configuration
            return new AppConfig
            {
                Modules = new Dictionary<string, ModuleConfig>
                {
                    { "core", new ModuleConfig { Path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "verified_modules", "core.dll") } },
                    { "admin", new ModuleConfig { Path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "verified_modules", "admin.dll") } }
                }
            };
        }
        
        public class AppConfig
        {
            public Dictionary<string, ModuleConfig> Modules { get; set; }
        }
        
        public class ModuleConfig
        {
            public string Path { get; set; }
        }
// {fact rule=assembly-path-injection@v1.0 defects=0}

        [Microsoft.AspNetCore.Mvc.HttpGet]
        public IActionResult good_case_11([FromQuery] string pluginId)
        {
            // Use a cryptographic hash to verify plugin integrity
            string pluginsDirectory = Path.Combine(Directory.GetCurrentDirectory(), "verified_plugins");
            string hashesFile = Path.Combine(pluginsDirectory, "plugin_hashes.json");
            
            if (!System.IO.File.Exists(hashesFile))
            {
                return BadRequest("Plugin verification system not available");
            }
            
            string hashesJson = System.IO.File.ReadAllText(hashesFile);
            dynamic hashes = Newtonsoft.Json.JsonConvert.DeserializeObject(hashesJson);
            
            if (hashes.ContainsKey(pluginId))
            {
                string expectedHash = hashes[pluginId].hash;
                string pluginPath = Path.Combine(pluginsDirectory, pluginId + ".dll");
                
                if (System.IO.File.Exists(pluginPath))
                {
                    string actualHash = ComputeFileHash(pluginPath);
                    
                    if (string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                    {
                        // ok: csharp_assembly_path_injection
                        Assembly assembly = Assembly.LoadFrom(pluginPath);
                        return Ok(new { Name = assembly.GetName().Name });
                    }
                }
            }
            
            return BadRequest("Invalid or tampered plugin");
        }
// {/fact}
        
        private string ComputeFileHash(string filePath)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = System.IO.File.OpenRead(filePath))
                {
                    byte[] hashBytes = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }
            }
        }
// {fact rule=assembly-path-injection@v1.0 defects=0}

        public ActionResult good_case_12()
        {
            // Use the AssemblyLoadContext (modern approach) with security checks
            string pluginName = Request.QueryString["plugin"];
            
            // Validate plugin name format
            if (!Regex.IsMatch(pluginName, @"^[a-zA-Z0-9_-]+$"))
            {
                return View("Error", "Invalid plugin name format");
            }
            
            // Check if plugin is in the allowed list
            var allowedPlugins = new[] { "reporting", "analytics", "dashboard" };
            if (!allowedPlugins.Contains(pluginName))
            {
                return View("Error", "Plugin not allowed");
            }
            
            string pluginPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "secure_plugins", pluginName + ".dll");
            
            // Verify file exists in the expected location
            if (!File.Exists(pluginPath))
            {
                return View("Error", "Plugin not found");
            }
            
            // ok: csharp_assembly_path_injection
            // Using LoadFromAssemblyPath with proper validation
            var loadContext = new System.Runtime.Loader.AssemblyLoadContext(pluginName, true);
            var assembly = loadContext.LoadFromAssemblyPath(pluginPath);
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
// {fact rule=assembly-path-injection@v1.0 defects=0}

        public ActionResult good_case_13()
        {
            // Use a secure plugin registry with version control
            string pluginName = Request.QueryString["plugin"];
            string versionStr = Request.QueryString["version"];
            
            if (!Version.TryParse(versionStr, out Version requestedVersion))
            {
                return View("Error", "Invalid version format");
            }
            
            // Query the secure plugin registry
            PluginInfo pluginInfo = GetPluginFromRegistry(pluginName, requestedVersion);
            
            if (pluginInfo == null)
            {
                return View("Error", "Plugin not found in registry");
            }
            
            // Verify plugin signature
            if (!VerifyPluginSignature(pluginInfo.Path, pluginInfo.Signature))
            {
                return View("Error", "Plugin signature verification failed");
            }
            
            // ok: csharp_assembly_path_injection
            Assembly assembly = Assembly.LoadFile(pluginInfo.Path);
            
            return View("Result", assembly.GetName().Name);
        }
// {/fact}
        
        private PluginInfo GetPluginFromRegistry(string name, Version version)
        {
            // Implementation to securely retrieve plugin info from a registry
            // This would typically query a database or secure configuration
            
            // Simplified example
            if (name == "reporting" && version.Major == 1)
            {
                return new PluginInfo
                {
                    Name = "reporting",
                    Version = new Version(1, 0, 0),
                    Path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "verified_plugins", "reporting_1_0_0.dll"),
                    Signature = "validSignatureHash"
                };
            }
            
            return null;
        }
        
        public class PluginInfo
        {
            public string Name { get; set; }
            public Version Version { get; set; }
            public string Path { get; set; }
            public string Signature { get; set; }
        }
// {fact rule=assembly-path-injection@v1.0 defects=0}

        public ActionResult good_case_14()
        {
            // Use a dependency injection approach for plugins
            string featureName = Request.QueryString["feature"];
            
            // Get the plugin manager from the DI container
            var pluginManager = DependencyResolver.Current.GetService<IPluginManager>();
            
            // Let the plugin manager handle the assembly loading securely
            IFeature feature = pluginManager.GetFeature(featureName);
            
            if (feature == null)
            {
                return View("Error", "Feature not available");
            }
            
            return View("Result", feature.GetType().Assembly.GetName().Name);
        }
// {/fact}
        
        public interface IPluginManager
        {
            IFeature GetFeature(string featureName);
        }
        
        public interface IFeature
        {
            string Execute();
        }
        
        public class SecurePluginManager : IPluginManager
        {
            private readonly Dictionary<string, Lazy<IFeature>> _features = new Dictionary<string, Lazy<IFeature>>();
            
            public SecurePluginManager()
            {
                // Pre-load all allowed features securely
                RegisterFeature("reporting", () => LoadFeature("ReportingPlugin.dll", "ReportingFeature"));
                RegisterFeature("analytics", () => LoadFeature("AnalyticsPlugin.dll", "AnalyticsFeature"));
            }
            
            private void RegisterFeature(string name, Func<IFeature> factory)
            {
                _features[name] = new Lazy<IFeature>(factory);
            }
            
            private IFeature LoadFeature(string assemblyName, string typeName)
            {
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "secure_plugins", assemblyName);
                
                // ok: csharp_assembly_path_injection
                Assembly assembly = Assembly.LoadFile(path);
                Type type = assembly.GetType(typeName);
                return (IFeature)Activator.CreateInstance(type);
            }
            
            public IFeature GetFeature(string featureName)
            {
                if (_features.TryGetValue(featureName, out var feature))
                {
                    return feature.Value;
                }
                
                return null;
            }
        }
// {fact rule=assembly-path-injection@v1.0 defects=0}

        public ActionResult good_case_15()
        {
            // Use a secure plugin catalog with digital signatures and sandboxing
            string pluginId = Request.QueryString["id"];
            
            // Validate plugin ID format
            if (!Regex.IsMatch(pluginId, @"^[a-zA-Z0-9_-]+$"))
            {
                return View("Error", "Invalid plugin ID format");
            }
            
            // Load the secure plugin catalog
            var catalog = LoadPluginCatalog();
            
            if (!catalog.Plugins.TryGetValue(pluginId, out PluginMetadata metadata))
            {
                return View("Error", "Plugin not found in catalog");
            }
            
            // Verify plugin is not blacklisted
            if (IsPluginBlacklisted(pluginId))
            {
                return View("Error", "Plugin has been blacklisted");
            }
            
            // Verify plugin file hash
            string pluginPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "verified_plugins", metadata.Filename);
            if (!VerifyFileHash(pluginPath, metadata.FileHash))
            {
                return View("Error", "Plugin file integrity check failed");
            }
            
            // Create a sandbox AppDomain for loading the plugin
            AppDomainSetup setup = new AppDomainSetup
            {
                ApplicationBase = AppDomain.CurrentDomain.BaseDirectory,
                PrivateBinPath = "verified_plugins",
                ShadowCopyFiles = "true"
            };
            
            Evidence evidence = new Evidence();
            AppDomain sandbox = AppDomain.CreateDomain("PluginSandbox", evidence, setup);
            
            try
            {
                // ok: csharp_assembly_path_injection
                // Load the assembly in the sandbox with proper validation
                Assembly assembly = sandbox.Load(metadata.AssemblyName);
                string assemblyName = assembly.GetName().Name;
                
                // Unload the sandbox when done
                AppDomain.Unload(sandbox);
                
                return View("Result", assemblyName);
            }
            catch (Exception ex)
            {
                AppDomain.Unload(sandbox);
                return View("Error", ex.Message);
            }
        }
// {/fact}
        
        private PluginCatalog LoadPluginCatalog()
        {
            // Implementation to load a secure plugin catalog
            return new PluginCatalog
            {
                Plugins = new Dictionary<string, PluginMetadata>
                {
                    { 
                        "reporting", 
                        new PluginMetadata 
                        { 
                            Filename = "reporting.dll",
                            AssemblyName = "ReportingPlugin, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
                            FileHash = "validFileHash"
                        } 
                    }
                }
            };
        }
        
        private bool IsPluginBlacklisted(string pluginId)
        {
            // Implementation to check if a plugin is blacklisted
            string[] blacklistedPlugins = { "malicious_plugin", "vulnerable_plugin" };
            return blacklistedPlugins.Contains(pluginId);
        }
        
        private bool VerifyFileHash(string filePath, string expectedHash)
        {
            // Implementation to verify file hash
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    byte[] hashBytes = sha256.ComputeHash(stream);
                    string actualHash = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                    return string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase);
                }
            }
        }
        
        public class PluginCatalog
        {
            public Dictionary<string, PluginMetadata> Plugins { get; set; }
        }
        
        public class PluginMetadata
        {
            public string Filename { get; set; }
            public string AssemblyName { get; set; }
            public string FileHash { get; set; }
        }
    }
}