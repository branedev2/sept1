using System;
using System.IO;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Net;
using System.Text.RegularExpressions;
using System.Linq;
using Microsoft.AspNetCore.Hosting;
using System.Security.Cryptography;
using System.Text;

namespace PathTraversalExamples
{
    public class PathTraversalController : Controller
    {
        private readonly string basePath = @"C:\data\files\";
        private readonly IWebHostEnvironment _environment;

        public PathTraversalController(IWebHostEnvironment environment)
        {
            _environment = environment;
        }
// {fact rule=path-traversal@v1.0 defects=1}

        // True Positive Examples (Vulnerable Code)

        public ActionResult bad_case_1()
        {
            // Get filename from query string
            string fileName = Request.QueryString["file"];
            
            // ruleid: path-traversal-csharp-rule
            string content = System.IO.File.ReadAllText(basePath + fileName);
            
            return Content(content);
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

        public ActionResult bad_case_2()
        {
            // Get filename from form post
            string fileName = Request.Form["filename"];
            
            // ruleid: path-traversal-csharp-rule
            FileStream fs = new FileStream(basePath + fileName, FileMode.Open);
            
            byte[] fileBytes = new byte[fs.Length];
            fs.Read(fileBytes, 0, (int)fs.Length);
            fs.Close();
            
            return File(fileBytes, "application/octet-stream", fileName);
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

        public IActionResult bad_case_3()
        {
            // Get filename from route parameter
            string fileName = RouteData.Values["filename"] as string;
            
            // ruleid: path-traversal-csharp-rule
            using (StreamReader sr = new StreamReader(Path.Combine(basePath, fileName)))
            {
                string content = sr.ReadToEnd();
                return Content(content);
            }
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

        public IActionResult bad_case_4(IFormCollection form)
        {
            // Get filename from form
            string fileName = form["userFile"];
            
            // ruleid: path-traversal-csharp-rule
            var fileInfo = new FileInfo(basePath + fileName);
            if (fileInfo.Exists)
            {
                return PhysicalFile(fileInfo.FullName, "text/plain");
            }
            
            return NotFound();
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

        public IActionResult bad_case_5()
        {
            // Get filename from header
            string fileName = Request.Headers["X-Filename"];
            
            // ruleid: path-traversal-csharp-rule
            DirectoryInfo dirInfo = new DirectoryInfo(Path.Combine(basePath, fileName));
            
            var files = dirInfo.GetFiles();
            return Json(files.Select(f => f.Name).ToArray());
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

        public IActionResult bad_case_6()
        {
            // Get filename from cookie
            string fileName = Request.Cookies["preferred_file"];
            
            try
            {
                // ruleid: path-traversal-csharp-rule
                using (var fs = new FileStream(basePath + fileName, FileMode.Create))
                using (var writer = new StreamWriter(fs))
                {
                    writer.Write("New content");
                }
                return Ok();
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

        public IActionResult bad_case_7([FromQuery] string document)
        {
            // Get filename from query parameter with attribute
            string filePath = $"{basePath}{document}";
            
            // ruleid: path-traversal-csharp-rule
            if (System.IO.File.Exists(filePath))
            {
                byte[] fileBytes = System.IO.File.ReadAllBytes(filePath);
                return File(fileBytes, "application/pdf");
            }
            
            return NotFound();
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

        public IActionResult bad_case_8()
        {
            // Get filename from query string with complex path construction
            string category = Request.Query["category"];
            string fileName = Request.Query["file"];
            
            string filePath = Path.Combine(basePath, category);
            
            // ruleid: path-traversal-csharp-rule
            using (var fs = File.OpenRead(Path.Combine(filePath, fileName)))
            {
                byte[] buffer = new byte[fs.Length];
                fs.Read(buffer, 0, buffer.Length);
                return File(buffer, "application/octet-stream");
            }
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

        public IActionResult bad_case_9()
        {
            // Get directory name from query string
            string dirName = Request.Query["directory"];
            
            // ruleid: path-traversal-csharp-rule
            var directory = new DirectoryInfo(Path.Combine(basePath, dirName));
            
            if (directory.Exists)
            {
                var fileList = directory.GetFiles().Select(f => f.Name).ToList();
                return Json(fileList);
            }
            
            return NotFound();
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

        public IActionResult bad_case_10()
        {
            // Get filename from query with string manipulation
            string fileName = Request.Query["file"];
            fileName = fileName.Replace(" ", "_");
            
            // ruleid: path-traversal-csharp-rule
            using (var writer = new StreamWriter(basePath + fileName))
            {
                writer.WriteLine("User data saved");
            }
            
            return Ok("File saved");
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

        public IActionResult bad_case_11()
        {
            // Get filename from URL parameter with minimal processing
            string fileName = Request.Query["file"];
            string sanitized = fileName.Trim();
            
            // ruleid: path-traversal-csharp-rule
            if (Directory.Exists(Path.Combine(basePath, sanitized)))
            {
                var files = Directory.GetFiles(Path.Combine(basePath, sanitized));
                return Json(files);
            }
            
            return NotFound();
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

        public IActionResult bad_case_12()
        {
            // Get filename from form with string concatenation
            string fileName = Request.Form["filename"];
            string extension = Request.Form["extension"];
            string fullFileName = fileName + "." + extension;
            
            // ruleid: path-traversal-csharp-rule
            using (var fs = new FileStream(basePath + fullFileName, FileMode.Open))
            {
                byte[] buffer = new byte[fs.Length];
                fs.Read(buffer, 0, buffer.Length);
                return File(buffer, "application/octet-stream");
            }
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

        public IActionResult bad_case_13()
        {
            // Get filename from query with conditional logic
            string fileName = Request.Query["file"];
            string path;
            
            if (fileName.EndsWith(".txt"))
            {
                path = Path.Combine(basePath, "text", fileName);
            }
            else
            {
                path = Path.Combine(basePath, "other", fileName);
            }
            
            // ruleid: path-traversal-csharp-rule
            string content = File.ReadAllText(path);
            return Content(content);
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

        public IActionResult bad_case_14()
        {
            // Get filename from header with variable reassignment
            string fileName = Request.Headers["X-Filename"];
            string userDir = Request.Headers["X-UserDir"];
            
            string path = basePath;
            if (!string.IsNullOrEmpty(userDir))
            {
                path = Path.Combine(path, userDir);
            }
            
            // ruleid: path-traversal-csharp-rule
            using (var fs = File.Create(Path.Combine(path, fileName)))
            using (var writer = new StreamWriter(fs))
            {
                writer.Write("New file content");
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

        public IActionResult bad_case_15()
        {
            // Get multiple parameters to construct path
            string year = Request.Query["year"];
            string month = Request.Query["month"];
            string file = Request.Query["file"];
            
            string archivePath = Path.Combine(basePath, year, month);
            
            // ruleid: path-traversal-csharp-rule
            if (File.Exists(Path.Combine(archivePath, file)))
            {
                byte[] content = File.ReadAllBytes(Path.Combine(archivePath, file));
                return File(content, "application/octet-stream");
            }
            
            return NotFound();
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

        // True Negative Examples (Safe Code)

        public ActionResult good_case_1()
        {
            // Get filename from query string with validation
            string fileName = Request.QueryString["file"];
            
            // Validate that the filename doesn't contain path traversal sequences
            if (fileName.Contains("..") || fileName.Contains("/") || fileName.Contains("\\"))
            {
                return BadRequest("Invalid filename");
            }
            
            // ok: path-traversal-csharp-rule
            string content = System.IO.File.ReadAllText(Path.Combine(basePath, fileName));
            
            return Content(content);
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

        public ActionResult good_case_2()
        {
            // Get filename from form post with Path.GetFileName to remove path components
            string fileName = Request.Form["filename"];
            
            // Extract just the filename without any path components
            string safeFileName = Path.GetFileName(fileName);
            
            // ok: path-traversal-csharp-rule
            FileStream fs = new FileStream(Path.Combine(basePath, safeFileName), FileMode.Open);
            
            byte[] fileBytes = new byte[fs.Length];
            fs.Read(fileBytes, 0, (int)fs.Length);
            fs.Close();
            
            return File(fileBytes, "application/octet-stream", safeFileName);
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

        public IActionResult good_case_3()
        {
            // Get filename from route parameter with whitelist validation
            string fileName = RouteData.Values["filename"] as string;
            
            // Whitelist of allowed files
            string[] allowedFiles = { "report.pdf", "data.csv", "image.jpg" };
            
            if (!allowedFiles.Contains(fileName))
            {
                return BadRequest("File not in allowed list");
            }
            
            // ok: path-traversal-csharp-rule
            using (StreamReader sr = new StreamReader(Path.Combine(basePath, fileName)))
            {
                string content = sr.ReadToEnd();
                return Content(content);
            }
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

        public IActionResult good_case_4(IFormCollection form)
        {
            // Get filename from form with regex validation
            string fileName = form["userFile"];
            
            // Validate filename format using regex (alphanumeric + extension)
            if (!Regex.IsMatch(fileName, @"^[a-zA-Z0-9]+\.[a-zA-Z0-9]+$"))
            {
                return BadRequest("Invalid filename format");
            }
            
            // ok: path-traversal-csharp-rule
            var fileInfo = new FileInfo(Path.Combine(basePath, fileName));
            if (fileInfo.Exists)
            {
                return PhysicalFile(fileInfo.FullName, "text/plain");
            }
            
            return NotFound();
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

        public IActionResult good_case_5()
        {
            // Get filename from header with Path.GetFullPath validation
            string fileName = Request.Headers["X-Filename"];
            
            // Combine paths and check if the result is within the intended directory
            string fullPath = Path.GetFullPath(Path.Combine(basePath, fileName));
            if (!fullPath.StartsWith(Path.GetFullPath(basePath), StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest("Path traversal attempt detected");
            }
            
            // ok: path-traversal-csharp-rule
            DirectoryInfo dirInfo = new DirectoryInfo(fullPath);
            
            var files = dirInfo.GetFiles();
            return Json(files.Select(f => f.Name).ToArray());
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

        public IActionResult good_case_6()
        {
            // Get filename from cookie with GUID replacement for security
            string fileName = Request.Cookies["preferred_file"];
            
            // Generate a safe filename using a GUID
            string safeFileName = Guid.NewGuid().ToString() + ".txt";
            
            try
            {
                // ok: path-traversal-csharp-rule
                using (var fs = new FileStream(Path.Combine(basePath, safeFileName), FileMode.Create))
                using (var writer = new StreamWriter(fs))
                {
                    writer.Write("New content for " + fileName);
                }
                return Ok();
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

        public IActionResult good_case_7([FromQuery] string document)
        {
            // Get filename from query parameter with attribute and sanitization
            
            // Remove any directory traversal characters
            string sanitizedName = document.Replace("..", "").Replace("/", "").Replace("\\", "");
            
            // ok: path-traversal-csharp-rule
            string filePath = Path.Combine(basePath, sanitizedName);
            
            if (System.IO.File.Exists(filePath))
            {
                byte[] fileBytes = System.IO.File.ReadAllBytes(filePath);
                return File(fileBytes, "application/pdf");
            }
            
            return NotFound();
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

        public IActionResult good_case_8()
        {
            // Get filename from query string with hash-based validation
            string fileName = Request.Query["file"];
            
            // Create a hash of the filename for secure storage
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(fileName));
                string hashedName = Convert.ToBase64String(hashBytes).Replace("/", "_").Replace("+", "-").Substring(0, 20) + ".dat";
                
                // ok: path-traversal-csharp-rule
                using (var fs = File.OpenRead(Path.Combine(basePath, hashedName)))
                {
                    byte[] buffer = new byte[fs.Length];
                    fs.Read(buffer, 0, buffer.Length);
                    return File(buffer, "application/octet-stream");
                }
            }
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

        public IActionResult good_case_9()
        {
            // Get directory name from query string with mapping to safe values
            string dirName = Request.Query["directory"];
            
            // Map user input to predefined safe directories
            Dictionary<string, string> safeDirs = new Dictionary<string, string>
            {
                { "docs", "documents" },
                { "img", "images" },
                { "data", "datafiles" }
            };
            
            if (!safeDirs.ContainsKey(dirName))
            {
                return BadRequest("Invalid directory");
            }
            
            // ok: path-traversal-csharp-rule
            var directory = new DirectoryInfo(Path.Combine(basePath, safeDirs[dirName]));
            
            if (directory.Exists)
            {
                var fileList = directory.GetFiles().Select(f => f.Name).ToList();
                return Json(fileList);
            }
            
            return NotFound();
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

        public IActionResult good_case_10()
        {
            // Get filename from query with proper sanitization
            string fileName = Request.Query["file"];
            
            // Sanitize by only allowing alphanumeric and some special chars
            string sanitized = new string(fileName.Where(c => char.IsLetterOrDigit(c) || c == '.' || c == '_' || c == '-').ToArray());
            
            // ok: path-traversal-csharp-rule
            using (var writer = new StreamWriter(Path.Combine(basePath, sanitized)))
            {
                writer.WriteLine("User data saved");
            }
            
            return Ok("File saved");
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

        public IActionResult good_case_11()
        {
            // Use web host environment to get safe paths
            string fileName = Request.Query["file"];
            
            // Only allow specific extensions
            if (!fileName.EndsWith(".html") && !fileName.EndsWith(".txt"))
            {
                return BadRequest("Only HTML and TXT files are allowed");
            }
            
            // Use web root path for safe file access
            string webRootPath = _environment.WebRootPath;
            
            // ok: path-traversal-csharp-rule
            string fullPath = Path.Combine(webRootPath, "files", Path.GetFileName(fileName));
            
            if (System.IO.File.Exists(fullPath))
            {
                string content = System.IO.File.ReadAllText(fullPath);
                return Content(content);
            }
            
            return NotFound();
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

        public IActionResult good_case_12()
        {
            // Use a database to map IDs to filenames
            string fileId = Request.Form["fileId"];
            
            // In a real app, this would be a database lookup
            Dictionary<string, string> fileMap = new Dictionary<string, string>
            {
                { "1", "document1.pdf" },
                { "2", "report.xlsx" },
                { "3", "image.jpg" }
            };
            
            if (!fileMap.ContainsKey(fileId))
            {
                return NotFound();
            }
            
            string safeFileName = fileMap[fileId];
            
            // ok: path-traversal-csharp-rule
            using (var fs = new FileStream(Path.Combine(basePath, safeFileName), FileMode.Open))
            {
                byte[] buffer = new byte[fs.Length];
                fs.Read(buffer, 0, buffer.Length);
                return File(buffer, "application/octet-stream");
            }
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

        public IActionResult good_case_13()
        {
            // Use content addressing with file hashes
            string requestedHash = Request.Query["hash"];
            
            // Validate hash format (SHA-256 is 64 hex chars)
            if (!Regex.IsMatch(requestedHash, "^[a-f0-9]{64}$"))
            {
                return BadRequest("Invalid hash format");
            }
            
            // First two chars used for directory sharding
            string directory = requestedHash.Substring(0, 2);
            string filename = requestedHash.Substring(2);
            
            // ok: path-traversal-csharp-rule
            string filePath = Path.Combine(basePath, directory, filename);
            
            if (File.Exists(filePath))
            {
                return PhysicalFile(filePath, "application/octet-stream");
            }
            
            return NotFound();
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

        public IActionResult good_case_14()
        {
            // Use a virtual path provider approach
            string virtualPath = Request.Headers["X-Virtual-Path"];
            
            // Map virtual paths to physical paths securely
            Dictionary<string, string> pathMap = new Dictionary<string, string>
            {
                { "/public/docs", Path.Combine(basePath, "documents") },
                { "/public/images", Path.Combine(basePath, "images") },
                { "/shared/files", Path.Combine(basePath, "shared") }
            };
            
            // Check if the virtual path is in our allowed list
            string physicalBasePath = null;
            foreach (var mapping in pathMap)
            {
                if (virtualPath.StartsWith(mapping.Key))
                {
                    physicalBasePath = mapping.Value;
                    virtualPath = virtualPath.Substring(mapping.Key.Length);
                    break;
                }
            }
            
            if (physicalBasePath == null)
            {
                return BadRequest("Invalid virtual path");
            }
            
            // Extract just the filename without any path components
            string safeFileName = Path.GetFileName(virtualPath);
            
            // ok: path-traversal-csharp-rule
            string fullPath = Path.Combine(physicalBasePath, safeFileName);
            
            if (File.Exists(fullPath))
            {
                return PhysicalFile(fullPath, "application/octet-stream");
            }
            
            return NotFound();
        }
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

        public IActionResult good_case_15()
        {
            // Use a secure temporary file approach
            string userFileName = Request.Query["filename"];
            
            // Generate a temporary file with a safe name
            string tempFileName = Path.GetTempFileName();
            
            try
            {
                // Write user content to the temp file
                using (var writer = new StreamWriter(tempFileName))
                {
                    writer.WriteLine("User content for: " + userFileName);
                }
                
                // ok: path-traversal-csharp-rule
                byte[] fileContent = File.ReadAllBytes(tempFileName);
                
                // Clean up
                File.Delete(tempFileName);
                
                // Return the content with the user's original filename
                return File(fileContent, "application/octet-stream", Path.GetFileName(userFileName));
            }
            catch (Exception ex)
            {
                // Clean up on error
                if (File.Exists(tempFileName))
                {
                    File.Delete(tempFileName);
                }
                return StatusCode(500, ex.Message);
            }
        }
// {/fact}
    }
}