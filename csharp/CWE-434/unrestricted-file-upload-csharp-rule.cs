using System;
using System.IO;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;

namespace UnrestrictedFileUploadExamples
{
    // TRUE POSITIVES - Vulnerable code examples

    public class VulnerableFileUploadController : Controller
    {
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
        // Example 1: Basic file upload with user-controlled filename
        public ActionResult bad_case_1()
        {
            HttpPostedFileBase file = Request.Files["userFile"];
            string fileName = Request.Form["fileName"];
            
            // ruleid: unrestricted-file-upload-csharp-rule
            string path = Path.Combine(Server.MapPath("~/uploads"), fileName);
            file.SaveAs(path);
            
            return Content("File uploaded successfully");
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
        
        // Example 2: Using query string parameter as filename
        public ActionResult bad_case_2()
        {
            HttpPostedFileBase file = Request.Files["userFile"];
            string fileName = Request.QueryString["fileName"];
            
            // ruleid: unrestricted-file-upload-csharp-rule
            string path = Path.Combine(Server.MapPath("~/uploads"), fileName);
            file.SaveAs(path);
            
            return Content("File uploaded successfully");
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
        
        // Example 3: Using header value as part of filename
        public ActionResult bad_case_3()
        {
            HttpPostedFileBase file = Request.Files["userFile"];
            string userFolder = Request.Headers["User-Folder"];
            string fileName = Guid.NewGuid().ToString() + "_" + userFolder;
            
            // ruleid: unrestricted-file-upload-csharp-rule
            string path = Path.Combine(Server.MapPath("~/uploads"), fileName);
            file.SaveAs(path);
            
            return Content("File uploaded successfully");
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
        
        // Example 4: Using cookie value in filename
        public ActionResult bad_case_4()
        {
            HttpPostedFileBase file = Request.Files["userFile"];
            string userIdentifier = Request.Cookies["user_id"]?.Value;
            string fileName = userIdentifier + "_" + DateTime.Now.Ticks;
            
            // ruleid: unrestricted-file-upload-csharp-rule
            string path = Path.Combine(Server.MapPath("~/uploads"), fileName);
            file.SaveAs(path);
            
            return Content("File uploaded successfully");
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
        
        // Example 5: Using multiple user inputs to construct filename
        public ActionResult bad_case_5()
        {
            HttpPostedFileBase file = Request.Files["userFile"];
            string category = Request.Form["category"];
            string customName = Request.Form["customName"];
            string fileName = category + "/" + customName;
            
            // ruleid: unrestricted-file-upload-csharp-rule
            string path = Path.Combine(Server.MapPath("~/uploads"), fileName);
            file.SaveAs(path);
            
            return Content("File uploaded successfully");
        }
// {/fact}
    }

    // ASP.NET Core examples
    [ApiController]
    [Route("api/[controller]")]
    public class ModernFileUploadController : ControllerBase
    {
        private readonly IWebHostEnvironment _environment;
        
        public ModernFileUploadController(IWebHostEnvironment environment)
        {
            _environment = environment;
        }
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
        
        // Example 6: ASP.NET Core with user-controlled filename
        [HttpPost("upload")]
        public IActionResult bad_case_6([FromForm] IFormFile file)
        {
            string fileName = Request.Form["fileName"];
            
            // ruleid: unrestricted-file-upload-csharp-rule
            string path = Path.Combine(_environment.WebRootPath, "uploads", fileName);
            using (var stream = new FileStream(path, FileMode.Create))
            {
                file.CopyTo(stream);
            }
            
            return Ok("File uploaded successfully");
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
        
        // Example 7: Using route parameter as filename
        [HttpPost("upload/{fileName}")]
        public IActionResult bad_case_7([FromRoute] string fileName, [FromForm] IFormFile file)
        {
            // ruleid: unrestricted-file-upload-csharp-rule
            string path = Path.Combine(_environment.WebRootPath, "uploads", fileName);
            using (var stream = new FileStream(path, FileMode.Create))
            {
                file.CopyTo(stream);
            }
            
            return Ok("File uploaded successfully");
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
        
        // Example 8: Using JSON body parameter for filename
        [HttpPost("upload-json")]
        public IActionResult bad_case_8([FromBody] UploadModel model, [FromForm] IFormFile file)
        {
            // ruleid: unrestricted-file-upload-csharp-rule
            string path = Path.Combine(_environment.WebRootPath, "uploads", model.FileName);
            using (var stream = new FileStream(path, FileMode.Create))
            {
                file.CopyTo(stream);
            }
            
            return Ok("File uploaded successfully");
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
        
        // Example 9: Using user input for directory and filename
        [HttpPost("upload-to-directory")]
        public IActionResult bad_case_9([FromForm] IFormFile file)
        {
            string directory = Request.Form["directory"];
            string fileName = Request.Form["fileName"];
            
            // ruleid: unrestricted-file-upload-csharp-rule
            string path = Path.Combine(_environment.WebRootPath, directory, fileName);
            using (var stream = new FileStream(path, FileMode.Create))
            {
                file.CopyTo(stream);
            }
            
            return Ok("File uploaded successfully");
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
        
        // Example 10: Using query parameters for filename
        [HttpPost("upload-with-query")]
        public IActionResult bad_case_10([FromForm] IFormFile file)
        {
            string fileName = Request.Query["fileName"];
            
            // ruleid: unrestricted-file-upload-csharp-rule
            string path = Path.Combine(_environment.WebRootPath, "uploads", fileName);
            using (var stream = new FileStream(path, FileMode.Create))
            {
                file.CopyTo(stream);
            }
            
            return Ok("File uploaded successfully");
        }
// {/fact}
    }
    
    // Non-MVC examples
    public class FileUploadService
    {
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
        // Example 11: Using HttpContext directly
        public void bad_case_11(HttpContext context)
        {
            var file = context.Request.Form.Files[0];
            string fileName = context.Request.Form["fileName"];
            
            // ruleid: unrestricted-file-upload-csharp-rule
            string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "uploads", fileName);
            using (var stream = new FileStream(path, FileMode.Create))
            {
                file.CopyTo(stream);
            }
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
        
        // Example 12: Using HttpRequest directly
        public void bad_case_12(HttpRequest request)
        {
            var file = request.Form.Files[0];
            string fileName = request.Form["fileName"];
            
            // ruleid: unrestricted-file-upload-csharp-rule
            string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "uploads", fileName);
            using (var stream = new FileStream(path, FileMode.Create))
            {
                file.CopyTo(stream);
            }
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
        
        // Example 13: Using HttpClient to download file with user-controlled name
        public async Task bad_case_13(HttpContext context)
        {
            string fileUrl = context.Request.Form["fileUrl"];
            string fileName = context.Request.Form["fileName"];
            
            using (var httpClient = new HttpClient())
            {
                var response = await httpClient.GetAsync(fileUrl);
                response.EnsureSuccessStatusCode();
                
                // ruleid: unrestricted-file-upload-csharp-rule
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "downloads", fileName);
                using (var fileStream = new FileStream(path, FileMode.Create))
                {
                    await response.Content.CopyToAsync(fileStream);
                }
            }
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
        
        // Example 14: Using Stream to write file with user-controlled name
        public void bad_case_14(HttpContext context)
        {
            var file = context.Request.Form.Files[0];
            string fileName = context.Request.Form["fileName"];
            
            using (var memoryStream = new MemoryStream())
            {
                file.CopyTo(memoryStream);
                byte[] fileBytes = memoryStream.ToArray();
                
                // ruleid: unrestricted-file-upload-csharp-rule
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "uploads", fileName);
                File.WriteAllBytes(path, fileBytes);
            }
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
        
        // Example 15: Using FileInfo with user-controlled name
        public void bad_case_15(HttpContext context)
        {
            var file = context.Request.Form.Files[0];
            string fileName = context.Request.Form["fileName"];
            
            // ruleid: unrestricted-file-upload-csharp-rule
            string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "uploads", fileName);
            FileInfo fileInfo = new FileInfo(path);
            
            using (var stream = fileInfo.Create())
            {
                file.CopyTo(stream);
            }
        }
// {/fact}
    }

    // TRUE NEGATIVES - Secure code examples
    
    public class SecureFileUploadController : Controller
    {
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
        // Example 1: Using GUID for filename
        public ActionResult good_case_1()
        {
            HttpPostedFileBase file = Request.Files["userFile"];
            string originalFileName = Path.GetFileName(file.FileName);
            string extension = Path.GetExtension(originalFileName);
            
            // ok: unrestricted-file-upload-csharp-rule
            string safeFileName = Guid.NewGuid().ToString() + extension;
            string path = Path.Combine(Server.MapPath("~/uploads"), safeFileName);
            file.SaveAs(path);
            
            return Content("File uploaded successfully");
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
        
        // Example 2: Validating file extension
        public ActionResult good_case_2()
        {
            HttpPostedFileBase file = Request.Files["userFile"];
            string fileName = Request.Form["fileName"];
            string extension = Path.GetExtension(fileName).ToLower();
            
            // Validate allowed extensions
            string[] allowedExtensions = { ".jpg", ".jpeg", ".png", ".gif" };
            if (!Array.Exists(allowedExtensions, ext => ext == extension))
            {
                return Content("Invalid file type");
            }
            
            // ok: unrestricted-file-upload-csharp-rule
            string safeFileName = Guid.NewGuid().ToString() + extension;
            string path = Path.Combine(Server.MapPath("~/uploads"), safeFileName);
            file.SaveAs(path);
            
            return Content("File uploaded successfully");
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
        
        // Example 3: Sanitizing user input for filename
        public ActionResult good_case_3()
        {
            HttpPostedFileBase file = Request.Files["userFile"];
            string userProvidedName = Request.Form["fileName"];
            
            // Sanitize the filename
            // ok: unrestricted-file-upload-csharp-rule
            string safeFileName = Regex.Replace(userProvidedName, @"[^\w\.-]", "_");
            safeFileName = Path.GetFileNameWithoutExtension(safeFileName).Substring(0, Math.Min(50, safeFileName.Length)) 
                + Path.GetExtension(file.FileName);
            
            string path = Path.Combine(Server.MapPath("~/uploads"), safeFileName);
            file.SaveAs(path);
            
            return Content("File uploaded successfully");
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
        
        // Example 4: Using timestamp and original filename
        public ActionResult good_case_4()
        {
            HttpPostedFileBase file = Request.Files["userFile"];
            string originalFileName = Path.GetFileName(file.FileName);
            
            // ok: unrestricted-file-upload-csharp-rule
            string safeFileName = DateTime.Now.Ticks + "_" + 
                Regex.Replace(originalFileName, @"[^\w\.-]", "_");
            
            string path = Path.Combine(Server.MapPath("~/uploads"), safeFileName);
            file.SaveAs(path);
            
            return Content("File uploaded successfully");
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
        
        // Example 5: Using hash of original filename
        public ActionResult good_case_5()
        {
            HttpPostedFileBase file = Request.Files["userFile"];
            string originalFileName = file.FileName;
            string extension = Path.GetExtension(originalFileName);
            
            // Generate hash of original filename
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(originalFileName + DateTime.Now.ToString()));
                string hash = BitConverter.ToString(hashBytes).Replace("-", "").Substring(0, 16);
                
                // ok: unrestricted-file-upload-csharp-rule
                string safeFileName = hash + extension;
                string path = Path.Combine(Server.MapPath("~/uploads"), safeFileName);
                file.SaveAs(path);
            }
            
            return Content("File uploaded successfully");
        }
// {/fact}
    }
    
    // ASP.NET Core secure examples
    [ApiController]
    [Route("api/[controller]")]
    public class SecureModernFileUploadController : ControllerBase
    {
        private readonly IWebHostEnvironment _environment;
        
        public SecureModernFileUploadController(IWebHostEnvironment environment)
        {
            _environment = environment;
        }
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
        
        // Example 6: ASP.NET Core with secure filename generation
        [HttpPost("upload")]
        public IActionResult good_case_6([FromForm] IFormFile file)
        {
            string originalExtension = Path.GetExtension(file.FileName);
            
            // ok: unrestricted-file-upload-csharp-rule
            string safeFileName = Guid.NewGuid().ToString() + originalExtension;
            string path = Path.Combine(_environment.WebRootPath, "uploads", safeFileName);
            
            using (var stream = new FileStream(path, FileMode.Create))
            {
                file.CopyTo(stream);
            }
            
            return Ok(new { fileName = safeFileName });
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
        
        // Example 7: Content type validation and secure filename
        [HttpPost("upload-with-validation")]
        public IActionResult good_case_7([FromForm] IFormFile file)
        {
            // Validate content type
            string[] allowedTypes = { "image/jpeg", "image/png", "image/gif" };
            if (!Array.Exists(allowedTypes, type => type == file.ContentType))
            {
                return BadRequest("Invalid file type");
            }
            
            // ok: unrestricted-file-upload-csharp-rule
            string safeFileName = DateTime.Now.Ticks + "_" + Guid.NewGuid().ToString().Substring(0, 8) + 
                Path.GetExtension(file.FileName);
            
            string path = Path.Combine(_environment.WebRootPath, "uploads", safeFileName);
            using (var stream = new FileStream(path, FileMode.Create))
            {
                file.CopyTo(stream);
            }
            
            return Ok(new { fileName = safeFileName });
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
        
        // Example 8: Using user ID with validation for organizing uploads
        [HttpPost("upload-to-user-folder")]
        public IActionResult good_case_8([FromForm] IFormFile file)
        {
            string userId = User.Identity.Name; // Authenticated user ID
            string originalExtension = Path.GetExtension(file.FileName);
            
            // Validate extension
            string[] allowedExtensions = { ".jpg", ".jpeg", ".png", ".pdf", ".docx" };
            if (!Array.Exists(allowedExtensions, ext => ext.Equals(originalExtension, StringComparison.OrdinalIgnoreCase)))
            {
                return BadRequest("Invalid file type");
            }
            
            // Create user directory if it doesn't exist
            string userDirectory = Path.Combine(_environment.WebRootPath, "uploads", userId);
            Directory.CreateDirectory(userDirectory);
            
            // ok: unrestricted-file-upload-csharp-rule
            string safeFileName = Guid.NewGuid().ToString() + originalExtension;
            string path = Path.Combine(userDirectory, safeFileName);
            
            using (var stream = new FileStream(path, FileMode.Create))
            {
                file.CopyTo(stream);
            }
            
            return Ok(new { fileName = safeFileName, path = $"/uploads/{userId}/{safeFileName}" });
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
        
        // Example 9: File size validation with secure filename
        [HttpPost("upload-with-size-limit")]
        public IActionResult good_case_9([FromForm] IFormFile file)
        {
            // Validate file size (5MB limit)
            if (file.Length > 5 * 1024 * 1024)
            {
                return BadRequest("File size exceeds the limit");
            }
            
            string originalExtension = Path.GetExtension(file.FileName);
            
            // ok: unrestricted-file-upload-csharp-rule
            string safeFileName = "upload_" + DateTime.Now.ToString("yyyyMMddHHmmss") + "_" + 
                Guid.NewGuid().ToString().Substring(0, 6) + originalExtension;
            
            string path = Path.Combine(_environment.WebRootPath, "uploads", safeFileName);
            using (var stream = new FileStream(path, FileMode.Create))
            {
                file.CopyTo(stream);
            }
            
            return Ok(new { fileName = safeFileName });
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
        
        // Example 10: Using content hash as filename
        [HttpPost("upload-with-hash")]
        public async Task<IActionResult> good_case_10([FromForm] IFormFile file)
        {
            // Calculate file hash for naming
            using (var memoryStream = new MemoryStream())
            {
                await file.CopyToAsync(memoryStream);
                memoryStream.Position = 0;
                
                using (var sha256 = SHA256.Create())
                {
                    byte[] hashBytes = sha256.ComputeHash(memoryStream);
                    string fileHash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                    string originalExtension = Path.GetExtension(file.FileName);
                    
                    // ok: unrestricted-file-upload-csharp-rule
                    string safeFileName = fileHash.Substring(0, 16) + originalExtension;
                    
                    // Reset stream position for saving
                    memoryStream.Position = 0;
                    string path = Path.Combine(_environment.WebRootPath, "uploads", safeFileName);
                    
                    using (var fileStream = new FileStream(path, FileMode.Create))
                    {
                        await memoryStream.CopyToAsync(fileStream);
                    }
                    
                    return Ok(new { fileName = safeFileName });
                }
            }
        }
// {/fact}
    }
    
    // Non-MVC secure examples
    public class SecureFileUploadService
    {
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
        // Example 11: Using HttpContext with secure filename
        public void good_case_11(HttpContext context)
        {
            var file = context.Request.Form.Files[0];
            string originalExtension = Path.GetExtension(file.FileName);
            
            // ok: unrestricted-file-upload-csharp-rule
            string safeFileName = Guid.NewGuid().ToString() + originalExtension;
            string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "uploads", safeFileName);
            
            using (var stream = new FileStream(path, FileMode.Create))
            {
                file.CopyTo(stream);
            }
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
        
        // Example 12: Using HttpRequest with content validation
        public void good_case_12(HttpRequest request)
        {
            var file = request.Form.Files[0];
            
            // Validate content type
            string[] allowedTypes = { "image/jpeg", "image/png", "application/pdf" };
            if (!Array.Exists(allowedTypes, type => type == file.ContentType))
            {
                throw new InvalidOperationException("Invalid file type");
            }
            
            string originalExtension = Path.GetExtension(file.FileName);
            
            // ok: unrestricted-file-upload-csharp-rule
            string safeFileName = "secure_" + DateTime.Now.Ticks + originalExtension;
            string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "uploads", safeFileName);
            
            using (var stream = new FileStream(path, FileMode.Create))
            {
                file.CopyTo(stream);
            }
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
        
        // Example 13: Using HttpClient with secure download name
        public async Task good_case_13(HttpContext context)
        {
            string fileUrl = context.Request.Form["fileUrl"];
            
            using (var httpClient = new HttpClient())
            {
                var response = await httpClient.GetAsync(fileUrl);
                response.EnsureSuccessStatusCode();
                
                // Extract original filename from content disposition if available
                string originalFileName = "download";
                if (response.Content.Headers.ContentDisposition != null)
                {
                    originalFileName = response.Content.Headers.ContentDisposition.FileName?.Trim('"') ?? "download";
                }
                
                string extension = Path.GetExtension(originalFileName);
                
                // ok: unrestricted-file-upload-csharp-rule
                string safeFileName = "download_" + Guid.NewGuid().ToString() + extension;
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "downloads", safeFileName);
                
                using (var fileStream = new FileStream(path, FileMode.Create))
                {
                    await response.Content.CopyToAsync(fileStream);
                }
            }
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
        
        // Example 14: Using Stream with secure filename
        public void good_case_14(HttpContext context)
        {
            var file = context.Request.Form.Files[0];
            string originalExtension = Path.GetExtension(file.FileName);
            
            // Validate extension
            string[] allowedExtensions = { ".jpg", ".jpeg", ".png", ".pdf" };
            if (!Array.Exists(allowedExtensions, ext => ext.Equals(originalExtension, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException("Invalid file type");
            }
            
            using (var memoryStream = new MemoryStream())
            {
                file.CopyTo(memoryStream);
                byte[] fileBytes = memoryStream.ToArray();
                
                // ok: unrestricted-file-upload-csharp-rule
                string safeFileName = "file_" + DateTime.Now.ToString("yyyyMMddHHmmss") + originalExtension;
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "uploads", safeFileName);
                
                File.WriteAllBytes(path, fileBytes);
            }
        }
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
        
        // Example 15: Using FileInfo with secure filename
        public void good_case_15(HttpContext context)
        {
            var file = context.Request.Form.Files[0];
            
            // Generate a random filename with original extension
            string originalExtension = Path.GetExtension(file.FileName);
            
            // ok: unrestricted-file-upload-csharp-rule
            string safeFileName = Path.GetRandomFileName() + originalExtension;
            string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "uploads", safeFileName);
            
            FileInfo fileInfo = new FileInfo(path);
            Directory.CreateDirectory(fileInfo.DirectoryName);
            
            using (var stream = fileInfo.Create())
            {
                file.CopyTo(stream);
            }
        }
// {/fact}
    }
    
    public class UploadModel
    {
        public string FileName { get; set; }
    }
}