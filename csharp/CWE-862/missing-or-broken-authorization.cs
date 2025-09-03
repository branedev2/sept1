using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;

// TRUE POSITIVES (Vulnerable Code)

// Example 1: Controller with no authorization for sensitive data
public class bad_case_1 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=1}
    
    public bad_case_1(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ruleid: missing-or-broken-authorization
    [HttpGet("api/users/{id}")]
    public async Task<IActionResult> GetUserDetails(int id)
    {
        var user = await _context.Users.FindAsync(id);
        
        if (user == null)
        {
            return NotFound();
        }
        
        return Ok(user);
    }
}

// Example 2: Admin functionality without authorization check
public class bad_case_2 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=1}
    
    public bad_case_2(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ruleid: missing-or-broken-authorization
    [HttpPost("api/users/delete/{id}")]
    public async Task<IActionResult> DeleteUser(int id)
    {
        var user = await _context.Users.FindAsync(id);
        
        if (user == null)
        {
            return NotFound();
        }
        
        _context.Users.Remove(user);
        await _context.SaveChangesAsync();
        
        return NoContent();
    }
}

// Example 3: Financial transaction without authorization
public class bad_case_3 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=1}
    
    public bad_case_3(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ruleid: missing-or-broken-authorization
    [HttpPost("api/accounts/transfer")]
    public async Task<IActionResult> TransferFunds([FromBody] TransferRequest request)
    {
        var sourceAccount = await _context.Accounts.FindAsync(request.SourceAccountId);
        var targetAccount = await _context.Accounts.FindAsync(request.TargetAccountId);
        
        if (sourceAccount == null || targetAccount == null)
        {
            return NotFound("One or both accounts not found");
        }
        
        sourceAccount.Balance -= request.Amount;
        targetAccount.Balance += request.Amount;
        
        await _context.SaveChangesAsync();
        
        return Ok(new { Message = "Transfer successful" });
    }
}

// Example 4: API endpoint with broken authorization (only checking if user is authenticated)
public class bad_case_4 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=1}
    
    public bad_case_4(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ruleid: missing-or-broken-authorization
    [HttpGet("api/reports/sensitive")]
    [Authorize] // Only checks if user is authenticated, not if they have the right role
    public async Task<IActionResult> GetSensitiveReports()
    {
        var reports = await _context.SensitiveReports.ToListAsync();
        return Ok(reports);
    }
}

// Example 5: Missing authorization for document access
public class bad_case_5 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=1}
    
    public bad_case_5(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ruleid: missing-or-broken-authorization
    [HttpGet("api/documents/{id}")]
    public async Task<IActionResult> GetDocument(int id)
    {
        var document = await _context.Documents.FindAsync(id);
        
        if (document == null)
        {
            return NotFound();
        }
        
        return Ok(document);
    }
}

// Example 6: Missing authorization in API endpoint that modifies data
public class bad_case_6 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=1}
    
    public bad_case_6(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ruleid: missing-or-broken-authorization
    [HttpPut("api/products/{id}")]
    public async Task<IActionResult> UpdateProduct(int id, [FromBody] Product product)
    {
        if (id != product.Id)
        {
            return BadRequest();
        }
        
        _context.Entry(product).State = EntityState.Modified;
        await _context.SaveChangesAsync();
        
        return NoContent();
    }
}

// Example 7: Missing authorization in a settings controller
public class bad_case_7 : Controller
{
    private readonly IConfiguration _configuration;
// {fact rule=missing-authorization@v1.0 defects=1}
    
    public bad_case_7(IConfiguration configuration)
    {
        _configuration = configuration;
    }
// {/fact}
    
    // ruleid: missing-or-broken-authorization
    [HttpPost("api/settings/update")]
    public IActionResult UpdateSettings([FromBody] Dictionary<string, string> settings)
    {
        foreach (var setting in settings)
        {
            // Updating application settings without authorization
            // This is a simplified example - in reality, this would use a configuration provider
            Console.WriteLine($"Updating setting {setting.Key} to {setting.Value}");
        }
        
        return Ok(new { Message = "Settings updated" });
    }
}

// Example 8: Missing authorization in a file upload endpoint
public class bad_case_8 : Controller
{
    private readonly string _uploadPath;
// {fact rule=missing-authorization@v1.0 defects=1}
    
    public bad_case_8(IConfiguration configuration)
    {
        _uploadPath = configuration["UploadPath"];
    }
// {/fact}
    
    // ruleid: missing-or-broken-authorization
    [HttpPost("api/files/upload")]
    public async Task<IActionResult> UploadFile(IFormFile file)
    {
        if (file == null || file.Length == 0)
        {
            return BadRequest("No file uploaded");
        }
        
        var filePath = System.IO.Path.Combine(_uploadPath, file.FileName);
        
        using (var stream = new System.IO.FileStream(filePath, System.IO.FileMode.Create))
        {
            await file.CopyToAsync(stream);
        }
        
        return Ok(new { filePath });
    }
}

// Example 9: Missing authorization in an endpoint that returns all users
public class bad_case_9 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=1}
    
    public bad_case_9(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ruleid: missing-or-broken-authorization
    [HttpGet("api/users")]
    public async Task<IActionResult> GetAllUsers()
    {
        var users = await _context.Users.ToListAsync();
        return Ok(users);
    }
}

// Example 10: Missing authorization in a password reset endpoint
public class bad_case_10 : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
// {fact rule=missing-authorization@v1.0 defects=1}
    
    public bad_case_10(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }
// {/fact}
    
    // ruleid: missing-or-broken-authorization
    [HttpPost("api/users/reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        
        if (user == null)
        {
            return NotFound();
        }
        
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var result = await _userManager.ResetPasswordAsync(user, token, request.NewPassword);
        
        if (result.Succeeded)
        {
            return Ok(new { Message = "Password reset successful" });
        }
        
        return BadRequest(result.Errors);
    }
}

// Example 11: Missing authorization in an API that exposes personal data
public class bad_case_11 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=1}
    
    public bad_case_11(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ruleid: missing-or-broken-authorization
    [HttpGet("api/employees/{id}/salary")]
    public async Task<IActionResult> GetEmployeeSalary(int id)
    {
        var employee = await _context.Employees.FindAsync(id);
        
        if (employee == null)
        {
            return NotFound();
        }
        
        return Ok(new { Salary = employee.Salary });
    }
}

// Example 12: Missing authorization in an API that modifies system configuration
public class bad_case_12 : Controller
{
    private readonly IConfiguration _configuration;
// {fact rule=missing-authorization@v1.0 defects=1}
    
    public bad_case_12(IConfiguration configuration)
    {
        _configuration = configuration;
    }
// {/fact}
    
    // ruleid: missing-or-broken-authorization
    [HttpPost("api/system/maintenance-mode")]
    public IActionResult SetMaintenanceMode([FromBody] bool enabled)
    {
        // Setting system-wide maintenance mode without authorization
        Console.WriteLine($"Setting maintenance mode to {enabled}");
        
        return Ok(new { MaintenanceModeEnabled = enabled });
    }
}

// Example 13: Missing authorization in an API that creates new users
public class bad_case_13 : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
// {fact rule=missing-authorization@v1.0 defects=1}
    
    public bad_case_13(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }
// {/fact}
    
    // ruleid: missing-or-broken-authorization
    [HttpPost("api/users/create")]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
    {
        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email
        };
        
        var result = await _userManager.CreateAsync(user, request.Password);
        
        if (result.Succeeded)
        {
            return Ok(new { UserId = user.Id });
        }
        
        return BadRequest(result.Errors);
    }
}

// Example 14: Missing authorization in an API that deletes data
public class bad_case_14 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=1}
    
    public bad_case_14(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ruleid: missing-or-broken-authorization
    [HttpDelete("api/orders/{id}")]
    public async Task<IActionResult> DeleteOrder(int id)
    {
        var order = await _context.Orders.FindAsync(id);
        
        if (order == null)
        {
            return NotFound();
        }
        
        _context.Orders.Remove(order);
        await _context.SaveChangesAsync();
        
        return NoContent();
    }
}

// Example 15: Missing authorization in an API that exports data
public class bad_case_15 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=1}
    
    public bad_case_15(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ruleid: missing-or-broken-authorization
    [HttpGet("api/data/export")]
    public async Task<IActionResult> ExportData()
    {
        var data = await _context.SensitiveData.ToListAsync();
        
        // Convert to CSV or another export format
        var exportData = ConvertToExportFormat(data);
        
        return File(exportData, "application/octet-stream", "export.csv");
    }
    
    private byte[] ConvertToExportFormat(List<SensitiveData> data)
    {
        // Implementation of export conversion
        return System.Text.Encoding.UTF8.GetBytes("Exported data");
    }
}

// TRUE NEGATIVES (Secure Code)

// Example 1: Controller with proper role-based authorization
public class good_case_1 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=0}
    
    public good_case_1(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ok: missing-or-broken-authorization
    [HttpGet("api/users/{id}")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetUserDetails(int id)
    {
        var user = await _context.Users.FindAsync(id);
        
        if (user == null)
        {
            return NotFound();
        }
        
        return Ok(user);
    }
}

// Example 2: Admin functionality with proper authorization
public class good_case_2 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=0}
    
    public good_case_2(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ok: missing-or-broken-authorization
    [HttpPost("api/users/delete/{id}")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> DeleteUser(int id)
    {
        var user = await _context.Users.FindAsync(id);
        
        if (user == null)
        {
            return NotFound();
        }
        
        _context.Users.Remove(user);
        await _context.SaveChangesAsync();
        
        return NoContent();
    }
}

// Example 3: Financial transaction with proper authorization
public class good_case_3 : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
// {fact rule=missing-authorization@v1.0 defects=0}
    
    public good_case_3(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
    {
        _context = context;
        _userManager = userManager;
    }
// {/fact}
    
    // ok: missing-or-broken-authorization
    [HttpPost("api/accounts/transfer")]
    [Authorize]
    public async Task<IActionResult> TransferFunds([FromBody] TransferRequest request)
    {
        // Get the current user
        var user = await _userManager.GetUserAsync(User);
        var sourceAccount = await _context.Accounts.FindAsync(request.SourceAccountId);
        
        if (sourceAccount == null)
        {
            return NotFound("Source account not found");
        }
        
        // Check if the current user owns the source account
        if (sourceAccount.UserId != user.Id)
        {
            return Forbid();
        }
        
        var targetAccount = await _context.Accounts.FindAsync(request.TargetAccountId);
        
        if (targetAccount == null)
        {
            return NotFound("Target account not found");
        }
        
        sourceAccount.Balance -= request.Amount;
        targetAccount.Balance += request.Amount;
        
        await _context.SaveChangesAsync();
        
        return Ok(new { Message = "Transfer successful" });
    }
}

// Example 4: API endpoint with proper role-based authorization
public class good_case_4 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=0}
    
    public good_case_4(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ok: missing-or-broken-authorization
    [HttpGet("api/reports/sensitive")]
    [Authorize(Roles = "Admin,Manager")]
    public async Task<IActionResult> GetSensitiveReports()
    {
        var reports = await _context.SensitiveReports.ToListAsync();
        return Ok(reports);
    }
}

// Example 5: Document access with proper authorization
public class good_case_5 : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
// {fact rule=missing-authorization@v1.0 defects=0}
    
    public good_case_5(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
    {
        _context = context;
        _userManager = userManager;
    }
// {/fact}
    
    // ok: missing-or-broken-authorization
    [HttpGet("api/documents/{id}")]
    [Authorize]
    public async Task<IActionResult> GetDocument(int id)
    {
        var document = await _context.Documents.FindAsync(id);
        
        if (document == null)
        {
            return NotFound();
        }
        
        // Get the current user
        var user = await _userManager.GetUserAsync(User);
        
        // Check if the user has access to this document
        if (document.OwnerId != user.Id && !User.IsInRole("Admin"))
        {
            return Forbid();
        }
        
        return Ok(document);
    }
}

// Example 6: API endpoint with proper authorization for data modification
public class good_case_6 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=0}
    
    public good_case_6(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ok: missing-or-broken-authorization
    [HttpPut("api/products/{id}")]
    [Authorize(Roles = "Admin,ProductManager")]
    public async Task<IActionResult> UpdateProduct(int id, [FromBody] Product product)
    {
        if (id != product.Id)
        {
            return BadRequest();
        }
        
        _context.Entry(product).State = EntityState.Modified;
        await _context.SaveChangesAsync();
        
        return NoContent();
    }
}

// Example 7: Settings controller with proper authorization
public class good_case_7 : Controller
{
    private readonly IConfiguration _configuration;
// {fact rule=missing-authorization@v1.0 defects=0}
    
    public good_case_7(IConfiguration configuration)
    {
        _configuration = configuration;
    }
// {/fact}
    
    // ok: missing-or-broken-authorization
    [HttpPost("api/settings/update")]
    [Authorize(Roles = "Admin")]
    public IActionResult UpdateSettings([FromBody] Dictionary<string, string> settings)
    {
        foreach (var setting in settings)
        {
            // Updating application settings with proper authorization
            Console.WriteLine($"Updating setting {setting.Key} to {setting.Value}");
        }
        
        return Ok(new { Message = "Settings updated" });
    }
}

// Example 8: File upload with proper authorization
public class good_case_8 : Controller
{
    private readonly string _uploadPath;
// {fact rule=missing-authorization@v1.0 defects=0}
    
    public good_case_8(IConfiguration configuration)
    {
        _uploadPath = configuration["UploadPath"];
    }
// {/fact}
    
    // ok: missing-or-broken-authorization
    [HttpPost("api/files/upload")]
    [Authorize]
    public async Task<IActionResult> UploadFile(IFormFile file)
    {
        if (file == null || file.Length == 0)
        {
            return BadRequest("No file uploaded");
        }
        
        // Create a unique filename to prevent overwriting
        var fileName = $"{Guid.NewGuid()}_{file.FileName}";
        var filePath = System.IO.Path.Combine(_uploadPath, fileName);
        
        using (var stream = new System.IO.FileStream(filePath, System.IO.FileMode.Create))
        {
            await file.CopyToAsync(stream);
        }
        
        // Store the file metadata with the current user's ID
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        
        return Ok(new { filePath, userId });
    }
}

// Example 9: Endpoint that returns users with proper authorization
public class good_case_9 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=0}
    
    public good_case_9(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ok: missing-or-broken-authorization
    [HttpGet("api/users")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetAllUsers()
    {
        var users = await _context.Users.ToListAsync();
        return Ok(users);
    }
}

// Example 10: Password reset with proper authorization
public class good_case_10 : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
// {fact rule=missing-authorization@v1.0 defects=0}
    
    public good_case_10(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }
// {/fact}
    
    // ok: missing-or-broken-authorization
    [HttpPost("api/users/reset-password")]
    [Authorize]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        // Get the current user
        var user = await _userManager.GetUserAsync(User);
        
        // Ensure the user can only reset their own password unless they're an admin
        if (user.Email != request.Email && !User.IsInRole("Admin"))
        {
            return Forbid();
        }
        
        var userToReset = await _userManager.FindByEmailAsync(request.Email);
        
        if (userToReset == null)
        {
            return NotFound();
        }
        
        var token = await _userManager.GeneratePasswordResetTokenAsync(userToReset);
        var result = await _userManager.ResetPasswordAsync(userToReset, token, request.NewPassword);
        
        if (result.Succeeded)
        {
            return Ok(new { Message = "Password reset successful" });
        }
        
        return BadRequest(result.Errors);
    }
}

// Example 11: API that exposes personal data with proper authorization
public class good_case_11 : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
// {fact rule=missing-authorization@v1.0 defects=0}
    
    public good_case_11(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
    {
        _context = context;
        _userManager = userManager;
    }
// {/fact}
    
    // ok: missing-or-broken-authorization
    [HttpGet("api/employees/{id}/salary")]
    [Authorize]
    public async Task<IActionResult> GetEmployeeSalary(int id)
    {
        var employee = await _context.Employees.FindAsync(id);
        
        if (employee == null)
        {
            return NotFound();
        }
        
        // Get the current user
        var user = await _userManager.GetUserAsync(User);
        
        // Check if the current user is the employee, their manager, or HR/Admin
        if (employee.UserId != user.Id && 
            employee.ManagerId != user.Id && 
            !User.IsInRole("HR") && 
            !User.IsInRole("Admin"))
        {
            return Forbid();
        }
        
        return Ok(new { Salary = employee.Salary });
    }
}

// Example 12: API that modifies system configuration with proper authorization
public class good_case_12 : Controller
{
    private readonly IConfiguration _configuration;
// {fact rule=missing-authorization@v1.0 defects=0}
    
    public good_case_12(IConfiguration configuration)
    {
        _configuration = configuration;
    }
// {/fact}
    
    // ok: missing-or-broken-authorization
    [HttpPost("api/system/maintenance-mode")]
    [Authorize(Roles = "Admin,SystemOperator")]
    public IActionResult SetMaintenanceMode([FromBody] bool enabled)
    {
        // Setting system-wide maintenance mode with proper authorization
        Console.WriteLine($"Setting maintenance mode to {enabled}");
        
        // Log who made the change
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        Console.WriteLine($"Maintenance mode changed by user {userId}");
        
        return Ok(new { MaintenanceModeEnabled = enabled });
    }
}

// Example 13: API that creates new users with proper authorization
public class good_case_13 : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
// {fact rule=missing-authorization@v1.0 defects=0}
    
    public good_case_13(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }
// {/fact}
    
    // ok: missing-or-broken-authorization
    [HttpPost("api/users/create")]
    [Authorize(Roles = "Admin,UserManager")]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
    {
        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email
        };
        
        var result = await _userManager.CreateAsync(user, request.Password);
        
        if (result.Succeeded)
        {
            // Log who created the user
            var adminId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            Console.WriteLine($"User {user.Id} created by admin {adminId}");
            
            return Ok(new { UserId = user.Id });
        }
        
        return BadRequest(result.Errors);
    }
}

// Example 14: API that deletes data with proper authorization
public class good_case_14 : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
// {fact rule=missing-authorization@v1.0 defects=0}
    
    public good_case_14(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
    {
        _context = context;
        _userManager = userManager;
    }
// {/fact}
    
    // ok: missing-or-broken-authorization
    [HttpDelete("api/orders/{id}")]
    [Authorize]
    public async Task<IActionResult> DeleteOrder(int id)
    {
        var order = await _context.Orders.FindAsync(id);
        
        if (order == null)
        {
            return NotFound();
        }
        
        // Get the current user
        var user = await _userManager.GetUserAsync(User);
        
        // Check if the user owns this order or is an admin
        if (order.UserId != user.Id && !User.IsInRole("Admin"))
        {
            return Forbid();
        }
        
        _context.Orders.Remove(order);
        await _context.SaveChangesAsync();
        
        return NoContent();
    }
}

// Example 15: API that exports data with proper authorization
public class good_case_15 : Controller
{
    private readonly ApplicationDbContext _context;
// {fact rule=missing-authorization@v1.0 defects=0}
    
    public good_case_15(ApplicationDbContext context)
    {
        _context = context;
    }
// {/fact}
    
    // ok: missing-or-broken-authorization
    [HttpGet("api/data/export")]
    [Authorize(Roles = "Admin,DataAnalyst")]
    public async Task<IActionResult> ExportData()
    {
        var data = await _context.SensitiveData.ToListAsync();
        
        // Convert to CSV or another export format
        var exportData = ConvertToExportFormat(data);
        
        // Log the export operation
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        Console.WriteLine($"Data exported by user {userId}");
        
        return File(exportData, "application/octet-stream", "export.csv");
    }
    
    private byte[] ConvertToExportFormat(List<SensitiveData> data)
    {
        // Implementation of export conversion
        return System.Text.Encoding.UTF8.GetBytes("Exported data");
    }
}

// Supporting classes for the examples
public class ApplicationDbContext : DbContext
{
    public DbSet<ApplicationUser> Users { get; set; }
    public DbSet<Account> Accounts { get; set; }
    public DbSet<SensitiveReport> SensitiveReports { get; set; }
    public DbSet<Document> Documents { get; set; }
    public DbSet<Product> Products { get; set; }
    public DbSet<SensitiveData> SensitiveData { get; set; }
    public DbSet<Order> Orders { get; set; }
    public DbSet<Employee> Employees { get; set; }
}

public class ApplicationUser
{
    public string Id { get; set; }
    public string UserName { get; set; }
    public string Email { get; set; }
}

public class Account
{
    public int Id { get; set; }
    public string UserId { get; set; }
    public decimal Balance { get; set; }
}

public class TransferRequest
{
    public int SourceAccountId { get; set; }
    public int TargetAccountId { get; set; }
    public decimal Amount { get; set; }
}

public class SensitiveReport
{
    public int Id { get; set; }
    public string Content { get; set; }
}

public class Document
{
    public int Id { get; set; }
    public string OwnerId { get; set; }
    public string Content { get; set; }
}

public class Product
{
    public int Id { get; set; }
    public string Name { get; set; }
    public decimal Price { get; set; }
}

public class ResetPasswordRequest
{
    public string Email { get; set; }
    public string NewPassword { get; set; }
}

public class CreateUserRequest
{
    public string Email { get; set; }
    public string Password { get; set; }
}

public class SensitiveData
{
    public int Id { get; set; }
    public string Data { get; set; }
}

public class Order
{
    public int Id { get; set; }
    public string UserId { get; set; }
    public decimal Total { get; set; }
}

public class Employee
{
    public int Id { get; set; }
    public string UserId { get; set; }
    public string ManagerId { get; set; }
    public decimal Salary { get; set; }
}