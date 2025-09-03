using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System.Net.Http.Headers;

// Database context for examples
public class ApplicationDbContext : DbContext
{
    public DbSet<User> Users { get; set; }
    public DbSet<Product> Products { get; set; }
    public DbSet<Order> Orders { get; set; }
    
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.UseSqlServer("Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;");
    }
}

// Models for examples
public class User
{
    public int Id { get; set; }
    public string Name { get; set; }
    public string Email { get; set; }
}

public class Product
{
    public int Id { get; set; }
    public string Name { get; set; }
    public decimal Price { get; set; }
}

public class Order
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public DateTime OrderDate { get; set; }
    public decimal TotalAmount { get; set; }
}

public class PaginatedList<T>
{
    public List<T> Items { get; set; }
    public int PageIndex { get; set; }
    public int TotalPages { get; set; }
    public int TotalCount { get; set; }
    
    public PaginatedList(List<T> items, int count, int pageIndex, int pageSize)
    {
        PageIndex = pageIndex;
        TotalPages = (int)Math.Ceiling(count / (double)pageSize);
        TotalCount = count;
        Items = items;
    }
    
    public bool HasPreviousPage => PageIndex > 1;
    public bool HasNextPage => PageIndex < TotalPages;
}

// Controller with examples
[ApiController]
[Route("api/[controller]")]
public class ExamplesController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly HttpClient _httpClient;
    
    public ExamplesController(ApplicationDbContext context)
    {
        _context = context;
        _httpClient = new HttpClient();
    }
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    
    // True Positive Examples (Vulnerable Code)
    
    [HttpGet("bad_case_1")]
    public IActionResult bad_case_1()
    {
        // ruleid: csharp_missing_pagination
        var users = _context.Users.ToList();
        return Ok(users);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    
    [HttpGet("bad_case_2")]
    public async Task<IActionResult> bad_case_2()
    {
        // ruleid: csharp_missing_pagination
        var response = await _httpClient.GetAsync("https://api.example.com/users");
        var content = await response.Content.ReadAsStringAsync();
        var users = JsonConvert.DeserializeObject<List<User>>(content);
        return Ok(users);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    
    [HttpGet("bad_case_3")]
    public IActionResult bad_case_3()
    {
        // ruleid: csharp_missing_pagination
        var products = _context.Products
            .Where(p => p.Price > 10)
            .OrderBy(p => p.Name)
            .ToList();
        return Ok(products);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    
    [HttpGet("bad_case_4")]
    public async Task<IActionResult> bad_case_4()
    {
        string apiUrl = "https://api.github.com/repos/octocat/hello-world/issues";
        _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("MyApp", "1.0"));
        
        // ruleid: csharp_missing_pagination
        var response = await _httpClient.GetAsync(apiUrl);
        var content = await response.Content.ReadAsStringAsync();
        var issues = JsonConvert.DeserializeObject<List<dynamic>>(content);
        return Ok(issues);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    
    [HttpGet("bad_case_5")]
    public IActionResult bad_case_5([FromQuery] string category)
    {
        // ruleid: csharp_missing_pagination
        var filteredProducts = _context.Products
            .Where(p => p.Name.Contains(category))
            .ToList();
        return Ok(filteredProducts);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    
    [HttpGet("bad_case_6")]
    public IActionResult bad_case_6([FromQuery] int userId)
    {
        // ruleid: csharp_missing_pagination
        var orders = _context.Orders
            .Where(o => o.UserId == userId)
            .OrderByDescending(o => o.OrderDate)
            .ToList();
        return Ok(orders);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    
    [HttpGet("bad_case_7")]
    public async Task<IActionResult> bad_case_7()
    {
        // ruleid: csharp_missing_pagination
        using (var connection = new System.Data.SqlClient.SqlConnection("connection_string"))
        {
            await connection.OpenAsync();
            var command = new System.Data.SqlClient.SqlCommand("SELECT * FROM Users", connection);
            var reader = await command.ExecuteReaderAsync();
            var users = new List<User>();
            
            while (await reader.ReadAsync())
            {
                users.Add(new User
                {
                    Id = reader.GetInt32(0),
                    Name = reader.GetString(1),
                    Email = reader.GetString(2)
                });
            }
            
            return Ok(users);
        }
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    
    [HttpGet("bad_case_8")]
    public IActionResult bad_case_8([FromQuery] string searchTerm)
    {
        if (string.IsNullOrEmpty(searchTerm))
        {
            return BadRequest("Search term is required");
        }
        
        // ruleid: csharp_missing_pagination
        var searchResults = _context.Products
            .Where(p => p.Name.Contains(searchTerm))
            .ToList();
        
        return Ok(searchResults);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    
    [HttpGet("bad_case_9")]
    public async Task<IActionResult> bad_case_9()
    {
        // ruleid: csharp_missing_pagination
        var allOrders = await _context.Orders
            .Include(o => o.User)
            .ToListAsync();
            
        return Ok(allOrders);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    
    [HttpGet("bad_case_10")]
    public async Task<IActionResult> bad_case_10([FromQuery] DateTime startDate, [FromQuery] DateTime endDate)
    {
        // ruleid: csharp_missing_pagination
        var orders = await _context.Orders
            .Where(o => o.OrderDate >= startDate && o.OrderDate <= endDate)
            .ToListAsync();
            
        return Ok(orders);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    
    [HttpGet("bad_case_11")]
    public IActionResult bad_case_11()
    {
        // ruleid: csharp_missing_pagination
        var result = (from u in _context.Users
                     join o in _context.Orders on u.Id equals o.UserId
                     select new { User = u, Order = o })
                    .ToList();
                    
        return Ok(result);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    
    [HttpGet("bad_case_12")]
    public async Task<IActionResult> bad_case_12()
    {
        string apiUrl = "https://api.example.com/products";
        
        // ruleid: csharp_missing_pagination
        List<Product> allProducts = new List<Product>();
        var response = await _httpClient.GetAsync(apiUrl);
        
        if (response.IsSuccessStatusCode)
        {
            var content = await response.Content.ReadAsStringAsync();
            var products = JsonConvert.DeserializeObject<List<Product>>(content);
            allProducts.AddRange(products);
        }
        
        return Ok(allProducts);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    
    [HttpGet("bad_case_13")]
    public IActionResult bad_case_13([FromQuery] decimal minPrice)
    {
        // ruleid: csharp_missing_pagination
        var expensiveProducts = _context.Products
            .Where(p => p.Price >= minPrice)
            .OrderByDescending(p => p.Price)
            .ToList();
            
        return Ok(expensiveProducts);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    
    [HttpGet("bad_case_14")]
    public async Task<IActionResult> bad_case_14()
    {
        // ruleid: csharp_missing_pagination
        var users = await _context.Users
            .Where(u => u.Email.EndsWith("@example.com"))
            .ToListAsync();
            
        return Ok(users);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    
    [HttpGet("bad_case_15")]
    public async Task<IActionResult> bad_case_15([FromQuery] string category)
    {
        // ruleid: csharp_missing_pagination
        using (var connection = new System.Data.SqlClient.SqlConnection("connection_string"))
        {
            await connection.OpenAsync();
            var command = new System.Data.SqlClient.SqlCommand(
                $"SELECT * FROM Products WHERE Category = '{category}'", 
                connection);
                
            var reader = await command.ExecuteReaderAsync();
            var products = new List<Product>();
            
            while (await reader.ReadAsync())
            {
                products.Add(new Product
                {
                    Id = reader.GetInt32(0),
                    Name = reader.GetString(1),
                    Price = reader.GetDecimal(2)
                });
            }
            
            return Ok(products);
        }
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
    
    // True Negative Examples (Safe Code)
    
    [HttpGet("good_case_1")]
    public IActionResult good_case_1([FromQuery] int page = 1, [FromQuery] int pageSize = 10)
    {
        // ok: csharp_missing_pagination
        var users = _context.Users
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();
            
        var totalCount = _context.Users.Count();
        var result = new PaginatedList<User>(users, totalCount, page, pageSize);
        
        return Ok(result);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
    
    [HttpGet("good_case_2")]
    public async Task<IActionResult> good_case_2([FromQuery] int page = 1, [FromQuery] int pageSize = 10)
    {
        string apiUrl = $"https://api.example.com/users?page={page}&pageSize={pageSize}";
        
        // ok: csharp_missing_pagination
        var response = await _httpClient.GetAsync(apiUrl);
        var content = await response.Content.ReadAsStringAsync();
        var paginatedResponse = JsonConvert.DeserializeObject<PaginatedList<User>>(content);
        
        return Ok(paginatedResponse);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
    
    [HttpGet("good_case_3")]
    public IActionResult good_case_3([FromQuery] int page = 1, [FromQuery] int pageSize = 10, [FromQuery] decimal minPrice = 0)
    {
        var query = _context.Products.Where(p => p.Price > minPrice);
        var totalCount = query.Count();
        
        // ok: csharp_missing_pagination
        var products = query
            .OrderBy(p => p.Name)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();
            
        var result = new PaginatedList<Product>(products, totalCount, page, pageSize);
        return Ok(result);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
    
    [HttpGet("good_case_4")]
    public async Task<IActionResult> good_case_4([FromQuery] int page = 1)
    {
        string apiUrl = $"https://api.github.com/repos/octocat/hello-world/issues?page={page}&per_page=30";
        _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("MyApp", "1.0"));
        
        // ok: csharp_missing_pagination
        var response = await _httpClient.GetAsync(apiUrl);
        var content = await response.Content.ReadAsStringAsync();
        var issues = JsonConvert.DeserializeObject<List<dynamic>>(content);
        
        // Check for next page link in headers
        var hasNextPage = response.Headers.Contains("Link") && 
                         response.Headers.GetValues("Link").First().Contains("rel=\"next\"");
        
        return Ok(new { 
            Issues = issues, 
            CurrentPage = page, 
            HasNextPage = hasNextPage 
        });
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
    
    [HttpGet("good_case_5")]
    public IActionResult good_case_5([FromQuery] string category, [FromQuery] int page = 1, [FromQuery] int pageSize = 10)
    {
        var query = _context.Products.Where(p => p.Name.Contains(category));
        var totalCount = query.Count();
        
        // ok: csharp_missing_pagination
        var filteredProducts = query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();
            
        var result = new PaginatedList<Product>(filteredProducts, totalCount, page, pageSize);
        return Ok(result);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
    
    [HttpGet("good_case_6")]
    public IActionResult good_case_6([FromQuery] int userId, [FromQuery] int page = 1, [FromQuery] int pageSize = 10)
    {
        var query = _context.Orders.Where(o => o.UserId == userId);
        var totalCount = query.Count();
        
        // ok: csharp_missing_pagination
        var orders = query
            .OrderByDescending(o => o.OrderDate)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();
            
        var result = new PaginatedList<Order>(orders, totalCount, page, pageSize);
        return Ok(result);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
    
    [HttpGet("good_case_7")]
    public async Task<IActionResult> good_case_7([FromQuery] int page = 1, [FromQuery] int pageSize = 10)
    {
        // ok: csharp_missing_pagination
        using (var connection = new System.Data.SqlClient.SqlConnection("connection_string"))
        {
            await connection.OpenAsync();
            
            // Get total count
            var countCommand = new System.Data.SqlClient.SqlCommand("SELECT COUNT(*) FROM Users", connection);
            var totalCount = Convert.ToInt32(await countCommand.ExecuteScalarAsync());
            
            // Get paginated data
            var offset = (page - 1) * pageSize;
            var dataCommand = new System.Data.SqlClient.SqlCommand(
                $"SELECT * FROM Users ORDER BY Id OFFSET {offset} ROWS FETCH NEXT {pageSize} ROWS ONLY", 
                connection);
                
            var reader = await dataCommand.ExecuteReaderAsync();
            var users = new List<User>();
            
            while (await reader.ReadAsync())
            {
                users.Add(new User
                {
                    Id = reader.GetInt32(0),
                    Name = reader.GetString(1),
                    Email = reader.GetString(2)
                });
            }
            
            var result = new PaginatedList<User>(users, totalCount, page, pageSize);
            return Ok(result);
        }
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
    
    [HttpGet("good_case_8")]
    public IActionResult good_case_8([FromQuery] string searchTerm, [FromQuery] int page = 1, [FromQuery] int pageSize = 10)
    {
        if (string.IsNullOrEmpty(searchTerm))
        {
            return BadRequest("Search term is required");
        }
        
        var query = _context.Products.Where(p => p.Name.Contains(searchTerm));
        var totalCount = query.Count();
        
        // ok: csharp_missing_pagination
        var searchResults = query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();
        
        var result = new PaginatedList<Product>(searchResults, totalCount, page, pageSize);
        return Ok(result);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
    
    [HttpGet("good_case_9")]
    public async Task<IActionResult> good_case_9([FromQuery] int page = 1, [FromQuery] int pageSize = 10)
    {
        var totalCount = await _context.Orders.CountAsync();
        
        // ok: csharp_missing_pagination
        var orders = await _context.Orders
            .Include(o => o.User)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
            
        var result = new PaginatedList<Order>(orders, totalCount, page, pageSize);
        return Ok(result);
    }
// {/fact}
    
    [HttpGet("good_case_10")]
    public async Task<IActionResult> good_case_10(
        [FromQuery] DateTime startDate, 
        [FromQuery] DateTime endDate, 
        [FromQuery] int page = 1, 
        [FromQuery] int pageSize = 10)
    {
        var query = _context.Orders.Where(o => o.OrderDate >= startDate && o.OrderDate <= endDate);
        var totalCount = await query.CountAsync();
        
        // ok: csharp_missing_pagination
        var orders = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
            
        var result = new PaginatedList<Order>(orders, totalCount, page, pageSize);
        return Ok(result);
    }
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
    
    [HttpGet("good_case_11")]
    public IActionResult good_case_11([FromQuery] int page = 1, [FromQuery] int pageSize = 10)
    {
        var query = from u in _context.Users
                   join o in _context.Orders on u.Id equals o.UserId
                   select new { User = u, Order = o };
                   
        var totalCount = query.Count();
        
        // ok: csharp_missing_pagination
        var result = query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();
                    
        var paginatedResult = new
        {
            Items = result,
            TotalCount = totalCount,
            PageIndex = page,
            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize),
            HasPreviousPage = page > 1,
            HasNextPage = page < (int)Math.Ceiling(totalCount / (double)pageSize)
        };
        
        return Ok(paginatedResult);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
    
    [HttpGet("good_case_12")]
    public async Task<IActionResult> good_case_12([FromQuery] int maxPages = 5)
    {
        string baseApiUrl = "https://api.example.com/products";
        List<Product> allProducts = new List<Product>();
        int currentPage = 1;
        
        // ok: csharp_missing_pagination
        while (currentPage <= maxPages)
        {
            string apiUrl = $"{baseApiUrl}?page={currentPage}&pageSize=100";
            var response = await _httpClient.GetAsync(apiUrl);
            
            if (!response.IsSuccessStatusCode)
                break;
                
            var content = await response.Content.ReadAsStringAsync();
            var paginatedResponse = JsonConvert.DeserializeObject<PaginatedList<Product>>(content);
            
            if (paginatedResponse.Items.Count == 0)
                break;
                
            allProducts.AddRange(paginatedResponse.Items);
            
            if (!paginatedResponse.HasNextPage)
                break;
                
            currentPage++;
        }
        
        return Ok(new { 
            Products = allProducts, 
            TotalCount = allProducts.Count,
            PagesProcessed = currentPage
        });
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
    
    [HttpGet("good_case_13")]
    public IActionResult good_case_13([FromQuery] decimal minPrice, [FromQuery] int page = 1, [FromQuery] int pageSize = 10)
    {
        var query = _context.Products.Where(p => p.Price >= minPrice);
        var totalCount = query.Count();
        
        // ok: csharp_missing_pagination
        var expensiveProducts = query
            .OrderByDescending(p => p.Price)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();
            
        var result = new PaginatedList<Product>(expensiveProducts, totalCount, page, pageSize);
        return Ok(result);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
    
    [HttpGet("good_case_14")]
    public async Task<IActionResult> good_case_14([FromQuery] int page = 1, [FromQuery] int pageSize = 10)
    {
        var query = _context.Users.Where(u => u.Email.EndsWith("@example.com"));
        var totalCount = await query.CountAsync();
        
        // ok: csharp_missing_pagination
        var users = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
            
        var result = new PaginatedList<User>(users, totalCount, page, pageSize);
        return Ok(result);
    }
// {/fact}
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
    
    [HttpGet("good_case_15")]
    public async Task<IActionResult> good_case_15([FromQuery] string category, [FromQuery] int page = 1, [FromQuery] int pageSize = 10)
    {
        // ok: csharp_missing_pagination
        using (var connection = new System.Data.SqlClient.SqlConnection("connection_string"))
        {
            await connection.OpenAsync();
            
            // Get total count
            var countCommand = new System.Data.SqlClient.SqlCommand(
                $"SELECT COUNT(*) FROM Products WHERE Category = @Category", 
                connection);
            countCommand.Parameters.AddWithValue("@Category", category);
            var totalCount = Convert.ToInt32(await countCommand.ExecuteScalarAsync());
            
            // Get paginated data
            var offset = (page - 1) * pageSize;
            var dataCommand = new System.Data.SqlClient.SqlCommand(
                $"SELECT * FROM Products WHERE Category = @Category ORDER BY Id OFFSET @Offset ROWS FETCH NEXT @PageSize ROWS ONLY", 
                connection);
            dataCommand.Parameters.AddWithValue("@Category", category);
            dataCommand.Parameters.AddWithValue("@Offset", offset);
            dataCommand.Parameters.AddWithValue("@PageSize", pageSize);
                
            var reader = await dataCommand.ExecuteReaderAsync();
            var products = new List<Product>();
            
            while (await reader.ReadAsync())
            {
                products.Add(new Product
                {
                    Id = reader.GetInt32(0),
                    Name = reader.GetString(1),
                    Price = reader.GetDecimal(2)
                });
            }
            
            var result = new PaginatedList<Product>(products, totalCount, page, pageSize);
            return Ok(result);
        }
    }
// {/fact}
}