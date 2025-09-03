using System;
using System.Data;
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Web;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using MySql.Data.MySqlClient;
using Npgsql;
using Oracle.ManagedDataAccess.Client;

namespace SqlInjectionExamples
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly string _connectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";
// {fact rule=cross-site-scripting@v1.0 defects=1}

        // True Positive Examples (Vulnerable Code)

        [HttpGet("bad_case_1")]
        public IActionResult bad_case_1()
        {
            string username = Request.Query["username"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Users WHERE Username = '" + username + "'";
                
                // ruleid: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    SqlDataReader reader = command.ExecuteReader();
                    // Process results
                    return Ok("Query executed");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpPost("bad_case_2")]
        public IActionResult bad_case_2()
        {
            string userId = Request.Form["userId"];
            string role = Request.Form["role"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string query = $"UPDATE Users SET Role = '{role}' WHERE UserId = {userId}";
                
                // ruleid: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    int rowsAffected = command.ExecuteNonQuery();
                    return Ok($"{rowsAffected} rows updated");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad_case_3")]
        public IActionResult bad_case_3()
        {
            string category = Request.Headers["X-Category"];
            string minPrice = Request.Query["minPrice"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Products WHERE Category = '" + category + 
                             "' AND Price > " + minPrice;
                
                // ruleid: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Products retrieved");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad_case_4")]
        public IActionResult bad_case_4()
        {
            string searchTerm = Request.Query["search"];
            
            using (SqliteConnection connection = new SqliteConnection("Data Source=app.db"))
            {
                connection.Open();
                string sql = "SELECT * FROM Articles WHERE Title LIKE '%" + searchTerm + "%'";
                
                // ruleid: csharp-sql-injection-ide
                using (SqliteCommand command = new SqliteCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Articles found");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpPost("bad_case_5")]
        public IActionResult bad_case_5()
        {
            string sortColumn = Request.Form["sortColumn"];
            string sortOrder = Request.Form["sortOrder"];
            
            using (MySqlConnection connection = new MySqlConnection("server=localhost;database=mydb;uid=root;pwd=password"))
            {
                connection.Open();
                string sql = $"SELECT * FROM Products ORDER BY {sortColumn} {sortOrder}";
                
                // ruleid: csharp-sql-injection-ide
                using (MySqlCommand command = new MySqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Sorted products");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad_case_6")]
        public IActionResult bad_case_6()
        {
            string productId = Request.Cookies["productId"];
            
            using (NpgsqlConnection connection = new NpgsqlConnection("Host=localhost;Username=postgres;Password=password;Database=mydb"))
            {
                connection.Open();
                string sql = "DELETE FROM Products WHERE Id = " + productId;
                
                // ruleid: csharp-sql-injection-ide
                using (NpgsqlCommand command = new NpgsqlCommand(sql, connection))
                {
                    int rowsAffected = command.ExecuteNonQuery();
                    return Ok($"{rowsAffected} products deleted");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad_case_7")]
        public IActionResult bad_case_7()
        {
            string tableName = Request.Query["table"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT COUNT(*) FROM " + tableName;
                
                // ruleid: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    int count = (int)command.ExecuteScalar();
                    return Ok($"Count: {count}");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpPost("bad_case_8")]
        public IActionResult bad_case_8()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            using (OracleConnection connection = new OracleConnection("Data Source=MyOracleDB;User Id=myUsername;Password=myPassword;"))
            {
                connection.Open();
                string sql = "SELECT * FROM Users WHERE Username = '" + username + "' AND Password = '" + password + "'";
                
                // ruleid: csharp-sql-injection-ide
                using (OracleCommand command = new OracleCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    if (reader.HasRows)
                    {
                        return Ok("Login successful");
                    }
                    return BadRequest("Login failed");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad_case_9")]
        public IActionResult bad_case_9()
        {
            string dateFilter = Request.Query["date"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                
                string sql = @"
                    SELECT * FROM Orders 
                    WHERE OrderDate >= '" + dateFilter + "'";
                
                // ruleid: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Orders retrieved");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpPost("bad_case_10")]
        public IActionResult bad_case_10()
        {
            var ids = Request.Form["ids"].ToString();
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Products WHERE ProductId IN (" + ids + ")";
                
                // ruleid: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Products retrieved");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad_case_11")]
        public IActionResult bad_case_11()
        {
            string userId = Request.Query["userId"];
            string fields = Request.Query["fields"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT " + fields + " FROM Users WHERE UserId = " + userId;
                
                // ruleid: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("User data retrieved");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad_case_12")]
        public IActionResult bad_case_12()
        {
            string searchTerm = HttpUtility.UrlDecode(Request.Query["q"]);
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = $"SELECT * FROM Products WHERE Name LIKE '%{searchTerm}%' OR Description LIKE '%{searchTerm}%'";
                
                // ruleid: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Search results");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpPost("bad_case_13")]
        public IActionResult bad_case_13()
        {
            string categoryId = Request.Form["categoryId"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                
                // String concatenation with variable inside a multi-line string
                string sql = @"
                    SELECT p.*, c.Name as CategoryName
                    FROM Products p
                    JOIN Categories c ON p.CategoryId = c.Id
                    WHERE c.Id = " + categoryId;
                
                // ruleid: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Products by category");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad_case_14")]
        public IActionResult bad_case_14()
        {
            string limit = Request.Query["limit"];
            string offset = Request.Query["offset"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                
                // Multiple variables in the query
                string sql = "SELECT * FROM Products ORDER BY Name LIMIT " + limit + " OFFSET " + offset;
                
                // ruleid: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Paginated products");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpPost("bad_case_15")]
        public IActionResult bad_case_15()
        {
            string condition = Request.Form["condition"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                
                // Directly using user input as part of the WHERE clause
                string sql = "SELECT * FROM Products WHERE " + condition;
                
                // ruleid: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Filtered products");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        // True Negative Examples (Safe Code)

        [HttpGet("good_case_1")]
        public IActionResult good_case_1()
        {
            string username = Request.Query["username"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Users WHERE Username = @Username";
                
                // ok: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    SqlDataReader reader = command.ExecuteReader();
                    // Process results
                    return Ok("Query executed safely");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpPost("good_case_2")]
        public IActionResult good_case_2()
        {
            string userId = Request.Form["userId"];
            string role = Request.Form["role"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string query = "UPDATE Users SET Role = @Role WHERE UserId = @UserId";
                
                // ok: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.Add("@Role", SqlDbType.VarChar).Value = role;
                    command.Parameters.Add("@UserId", SqlDbType.Int).Value = int.Parse(userId);
                    int rowsAffected = command.ExecuteNonQuery();
                    return Ok($"{rowsAffected} rows updated safely");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good_case_3")]
        public IActionResult good_case_3()
        {
            string category = Request.Headers["X-Category"];
            string minPriceStr = Request.Query["minPrice"];
            
            if (!decimal.TryParse(minPriceStr, out decimal minPrice))
            {
                return BadRequest("Invalid price format");
            }
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Products WHERE Category = @Category AND Price > @MinPrice";
                
                // ok: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@Category", category);
                    command.Parameters.AddWithValue("@MinPrice", minPrice);
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Products retrieved safely");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good_case_4")]
        public IActionResult good_case_4()
        {
            string searchTerm = Request.Query["search"];
            
            using (SqliteConnection connection = new SqliteConnection("Data Source=app.db"))
            {
                connection.Open();
                string sql = "SELECT * FROM Articles WHERE Title LIKE @SearchTerm";
                
                // ok: csharp-sql-injection-ide
                using (SqliteCommand command = new SqliteCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@SearchTerm", "%" + searchTerm + "%");
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Articles found safely");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpPost("good_case_5")]
        public IActionResult good_case_5()
        {
            string sortColumn = Request.Form["sortColumn"];
            string sortOrder = Request.Form["sortOrder"];
            
            // Validate sort column against a whitelist
            List<string> allowedColumns = new List<string> { "Name", "Price", "CreatedDate" };
            if (!allowedColumns.Contains(sortColumn))
            {
                sortColumn = "Name"; // Default to a safe column
            }
            
            // Validate sort order
            if (sortOrder != "ASC" && sortOrder != "DESC")
            {
                sortOrder = "ASC"; // Default to ascending
            }
            
            using (MySqlConnection connection = new MySqlConnection("server=localhost;database=mydb;uid=root;pwd=password"))
            {
                connection.Open();
                string sql = $"SELECT * FROM Products ORDER BY {sortColumn} {sortOrder}";
                
                // ok: csharp-sql-injection-ide
                using (MySqlCommand command = new MySqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Sorted products safely");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good_case_6")]
        public IActionResult good_case_6()
        {
            string productIdStr = Request.Cookies["productId"];
            
            if (!int.TryParse(productIdStr, out int productId))
            {
                return BadRequest("Invalid product ID");
            }
            
            using (NpgsqlConnection connection = new NpgsqlConnection("Host=localhost;Username=postgres;Password=password;Database=mydb"))
            {
                connection.Open();
                string sql = "DELETE FROM Products WHERE Id = @ProductId";
                
                // ok: csharp-sql-injection-ide
                using (NpgsqlCommand command = new NpgsqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@ProductId", productId);
                    int rowsAffected = command.ExecuteNonQuery();
                    return Ok($"{rowsAffected} products deleted safely");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good_case_7")]
        public IActionResult good_case_7()
        {
            string tableName = Request.Query["table"];
            
            // Validate table name against a whitelist
            Dictionary<string, string> allowedTables = new Dictionary<string, string>
            {
                { "products", "Products" },
                { "users", "Users" },
                { "orders", "Orders" }
            };
            
            if (!allowedTables.TryGetValue(tableName.ToLower(), out string validTableName))
            {
                return BadRequest("Invalid table name");
            }
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = $"SELECT COUNT(*) FROM {validTableName}";
                
                // ok: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    int count = (int)command.ExecuteScalar();
                    return Ok($"Count: {count}");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpPost("good_case_8")]
        public IActionResult good_case_8()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            using (OracleConnection connection = new OracleConnection("Data Source=MyOracleDB;User Id=myUsername;Password=myPassword;"))
            {
                connection.Open();
                string sql = "SELECT * FROM Users WHERE Username = :Username AND Password = :Password";
                
                // ok: csharp-sql-injection-ide
                using (OracleCommand command = new OracleCommand(sql, connection))
                {
                    command.Parameters.Add(":Username", OracleDbType.Varchar2).Value = username;
                    command.Parameters.Add(":Password", OracleDbType.Varchar2).Value = password;
                    var reader = command.ExecuteReader();
                    if (reader.HasRows)
                    {
                        return Ok("Login successful");
                    }
                    return BadRequest("Login failed");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good_case_9")]
        public IActionResult good_case_9()
        {
            string dateFilter = Request.Query["date"];
            
            if (!DateTime.TryParse(dateFilter, out DateTime parsedDate))
            {
                return BadRequest("Invalid date format");
            }
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                
                string sql = @"
                    SELECT * FROM Orders 
                    WHERE OrderDate >= @DateFilter";
                
                // ok: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@DateFilter", parsedDate);
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Orders retrieved safely");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpPost("good_case_10")]
        public IActionResult good_case_10()
        {
            var idsString = Request.Form["ids"].ToString();
            
            // Parse and validate IDs
            var idStrings = idsString.Split(',');
            var idParameters = new List<SqlParameter>();
            var paramNames = new List<string>();
            
            for (int i = 0; i < idStrings.Length; i++)
            {
                if (int.TryParse(idStrings[i], out int id))
                {
                    string paramName = $"@Id{i}";
                    paramNames.Add(paramName);
                    idParameters.Add(new SqlParameter(paramName, id));
                }
            }
            
            if (paramNames.Count == 0)
            {
                return BadRequest("No valid IDs provided");
            }
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = $"SELECT * FROM Products WHERE ProductId IN ({string.Join(",", paramNames)})";
                
                // ok: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddRange(idParameters.ToArray());
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Products retrieved safely");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good_case_11")]
        public IActionResult good_case_11()
        {
            string userIdStr = Request.Query["userId"];
            string fields = Request.Query["fields"];
            
            if (!int.TryParse(userIdStr, out int userId))
            {
                return BadRequest("Invalid user ID");
            }
            
            // Validate fields against a whitelist
            var allowedFields = new HashSet<string> { "Id", "Username", "Email", "CreatedDate" };
            var requestedFields = fields.Split(',');
            
            var validFields = new List<string>();
            foreach (var field in requestedFields)
            {
                if (allowedFields.Contains(field.Trim()))
                {
                    validFields.Add(field.Trim());
                }
            }
            
            if (validFields.Count == 0)
            {
                validFields.Add("Id"); // Default field
            }
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = $"SELECT {string.Join(", ", validFields)} FROM Users WHERE UserId = @UserId";
                
                // ok: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@UserId", userId);
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("User data retrieved safely");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good_case_12")]
        public IActionResult good_case_12()
        {
            string searchTerm = HttpUtility.UrlDecode(Request.Query["q"]);
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Products WHERE Name LIKE @SearchTerm OR Description LIKE @SearchTerm";
                
                // ok: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var searchParam = "%" + searchTerm + "%";
                    command.Parameters.AddWithValue("@SearchTerm", searchParam);
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Search results");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpPost("good_case_13")]
        public IActionResult good_case_13()
        {
            string categoryIdStr = Request.Form["categoryId"];
            
            if (!int.TryParse(categoryIdStr, out int categoryId))
            {
                return BadRequest("Invalid category ID");
            }
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                
                string sql = @"
                    SELECT p.*, c.Name as CategoryName
                    FROM Products p
                    JOIN Categories c ON p.CategoryId = c.Id
                    WHERE c.Id = @CategoryId";
                
                // ok: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@CategoryId", categoryId);
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Products by category");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good_case_14")]
        public IActionResult good_case_14()
        {
            string limitStr = Request.Query["limit"];
            string offsetStr = Request.Query["offset"];
            
            if (!int.TryParse(limitStr, out int limit) || limit <= 0)
            {
                limit = 10; // Default limit
            }
            
            if (!int.TryParse(offsetStr, out int offset) || offset < 0)
            {
                offset = 0; // Default offset
            }
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                
                string sql = "SELECT * FROM Products ORDER BY Name LIMIT @Limit OFFSET @Offset";
                
                // ok: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@Limit", limit);
                    command.Parameters.AddWithValue("@Offset", offset);
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Paginated products");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpPost("good_case_15")]
        public IActionResult good_case_15()
        {
            string condition = Request.Form["condition"];
            
            // Instead of using user input directly in the WHERE clause,
            // parse and validate the condition to create a safe query
            
            // For example, if condition is expected to be a status filter
            Dictionary<string, string> allowedConditions = new Dictionary<string, string>
            {
                { "active", "Status = 'Active'" },
                { "inactive", "Status = 'Inactive'" },
                { "all", "1=1" }
            };
            
            if (!allowedConditions.TryGetValue(condition.ToLower(), out string safeCondition))
            {
                safeCondition = "1=1"; // Default condition
            }
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                
                string sql = "SELECT * FROM Products WHERE " + safeCondition;
                
                // ok: csharp-sql-injection-ide
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                    return Ok("Filtered products");
                }
            }
        }
// {/fact}
    }
}