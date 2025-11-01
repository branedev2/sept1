using System;
using System.Data;
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using MySql.Data.MySqlClient;
using Npgsql;
using Oracle.ManagedDataAccess.Client;

namespace SqlInjectionExamples
{
    [ApiController]
    [Route("api/[controller]")]
    public class SqlInjectionController : ControllerBase
    {
        private readonly string _connectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";
// {fact rule=cross-site-scripting@v1.0 defects=1}

        // True Positive Examples (Vulnerable Code)

        [HttpGet("bad1")]
        public IActionResult bad_case_1()
        {
            string username = Request.Query["username"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Users WHERE Username = '" + username + "'";
                
                // ruleid: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    SqlDataReader reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpPost("bad2")]
        public IActionResult bad_case_2([FromForm] string userId)
        {
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = $"DELETE FROM Users WHERE Id = {userId}";
                
                // ruleid: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    int rowsAffected = command.ExecuteNonQuery();
                    return Ok($"{rowsAffected} rows deleted");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad3")]
        public IActionResult bad_case_3()
        {
            string sortColumn = Request.Query["sort"];
            string sortOrder = Request.Query["order"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = $"SELECT * FROM Products ORDER BY {sortColumn} {sortOrder}";
                
                // ruleid: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad4")]
        public IActionResult bad_case_4()
        {
            string searchTerm = Request.Headers["X-Search-Term"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Products WHERE Name LIKE '%" + searchTerm + "%'";
                
                // ruleid: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpPost("bad5")]
        public IActionResult bad_case_5()
        {
            var form = Request.Form;
            string tableName = form["table"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT COUNT(*) FROM " + tableName;
                
                // ruleid: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    int count = (int)command.ExecuteScalar();
                    return Ok(new { Count = count });
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad6")]
        public IActionResult bad_case_6()
        {
            string category = Request.Query["category"];
            int minPrice = int.Parse(Request.Query["minPrice"]);
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = $"SELECT * FROM Products WHERE Category = '{category}' AND Price > {minPrice}";
                
                // ruleid: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad7")]
        public IActionResult bad_case_7()
        {
            string cookieValue = Request.Cookies["filter"];
            
            using (MySqlConnection connection = new MySqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Products WHERE Tags LIKE '%" + cookieValue + "%'";
                
                // ruleid: sql-injection-csharp-rule
                using (MySqlCommand command = new MySqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpPost("bad8")]
        public IActionResult bad_case_8([FromBody] Dictionary<string, string> data)
        {
            string userInput = data["query"];
            string processedInput = userInput.Replace("'", "''"); // Insufficient escaping
            
            using (NpgsqlConnection connection = new NpgsqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Users WHERE email = '" + processedInput + "'";
                
                // ruleid: sql-injection-csharp-rule
                using (NpgsqlCommand command = new NpgsqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad9")]
        public IActionResult bad_case_9()
        {
            string[] ids = Request.Query["ids"].ToString().Split(',');
            string idList = string.Join("','", ids);
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = $"SELECT * FROM Products WHERE Id IN ('{idList}')";
                
                // ruleid: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad10")]
        public IActionResult bad_case_10()
        {
            string searchQuery = Request.Query["q"];
            if (!string.IsNullOrEmpty(searchQuery))
            {
                searchQuery = searchQuery.ToLower(); // Some processing, but still vulnerable
            }
            
            using (SqliteConnection connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Products WHERE LOWER(Name) LIKE '%" + searchQuery + "%'";
                
                // ruleid: sql-injection-csharp-rule
                using (SqliteCommand command = new SqliteCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpPost("bad11")]
        public IActionResult bad_case_11()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            using (OracleConnection connection = new OracleConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Users WHERE Username = '" + username + "' AND Password = '" + password + "'";
                
                // ruleid: sql-injection-csharp-rule
                using (OracleCommand command = new OracleCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad12")]
        public IActionResult bad_case_12()
        {
            string field = Request.Query["field"];
            string value = Request.Query["value"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = $"UPDATE Users SET {field} = '{value}' WHERE Id = 1";
                
                // ruleid: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    int rowsAffected = command.ExecuteNonQuery();
                    return Ok($"{rowsAffected} rows updated");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad13")]
        public IActionResult bad_case_13()
        {
            string userAgent = Request.Headers["User-Agent"].ToString();
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "INSERT INTO AccessLogs (UserAgent, Timestamp) VALUES ('" + userAgent + "', GETDATE())";
                
                // ruleid: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.ExecuteNonQuery();
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpPost("bad14")]
        public IActionResult bad_case_14([FromBody] Dictionary<string, string> filters)
        {
            string whereClause = "";
            foreach (var filter in filters)
            {
                whereClause += $"{filter.Key} = '{filter.Value}' AND ";
            }
            
            if (whereClause.EndsWith(" AND "))
            {
                whereClause = whereClause.Substring(0, whereClause.Length - 5);
            }
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Products WHERE " + whereClause;
                
                // ruleid: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

        [HttpGet("bad15")]
        public IActionResult bad_case_15()
        {
            string dynamicQuery = Request.Query["query"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                
                // ruleid: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(dynamicQuery, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        // True Negative Examples (Safe Code)

        [HttpGet("good1")]
        public IActionResult good_case_1()
        {
            string username = Request.Query["username"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Users WHERE Username = @Username";
                
                // ok: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    SqlDataReader reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpPost("good2")]
        public IActionResult good_case_2([FromForm] string userId)
        {
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "DELETE FROM Users WHERE Id = @UserId";
                
                // ok: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@UserId", userId);
                    int rowsAffected = command.ExecuteNonQuery();
                    return Ok($"{rowsAffected} rows deleted");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good3")]
        public IActionResult good_case_3()
        {
            string sortColumn = Request.Query["sort"];
            string sortOrder = Request.Query["order"];
            
            // Validate sort column against whitelist
            List<string> allowedColumns = new List<string> { "Name", "Price", "CreatedDate" };
            if (!allowedColumns.Contains(sortColumn))
            {
                sortColumn = "Name"; // Default
            }
            
            // Validate sort order
            if (sortOrder != "ASC" && sortOrder != "DESC")
            {
                sortOrder = "ASC"; // Default
            }
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = $"SELECT * FROM Products ORDER BY {sortColumn} {sortOrder}";
                
                // ok: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good4")]
        public IActionResult good_case_4()
        {
            string searchTerm = Request.Headers["X-Search-Term"].ToString();
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Products WHERE Name LIKE @SearchTerm";
                
                // ok: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@SearchTerm", "%" + searchTerm + "%");
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpPost("good5")]
        public IActionResult good_case_5()
        {
            var form = Request.Form;
            string tableName = form["table"];
            
            // Whitelist validation for table name
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
                
                // ok: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    int count = (int)command.ExecuteScalar();
                    return Ok(new { Count = count });
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good6")]
        public IActionResult good_case_6()
        {
            string category = Request.Query["category"];
            int minPrice = int.Parse(Request.Query["minPrice"]);
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Products WHERE Category = @Category AND Price > @MinPrice";
                
                // ok: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@Category", category);
                    command.Parameters.AddWithValue("@MinPrice", minPrice);
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good7")]
        public IActionResult good_case_7()
        {
            string cookieValue = Request.Cookies["filter"];
            
            using (MySqlConnection connection = new MySqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Products WHERE Tags LIKE @Filter";
                
                // ok: sql-injection-csharp-rule
                using (MySqlCommand command = new MySqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@Filter", "%" + cookieValue + "%");
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpPost("good8")]
        public IActionResult good_case_8([FromBody] Dictionary<string, string> data)
        {
            string userInput = data["query"];
            
            using (NpgsqlConnection connection = new NpgsqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Users WHERE email = @Email";
                
                // ok: sql-injection-csharp-rule
                using (NpgsqlCommand command = new NpgsqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@Email", userInput);
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good9")]
        public IActionResult good_case_9()
        {
            string[] ids = Request.Query["ids"].ToString().Split(',');
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Products WHERE Id IN (SELECT value FROM STRING_SPLIT(@IdList, ','))";
                
                // ok: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@IdList", string.Join(",", ids));
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good10")]
        public IActionResult good_case_10()
        {
            string searchQuery = Request.Query["q"];
            
            using (SqliteConnection connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                string sql = "SELECT * FROM Products WHERE LOWER(Name) LIKE @SearchQuery";
                
                // ok: sql-injection-csharp-rule
                using (SqliteCommand command = new SqliteCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@SearchQuery", "%" + searchQuery.ToLower() + "%");
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpPost("good11")]
        public IActionResult good_case_11()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            
            // Hash the password before comparing
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                string hashedPassword = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                
                using (OracleConnection connection = new OracleConnection(_connectionString))
                {
                    connection.Open();
                    string sql = "SELECT * FROM Users WHERE Username = :Username AND Password = :Password";
                    
                    // ok: sql-injection-csharp-rule
                    using (OracleCommand command = new OracleCommand(sql, connection))
                    {
                        command.Parameters.Add(":Username", OracleDbType.Varchar2).Value = username;
                        command.Parameters.Add(":Password", OracleDbType.Varchar2).Value = hashedPassword;
                        var reader = command.ExecuteReader();
                        // Process results
                    }
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good12")]
        public IActionResult good_case_12()
        {
            string field = Request.Query["field"];
            string value = Request.Query["value"];
            
            // Whitelist validation for field name
            Dictionary<string, string> allowedFields = new Dictionary<string, string>
            {
                { "name", "Name" },
                { "email", "Email" },
                { "status", "Status" }
            };
            
            if (!allowedFields.TryGetValue(field.ToLower(), out string validField))
            {
                return BadRequest("Invalid field name");
            }
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = $"UPDATE Users SET {validField} = @Value WHERE Id = 1";
                
                // ok: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@Value", value);
                    int rowsAffected = command.ExecuteNonQuery();
                    return Ok($"{rowsAffected} rows updated");
                }
            }
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good13")]
        public IActionResult good_case_13()
        {
            string userAgent = Request.Headers["User-Agent"].ToString();
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string sql = "INSERT INTO AccessLogs (UserAgent, Timestamp) VALUES (@UserAgent, GETDATE())";
                
                // ok: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@UserAgent", userAgent);
                    command.ExecuteNonQuery();
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpPost("good14")]
        public IActionResult good_case_14([FromBody] Dictionary<string, string> filters)
        {
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                
                // Build parameterized query
                List<string> conditions = new List<string>();
                int paramIndex = 0;
                
                string sql = "SELECT * FROM Products WHERE 1=1";
                
                // ok: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    foreach (var filter in filters)
                    {
                        string paramName = $"@Param{paramIndex}";
                        string fieldName = Regex.Replace(filter.Key, "[^a-zA-Z0-9_]", ""); // Sanitize field name
                        
                        if (!string.IsNullOrEmpty(fieldName))
                        {
                            command.CommandText += $" AND {fieldName} = {paramName}";
                            command.Parameters.AddWithValue(paramName, filter.Value);
                            paramIndex++;
                        }
                    }
                    
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

        [HttpGet("good15")]
        public IActionResult good_case_15()
        {
            // Instead of executing arbitrary queries, use a predefined set
            string queryType = Request.Query["queryType"];
            
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                
                string sql;
                // ok: sql-injection-csharp-rule
                using (SqlCommand command = new SqlCommand())
                {
                    command.Connection = connection;
                    
                    switch (queryType)
                    {
                        case "recent":
                            command.CommandText = "SELECT TOP 10 * FROM Products ORDER BY CreatedDate DESC";
                            break;
                        case "popular":
                            command.CommandText = "SELECT TOP 10 * FROM Products ORDER BY Views DESC";
                            break;
                        case "featured":
                            command.CommandText = "SELECT * FROM Products WHERE Featured = 1";
                            break;
                        default:
                            command.CommandText = "SELECT * FROM Products";
                            break;
                    }
                    
                    var reader = command.ExecuteReader();
                    // Process results
                }
            }
            
            return Ok();
        }
// {/fact}
    }
}