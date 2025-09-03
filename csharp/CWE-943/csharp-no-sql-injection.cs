using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using MongoDB.Bson;
using Microsoft.AspNetCore.Http;
using System.Text.RegularExpressions;
using System.Configuration;
using Microsoft.Extensions.Configuration;

namespace NoSqlInjectionExamples
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IMongoCollection<BsonDocument> _collection;
        private readonly IMongoDatabase _database;

        public UserController(IMongoClient client)
        {
            _database = client.GetDatabase("userdb");
            _collection = _database.GetCollection<BsonDocument>("users");
        }
// {fact rule=nosql-injection@v1.0 defects=1}

        // True Positive Examples (Vulnerable Code)

        [HttpGet("bad_case_1")]
        public IActionResult bad_case_1()
        {
            string username = Request.Query["username"];
            
            // Direct string interpolation in filter
            var filter = "{username: \"" + username + "\"}";
            
            // ruleid: csharp-no-sql-injection
            var result = _collection.Find(filter).ToList();
            
            return Ok(result);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

        [HttpGet("bad_case_2")]
        public IActionResult bad_case_2()
        {
            string id = Request.Query["id"];
            
            // Using string concatenation to build a filter
            string filterString = "{ _id: ObjectId('" + id + "') }";
            
            // ruleid: csharp-no-sql-injection
            var user = _collection.Find(filterString).FirstOrDefault();
            
            return Ok(user);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

        [HttpPost("bad_case_3")]
        public IActionResult bad_case_3()
        {
            string searchQuery = Request.Form["query"];
            
            // Using string format to build a filter
            var filter = string.Format("{{ name: {{ $regex: '{0}', $options: 'i' }} }}", searchQuery);
            
            // ruleid: csharp-no-sql-injection
            var results = _collection.Find(filter).ToList();
            
            return Ok(results);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

        [HttpGet("bad_case_4")]
        public IActionResult bad_case_4()
        {
            string role = Request.Headers["X-User-Role"];
            
            // Building filter with header value
            var filterString = "{ role: \"" + role + "\" }";
            
            // ruleid: csharp-no-sql-injection
            var users = _collection.Find(filterString).ToList();
            
            return Ok(users);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

        [HttpGet("bad_case_5")]
        public IActionResult bad_case_5()
        {
            string email = Request.Cookies["userEmail"];
            
            // Using cookie value in filter
            var filter = "{ email: \"" + email + "\" }";
            
            // ruleid: csharp-no-sql-injection
            var user = _collection.Find(filter).FirstOrDefault();
            
            return Ok(user);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

        [HttpPost("bad_case_6")]
        public IActionResult bad_case_6()
        {
            string minAge = Request.Form["minAge"];
            string maxAge = Request.Form["maxAge"];
            
            // Building complex filter with multiple inputs
            var filter = "{ age: { $gte: " + minAge + ", $lte: " + maxAge + " } }";
            
            // ruleid: csharp-no-sql-injection
            var users = _collection.Find(filter).ToList();
            
            return Ok(users);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

        [HttpGet("bad_case_7")]
        public IActionResult bad_case_7()
        {
            string sortField = Request.Query["sortBy"];
            string sortOrder = Request.Query["order"];
            
            // Using user input for sort specification
            var sortSpec = "{ " + sortField + ": " + (sortOrder == "desc" ? "-1" : "1") + " }";
            
            // ruleid: csharp-no-sql-injection
            var users = _collection.Find("{}").Sort(sortSpec).ToList();
            
            return Ok(users);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

        [HttpGet("bad_case_8")]
        public IActionResult bad_case_8()
        {
            string field = Request.Query["field"];
            string value = Request.Query["value"];
            
            // Dynamic field name in filter
            var filter = "{ \"" + field + "\": \"" + value + "\" }";
            
            // ruleid: csharp-no-sql-injection
            var result = _collection.Find(filter).ToList();
            
            return Ok(result);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

        [HttpPost("bad_case_9")]
        public IActionResult bad_case_9()
        {
            string username = Request.Form["username"];
            
            // Using JavaScript expressions in MongoDB
            var filter = "{ $where: \"this.username == '" + username + "'\" }";
            
            // ruleid: csharp-no-sql-injection
            var user = _collection.Find(filter).FirstOrDefault();
            
            return Ok(user);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

        [HttpGet("bad_case_10")]
        public IActionResult bad_case_10()
        {
            string searchTerm = Request.Query["search"];
            
            if (!string.IsNullOrEmpty(searchTerm))
            {
                // Concatenating in conditional logic
                var filter = "{ $text: { $search: \"" + searchTerm + "\" } }";
                
                // ruleid: csharp-no-sql-injection
                var results = _collection.Find(filter).ToList();
                return Ok(results);
            }
            
            return NotFound();
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

        [HttpPost("bad_case_11")]
        public IActionResult bad_case_11()
        {
            string userId = Request.Form["userId"];
            string updateField = Request.Form["field"];
            string updateValue = Request.Form["value"];
            
            // Using string interpolation for update operation
            var filter = "{ _id: ObjectId('" + userId + "') }";
            var update = "{ $set: { \"" + updateField + "\": \"" + updateValue + "\" } }";
            
            // ruleid: csharp-no-sql-injection
            _collection.UpdateOne(filter, update);
            
            return Ok("Updated successfully");
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

        [HttpDelete("bad_case_12")]
        public IActionResult bad_case_12()
        {
            string condition = Request.Query["condition"];
            
            // Direct user input in delete filter
            var filter = condition;
            
            // ruleid: csharp-no-sql-injection
            var result = _collection.DeleteMany(filter);
            
            return Ok($"Deleted {result.DeletedCount} documents");
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

        [HttpGet("bad_case_13")]
        public IActionResult bad_case_13()
        {
            string pipeline = Request.Query["pipeline"];
            
            // Using raw aggregation pipeline from user input
            // ruleid: csharp-no-sql-injection
            var result = _collection.Aggregate(pipeline).ToList();
            
            return Ok(result);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

        [HttpGet("bad_case_14")]
        public IActionResult bad_case_14()
        {
            string userInput = Request.Query["query"];
            
            try
            {
                // Error handling doesn't prevent injection
                var filter = "{ $and: [" + userInput + "] }";
                
                // ruleid: csharp-no-sql-injection
                var results = _collection.Find(filter).ToList();
                return Ok(results);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

        [HttpGet("bad_case_15")]
        public IActionResult bad_case_15()
        {
            string username = Request.Query["username"];
            string password = Request.Query["password"];
            
            // Multiple inputs in filter
            var filter = "{ username: \"" + username + "\", password: \"" + password + "\" }";
            
            // ruleid: csharp-no-sql-injection
            var user = _collection.Find(filter).FirstOrDefault();
            
            return user != null ? Ok(user) : Unauthorized();
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        [HttpGet("good_case_1")]
        public IActionResult good_case_1()
        {
            string username = Request.Query["username"];
            
            // Using FilterDefinition for safe queries
            var filter = Builders<BsonDocument>.Filter.Eq("username", username);
            
            // ok: csharp-no-sql-injection
            var result = _collection.Find(filter).ToList();
            
            return Ok(result);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

        [HttpGet("good_case_2")]
        public IActionResult good_case_2()
        {
            string idString = Request.Query["id"];
            
            if (ObjectId.TryParse(idString, out ObjectId id))
            {
                var filter = Builders<BsonDocument>.Filter.Eq("_id", id);
                
                // ok: csharp-no-sql-injection
                var user = _collection.Find(filter).FirstOrDefault();
                return Ok(user);
            }
            
            return BadRequest("Invalid ID format");
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

        [HttpPost("good_case_3")]
        public IActionResult good_case_3()
        {
            string searchQuery = Request.Form["query"];
            
            // Using regex builder for safe pattern matching
            var filter = Builders<BsonDocument>.Filter.Regex("name", new BsonRegularExpression(Regex.Escape(searchQuery), "i"));
            
            // ok: csharp-no-sql-injection
            var results = _collection.Find(filter).ToList();
            
            return Ok(results);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

        [HttpGet("good_case_4")]
        public IActionResult good_case_4()
        {
            string role = Request.Headers["X-User-Role"];
            
            // Validating input against allowed values
            List<string> validRoles = new List<string> { "admin", "user", "guest" };
            if (!validRoles.Contains(role))
            {
                return BadRequest("Invalid role specified");
            }
            
            var filter = Builders<BsonDocument>.Filter.Eq("role", role);
            
            // ok: csharp-no-sql-injection
            var users = _collection.Find(filter).ToList();
            
            return Ok(users);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

        [HttpGet("good_case_5")]
        public IActionResult good_case_5()
        {
            string email = Request.Cookies["userEmail"];
            
            // Input validation for email format
            if (!Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
            {
                return BadRequest("Invalid email format");
            }
            
            var filter = Builders<BsonDocument>.Filter.Eq("email", email);
            
            // ok: csharp-no-sql-injection
            var user = _collection.Find(filter).FirstOrDefault();
            
            return Ok(user);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

        [HttpPost("good_case_6")]
        public IActionResult good_case_6()
        {
            if (int.TryParse(Request.Form["minAge"], out int minAge) && 
                int.TryParse(Request.Form["maxAge"], out int maxAge))
            {
                // Using filter builder for range queries
                var filter = Builders<BsonDocument>.Filter.And(
                    Builders<BsonDocument>.Filter.Gte("age", minAge),
                    Builders<BsonDocument>.Filter.Lte("age", maxAge)
                );
                
                // ok: csharp-no-sql-injection
                var users = _collection.Find(filter).ToList();
                return Ok(users);
            }
            
            return BadRequest("Invalid age parameters");
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

        [HttpGet("good_case_7")]
        public IActionResult good_case_7()
        {
            string sortField = Request.Query["sortBy"];
            string sortOrder = Request.Query["order"];
            
            // Validate sort field against allowed values
            List<string> allowedSortFields = new List<string> { "name", "age", "createdAt" };
            if (!allowedSortFields.Contains(sortField))
            {
                return BadRequest("Invalid sort field");
            }
            
            // Using SortDefinition
            var sortDefinition = sortOrder == "desc" 
                ? Builders<BsonDocument>.Sort.Descending(sortField)
                : Builders<BsonDocument>.Sort.Ascending(sortField);
            
            // ok: csharp-no-sql-injection
            var users = _collection.Find(Builders<BsonDocument>.Filter.Empty).Sort(sortDefinition).ToList();
            
            return Ok(users);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

        [HttpGet("good_case_8")]
        public IActionResult good_case_8()
        {
            string field = Request.Query["field"];
            string value = Request.Query["value"];
            
            // Whitelist allowed fields
            Dictionary<string, Func<string, FilterDefinition<BsonDocument>>> allowedFields = 
                new Dictionary<string, Func<string, FilterDefinition<BsonDocument>>>
                {
                    { "name", val => Builders<BsonDocument>.Filter.Eq("name", val) },
                    { "email", val => Builders<BsonDocument>.Filter.Eq("email", val) },
                    { "status", val => Builders<BsonDocument>.Filter.Eq("status", val) }
                };
            
            if (!allowedFields.ContainsKey(field))
            {
                return BadRequest("Invalid field specified");
            }
            
            var filter = allowedFields[field](value);
            
            // ok: csharp-no-sql-injection
            var result = _collection.Find(filter).ToList();
            
            return Ok(result);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

        [HttpPost("good_case_9")]
        public IActionResult good_case_9()
        {
            string username = Request.Form["username"];
            
            // Sanitize input for JavaScript expressions
            username = Regex.Replace(username, @"[^\w\s]", "");
            
            // Using filter builder instead of $where
            var filter = Builders<BsonDocument>.Filter.Eq("username", username);
            
            // ok: csharp-no-sql-injection
            var user = _collection.Find(filter).FirstOrDefault();
            
            return Ok(user);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

        [HttpGet("good_case_10")]
        public IActionResult good_case_10()
        {
            string searchTerm = Request.Query["search"];
            
            if (!string.IsNullOrEmpty(searchTerm))
            {
                // Using text search with proper filter builder
                var filter = Builders<BsonDocument>.Filter.Text(searchTerm);
                
                // ok: csharp-no-sql-injection
                var results = _collection.Find(filter).ToList();
                return Ok(results);
            }
            
            return NotFound();
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

        [HttpPost("good_case_11")]
        public IActionResult good_case_11()
        {
            string userId = Request.Form["userId"];
            string updateField = Request.Form["field"];
            string updateValue = Request.Form["value"];
            
            // Validate ObjectId
            if (!ObjectId.TryParse(userId, out ObjectId id))
            {
                return BadRequest("Invalid user ID");
            }
            
            // Whitelist allowed update fields
            List<string> allowedFields = new List<string> { "name", "email", "status" };
            if (!allowedFields.Contains(updateField))
            {
                return BadRequest("Cannot update this field");
            }
            
            var filter = Builders<BsonDocument>.Filter.Eq("_id", id);
            var update = Builders<BsonDocument>.Update.Set(updateField, updateValue);
            
            // ok: csharp-no-sql-injection
            _collection.UpdateOne(filter, update);
            
            return Ok("Updated successfully");
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

        [HttpDelete("good_case_12")]
        public IActionResult good_case_12()
        {
            string idToDelete = Request.Query["id"];
            
            // Validate ID format
            if (!ObjectId.TryParse(idToDelete, out ObjectId id))
            {
                return BadRequest("Invalid ID format");
            }
            
            var filter = Builders<BsonDocument>.Filter.Eq("_id", id);
            
            // ok: csharp-no-sql-injection
            var result = _collection.DeleteOne(filter);
            
            return Ok($"Deleted {result.DeletedCount} document");
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

        [HttpGet("good_case_13")]
        public IActionResult good_case_13()
        {
            string ageStr = Request.Query["minAge"];
            
            if (!int.TryParse(ageStr, out int minAge))
            {
                return BadRequest("Invalid age parameter");
            }
            
            // Building safe aggregation pipeline
            var pipeline = new BsonDocument[]
            {
                new BsonDocument("$match", new BsonDocument("age", new BsonDocument("$gte", minAge))),
                new BsonDocument("$group", new BsonDocument
                {
                    { "_id", "$department" },
                    { "avgAge", new BsonDocument("$avg", "$age") }
                })
            };
            
            // ok: csharp-no-sql-injection
            var result = _collection.Aggregate<BsonDocument>(pipeline).ToList();
            
            return Ok(result);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

        [HttpGet("good_case_14")]
        public IActionResult good_case_14()
        {
            string status = Request.Query["status"];
            string category = Request.Query["category"];
            
            // Building filter with multiple conditions safely
            var filterBuilder = Builders<BsonDocument>.Filter;
            var filter = filterBuilder.Empty;
            
            if (!string.IsNullOrEmpty(status))
            {
                filter = filterBuilder.And(filter, filterBuilder.Eq("status", status));
            }
            
            if (!string.IsNullOrEmpty(category))
            {
                filter = filterBuilder.And(filter, filterBuilder.Eq("category", category));
            }
            
            // ok: csharp-no-sql-injection
            var results = _collection.Find(filter).ToList();
            
            return Ok(results);
        }
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

        [HttpGet("good_case_15")]
        public IActionResult good_case_15()
        {
            string username = Request.Query["username"];
            string password = Request.Query["password"];
            
            // Using filter builder for authentication
            var filter = Builders<BsonDocument>.Filter.And(
                Builders<BsonDocument>.Filter.Eq("username", username),
                Builders<BsonDocument>.Filter.Eq("password", password)
            );
            
            // ok: csharp-no-sql-injection
            var user = _collection.Find(filter).FirstOrDefault();
            
            return user != null ? Ok(user) : Unauthorized();
        }
// {/fact}
    }
}