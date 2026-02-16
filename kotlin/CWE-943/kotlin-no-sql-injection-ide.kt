import org.springframework.web.bind.annotation.*
import org.springframework.http.ResponseEntity
import com.mongodb.MongoClient
import com.mongodb.client.MongoDatabase
import com.mongodb.client.MongoCollection
import org.bson.Document
import org.springframework.data.mongodb.core.MongoTemplate
import org.springframework.data.mongodb.core.query.Query
import org.springframework.data.mongodb.core.query.Criteria
import org.springframework.data.mongodb.core.query.BasicQuery
import com.mongodb.BasicDBObject
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import javax.servlet.http.HttpServletRequest
import org.springframework.data.mongodb.repository.MongoRepository
import org.springframework.data.mongodb.core.MongoOperations
import java.util.regex.Pattern

// True Positive Cases (Vulnerable Code)

@Controller
class NoSqlInjectionExamples {

    // Case 1: Direct use of user input in MongoDB query
// {fact rule=nosql-injection@v1.0 defects=1}
    @GetMapping("/users/search")
    fun bad_case_1(@RequestParam username: String): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("userdb")
        val collection = database.getCollection("users")
        
        // ruleid: kotlin-no-sql-injection-ide
        val query = Document("username", username)
        val result = collection.find(query).first()
        
        return ResponseEntity.ok(result)
    }
// {/fact}

    // Case 2: Using user input in JSON query string
// {fact rule=nosql-injection@v1.0 defects=1}
    @GetMapping("/products")
    fun bad_case_2(@RequestParam category: String): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("shop")
        val collection = database.getCollection("products")
        
        val queryJson = """{ "category": "$category" }"""
        // ruleid: kotlin-no-sql-injection-ide
        val query = Document.parse(queryJson)
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 3: Using Spring Data MongoDB with user input
// {fact rule=nosql-injection@v1.0 defects=1}
    @GetMapping("/orders")
    fun bad_case_3(@RequestParam orderId: String, mongoTemplate: MongoTemplate): ResponseEntity<Any> {
        // ruleid: kotlin-no-sql-injection-ide
        val query = Query.query(Criteria.where("_id").is(orderId))
        val result = mongoTemplate.find(query, Document::class.java, "orders")
        
        return ResponseEntity.ok(result)
    }
// {/fact}

    // Case 4: Using BasicDBObject with user input
// {fact rule=nosql-injection@v1.0 defects=1}
    @PostMapping("/comments/find")
    fun bad_case_4(@RequestBody payload: Map<String, String>): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("blog")
        val collection = database.getCollection("comments")
        
        val author = payload["author"]
        // ruleid: kotlin-no-sql-injection-ide
        val query = BasicDBObject("author", author)
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 5: Using string concatenation in query
// {fact rule=nosql-injection@v1.0 defects=1}
    @GetMapping("/articles")
    fun bad_case_5(@RequestParam tag: String): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("blog")
        val collection = database.getCollection("articles")
        
        // ruleid: kotlin-no-sql-injection-ide
        val queryJson = "{ \"tags\": \"$tag\" }"
        val query = Document.parse(queryJson)
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 6: Using request parameters in multiple fields
// {fact rule=nosql-injection@v1.0 defects=1}
    @GetMapping("/search")
    fun bad_case_6(@RequestParam firstName: String, @RequestParam lastName: String): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("people")
        val collection = database.getCollection("contacts")
        
        // ruleid: kotlin-no-sql-injection-ide
        val query = Document()
            .append("firstName", firstName)
            .append("lastName", lastName)
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 7: Using header values in query
    @GetMapping("/api/data")
    fun bad_case_7(@RequestHeader("X-User-Id") userId: String): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("api")
        val collection = database.getCollection("data")
        
        // ruleid: kotlin-no-sql-injection-ide
        val query = Document("userId", userId)
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }

    // Case 8: Using path variable in query
// {fact rule=nosql-injection@v1.0 defects=1}
    @GetMapping("/profile/{username}")
    fun bad_case_8(@PathVariable username: String): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("social")
        val collection = database.getCollection("profiles")
        
        // ruleid: kotlin-no-sql-injection-ide
        val query = Document("username", username)
        val result = collection.find(query).first()
        
        return ResponseEntity.ok(result)
    }
// {/fact}

    // Case 9: Using request body in complex query
// {fact rule=nosql-injection@v1.0 defects=1}
    @PostMapping("/advanced-search")
    fun bad_case_9(@RequestBody searchCriteria: Map<String, Any>): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("products")
        val collection = database.getCollection("inventory")
        
        val category = searchCriteria["category"] as String
        val minPrice = searchCriteria["minPrice"] as Double
        
        // ruleid: kotlin-no-sql-injection-ide
        val query = Document()
            .append("category", category)
            .append("price", Document("\$gte", minPrice))
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 10: Using string template in BasicQuery
// {fact rule=nosql-injection@v1.0 defects=1}
    @GetMapping("/documents")
    fun bad_case_10(@RequestParam type: String, mongoTemplate: MongoTemplate): ResponseEntity<Any> {
        // ruleid: kotlin-no-sql-injection-ide
        val queryString = "{ type: '$type' }"
        val query = BasicQuery(queryString)
        val results = mongoTemplate.find(query, Document::class.java, "documents")
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 11: Using request parameter in regex query
// {fact rule=nosql-injection@v1.0 defects=1}
    @GetMapping("/users/search-by-email")
    fun bad_case_11(@RequestParam emailDomain: String): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("users")
        val collection = database.getCollection("profiles")
        
        // ruleid: kotlin-no-sql-injection-ide
        val query = Document("email", Document("\$regex", ".*@$emailDomain"))
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 12: Using cookie value in query
    @GetMapping("/preferences")
    fun bad_case_12(@CookieValue("user_id") userId: String): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("app")
        val collection = database.getCollection("preferences")
        
        // ruleid: kotlin-no-sql-injection-ide
        val query = Document("userId", userId)
        val result = collection.find(query).first()
        
        return ResponseEntity.ok(result)
    }

    // Case 13: Using request parameter in array query
// {fact rule=nosql-injection@v1.0 defects=1}
    @GetMapping("/posts/with-tags")
    fun bad_case_13(@RequestParam tag: String): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("blog")
        val collection = database.getCollection("posts")
        
        // ruleid: kotlin-no-sql-injection-ide
        val query = Document("tags", Document("\$in", listOf(tag)))
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 14: Using request parameter in complex criteria
// {fact rule=nosql-injection@v1.0 defects=1}
    @GetMapping("/events")
    fun bad_case_14(@RequestParam location: String, mongoTemplate: MongoTemplate): ResponseEntity<Any> {
        // ruleid: kotlin-no-sql-injection-ide
        val criteria = Criteria.where("location").`is`(location)
            .and("date").gte(System.currentTimeMillis())
        val query = Query.query(criteria)
        val results = mongoTemplate.find(query, Document::class.java, "events")
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 15: Using multiple request parameters in OR query
// {fact rule=nosql-injection@v1.0 defects=1}
    @GetMapping("/search/multi")
    fun bad_case_15(@RequestParam name: String, @RequestParam email: String): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("contacts")
        val collection = database.getCollection("people")
        
        val orConditions = listOf(
            Document("name", name),
            Document("email", email)
        )
        
        // ruleid: kotlin-no-sql-injection-ide
        val query = Document("\$or", orConditions)
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // True Negative Cases (Safe Code)

    // Case 1: Using validation before query
// {fact rule=nosql-injection@v1.0 defects=0}
    @GetMapping("/users/safe-search")
    fun good_case_1(@RequestParam username: String): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("userdb")
        val collection = database.getCollection("users")
        
        // Validate input
        if (!username.matches(Regex("^[a-zA-Z0-9_]{3,20}$"))) {
            return ResponseEntity.badRequest().body("Invalid username format")
        }
        
        // ok: kotlin-no-sql-injection-ide
        val query = Document("username", username)
        val result = collection.find(query).first()
        
        return ResponseEntity.ok(result)
    }
// {/fact}

    // Case 2: Using parameterized query with type checking
// {fact rule=nosql-injection@v1.0 defects=0}
    @GetMapping("/products/safe")
    fun good_case_2(@RequestParam categoryId: String): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("shop")
        val collection = database.getCollection("products")
        
        // Convert to integer and validate
        val categoryIdInt = try {
            categoryId.toInt()
        } catch (e: NumberFormatException) {
            return ResponseEntity.badRequest().body("Category ID must be a number")
        }
        
        // ok: kotlin-no-sql-injection-ide
        val query = Document("categoryId", categoryIdInt)
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 3: Using Spring Data MongoDB with validated input
// {fact rule=nosql-injection@v1.0 defects=0}
    @GetMapping("/orders/safe")
    fun good_case_3(@RequestParam orderId: String, mongoTemplate: MongoTemplate): ResponseEntity<Any> {
        // Validate order ID format
        if (!orderId.matches(Regex("^[a-f0-9]{24}$"))) {
            return ResponseEntity.badRequest().body("Invalid order ID format")
        }
        
        // ok: kotlin-no-sql-injection-ide
        val query = Query.query(Criteria.where("_id").is(orderId))
        val result = mongoTemplate.find(query, Document::class.java, "orders")
        
        return ResponseEntity.ok(result)
    }
// {/fact}

    // Case 4: Using whitelist for query values
// {fact rule=nosql-injection@v1.0 defects=0}
    @PostMapping("/comments/safe-find")
    fun good_case_4(@RequestBody payload: Map<String, String>): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("blog")
        val collection = database.getCollection("comments")
        
        val author = payload["author"] ?: return ResponseEntity.badRequest().body("Author is required")
        
        // Whitelist of allowed authors
        val allowedAuthors = setOf("admin", "moderator", "editor")
        if (author !in allowedAuthors) {
            return ResponseEntity.badRequest().body("Invalid author")
        }
        
        // ok: kotlin-no-sql-injection-ide
        val query = BasicDBObject("author", author)
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 5: Using sanitized input in query
// {fact rule=nosql-injection@v1.0 defects=0}
    @GetMapping("/articles/safe")
    fun good_case_5(@RequestParam tag: String): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("blog")
        val collection = database.getCollection("articles")
        
        // Sanitize input by removing special characters
        val sanitizedTag = tag.replace(Regex("[^a-zA-Z0-9-]"), "")
        
        // ok: kotlin-no-sql-injection-ide
        val query = Document("tags", sanitizedTag)
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 6: Using enum for safe parameter values
// {fact rule=nosql-injection@v1.0 defects=0}
    @GetMapping("/search/safe")
    fun good_case_6(@RequestParam status: String): ResponseEntity<Any> {
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("tasks")
        val collection = database.getCollection("items")
        
        // Use enum for safe values
        val validStatus = try {
            TaskStatus.valueOf(status.toUpperCase())
        } catch (e: IllegalArgumentException) {
            return ResponseEntity.badRequest().body("Invalid status")
        }
        
        // ok: kotlin-no-sql-injection-ide
        val query = Document("status", validStatus.toString())
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 7: Using prepared criteria with validated input
    @GetMapping("/api/data/safe")
    fun good_case_7(@RequestHeader("X-User-Id") userId: String): ResponseEntity<Any> {
        // Validate UUID format
        if (!userId.matches(Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))) {
            return ResponseEntity.badRequest().body("Invalid user ID format")
        }
        
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("api")
        val collection = database.getCollection("data")
        
        // ok: kotlin-no-sql-injection-ide
        val query = Document("userId", userId)
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }

    // Case 8: Using path variable with pattern matching
// {fact rule=nosql-injection@v1.0 defects=0}
    @GetMapping("/profile/safe/{username}")
    fun good_case_8(@PathVariable username: String): ResponseEntity<Any> {
        val pattern = Pattern.compile("^[a-zA-Z0-9_]{3,20}$")
        if (!pattern.matcher(username).matches()) {
            return ResponseEntity.badRequest().body("Invalid username format")
        }
        
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("social")
        val collection = database.getCollection("profiles")
        
        // ok: kotlin-no-sql-injection-ide
        val query = Document("username", username)
        val result = collection.find(query).first()
        
        return ResponseEntity.ok(result)
    }
// {/fact}

    // Case 9: Using validated request body in query
// {fact rule=nosql-injection@v1.0 defects=0}
    @PostMapping("/advanced-search/safe")
    fun good_case_9(@RequestBody searchCriteria: SearchCriteria): ResponseEntity<Any> {
        // SearchCriteria is a validated data class
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("products")
        val collection = database.getCollection("inventory")
        
        // Validate category against allowed values
        val allowedCategories = listOf("electronics", "clothing", "books", "home")
        if (searchCriteria.category !in allowedCategories) {
            return ResponseEntity.badRequest().body("Invalid category")
        }
        
        // Validate price range
        if (searchCriteria.minPrice < 0 || searchCriteria.minPrice > 10000) {
            return ResponseEntity.badRequest().body("Invalid price range")
        }
        
        // ok: kotlin-no-sql-injection-ide
        val query = Document()
            .append("category", searchCriteria.category)
            .append("price", Document("\$gte", searchCriteria.minPrice))
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 10: Using predefined query templates
// {fact rule=nosql-injection@v1.0 defects=0}
    @GetMapping("/documents/safe")
    fun good_case_10(@RequestParam typeId: String, mongoTemplate: MongoTemplate): ResponseEntity<Any> {
        // Convert to integer and validate
        val typeIdInt = try {
            typeId.toInt()
        } catch (e: NumberFormatException) {
            return ResponseEntity.badRequest().body("Type ID must be a number")
        }
        
        // Validate range
        if (typeIdInt < 1 || typeIdInt > 5) {
            return ResponseEntity.badRequest().body("Type ID must be between 1 and 5")
        }
        
        // ok: kotlin-no-sql-injection-ide
        val query = BasicQuery("{ \"typeId\": $typeIdInt }")
        val results = mongoTemplate.find(query, Document::class.java, "documents")
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 11: Using regex pattern with validated input
// {fact rule=nosql-injection@v1.0 defects=0}
    @GetMapping("/users/safe-email-search")
    fun good_case_11(@RequestParam emailDomain: String): ResponseEntity<Any> {
        // Validate domain format
        if (!emailDomain.matches(Regex("^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}$"))) {
            return ResponseEntity.badRequest().body("Invalid email domain format")
        }
        
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("users")
        val collection = database.getCollection("profiles")
        
        // ok: kotlin-no-sql-injection-ide
        val query = Document("email", Document("\$regex", ".*@$emailDomain"))
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 12: Using validated cookie value
    @GetMapping("/preferences/safe")
    fun good_case_12(@CookieValue("user_id") userId: String): ResponseEntity<Any> {
        // Validate user ID format (numeric only)
        if (!userId.matches(Regex("^[0-9]{1,10}$"))) {
            return ResponseEntity.badRequest().body("Invalid user ID format")
        }
        
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("app")
        val collection = database.getCollection("preferences")
        
        // ok: kotlin-no-sql-injection-ide
        val query = Document("userId", userId.toInt())
        val result = collection.find(query).first()
        
        return ResponseEntity.ok(result)
    }

    // Case 13: Using request parameter with validation in array query
// {fact rule=nosql-injection@v1.0 defects=0}
    @GetMapping("/posts/safe-tags")
    fun good_case_13(@RequestParam tag: String): ResponseEntity<Any> {
        // Validate tag format
        if (!tag.matches(Regex("^[a-zA-Z0-9-]{2,20}$"))) {
            return ResponseEntity.badRequest().body("Invalid tag format")
        }
        
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("blog")
        val collection = database.getCollection("posts")
        
        // ok: kotlin-no-sql-injection-ide
        val query = Document("tags", Document("\$in", listOf(tag)))
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 14: Using request parameter with validation in criteria
// {fact rule=nosql-injection@v1.0 defects=0}
    @GetMapping("/events/safe")
    fun good_case_14(@RequestParam location: String, mongoTemplate: MongoTemplate): ResponseEntity<Any> {
        // Validate location format
        if (!location.matches(Regex("^[a-zA-Z\\s]{2,50}$"))) {
            return ResponseEntity.badRequest().body("Invalid location format")
        }
        
        // ok: kotlin-no-sql-injection-ide
        val criteria = Criteria.where("location").`is`(location)
            .and("date").gte(System.currentTimeMillis())
        val query = Query.query(criteria)
        val results = mongoTemplate.find(query, Document::class.java, "events")
        
        return ResponseEntity.ok(results)
    }
// {/fact}

    // Case 15: Using multiple validated parameters in OR query
// {fact rule=nosql-injection@v1.0 defects=0}
    @GetMapping("/search/multi/safe")
    fun good_case_15(@RequestParam name: String, @RequestParam email: String): ResponseEntity<Any> {
        // Validate name
        if (!name.matches(Regex("^[a-zA-Z\\s]{2,50}$"))) {
            return ResponseEntity.badRequest().body("Invalid name format")
        }
        
        // Validate email
        if (!email.matches(Regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$"))) {
            return ResponseEntity.badRequest().body("Invalid email format")
        }
        
        val mongoClient = MongoClient("localhost", 27017)
        val database = mongoClient.getDatabase("contacts")
        val collection = database.getCollection("people")
        
        val orConditions = listOf(
            Document("name", name),
            Document("email", email)
        )
        
        // ok: kotlin-no-sql-injection-ide
        val query = Document("\$or", orConditions)
        val results = collection.find(query).toList()
        
        return ResponseEntity.ok(results)
    }
// {/fact}
}

// Helper classes
enum class TaskStatus {
    PENDING,
    IN_PROGRESS,
    COMPLETED,
    CANCELLED
}

data class SearchCriteria(
    val category: String,
    val minPrice: Double,
    val maxPrice: Double
)