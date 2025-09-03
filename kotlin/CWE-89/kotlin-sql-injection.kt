import java.sql.Connection
import java.sql.DriverManager
import java.sql.PreparedStatement
import java.sql.Statement
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.web.bind.annotation.*
import org.springframework.stereotype.Controller
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.http.ResponseEntity
import io.ktor.application.*
import io.ktor.request.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.engine.*
import io.ktor.http.*

// Vulnerable examples (True Positives)

@Controller
class VulnerableSqlController {
    
// {fact rule=cross-site-scripting@v1.0 defects=1}
    fun bad_case_1(request: HttpServletRequest, response: HttpServletResponse) {
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        val userId = request.getParameter("id")
        val query = "SELECT * FROM users WHERE id = $userId"
        
        // ruleid: kotlin-sql-injection
        val statement = connection.createStatement()
        val resultSet = statement.executeQuery(query)
        
        // Process resultSet...
        connection.close()
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/users")
    fun bad_case_2(@RequestParam username: String): ResponseEntity<String> {
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        val query = "SELECT * FROM users WHERE username = '$username'"
        
        // ruleid: kotlin-sql-injection
        val statement = connection.createStatement()
        val resultSet = statement.executeQuery(query)
        
        // Process and return result
        connection.close()
        return ResponseEntity.ok("Results for $username")
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @PostMapping("/update-profile")
    fun bad_case_3(@RequestParam email: String, @RequestParam userId: String): String {
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        val updateQuery = "UPDATE users SET email = '$email' WHERE id = $userId"
        
        // ruleid: kotlin-sql-injection
        val statement = connection.createStatement()
        statement.executeUpdate(updateQuery)
        
        connection.close()
        return "Profile updated"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/search")
    fun bad_case_4(request: HttpServletRequest): String {
        val searchTerm = request.getParameter("q")
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        
        val query = """
            SELECT * FROM products 
            WHERE name LIKE '%$searchTerm%' 
            OR description LIKE '%$searchTerm%'
        """.trimIndent()
        
        // ruleid: kotlin-sql-injection
        val statement = connection.createStatement()
        val resultSet = statement.executeQuery(query)
        
        // Process resultSet...
        connection.close()
        return "Search results"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/orders")
    fun bad_case_5(request: HttpServletRequest): String {
        val sortColumn = request.getParameter("sort") ?: "created_at"
        val sortDirection = request.getParameter("direction") ?: "DESC"
        
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        val query = "SELECT * FROM orders ORDER BY $sortColumn $sortDirection"
        
        // ruleid: kotlin-sql-injection
        val statement = connection.createStatement()
        val resultSet = statement.executeQuery(query)
        
        // Process resultSet...
        connection.close()
        return "Orders list"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @DeleteMapping("/delete-user")
    fun bad_case_6(request: HttpServletRequest): String {
        val userId = request.getParameter("id")
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        
        // ruleid: kotlin-sql-injection
        val statement = connection.createStatement()
        statement.execute("DELETE FROM users WHERE id = $userId")
        
        connection.close()
        return "User deleted"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/products")
    fun bad_case_7(request: HttpServletRequest): String {
        val category = request.getParameter("category")
        val minPrice = request.getParameter("min_price")
        
        val jdbcTemplate = JdbcTemplate()
        val query = "SELECT * FROM products WHERE category = '$category' AND price >= $minPrice"
        
        // ruleid: kotlin-sql-injection
        val products = jdbcTemplate.queryForList(query)
        
        return "Products list"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @PostMapping("/add-comment")
    fun bad_case_8(request: HttpServletRequest): String {
        val postId = request.getParameter("post_id")
        val comment = request.getParameter("comment")
        val userId = request.getParameter("user_id")
        
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        val query = "INSERT INTO comments (post_id, user_id, comment_text) VALUES ($postId, $userId, '$comment')"
        
        // ruleid: kotlin-sql-injection
        val statement = connection.createStatement()
        statement.executeUpdate(query)
        
        connection.close()
        return "Comment added"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/filter-logs")
    fun bad_case_9(request: HttpServletRequest): String {
        val startDate = request.getParameter("start_date")
        val endDate = request.getParameter("end_date")
        val level = request.getParameter("level")
        
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        val query = """
            SELECT * FROM logs 
            WHERE timestamp BETWEEN '$startDate' AND '$endDate'
            AND level = '$level'
        """.trimIndent()
        
        // ruleid: kotlin-sql-injection
        val statement = connection.createStatement()
        val resultSet = statement.executeQuery(query)
        
        connection.close()
        return "Logs filtered"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=1}
    fun bad_case_10(request: HttpServletRequest): String {
        val table = request.getParameter("table")
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        
        // Dynamic table name - very dangerous!
        val query = "SELECT COUNT(*) FROM $table"
        
        // ruleid: kotlin-sql-injection
        val statement = connection.createStatement()
        val resultSet = statement.executeQuery(query)
        
        connection.close()
        return "Count retrieved"
    }
// {/fact}
}

class KtorVulnerableExamples {
// {fact rule=cross-site-scripting@v1.0 defects=1}
    fun bad_case_11() {
        embeddedServer(io.ktor.server.netty.Netty, port = 8080) {
            routing {
                get("/user") {
                    val userId = call.request.queryParameters["id"]
                    val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
                    
                    // ruleid: kotlin-sql-injection
                    val statement = connection.createStatement()
                    val resultSet = statement.executeQuery("SELECT * FROM users WHERE id = $userId")
                    
                    // Process resultSet...
                    connection.close()
                    call.respondText("User details")
                }
            }
        }.start(wait = true)
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=1}
    fun bad_case_12() {
        embeddedServer(io.ktor.server.netty.Netty, port = 8080) {
            routing {
                post("/execute-query") {
                    val parameters = call.receiveParameters()
                    val customQuery = parameters["query"] ?: ""
                    
                    val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
                    
                    // ruleid: kotlin-sql-injection
                    val statement = connection.createStatement()
                    val resultSet = statement.executeQuery(customQuery)
                    
                    connection.close()
                    call.respondText("Query executed")
                }
            }
        }.start(wait = true)
    }
// {/fact}
}

class StringConcatenationVulnerabilities {
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/user-search")
    fun bad_case_13(request: HttpServletRequest): String {
        val firstName = request.getParameter("first_name")
        val lastName = request.getParameter("last_name")
        
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        
        // String concatenation with multiple parameters
        val query = StringBuilder()
        query.append("SELECT * FROM users WHERE 1=1")
        
        if (firstName.isNotEmpty()) {
            query.append(" AND first_name = '").append(firstName).append("'")
        }
        
        if (lastName.isNotEmpty()) {
            query.append(" AND last_name = '").append(lastName).append("'")
        }
        
        // ruleid: kotlin-sql-injection
        val statement = connection.createStatement()
        val resultSet = statement.executeQuery(query.toString())
        
        connection.close()
        return "Search results"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/complex-query")
    fun bad_case_14(request: HttpServletRequest): String {
        val userId = request.getParameter("user_id")
        val status = request.getParameter("status")
        
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        
        // String interpolation
        val query = """
            SELECT o.*, p.name 
            FROM orders o 
            JOIN products p ON o.product_id = p.id 
            WHERE o.user_id = ${userId} 
            AND o.status = '${status}'
        """.trimIndent()
        
        // ruleid: kotlin-sql-injection
        val statement = connection.createStatement()
        val resultSet = statement.executeQuery(query)
        
        connection.close()
        return "Complex query results"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/in-clause")
    fun bad_case_15(request: HttpServletRequest): String {
        val categoryIds = request.getParameter("category_ids") // Comma-separated list of IDs
        
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        val query = "SELECT * FROM products WHERE category_id IN ($categoryIds)"
        
        // ruleid: kotlin-sql-injection
        val statement = connection.createStatement()
        val resultSet = statement.executeQuery(query)
        
        connection.close()
        return "Products in categories"
    }
// {/fact}
}

// Safe examples (True Negatives)

@Controller
class SafeSqlController {
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    fun good_case_1(request: HttpServletRequest, response: HttpServletResponse) {
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        val userId = request.getParameter("id")
        
        // ok: kotlin-sql-injection
        val preparedStatement = connection.prepareStatement("SELECT * FROM users WHERE id = ?")
        preparedStatement.setString(1, userId)
        val resultSet = preparedStatement.executeQuery()
        
        // Process resultSet...
        connection.close()
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/users-safe")
    fun good_case_2(@RequestParam username: String): ResponseEntity<String> {
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        
        // ok: kotlin-sql-injection
        val preparedStatement = connection.prepareStatement("SELECT * FROM users WHERE username = ?")
        preparedStatement.setString(1, username)
        val resultSet = preparedStatement.executeQuery()
        
        // Process and return result
        connection.close()
        return ResponseEntity.ok("Results for $username")
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @PostMapping("/update-profile-safe")
    fun good_case_3(@RequestParam email: String, @RequestParam userId: String): String {
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        
        // ok: kotlin-sql-injection
        val preparedStatement = connection.prepareStatement("UPDATE users SET email = ? WHERE id = ?")
        preparedStatement.setString(1, email)
        preparedStatement.setString(2, userId)
        preparedStatement.executeUpdate()
        
        connection.close()
        return "Profile updated"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/search-safe")
    fun good_case_4(request: HttpServletRequest): String {
        val searchTerm = request.getParameter("q")
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        
        // ok: kotlin-sql-injection
        val preparedStatement = connection.prepareStatement(
            "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?"
        )
        val searchPattern = "%$searchTerm%"
        preparedStatement.setString(1, searchPattern)
        preparedStatement.setString(2, searchPattern)
        val resultSet = preparedStatement.executeQuery()
        
        // Process resultSet...
        connection.close()
        return "Search results"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/orders-safe")
    fun good_case_5(request: HttpServletRequest): String {
        val sortColumn = request.getParameter("sort") ?: "created_at"
        val sortDirection = request.getParameter("direction") ?: "DESC"
        
        // Validate sort column against a whitelist
        val allowedColumns = listOf("created_at", "total_amount", "status", "customer_name")
        val validatedColumn = if (sortColumn in allowedColumns) sortColumn else "created_at"
        
        // Validate sort direction
        val validatedDirection = if (sortDirection in listOf("ASC", "DESC")) sortDirection else "DESC"
        
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        
        // ok: kotlin-sql-injection
        val query = "SELECT * FROM orders ORDER BY $validatedColumn $validatedDirection"
        val statement = connection.createStatement()
        val resultSet = statement.executeQuery(query)
        
        // Process resultSet...
        connection.close()
        return "Orders list"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @DeleteMapping("/delete-user-safe")
    fun good_case_6(request: HttpServletRequest): String {
        val userId = request.getParameter("id")
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        
        // ok: kotlin-sql-injection
        val preparedStatement = connection.prepareStatement("DELETE FROM users WHERE id = ?")
        preparedStatement.setString(1, userId)
        preparedStatement.execute()
        
        connection.close()
        return "User deleted"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/products-safe")
    fun good_case_7(request: HttpServletRequest): String {
        val category = request.getParameter("category")
        val minPrice = request.getParameter("min_price")
        
        val jdbcTemplate = JdbcTemplate()
        
        // ok: kotlin-sql-injection
        val products = jdbcTemplate.queryForList(
            "SELECT * FROM products WHERE category = ? AND price >= ?",
            category, minPrice
        )
        
        return "Products list"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @PostMapping("/add-comment-safe")
    fun good_case_8(request: HttpServletRequest): String {
        val postId = request.getParameter("post_id")
        val comment = request.getParameter("comment")
        val userId = request.getParameter("user_id")
        
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        
        // ok: kotlin-sql-injection
        val preparedStatement = connection.prepareStatement(
            "INSERT INTO comments (post_id, user_id, comment_text) VALUES (?, ?, ?)"
        )
        preparedStatement.setString(1, postId)
        preparedStatement.setString(2, userId)
        preparedStatement.setString(3, comment)
        preparedStatement.executeUpdate()
        
        connection.close()
        return "Comment added"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/filter-logs-safe")
    fun good_case_9(request: HttpServletRequest): String {
        val startDate = request.getParameter("start_date")
        val endDate = request.getParameter("end_date")
        val level = request.getParameter("level")
        
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        
        // ok: kotlin-sql-injection
        val preparedStatement = connection.prepareStatement("""
            SELECT * FROM logs 
            WHERE timestamp BETWEEN ? AND ?
            AND level = ?
        """.trimIndent())
        
        preparedStatement.setString(1, startDate)
        preparedStatement.setString(2, endDate)
        preparedStatement.setString(3, level)
        val resultSet = preparedStatement.executeQuery()
        
        connection.close()
        return "Logs filtered"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    fun good_case_10(request: HttpServletRequest): String {
        val table = request.getParameter("table")
        
        // Validate table name against a whitelist
        val allowedTables = listOf("users", "products", "orders", "categories")
        if (table !in allowedTables) {
            return "Invalid table name"
        }
        
        val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
        
        // ok: kotlin-sql-injection
        val query = "SELECT COUNT(*) FROM $table"
        val statement = connection.createStatement()
        val resultSet = statement.executeQuery(query)
        
        connection.close()
        return "Count retrieved"
    }
// {/fact}
}

class KtorSafeExamples {
// {fact rule=cross-site-scripting@v1.0 defects=0}
    fun good_case_11() {
        embeddedServer(io.ktor.server.netty.Netty, port = 8080) {
            routing {
                get("/user") {
                    val userId = call.request.queryParameters["id"]
                    val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
                    
                    // ok: kotlin-sql-injection
                    val preparedStatement = connection.prepareStatement("SELECT * FROM users WHERE id = ?")
                    preparedStatement.setString(1, userId)
                    val resultSet = preparedStatement.executeQuery()
                    
                    // Process resultSet...
                    connection.close()
                    call.respondText("User details")
                }
            }
        }.start(wait = true)
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    fun good_case_12() {
        embeddedServer(io.ktor.server.netty.Netty, port = 8080) {
            routing {
                post("/execute-query") {
                    val parameters = call.receiveParameters()
                    val queryType = parameters["query_type"] ?: ""
                    
                    // Use predefined queries based on query type
                    val queryMap = mapOf(
                        "recent_users" to "SELECT * FROM users ORDER BY created_at DESC LIMIT 10",
                        "active_products" to "SELECT * FROM products WHERE active = TRUE",
                        "pending_orders" to "SELECT * FROM orders WHERE status = 'pending'"
                    )
                    
                    val query = queryMap[queryType] ?: "SELECT 1" // Default safe query
                    
                    val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
                    
                    // ok: kotlin-sql-injection
                    val statement = connection.createStatement()
                    val resultSet = statement.executeQuery(query)
                    
                    connection.close()
                    call.respondText("Query executed")
                }
            }
        }.start(wait = true)
    }
// {/fact}
}

class NamedParameterExamples {
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/user-search-safe")
    fun good_case_13(request: HttpServletRequest): String {
        val firstName = request.getParameter("first_name")
        val lastName = request.getParameter("last_name")
        
        val namedParameterJdbcTemplate = NamedParameterJdbcTemplate(JdbcTemplate())
        
        val params = MapSqlParameterSource()
        
        var query = "SELECT * FROM users WHERE 1=1"
        
        if (firstName.isNotEmpty()) {
            query += " AND first_name = :firstName"
            params.addValue("firstName", firstName)
        }
        
        if (lastName.isNotEmpty()) {
            query += " AND last_name = :lastName"
            params.addValue("lastName", lastName)
        }
        
        // ok: kotlin-sql-injection
        val users = namedParameterJdbcTemplate.queryForList(query, params)
        
        return "Search results"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/complex-query-safe")
    fun good_case_14(request: HttpServletRequest): String {
        val userId = request.getParameter("user_id")
        val status = request.getParameter("status")
        
        val namedParameterJdbcTemplate = NamedParameterJdbcTemplate(JdbcTemplate())
        
        val params = MapSqlParameterSource()
        params.addValue("userId", userId)
        params.addValue("status", status)
        
        val query = """
            SELECT o.*, p.name 
            FROM orders o 
            JOIN products p ON o.product_id = p.id 
            WHERE o.user_id = :userId 
            AND o.status = :status
        """.trimIndent()
        
        // ok: kotlin-sql-injection
        val results = namedParameterJdbcTemplate.queryForList(query, params)
        
        return "Complex query results"
    }
// {/fact}
    
// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/in-clause-safe")
    fun good_case_15(request: HttpServletRequest): String {
        val categoryIdsParam = request.getParameter("category_ids") // Comma-separated list of IDs
        val categoryIds = categoryIdsParam.split(",").map { it.trim() }
        
        val namedParameterJdbcTemplate = NamedParameterJdbcTemplate(JdbcTemplate())
        
        val params = MapSqlParameterSource()
        params.addValue("categoryIds", categoryIds)
        
        // ok: kotlin-sql-injection
        val products = namedParameterJdbcTemplate.queryForList(
            "SELECT * FROM products WHERE category_id IN (:categoryIds)",
            params
        )
        
        return "Products in categories"
    }
// {/fact}
}