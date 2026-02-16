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
import org.owasp.encoder.Encode
import java.util.regex.Pattern

// True Positive Examples (Vulnerable Code)

@Controller
class SqlInjectionExamples {

    private val dbUrl = "jdbc:mysql://localhost:3306/mydb"
    private val dbUser = "user"
    private val dbPassword = "password"
    private val jdbcTemplate = JdbcTemplate()
    private val namedParameterJdbcTemplate = NamedParameterJdbcTemplate(jdbcTemplate)

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/bad_case_1")
    fun bad_case_1(request: HttpServletRequest, response: HttpServletResponse) {
        val userId = request.getParameter("id")
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        val statement = connection.createStatement()
        
        // ruleid: kotlin-sql-injection-ide
        val resultSet = statement.executeQuery("SELECT * FROM users WHERE id = $userId")
        
        // Process resultSet
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @PostMapping("/bad_case_2")
    fun bad_case_2(request: HttpServletRequest, response: HttpServletResponse) {
        val username = request.getParameter("username")
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        val statement = connection.createStatement()
        
        // ruleid: kotlin-sql-injection-ide
        statement.executeUpdate("UPDATE users SET active = true WHERE username = '$username'")
        
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/bad_case_3")
    fun bad_case_3(request: HttpServletRequest, response: HttpServletResponse) {
        val tableName = request.getParameter("table")
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        val statement = connection.createStatement()
        
        // ruleid: kotlin-sql-injection-ide
        val resultSet = statement.executeQuery("SELECT * FROM $tableName")
        
        // Process resultSet
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @RequestMapping("/bad_case_4")
    fun bad_case_4(request: HttpServletRequest, response: HttpServletResponse) {
        val searchTerm = request.getParameter("search")
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        
        val query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'"
        val statement = connection.createStatement()
        
        // ruleid: kotlin-sql-injection-ide
        val resultSet = statement.executeQuery(query)
        
        // Process resultSet
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/bad_case_5")
    fun bad_case_5(request: HttpServletRequest, response: HttpServletResponse) {
        val sortColumn = request.getParameter("sort")
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        val statement = connection.createStatement()
        
        // ruleid: kotlin-sql-injection-ide
        val resultSet = statement.executeQuery("SELECT * FROM products ORDER BY $sortColumn")
        
        // Process resultSet
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @PostMapping("/bad_case_6")
    fun bad_case_6(request: HttpServletRequest, response: HttpServletResponse) {
        val userIds = request.getParameter("ids")
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        val statement = connection.createStatement()
        
        // ruleid: kotlin-sql-injection-ide
        statement.executeUpdate("DELETE FROM users WHERE id IN ($userIds)")
        
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/bad_case_7")
    fun bad_case_7(request: HttpServletRequest, response: HttpServletResponse) {
        val userId = request.getParameter("id")
        val role = request.getParameter("role")
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        val statement = connection.createStatement()
        
        // ruleid: kotlin-sql-injection-ide
        val resultSet = statement.executeQuery("SELECT * FROM users WHERE id = $userId AND role = '$role'")
        
        // Process resultSet
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @PostMapping("/bad_case_8")
    fun bad_case_8(request: HttpServletRequest, response: HttpServletResponse) {
        val userId = request.getParameter("id")
        val limit = request.getParameter("limit")
        
        // ruleid: kotlin-sql-injection-ide
        val results = jdbcTemplate.queryForList("SELECT * FROM users WHERE department_id = $userId LIMIT $limit")
        
        // Process results
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/bad_case_9")
    fun bad_case_9(request: HttpServletRequest, response: HttpServletResponse) {
        val category = request.getParameter("category")
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        
        val sql = StringBuilder()
        sql.append("SELECT * FROM products WHERE category = '")
        sql.append(category)
        sql.append("'")
        
        val statement = connection.createStatement()
        
        // ruleid: kotlin-sql-injection-ide
        val resultSet = statement.executeQuery(sql.toString())
        
        // Process resultSet
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @RequestMapping("/bad_case_10")
    fun bad_case_10(request: HttpServletRequest, response: HttpServletResponse) {
        val header = request.getHeader("X-Sort-Column")
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        val statement = connection.createStatement()
        
        // ruleid: kotlin-sql-injection-ide
        val resultSet = statement.executeQuery("SELECT * FROM products ORDER BY $header")
        
        // Process resultSet
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/bad_case_11")
    fun bad_case_11(request: HttpServletRequest, response: HttpServletResponse) {
        val cookie = request.getCookies().find { it.name == "user_filter" }?.value ?: ""
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        val statement = connection.createStatement()
        
        // ruleid: kotlin-sql-injection-ide
        val resultSet = statement.executeQuery("SELECT * FROM users WHERE role = '$cookie'")
        
        // Process resultSet
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @PostMapping("/bad_case_12")
    fun bad_case_12(request: HttpServletRequest, response: HttpServletResponse) {
        val userId = request.getParameter("id")
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        
        // Even with string concatenation in a variable, it's still vulnerable
        val query = "DELETE FROM users WHERE id = " + userId
        val statement = connection.createStatement()
        
        // ruleid: kotlin-sql-injection-ide
        statement.executeUpdate(query)
        
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/bad_case_13")
    fun bad_case_13(request: HttpServletRequest, response: HttpServletResponse) {
        val searchTerm = request.getParameter("search")
        val sortOrder = request.getParameter("order")
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        
        // Multiple user inputs in one query
        val query = "SELECT * FROM products WHERE name LIKE '%$searchTerm%' ORDER BY price $sortOrder"
        val statement = connection.createStatement()
        
        // ruleid: kotlin-sql-injection-ide
        val resultSet = statement.executeQuery(query)
        
        // Process resultSet
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @PostMapping("/bad_case_14")
    fun bad_case_14(request: HttpServletRequest, response: HttpServletResponse) {
        val tableName = request.getParameter("table")
        val columnName = request.getParameter("column")
        val value = request.getParameter("value")
        
        // ruleid: kotlin-sql-injection-ide
        jdbcTemplate.update("INSERT INTO $tableName ($columnName) VALUES ('$value')")
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
    @GetMapping("/bad_case_15")
    fun bad_case_15(request: HttpServletRequest, response: HttpServletResponse) {
        val userId = request.getParameter("id")
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        
        try {
            val statement = connection.createStatement()
            // Vulnerable even inside try-catch
            // ruleid: kotlin-sql-injection-ide
            val resultSet = statement.executeQuery("SELECT * FROM users WHERE id = $userId")
            // Process resultSet
        } catch (e: Exception) {
            e.printStackTrace()
        } finally {
            connection.close()
        }
    }
// {/fact}

    // True Negative Examples (Secure Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/good_case_1")
    fun good_case_1(request: HttpServletRequest, response: HttpServletResponse) {
        val userId = request.getParameter("id")
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        
        // ok: kotlin-sql-injection-ide
        val preparedStatement = connection.prepareStatement("SELECT * FROM users WHERE id = ?")
        preparedStatement.setString(1, userId)
        val resultSet = preparedStatement.executeQuery()
        
        // Process resultSet
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
    @PostMapping("/good_case_2")
    fun good_case_2(request: HttpServletRequest, response: HttpServletResponse) {
        val username = request.getParameter("username")
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        
        // ok: kotlin-sql-injection-ide
        val preparedStatement = connection.prepareStatement("UPDATE users SET active = true WHERE username = ?")
        preparedStatement.setString(1, username)
        preparedStatement.executeUpdate()
        
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/good_case_3")
    fun good_case_3(request: HttpServletRequest, response: HttpServletResponse) {
        val searchTerm = request.getParameter("search")
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        
        // ok: kotlin-sql-injection-ide
        val preparedStatement = connection.prepareStatement("SELECT * FROM products WHERE name LIKE ?")
        preparedStatement.setString(1, "%$searchTerm%")
        val resultSet = preparedStatement.executeQuery()
        
        // Process resultSet
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
    @RequestMapping("/good_case_4")
    fun good_case_4(request: HttpServletRequest, response: HttpServletResponse) {
        val userIds = request.getParameter("ids").split(",").map { it.trim() }
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        
        // Create a proper parameterized query with the right number of placeholders
        val placeholders = userIds.joinToString(", ") { "?" }
        
        // ok: kotlin-sql-injection-ide
        val preparedStatement = connection.prepareStatement("DELETE FROM users WHERE id IN ($placeholders)")
        
        // Set each parameter individually
        userIds.forEachIndexed { index, id ->
            preparedStatement.setString(index + 1, id)
        }
        
        preparedStatement.executeUpdate()
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/good_case_5")
    fun good_case_5(request: HttpServletRequest, response: HttpServletResponse) {
        val sortColumn = request.getParameter("sort")
        
        // Validate input against a whitelist of allowed columns
        val allowedColumns = listOf("name", "price", "date_added", "stock")
        val safeColumn = if (sortColumn in allowedColumns) sortColumn else "name"
        
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        val statement = connection.createStatement()
        
        // ok: kotlin-sql-injection-ide
        val resultSet = statement.executeQuery("SELECT * FROM products ORDER BY $safeColumn")
        
        // Process resultSet
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
    @PostMapping("/good_case_6")
    fun good_case_6(request: HttpServletRequest, response: HttpServletResponse) {
        val userId = request.getParameter("id")
        val role = request.getParameter("role")
        
        // ok: kotlin-sql-injection-ide
        val params = MapSqlParameterSource()
            .addValue("userId", userId)
            .addValue("role", role)
        
        val results = namedParameterJdbcTemplate.queryForList(
            "SELECT * FROM users WHERE id = :userId AND role = :role", 
            params
        )
        
        // Process results
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/good_case_7")
    fun good_case_7(request: HttpServletRequest, response: HttpServletResponse) {
        val userId = request.getParameter("id")
        val limit = request.getParameter("limit")
        
        // Validate numeric inputs
        val safeUserId = userId.toIntOrNull() ?: 0
        val safeLimit = limit.toIntOrNull()?.coerceIn(1, 100) ?: 10
        
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        
        // ok: kotlin-sql-injection-ide
        val preparedStatement = connection.prepareStatement(
            "SELECT * FROM users WHERE department_id = ? LIMIT ?"
        )
        preparedStatement.setInt(1, safeUserId)
        preparedStatement.setInt(2, safeLimit)
        
        val resultSet = preparedStatement.executeQuery()
        // Process resultSet
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
    @RequestMapping("/good_case_8")
    fun good_case_8(request: HttpServletRequest, response: HttpServletResponse) {
        val category = request.getParameter("category")
        
        // ok: kotlin-sql-injection-ide
        val results = jdbcTemplate.queryForList(
            "SELECT * FROM products WHERE category = ?",
            category
        )
        
        // Process results
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/good_case_9")
    fun good_case_9(request: HttpServletRequest, response: HttpServletResponse) {
        val header = request.getHeader("X-Sort-Column")
        
        // Whitelist validation for column names
        val validColumns = setOf("id", "name", "price", "created_at")
        val column = if (header in validColumns) header else "id"
        
        // ok: kotlin-sql-injection-ide
        val results = jdbcTemplate.queryForList("SELECT * FROM products ORDER BY $column")
        
        // Process results
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
    @PostMapping("/good_case_10")
    fun good_case_10(request: HttpServletRequest, response: HttpServletResponse) {
        val cookie = request.getCookies().find { it.name == "user_filter" }?.value ?: ""
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        
        // ok: kotlin-sql-injection-ide
        val preparedStatement = connection.prepareStatement("SELECT * FROM users WHERE role = ?")
        preparedStatement.setString(1, cookie)
        val resultSet = preparedStatement.executeQuery()
        
        // Process resultSet
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/good_case_11")
    fun good_case_11(request: HttpServletRequest, response: HttpServletResponse) {
        val tableName = request.getParameter("table")
        
        // Validate table name against a whitelist
        val allowedTables = setOf("products", "categories", "tags")
        if (tableName !in allowedTables) {
            response.sendError(400, "Invalid table name")
            return
        }
        
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        val statement = connection.createStatement()
        
        // ok: kotlin-sql-injection-ide
        val resultSet = statement.executeQuery("SELECT * FROM $tableName")
        
        // Process resultSet
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
    @PostMapping("/good_case_12")
    fun good_case_12(request: HttpServletRequest, response: HttpServletResponse) {
        val searchTerm = request.getParameter("search")
        val sortOrder = request.getParameter("order")
        
        // Validate sort order
        val safeOrder = if (sortOrder.equals("ASC", ignoreCase = true) || 
                            sortOrder.equals("DESC", ignoreCase = true)) {
            sortOrder.toUpperCase()
        } else {
            "ASC"
        }
        
        // ok: kotlin-sql-injection-ide
        val preparedStatement = jdbcTemplate.dataSource!!.connection.prepareStatement(
            "SELECT * FROM products WHERE name LIKE ? ORDER BY price $safeOrder"
        )
        preparedStatement.setString(1, "%$searchTerm%")
        val resultSet = preparedStatement.executeQuery()
        
        // Process resultSet
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/good_case_13")
    fun good_case_13(request: HttpServletRequest, response: HttpServletResponse) {
        val tableName = request.getParameter("table")
        val columnName = request.getParameter("column")
        val value = request.getParameter("value")
        
        // Validate table and column names using regex
        val validIdentifierPattern = Pattern.compile("^[a-zA-Z0-9_]+$")
        
        if (!validIdentifierPattern.matcher(tableName).matches() || 
            !validIdentifierPattern.matcher(columnName).matches()) {
            response.sendError(400, "Invalid table or column name")
            return
        }
        
        val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
        
        // ok: kotlin-sql-injection-ide
        val preparedStatement = connection.prepareStatement(
            "INSERT INTO $tableName ($columnName) VALUES (?)"
        )
        preparedStatement.setString(1, value)
        preparedStatement.executeUpdate()
        
        connection.close()
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
    @PostMapping("/good_case_14")
    fun good_case_14(request: HttpServletRequest, response: HttpServletResponse) {
        val userId = request.getParameter("id")
        
        try {
            val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
            
            // ok: kotlin-sql-injection-ide
            val preparedStatement = connection.prepareStatement(
                "SELECT * FROM users WHERE id = ?"
            )
            preparedStatement.setString(1, userId)
            val resultSet = preparedStatement.executeQuery()
            
            // Process resultSet
            connection.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
    @GetMapping("/good_case_15")
    fun good_case_15(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("input")
        
        // Sanitize input by escaping special characters
        val sanitizedInput = Encode.forHtml(userInput)
        
        // Additional validation - ensure it's a number
        val numericInput = userInput.toIntOrNull()
        
        if (numericInput != null) {
            val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
            
            // ok: kotlin-sql-injection-ide
            val preparedStatement = connection.prepareStatement(
                "SELECT * FROM data WHERE value = ?"
            )
            preparedStatement.setInt(1, numericInput)
            val resultSet = preparedStatement.executeQuery()
            
            // Process resultSet
            connection.close()
        } else {
            response.sendError(400, "Invalid input")
        }
    }
// {/fact}
}