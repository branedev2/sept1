import java.sql.*;
import javax.servlet.http.*;
import javax.servlet.*;
import java.io.*;
import org.springframework.web.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import com.amazonaws.services.redshiftdataapi.*;
import com.amazonaws.services.redshiftdataapi.model.*;
import spark.*;
import play.mvc.*;
import play.mvc.Http.Request;
import io.javalin.http.Context;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import com.zaxxer.hikari.HikariDataSource;
import org.apache.commons.dbcp2.BasicDataSource;
import org.apache.tomcat.jdbc.pool.DataSource;
import com.mchange.v2.c3p0.ComboPooledDataSource;
import org.jooq.DSLContext;
import org.jooq.impl.DSL;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.statement.PreparedBatch;
import com.querydsl.sql.SQLQueryFactory;
import com.querydsl.sql.Configuration;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.query.NativeQuery;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.UUID;
import java.util.regex.Pattern;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.OracleCodec;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.text.StringEscapeUtils;

// Security Issue: SQL Injection in Redshift database connections

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) throws SQLException {
    String userId = request.getParameter("id");
    Connection conn = DriverManager.getConnection("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
    Statement stmt = conn.createStatement();
    
    // ruleid: java-sql-injection-redshift
    ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE user_id = " + userId);
    
    while (rs.next()) {
        // Process results
    }
    rs.close();
    stmt.close();
    conn.close();
}

public void bad_case_2(HttpServletRequest request) throws SQLException {
    String searchTerm = request.getParameter("search");
    Connection conn = DriverManager.getConnection("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
    Statement stmt = conn.createStatement();
    
    // ruleid: java-sql-injection-redshift
    ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'");
    
    while (rs.next()) {
        // Process results
    }
    rs.close();
    stmt.close();
    conn.close();
}

@RestController
public class bad_case_3 {
    private JdbcTemplate jdbcTemplate;
    
    @GetMapping("/users/{username}")
    public List<Map<String, Object>> getUserData(@PathVariable String username) {
        // ruleid: java-sql-injection-redshift
        return jdbcTemplate.queryForList("SELECT * FROM user_data WHERE username = '" + username + "'");
    }
}

public void bad_case_4(HttpServletRequest request) {
    String tableName = request.getParameter("table");
    AmazonRedshiftDataAPIClient client = new AmazonRedshiftDataAPIClient();
    
    ExecuteStatementRequest executeStatementRequest = new ExecuteStatementRequest()
        .withClusterIdentifier("my-cluster")
        .withDatabase("dev")
        .withDbUser("admin");
    
    // ruleid: java-sql-injection-redshift
    executeStatementRequest.withSql("SELECT * FROM " + tableName + " LIMIT 100");
    
    client.executeStatement(executeStatementRequest);
}

public class bad_case_5 implements Handler {
    @Override
    public void handle(ratpack.handling.Context ctx) throws Exception {
        String sortColumn = ctx.getRequest().getQueryParams().get("sort");
        Connection conn = DriverManager.getConnection("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
        Statement stmt = conn.createStatement();
        
        // ruleid: java-sql-injection-redshift
        ResultSet rs = stmt.executeQuery("SELECT * FROM orders ORDER BY " + sortColumn);
        
        // Process and return results
        conn.close();
    }
}

public void bad_case_6(io.javalin.http.Context ctx) throws SQLException {
    String category = ctx.queryParam("category");
    Connection conn = DriverManager.getConnection("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
    
    // ruleid: java-sql-injection-redshift
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE category = '" + category + "'");
    
    // Process results
    conn.close();
}

@Controller
public class bad_case_7 {
    private final SessionFactory sessionFactory;
    
    @Get("/reports")
    public String getReports(HttpRequest<?> request) {
        String reportType = request.getParameters().get("type");
        Session session = sessionFactory.openSession();
        
        // ruleid: java-sql-injection-redshift
        NativeQuery<?> query = session.createNativeQuery("SELECT * FROM reports WHERE type = '" + reportType + "'");
        List<?> results = query.list();
        
        session.close();
        return results.toString();
    }
}

public void bad_case_8(play.mvc.Http.Request request) throws SQLException {
    String dateRange = request.getQueryString("date");
    Connection conn = DriverManager.getConnection("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
    
    // ruleid: java-sql-injection-redshift
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT * FROM sales WHERE sale_date BETWEEN " + dateRange);
    
    // Process results
    conn.close();
}

public void bad_case_9(spark.Request req, spark.Response res) throws SQLException {
    String status = req.queryParams("status");
    HikariDataSource ds = new HikariDataSource();
    ds.setJdbcUrl("jdbc:redshift://redshift-cluster.example.com:5439/mydb");
    ds.setUsername("username");
    ds.setPassword("password");
    
    Connection conn = ds.getConnection();
    // ruleid: java-sql-injection-redshift
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE status = '" + status + "'");
    
    // Process results
    conn.close();
}

public void bad_case_10(HttpServletRequest request) throws SQLException {
    String priceFilter = request.getParameter("price");
    BasicDataSource dataSource = new BasicDataSource();
    dataSource.setDriverClassName("com.amazon.redshift.jdbc.Driver");
    dataSource.setUrl("jdbc:redshift://redshift-cluster.example.com:5439/mydb");
    dataSource.setUsername("username");
    dataSource.setPassword("password");
    
    Connection conn = dataSource.getConnection();
    // ruleid: java-sql-injection-redshift
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE price > " + priceFilter);
    
    // Process results
    conn.close();
}

public void bad_case_11(HttpServletRequest request) throws SQLException {
    String region = request.getParameter("region");
    DSLContext create = DSL.using("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
    
    // ruleid: java-sql-injection-redshift
    List<Map<String, Object>> result = create.fetch("SELECT * FROM customers WHERE region = '" + region + "'")
        .intoMaps();
    
    // Process results
}

public void bad_case_12(HttpServletRequest request) throws SQLException {
    String limit = request.getParameter("limit");
    Jdbi jdbi = Jdbi.create("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
    
    List<Map<String, Object>> results = jdbi.withHandle(handle -> {
        // ruleid: java-sql-injection-redshift
        return handle.createQuery("SELECT * FROM transactions LIMIT " + limit)
            .mapToMap()
            .list();
    });
    
    // Process results
}

public void bad_case_13(HttpServletRequest request) throws SQLException {
    String userId = request.getParameter("userId");
    ComboPooledDataSource cpds = new ComboPooledDataSource();
    cpds.setDriverClass("com.amazon.redshift.jdbc.Driver");
    cpds.setJdbcUrl("jdbc:redshift://redshift-cluster.example.com:5439/mydb");
    cpds.setUser("username");
    cpds.setPassword("password");
    
    Connection conn = cpds.getConnection();
    // ruleid: java-sql-injection-redshift
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("DELETE FROM sessions WHERE user_id = " + userId);
    
    conn.close();
}

public void bad_case_14(HttpServletRequest request) throws SQLException {
    String columns = request.getParameter("columns");
    org.apache.tomcat.jdbc.pool.DataSource ds = new org.apache.tomcat.jdbc.pool.DataSource();
    ds.setDriverClassName("com.amazon.redshift.jdbc.Driver");
    ds.setUrl("jdbc:redshift://redshift-cluster.example.com:5439/mydb");
    ds.setUsername("username");
    ds.setPassword("password");
    
    Connection conn = ds.getConnection();
    // ruleid: java-sql-injection-redshift
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT " + columns + " FROM analytics");
    
    // Process results
    conn.close();
}

public void bad_case_15(HttpServletRequest request) throws SQLException {
    String groupBy = request.getParameter("groupBy");
    Connection conn = DriverManager.getConnection("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
    
    // ruleid: java-sql-injection-redshift
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT category, SUM(amount) FROM transactions GROUP BY " + groupBy);
    
    // Process results
    conn.close();
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) throws SQLException {
    String userId = request.getParameter("id");
    Connection conn = DriverManager.getConnection("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
    
    // ok: java-sql-injection-redshift
    PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE user_id = ?");
    pstmt.setString(1, userId);
    ResultSet rs = pstmt.executeQuery();
    
    while (rs.next()) {
        // Process results
    }
    rs.close();
    pstmt.close();
    conn.close();
}

public void good_case_2(HttpServletRequest request) throws SQLException {
    String searchTerm = request.getParameter("search");
    Connection conn = DriverManager.getConnection("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
    
    // ok: java-sql-injection-redshift
    PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM products WHERE name LIKE ?");
    pstmt.setString(1, "%" + searchTerm + "%");
    ResultSet rs = pstmt.executeQuery();
    
    while (rs.next()) {
        // Process results
    }
    rs.close();
    pstmt.close();
    conn.close();
}

@RestController
public class good_case_3 {
    private JdbcTemplate jdbcTemplate;
    
    @GetMapping("/users/{username}")
    public List<Map<String, Object>> getUserData(@PathVariable String username) {
        // ok: java-sql-injection-redshift
        return jdbcTemplate.queryForList("SELECT * FROM user_data WHERE username = ?", username);
    }
}

public void good_case_4(HttpServletRequest request) {
    String tableName = request.getParameter("table");
    // Validate against a whitelist of allowed table names
    List<String> allowedTables = Arrays.asList("customers", "orders", "products");
    if (!allowedTables.contains(tableName)) {
        tableName = "customers"; // Default to a safe value
    }
    
    AmazonRedshiftDataAPIClient client = new AmazonRedshiftDataAPIClient();
    
    ExecuteStatementRequest executeStatementRequest = new ExecuteStatementRequest()
        .withClusterIdentifier("my-cluster")
        .withDatabase("dev")
        .withDbUser("admin");
    
    // ok: java-sql-injection-redshift
    executeStatementRequest.withSql("SELECT * FROM " + tableName + " LIMIT 100");
    
    client.executeStatement(executeStatementRequest);
}

public class good_case_5 implements Handler {
    private final List<String> ALLOWED_SORT_COLUMNS = Arrays.asList("order_id", "order_date", "customer_id", "amount");
    
    @Override
    public void handle(ratpack.handling.Context ctx) throws Exception {
        String sortColumn = ctx.getRequest().getQueryParams().get("sort");
        
        // Validate sort column against whitelist
        if (!ALLOWED_SORT_COLUMNS.contains(sortColumn)) {
            sortColumn = "order_id"; // Default to a safe value
        }
        
        Connection conn = DriverManager.getConnection("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
        
        // ok: java-sql-injection-redshift
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM orders ORDER BY " + sortColumn);
        ResultSet rs = pstmt.executeQuery();
        
        // Process and return results
        conn.close();
    }
}

public void good_case_6(io.javalin.http.Context ctx) throws SQLException {
    String category = ctx.queryParam("category");
    Connection conn = DriverManager.getConnection("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
    
    // ok: java-sql-injection-redshift
    PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM products WHERE category = ?");
    pstmt.setString(1, category);
    ResultSet rs = pstmt.executeQuery();
    
    // Process results
    conn.close();
}

@Controller
public class good_case_7 {
    private final SessionFactory sessionFactory;
    
    @Get("/reports")
    public String getReports(HttpRequest<?> request) {
        String reportType = request.getParameters().get("type");
        Session session = sessionFactory.openSession();
        
        // ok: java-sql-injection-redshift
        NativeQuery<?> query = session.createNativeQuery("SELECT * FROM reports WHERE type = :type");
        query.setParameter("type", reportType);
        List<?> results = query.list();
        
        session.close();
        return results.toString();
    }
}

public void good_case_8(play.mvc.Http.Request request) throws SQLException {
    String startDate = request.getQueryString("startDate");
    String endDate = request.getQueryString("endDate");
    Connection conn = DriverManager.getConnection("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
    
    // ok: java-sql-injection-redshift
    PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM sales WHERE sale_date BETWEEN ? AND ?");
    pstmt.setString(1, startDate);
    pstmt.setString(2, endDate);
    ResultSet rs = pstmt.executeQuery();
    
    // Process results
    conn.close();
}

public void good_case_9(spark.Request req, spark.Response res) throws SQLException {
    String status = req.queryParams("status");
    HikariDataSource ds = new HikariDataSource();
    ds.setJdbcUrl("jdbc:redshift://redshift-cluster.example.com:5439/mydb");
    ds.setUsername("username");
    ds.setPassword("password");
    
    Connection conn = ds.getConnection();
    // ok: java-sql-injection-redshift
    PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM orders WHERE status = ?");
    pstmt.setString(1, status);
    ResultSet rs = pstmt.executeQuery();
    
    // Process results
    conn.close();
}

public void good_case_10(HttpServletRequest request) throws SQLException {
    String priceFilter = request.getParameter("price");
    BasicDataSource dataSource = new BasicDataSource();
    dataSource.setDriverClassName("com.amazon.redshift.jdbc.Driver");
    dataSource.setUrl("jdbc:redshift://redshift-cluster.example.com:5439/mydb");
    dataSource.setUsername("username");
    dataSource.setPassword("password");
    
    Connection conn = dataSource.getConnection();
    // ok: java-sql-injection-redshift
    PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM products WHERE price > ?");
    pstmt.setString(1, priceFilter);
    ResultSet rs = pstmt.executeQuery();
    
    // Process results
    conn.close();
}

public void good_case_11(HttpServletRequest request) throws SQLException {
    String region = request.getParameter("region");
    DSLContext create = DSL.using("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
    
    // ok: java-sql-injection-redshift
    List<Map<String, Object>> result = create.fetch("SELECT * FROM customers WHERE region = ?", region)
        .intoMaps();
    
    // Process results
}

public void good_case_12(HttpServletRequest request) throws SQLException {
    String limit = request.getParameter("limit");
    Jdbi jdbi = Jdbi.create("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
    
    List<Map<String, Object>> results = jdbi.withHandle(handle -> {
        // ok: java-sql-injection-redshift
        return handle.createQuery("SELECT * FROM transactions LIMIT :limit")
            .bind("limit", limit)
            .mapToMap()
            .list();
    });
    
    // Process results
}

public void good_case_13(HttpServletRequest request) throws SQLException {
    String userId = request.getParameter("userId");
    ComboPooledDataSource cpds = new ComboPooledDataSource();
    cpds.setDriverClass("com.amazon.redshift.jdbc.Driver");
    cpds.setJdbcUrl("jdbc:redshift://redshift-cluster.example.com:5439/mydb");
    cpds.setUser("username");
    cpds.setPassword("password");
    
    Connection conn = cpds.getConnection();
    // ok: java-sql-injection-redshift
    PreparedStatement pstmt = conn.prepareStatement("DELETE FROM sessions WHERE user_id = ?");
    pstmt.setString(1, userId);
    pstmt.executeUpdate();
    
    conn.close();
}

public void good_case_14(HttpServletRequest request) throws SQLException {
    String[] requestedColumns = request.getParameterValues("columns");
    // Validate columns against whitelist
    List<String> allowedColumns = Arrays.asList("id", "name", "date", "value");
    List<String> validColumns = new ArrayList<>();
    
    if (requestedColumns != null) {
        for (String col : requestedColumns) {
            if (allowedColumns.contains(col)) {
                validColumns.add(col);
            }
        }
    }
    
    // Default if no valid columns
    if (validColumns.isEmpty()) {
        validColumns.add("id");
    }
    
    String columns = String.join(", ", validColumns);
    
    org.apache.tomcat.jdbc.pool.DataSource ds = new org.apache.tomcat.jdbc.pool.DataSource();
    ds.setDriverClassName("com.amazon.redshift.jdbc.Driver");
    ds.setUrl("jdbc:redshift://redshift-cluster.example.com:5439/mydb");
    ds.setUsername("username");
    ds.setPassword("password");
    
    Connection conn = ds.getConnection();
    // ok: java-sql-injection-redshift
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT " + columns + " FROM analytics");
    
    // Process results
    conn.close();
}

public void good_case_15(HttpServletRequest request) throws SQLException {
    String groupBy = request.getParameter("groupBy");
    // Validate against whitelist
    Map<String, String> validGroupings = new HashMap<>();
    validGroupings.put("daily", "DATE(transaction_date)");
    validGroupings.put("monthly", "EXTRAC_REDACTED_TWILIO_ID(MONTH FROM transaction_date)");
    validGroupings.put("category", "category");
    
    String groupByClause = validGroupings.getOrDefault(groupBy, "category");
    
    Connection conn = DriverManager.getConnection("jdbc:redshift://redshift-cluster.example.com:5439/mydb", "username", "password");
    
    // ok: java-sql-injection-redshift
    PreparedStatement pstmt = conn.prepareStatement("SELECT " + groupByClause + ", SUM(amount) FROM transactions GROUP BY " + groupByClause);
    ResultSet rs = pstmt.executeQuery();
    
    // Process results
    conn.close();
}