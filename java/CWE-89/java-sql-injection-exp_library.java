import java.sql.*;
import javax.servlet.http.*;
import java.io.*;
import javax.servlet.*;
import org.springframework.web.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.hibernate.*;
import org.hibernate.query.Query;
import javax.persistence.*;
import org.apache.struts2.interceptor.ServletRequestAware;
import com.opensymphony.xwork2.ActionSupport;
import spark.*;
import play.mvc.*;
import play.db.*;
import io.javalin.http.Context;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.mysqlclient.MySQLPool;
import io.vertx.sqlclient.RowSet;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.Tuple;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import ratpack.http.Request;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.jooq.DSLContext;
import org.jooq.SQLDialect;
import org.jooq.impl.DSL;
import org.jdbi.v3.core.Jdbi;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.quarkus.hibernate.orm.panache.PanacheEntity;
import io.quarkus.hibernate.orm.panache.PanacheQuery;
import io.quarkus.panache.common.Parameters;
import org.apache.cayenne.ObjectContext;
import org.apache.cayenne.query.ObjectSelect;
import org.apache.cayenne.query.SQLTemplate;
import org.mybatis.dynamic.sql.SqlBuilder;
import org.mybatis.dynamic.sql.render.RenderingStrategies;
import org.mybatis.dynamic.sql.select.render.SelectStatementProvider;
import org.apache.commons.dbutils.QueryRunner;
import org.apache.commons.dbutils.handlers.MapListHandler;

// Security Issue: SQL Injection through unsanitized user input in SQL queries

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) throws SQLException {
    String username = request.getParameter("username");
    Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
    Statement stmt = conn.createStatement();
    // ruleid: java-sql-injection-exp
    ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
    while (rs.next()) {
        // Process results
    }
    conn.close();
}

public void bad_case_2(HttpServletRequest request) throws SQLException {
    String category = request.getParameter("category");
    Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
    // ruleid: java-sql-injection-exp
    PreparedStatement stmt = conn.prepareStatement("SELECT * FROM products WHERE category = '" + category + "' ORDER BY price");
    ResultSet rs = stmt.executeQuery();
    while (rs.next()) {
        // Process results
    }
    conn.close();
}

@RestController
public class bad_case_3 {
    private JdbcTemplate jdbcTemplate;
    
    @GetMapping("/users")
    public List<Map<String, Object>> getUsers(@RequestParam String department) {
        // ruleid: java-sql-injection-exp
        return jdbcTemplate.queryForList("SELECT * FROM employees WHERE department = '" + department + "'");
    }
}

public class bad_case_4 extends ActionSupport implements ServletRequestAware {
    private HttpServletRequest request;
    private SessionFactory sessionFactory;
    
    public String execute() {
        String productId = request.getParameter("productId");
        Session session = sessionFactory.openSession();
        // ruleid: java-sql-injection-exp
        Query<Product> query = session.createQuery("FROM Product p WHERE p.id = " + productId);
        List<Product> products = query.list();
        session.close();
        return SUCCESS;
    }
    
    @Override
    public void setServletRequest(HttpServletRequest request) {
        this.request = request;
    }
}

public class bad_case_5 {
    @PersistenceContext
    private EntityManager entityManager;
    
    public List<User> findUsers(HttpServletRequest request) {
        String role = request.getParameter("role");
        // ruleid: java-sql-injection-exp
        Query query = entityManager.createQuery("SELECT u FROM User u WHERE u.role = '" + role + "'");
        return query.getResultList();
    }
}

public class bad_case_6 {
    public static void main(String[] args) {
        Spark.get("/products", (req, res) -> {
            String minPrice = req.queryParams("minPrice");
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            // ruleid: java-sql-injection-exp
            ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE price > " + minPrice);
            // Process and return results
            conn.close();
            return "Products fetched";
        });
    }
}

public class bad_case_7 extends Controller {
    public Result getOrders(Http.Request request) {
        String status = request.getQueryString("status");
        Connection conn = DB.getConnection();
        try {
            Statement stmt = conn.createStatement();
            // ruleid: java-sql-injection-exp
            ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE status = '" + status + "'");
            // Process results
            return ok("Orders fetched");
        } catch (SQLException e) {
            return internalServerError(e.getMessage());
        }
    }
}

public class bad_case_8 {
    public void handleRequest(io.javalin.http.Context ctx) {
        String userId = ctx.queryParam("userId");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            // ruleid: java-sql-injection-exp
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM user_logs WHERE user_id = " + userId);
            ResultSet rs = stmt.executeQuery();
            // Process results
            conn.close();
        } catch (SQLException e) {
            ctx.status(500).result("Error: " + e.getMessage());
        }
    }
}

public class bad_case_9 {
    public void start() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.get("/customers").handler(rc -> {
            String region = rc.request().getParam("region");
            MySQLPool client = MySQLPool.pool(vertx, "connection-uri");
            
            // ruleid: java-sql-injection-exp
            client.query("SELECT * FROM customers WHERE region = '" + region + "'")
                .execute(ar -> {
                    if (ar.succeeded()) {
                        RowSet<Row> rows = ar.result();
                        // Process rows
                        rc.response().end("Customers fetched");
                    } else {
                        rc.response().setStatusCode(500).end(ar.cause().getMessage());
                    }
                });
        });
        
        vertx.createHttpServer().requestHandler(router).listen(8080);
    }
}

public class bad_case_10 implements Handler {
    @Override
    public void handle(ratpack.handling.Context ctx) {
        Request request = ctx.getRequest();
        String category = request.getQueryParams().get("category");
        
        ctx.blocking(() -> {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            // ruleid: java-sql-injection-exp
            ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE category = '" + category + "'");
            // Process and return results
            conn.close();
            return "Products fetched";
        }).then(ctx::render);
    }
}

public class bad_case_11 {
    public void searchItems(HttpServletRequest request) {
        String searchTerm = request.getParameter("search");
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
        config.setUsername("user");
        config.setPassword("password");
        
        try (HikariDataSource ds = new HikariDataSource(config);
             Connection conn = ds.getConnection();
             Statement stmt = conn.createStatement()) {
            
            // ruleid: java-sql-injection-exp
            ResultSet rs = stmt.executeQuery("SELECT * FROM items WHERE name LIKE '%" + searchTerm + "%'");
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}

public class bad_case_12 {
    public void getRecords(HttpServletRequest request) {
        String date = request.getParameter("date");
        DSLContext create = DSL.using("jdbc:mysql://localhost:3306/mydb", "user", "password", SQLDialect.MYSQL);
        
        // ruleid: java-sql-injection-exp
        Result<?> result = create.fetch("SELECT * FROM records WHERE created_date > '" + date + "'");
        // Process results
    }
}

public class bad_case_13 {
    public void getTransactions(HttpServletRequest request) {
        String accountId = request.getParameter("accountId");
        Jdbi jdbi = Jdbi.create("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        List<Map<String, Object>> results = jdbi.withHandle(handle -> {
            // ruleid: java-sql-injection-exp
            return handle.createQuery("SELECT * FROM transactions WHERE account_id = " + accountId)
                    .mapToMap()
                    .list();
        });
        // Process results
    }
}

@Controller
public class bad_case_14 {
    @Get("/reports")
    public String getReports(HttpRequest<?> request) {
        String reportType = request.getParameters().get("type");
        
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
             Statement stmt = conn.createStatement()) {
            
            // ruleid: java-sql-injection-exp
            ResultSet rs = stmt.executeQuery("SELECT * FROM reports WHERE type = '" + reportType + "'");
            // Process results
            return "Reports fetched";
        } catch (SQLException e) {
            return "Error: " + e.getMessage();
        }
    }
}

public class bad_case_15 {
    private ObjectContext context;
    
    public List<Map<String, Object>> getEmployeeData(HttpServletRequest request) {
        String department = request.getParameter("department");
        
        // ruleid: java-sql-injection-exp
        SQLTemplate query = new SQLTemplate(Employee.class, 
            "SELECT * FROM employees WHERE department = '" + department + "'");
        
        return context.performQuery(query);
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) throws SQLException {
    String username = request.getParameter("username");
    Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
    // ok: java-sql-injection-exp
    PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
    stmt.setString(1, username);
    ResultSet rs = stmt.executeQuery();
    while (rs.next()) {
        // Process results
    }
    conn.close();
}

public void good_case_2(HttpServletRequest request) throws SQLException {
    String category = request.getParameter("category");
    Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
    // ok: java-sql-injection-exp
    PreparedStatement stmt = conn.prepareStatement("SELECT * FROM products WHERE category = ? ORDER BY price");
    stmt.setString(1, category);
    ResultSet rs = stmt.executeQuery();
    while (rs.next()) {
        // Process results
    }
    conn.close();
}

@RestController
public class good_case_3 {
    private JdbcTemplate jdbcTemplate;
    
    @GetMapping("/users")
    public List<Map<String, Object>> getUsers(@RequestParam String department) {
        // ok: java-sql-injection-exp
        return jdbcTemplate.queryForList("SELECT * FROM employees WHERE department = ?", department);
    }
}

public class good_case_4 extends ActionSupport implements ServletRequestAware {
    private HttpServletRequest request;
    private SessionFactory sessionFactory;
    
    public String execute() {
        String productId = request.getParameter("productId");
        Session session = sessionFactory.openSession();
        // ok: java-sql-injection-exp
        Query<Product> query = session.createQuery("FROM Product p WHERE p.id = :id");
        query.setParameter("id", Integer.parseInt(productId));
        List<Product> products = query.list();
        session.close();
        return SUCCESS;
    }
    
    @Override
    public void setServletRequest(HttpServletRequest request) {
        this.request = request;
    }
}

public class good_case_5 {
    @PersistenceContext
    private EntityManager entityManager;
    
    public List<User> findUsers(HttpServletRequest request) {
        String role = request.getParameter("role");
        // ok: java-sql-injection-exp
        Query query = entityManager.createQuery("SELECT u FROM User u WHERE u.role = :role");
        query.setParameter("role", role);
        return query.getResultList();
    }
}

public class good_case_6 {
    public static void main(String[] args) {
        Spark.get("/products", (req, res) -> {
            String minPrice = req.queryParams("minPrice");
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            // ok: java-sql-injection-exp
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM products WHERE price > ?");
            stmt.setDouble(1, Double.parseDouble(minPrice));
            ResultSet rs = stmt.executeQuery();
            // Process and return results
            conn.close();
            return "Products fetched";
        });
    }
}

public class good_case_7 extends Controller {
    public Result getOrders(Http.Request request) {
        String status = request.getQueryString("status");
        Connection conn = DB.getConnection();
        try {
            // ok: java-sql-injection-exp
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM orders WHERE status = ?");
            stmt.setString(1, status);
            ResultSet rs = stmt.executeQuery();
            // Process results
            return ok("Orders fetched");
        } catch (SQLException e) {
            return internalServerError(e.getMessage());
        }
    }
}

public class good_case_8 {
    public void handleRequest(io.javalin.http.Context ctx) {
        String userId = ctx.queryParam("userId");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            // ok: java-sql-injection-exp
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM user_logs WHERE user_id = ?");
            stmt.setInt(1, Integer.parseInt(userId));
            ResultSet rs = stmt.executeQuery();
            // Process results
            conn.close();
        } catch (SQLException e) {
            ctx.status(500).result("Error: " + e.getMessage());
        }
    }
}

public class good_case_9 {
    public void start() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.get("/customers").handler(rc -> {
            String region = rc.request().getParam("region");
            MySQLPool client = MySQLPool.pool(vertx, "connection-uri");
            
            // ok: java-sql-injection-exp
            client.preparedQuery("SELECT * FROM customers WHERE region = ?")
                .execute(Tuple.of(region), ar -> {
                    if (ar.succeeded()) {
                        RowSet<Row> rows = ar.result();
                        // Process rows
                        rc.response().end("Customers fetched");
                    } else {
                        rc.response().setStatusCode(500).end(ar.cause().getMessage());
                    }
                });
        });
        
        vertx.createHttpServer().requestHandler(router).listen(8080);
    }
}

public class good_case_10 implements Handler {
    @Override
    public void handle(ratpack.handling.Context ctx) {
        Request request = ctx.getRequest();
        String category = request.getQueryParams().get("category");
        
        ctx.blocking(() -> {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            // ok: java-sql-injection-exp
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM products WHERE category = ?");
            stmt.setString(1, category);
            ResultSet rs = stmt.executeQuery();
            // Process and return results
            conn.close();
            return "Products fetched";
        }).then(ctx::render);
    }
}

public class good_case_11 {
    public void searchItems(HttpServletRequest request) {
        String searchTerm = request.getParameter("search");
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
        config.setUsername("user");
        config.setPassword("password");
        
        try (HikariDataSource ds = new HikariDataSource(config);
             Connection conn = ds.getConnection()) {
            
            // ok: java-sql-injection-exp
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM items WHERE name LIKE ?");
            stmt.setString(1, "%" + searchTerm + "%");
            ResultSet rs = stmt.executeQuery();
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}

public class good_case_12 {
    public void getRecords(HttpServletRequest request) {
        String date = request.getParameter("date");
        DSLContext create = DSL.using("jdbc:mysql://localhost:3306/mydb", "user", "password", SQLDialect.MYSQL);
        
        // ok: java-sql-injection-exp
        Result<?> result = create.fetch("SELECT * FROM records WHERE created_date > ?", date);
        // Process results
    }
}

public class good_case_13 {
    public void getTransactions(HttpServletRequest request) {
        String accountId = request.getParameter("accountId");
        Jdbi jdbi = Jdbi.create("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        List<Map<String, Object>> results = jdbi.withHandle(handle -> {
            // ok: java-sql-injection-exp
            return handle.createQuery("SELECT * FROM transactions WHERE account_id = :accountId")
                    .bind("accountId", Integer.parseInt(accountId))
                    .mapToMap()
                    .list();
        });
        // Process results
    }
}

@Controller
public class good_case_14 {
    @Get("/reports")
    public String getReports(HttpRequest<?> request) {
        String reportType = request.getParameters().get("type");
        
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")) {
            // ok: java-sql-injection-exp
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM reports WHERE type = ?");
            stmt.setString(1, reportType);
            ResultSet rs = stmt.executeQuery();
            // Process results
            return "Reports fetched";
        } catch (SQLException e) {
            return "Error: " + e.getMessage();
        }
    }
}

public class good_case_15 {
    public List<Map<String, Object>> getEmployeeData(HttpServletRequest request) throws SQLException {
        String department = request.getParameter("department");
        
        QueryRunner queryRunner = new QueryRunner();
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // ok: java-sql-injection-exp
        List<Map<String, Object>> results = queryRunner.query(
            conn, 
            "SELECT * FROM employees WHERE department = ?", 
            new MapListHandler(), 
            department
        );
        
        conn.close();
        return results;
    }
}