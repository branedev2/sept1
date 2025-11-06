import java.sql.*;
import javax.servlet.http.*;
import javax.servlet.*;
import java.io.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.*;
import org.springframework.web.*;
import org.hibernate.*;
import org.hibernate.query.Query;
import com.sun.net.httpserver.*;
import spark.*;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.micronaut.http.annotation.*;
import io.micronaut.http.*;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import com.zaxxer.hikari.HikariDataSource;
import org.apache.commons.dbutils.QueryRunner;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.statement.StatementContext;
import org.apache.cayenne.ObjectContext;
import org.apache.cayenne.query.SQLTemplate;
import org.apache.cayenne.access.DataContext;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.stmt.PreparedQuery;
import com.j256.ormlite.stmt.QueryBuilder;
import org.jooq.DSLContext;
import org.jooq.impl.DSL;
import org.jooq.SQLDialect;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.mysqlclient.MySQLPool;
import io.vertx.sqlclient.RowSet;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.Tuple;
import io.quarkus.vertx.web.Route;
import io.quarkus.vertx.web.RouteBase;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Http.Request;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

// Security Issue: SQL Injection vulnerability in Java applications

// True Positive Examples (Vulnerable/Insecure Code)

public class SqlInjectionExamples {

    // Using standard JDBC with HttpServlet
// {fact rule=cross-site-scripting@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String username = request.getParameter("username");
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        
        // ruleid: java-sql-injection-ide
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
        
        // Process results
        while (rs.next()) {
            response.getWriter().println(rs.getString("username"));
        }
        
        rs.close();
        stmt.close();
        conn.close();
    }

    // Using Spring JDBC Template
    @RestController
    public class bad_case_2 {
        private JdbcTemplate jdbcTemplate;
        
        public bad_case_2(JdbcTemplate jdbcTemplate) {
            this.jdbcTemplate = jdbcTemplate;
        }
        
        @GetMapping("/users")
        public List<Map<String, Object>> getUsers(@RequestParam String department) {
            // ruleid: java-sql-injection-ide
            return jdbcTemplate.queryForList("SELECT * FROM employees WHERE department = '" + department + "'");
        }
    }

    // Using Hibernate Session
    @RestController
    public class bad_case_3 {
        private final SessionFactory sessionFactory;
        
        public bad_case_3(SessionFactory sessionFactory) {
            this.sessionFactory = sessionFactory;
        }
        
        @PostMapping("/products")
        public List getProducts(HttpServletRequest request) {
            String category = request.getParameter("category");
            Session session = sessionFactory.openSession();
            
            // ruleid: java-sql-injection-ide
            List result = session.createSQLQuery("SELECT * FROM products WHERE category = '" + category + "'").list();
            
            session.close();
            return result;
        }
    }

    // Using Java built-in HttpServer
    public class bad_case_4 {
        public void startServer() throws IOException {
            HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
            server.createContext("/search", new SearchHandler());
            server.start();
        }
        
        class SearchHandler implements HttpHandler {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                String query = exchange.getRequestURI().getQuery();
                String searchTerm = query.substring(query.indexOf("=") + 1);
                
                try {
                    Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
                    Statement stmt = conn.createStatement();
                    
                    // ruleid: java-sql-injection-ide
                    ResultSet rs = stmt.executeQuery("SELECT * FROM articles WHERE title LIKE '%" + searchTerm + "%'");
                    
                    StringBuilder response = new StringBuilder();
                    while (rs.next()) {
                        response.append(rs.getString("title")).append("\n");
                    }
                    
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.toString().getBytes());
                    os.close();
                    
                    rs.close();
                    stmt.close();
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    // Using Spark Java framework
    public class bad_case_5 {
        public void setupRoutes() {
            Spark.get("/orders", (req, res) -> {
                String status = req.queryParams("status");
                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
                Statement stmt = conn.createStatement();
                
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE status = '" + status + "'");
                
                StringBuilder result = new StringBuilder();
                while (rs.next()) {
                    result.append(rs.getInt("id")).append(": ").append(rs.getString("description")).append("\n");
                }
                
                rs.close();
                stmt.close();
                conn.close();
                
                return result.toString();
            });
        }
    }

    // Using Javalin framework
    public class bad_case_6 {
        public void setupApp() {
            Javalin app = Javalin.create().start(7000);
            
            app.get("/customers", ctx -> {
                String city = ctx.queryParam("city");
                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
                Statement stmt = conn.createStatement();
                
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery("SELECT * FROM customers WHERE city = '" + city + "'");
                
                StringBuilder result = new StringBuilder();
                while (rs.next()) {
                    result.append(rs.getString("name")).append("\n");
                }
                
                ctx.result(result.toString());
                
                rs.close();
                stmt.close();
                conn.close();
            });
        }
    }

    // Using Micronaut framework
    @Controller("/api")
    public class bad_case_7 {
        
        private Connection getConnection() throws SQLException {
            return DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        }
        
        @Get("/suppliers")
        public HttpResponse<String> getSuppliers(HttpRequest request) {
            try {
                String country = request.getParameters().get("country");
                Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery("SELECT * FROM suppliers WHERE country = '" + country + "'");
                
                StringBuilder result = new StringBuilder();
                while (rs.next()) {
                    result.append(rs.getString("name")).append(", ").append(rs.getString("country")).append("\n");
                }
                
                rs.close();
                stmt.close();
                conn.close();
                
                return HttpResponse.ok(result.toString());
            } catch (SQLException e) {
                return HttpResponse.serverError("Database error");
            }
        }
    }

    // Using Ratpack framework
    public class bad_case_8 implements Handler {
        @Override
        public void handle(ratpack.handling.Context ctx) {
            String category = ctx.getRequest().getQueryParams().get("category");
            
            try {
                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
                Statement stmt = conn.createStatement();
                
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery("SELECT * FROM inventory WHERE category = '" + category + "'");
                
                StringBuilder result = new StringBuilder();
                while (rs.next()) {
                    result.append(rs.getString("item_name")).append(": ").append(rs.getInt("quantity")).append("\n");
                }
                
                ctx.render(result.toString());
                
                rs.close();
                stmt.close();
                conn.close();
            } catch (SQLException e) {
                ctx.render("Error: " + e.getMessage());
            }
        }
    }

    // Using HikariCP connection pool
    public class bad_case_9 {
        private HikariDataSource dataSource;
        
        public bad_case_9() {
            dataSource = new HikariDataSource();
            dataSource.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
            dataSource.setUsername("user");
            dataSource.setPassword("password");
        }
        
        public String getUserData(HttpServletRequest request) throws SQLException {
            String userId = request.getParameter("id");
            Connection conn = dataSource.getConnection();
            Statement stmt = conn.createStatement();
            
            // ruleid: java-sql-injection-ide
            ResultSet rs = stmt.executeQuery("SELECT * FROM user_data WHERE user_id = " + userId);
            
            StringBuilder result = new StringBuilder();
            while (rs.next()) {
                result.append(rs.getString("data_value")).append("\n");
            }
            
            rs.close();
            stmt.close();
            conn.close();
            
            return result.toString();
        }
    }

    // Using Apache Commons DbUtils
    public class bad_case_10 {
        private QueryRunner queryRunner;
        
        public bad_case_10() {
            queryRunner = new QueryRunner();
        }
        
        public List<Map<String, Object>> searchItems(HttpServletRequest request) throws SQLException {
            String keyword = request.getParameter("keyword");
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            
            // ruleid: java-sql-injection-ide
            ResultSet rs = conn.createStatement().executeQuery(
                "SELECT * FROM items WHERE name LIKE '%" + keyword + "%' OR description LIKE '%" + keyword + "%'"
            );
            
            List<Map<String, Object>> results = new ArrayList<>();
            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("id", rs.getInt("id"));
                row.put("name", rs.getString("name"));
                row.put("description", rs.getString("description"));
                results.add(row);
            }
            
            rs.close();
            conn.close();
            
            return results;
        }
    }

    // Using JDBI
    public class bad_case_11 {
        private Jdbi jdbi;
        
        public bad_case_11() {
            jdbi = Jdbi.create("jdbc:mysql://localhost:3306/mydb", "user", "password");
        }
        
        public List<Map<String, Object>> getTransactions(HttpServletRequest request) {
            String accountId = request.getParameter("accountId");
            
            // ruleid: java-sql-injection-ide
            return jdbi.withHandle(handle -> 
                handle.createQuery("SELECT * FROM transactions WHERE account_id = " + accountId)
                    .mapToMap()
                    .list()
            );
        }
    }

    // Using Apache Cayenne
    public class bad_case_12 {
        private ObjectContext context;
        
        public bad_case_12(ObjectContext context) {
            this.context = context;
        }
        
        public List<?> findEmployees(HttpServletRequest request) {
            String department = request.getParameter("department");
            
            // ruleid: java-sql-injection-ide
            SQLTemplate query = new SQLTemplate(Object.class, 
                "SELECT * FROM employees WHERE department = '" + department + "'");
            
            return context.performQuery(query);
        }
    }

    // Using ORMLite
    public class bad_case_13 {
        private JdbcConnectionSource connectionSource;
        
        public bad_case_13() throws SQLException {
            connectionSource = new JdbcConnectionSource(
                "jdbc:mysql://localhost:3306/mydb", "user", "password");
        }
        
        public List<Map<String, Object>> getReviews(HttpServletRequest request) throws SQLException {
            String productId = request.getParameter("productId");
            Connection conn = connectionSource.getConnection();
            Statement stmt = conn.createStatement();
            
            // ruleid: java-sql-injection-ide
            ResultSet rs = stmt.executeQuery("SELECT * FROM reviews WHERE product_id = " + productId);
            
            List<Map<String, Object>> results = new ArrayList<>();
            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("id", rs.getInt("id"));
                row.put("rating", rs.getInt("rating"));
                row.put("comment", rs.getString("comment"));
                results.add(row);
            }
            
            rs.close();
            stmt.close();
            
            return results;
        }
    }

    // Using jOOQ
    public class bad_case_14 {
        private DSLContext create;
        
        public bad_case_14() {
            Connection conn;
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
                create = DSL.using(conn, SQLDialect.MYSQL);
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        
        public String getProjectDetails(HttpServletRequest request) {
            String projectId = request.getParameter("id");
            
            // ruleid: java-sql-injection-ide
            Result<?> result = create.fetch("SELECT * FROM projects WHERE id = " + projectId);
            
            StringBuilder sb = new StringBuilder();
            for (Record r : result) {
                sb.append(r.getValue("name")).append(": ").append(r.getValue("description")).append("\n");
            }
            
            return sb.toString();
        }
    }

    // Using Vert.x
    public class bad_case_15 {
        private MySQLPool client;
        
        public void setupRoutes(Vertx vertx, Router router) {
            client = MySQLPool.pool(vertx, "jdbc:mysql://localhost:3306/mydb?user=user&password=password");
            
            router.get("/tasks").handler(this::getTasks);
        }
        
        private void getTasks(RoutingContext ctx) {
            String assignee = ctx.request().getParam("assignee");
            
            // ruleid: java-sql-injection-ide
            client.query("SELECT * FROM tasks WHERE assignee = '" + assignee + "'")
                .execute(ar -> {
                    if (ar.succeeded()) {
                        RowSet<Row> rows = ar.result();
                        JsonArray result = new JsonArray();
                        for (Row row : rows) {
                            result.add(new JsonObject()
                                .put("id", row.getInteger(0))
                                .put("title", row.getString(1))
                                .put("assignee", row.getString(2)));
                        }
                        ctx.response().putHeader("content-type", "application/json")
                            .end(result.encode());
                    } else {
                        ctx.response().setStatusCode(500).end(ar.cause().getMessage());
                    }
                });
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Using standard JDBC with HttpServlet - secure version
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String username = request.getParameter("username");
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // ok: java-sql-injection-ide
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
        pstmt.setString(1, username);
        ResultSet rs = pstmt.executeQuery();
        
        // Process results
        while (rs.next()) {
            response.getWriter().println(rs.getString("username"));
        }
        
        rs.close();
        pstmt.close();
        conn.close();
    }

    // Using Spring JDBC Template - secure version
    @RestController
    public class good_case_2 {
        private JdbcTemplate jdbcTemplate;
        
        public good_case_2(JdbcTemplate jdbcTemplate) {
            this.jdbcTemplate = jdbcTemplate;
        }
        
        @GetMapping("/users")
        public List<Map<String, Object>> getUsers(@RequestParam String department) {
            // ok: java-sql-injection-ide
            return jdbcTemplate.queryForList("SELECT * FROM employees WHERE department = ?", department);
        }
    }

    // Using Hibernate Session - secure version
    @RestController
    public class good_case_3 {
        private final SessionFactory sessionFactory;
        
        public good_case_3(SessionFactory sessionFactory) {
            this.sessionFactory = sessionFactory;
        }
        
        @PostMapping("/products")
        public List getProducts(HttpServletRequest request) {
            String category = request.getParameter("category");
            Session session = sessionFactory.openSession();
            
            // ok: java-sql-injection-ide
            Query<Object> query = session.createSQLQuery("SELECT * FROM products WHERE category = :category");
            query.setParameter("category", category);
            List result = query.list();
            
            session.close();
            return result;
        }
    }

    // Using Java built-in HttpServer - secure version
    public class good_case_4 {
        public void startServer() throws IOException {
            HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
            server.createContext("/search", new SearchHandler());
            server.start();
        }
        
        class SearchHandler implements HttpHandler {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                String query = exchange.getRequestURI().getQuery();
                String searchTerm = query.substring(query.indexOf("=") + 1);
                
                try {
                    Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
                    
                    // ok: java-sql-injection-ide
                    PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM articles WHERE title LIKE ?");
                    pstmt.setString(1, "%" + searchTerm + "%");
                    ResultSet rs = pstmt.executeQuery();
                    
                    StringBuilder response = new StringBuilder();
                    while (rs.next()) {
                        response.append(rs.getString("title")).append("\n");
                    }
                    
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.toString().getBytes());
                    os.close();
                    
                    rs.close();
                    pstmt.close();
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    // Using Spark Java framework - secure version
    public class good_case_5 {
        public void setupRoutes() {
            Spark.get("/orders", (req, res) -> {
                String status = req.queryParams("status");
                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
                
                // ok: java-sql-injection-ide
                PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM orders WHERE status = ?");
                pstmt.setString(1, status);
                ResultSet rs = pstmt.executeQuery();
                
                StringBuilder result = new StringBuilder();
                while (rs.next()) {
                    result.append(rs.getInt("id")).append(": ").append(rs.getString("description")).append("\n");
                }
                
                rs.close();
                pstmt.close();
                conn.close();
                
                return result.toString();
            });
        }
    }

    // Using Javalin framework - secure version
    public class good_case_6 {
        public void setupApp() {
            Javalin app = Javalin.create().start(7000);
            
            app.get("/customers", ctx -> {
                String city = ctx.queryParam("city");
                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
                
                // ok: java-sql-injection-ide
                PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM customers WHERE city = ?");
                pstmt.setString(1, city);
                ResultSet rs = pstmt.executeQuery();
                
                StringBuilder result = new StringBuilder();
                while (rs.next()) {
                    result.append(rs.getString("name")).append("\n");
                }
                
                ctx.result(result.toString());
                
                rs.close();
                pstmt.close();
                conn.close();
            });
        }
    }

    // Using Micronaut framework - secure version
    @Controller("/api")
    public class good_case_7 {
        
        private Connection getConnection() throws SQLException {
            return DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        }
        
        @Get("/suppliers")
        public HttpResponse<String> getSuppliers(HttpRequest request) {
            try {
                String country = request.getParameters().get("country");
                Connection conn = getConnection();
                
                // ok: java-sql-injection-ide
                PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM suppliers WHERE country = ?");
                pstmt.setString(1, country);
                ResultSet rs = pstmt.executeQuery();
                
                StringBuilder result = new StringBuilder();
                while (rs.next()) {
                    result.append(rs.getString("name")).append(", ").append(rs.getString("country")).append("\n");
                }
                
                rs.close();
                pstmt.close();
                conn.close();
                
                return HttpResponse.ok(result.toString());
            } catch (SQLException e) {
                return HttpResponse.serverError("Database error");
            }
        }
    }

    // Using Ratpack framework - secure version
    public class good_case_8 implements Handler {
        @Override
        public void handle(ratpack.handling.Context ctx) {
            String category = ctx.getRequest().getQueryParams().get("category");
            
            try {
                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
                
                // ok: java-sql-injection-ide
                PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM inventory WHERE category = ?");
                pstmt.setString(1, category);
                ResultSet rs = pstmt.executeQuery();
                
                StringBuilder result = new StringBuilder();
                while (rs.next()) {
                    result.append(rs.getString("item_name")).append(": ").append(rs.getInt("quantity")).append("\n");
                }
                
                ctx.render(result.toString());
                
                rs.close();
                pstmt.close();
                conn.close();
            } catch (SQLException e) {
                ctx.render("Error: " + e.getMessage());
            }
        }
    }

    // Using HikariCP connection pool - secure version
    public class good_case_9 {
        private HikariDataSource dataSource;
        
        public good_case_9() {
            dataSource = new HikariDataSource();
            dataSource.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
            dataSource.setUsername("user");
            dataSource.setPassword("password");
        }
        
        public String getUserData(HttpServletRequest request) throws SQLException {
            String userId = request.getParameter("id");
            Connection conn = dataSource.getConnection();
            
            // ok: java-sql-injection-ide
            PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM user_data WHERE user_id = ?");
            pstmt.setString(1, userId);
            ResultSet rs = pstmt.executeQuery();
            
            StringBuilder result = new StringBuilder();
            while (rs.next()) {
                result.append(rs.getString("data_value")).append("\n");
            }
            
            rs.close();
            pstmt.close();
            conn.close();
            
            return result.toString();
        }
    }

    // Using Apache Commons DbUtils - secure version
    public class good_case_10 {
        private QueryRunner queryRunner;
        
        public good_case_10() {
            queryRunner = new QueryRunner();
        }
        
        public List<Map<String, Object>> searchItems(HttpServletRequest request) throws SQLException {
            String keyword = request.getParameter("keyword");
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            
            // ok: java-sql-injection-ide
            PreparedStatement pstmt = conn.prepareStatement(
                "SELECT * FROM items WHERE name LIKE ? OR description LIKE ?"
            );
            pstmt.setString(1, "%" + keyword + "%");
            pstmt.setString(2, "%" + keyword + "%");
            ResultSet rs = pstmt.executeQuery();
            
            List<Map<String, Object>> results = new ArrayList<>();
            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("id", rs.getInt("id"));
                row.put("name", rs.getString("name"));
                row.put("description", rs.getString("description"));
                results.add(row);
            }
            
            rs.close();
            pstmt.close();
            conn.close();
            
            return results;
        }
    }

    // Using JDBI - secure version
    public class good_case_11 {
        private Jdbi jdbi;
        
        public good_case_11() {
            jdbi = Jdbi.create("jdbc:mysql://localhost:3306/mydb", "user", "password");
        }
        
        public List<Map<String, Object>> getTransactions(HttpServletRequest request) {
            String accountId = request.getParameter("accountId");
            
            // ok: java-sql-injection-ide
            return jdbi.withHandle(handle -> 
                handle.createQuery("SELECT * FROM transactions WHERE account_id = :accountId")
                    .bind("accountId", accountId)
                    .mapToMap()
                    .list()
            );
        }
    }

    // Using Apache Cayenne - secure version
    public class good_case_12 {
        private ObjectContext context;
        
        public good_case_12(ObjectContext context) {
            this.context = context;
        }
        
        public List<?> findEmployees(HttpServletRequest request) {
            String department = request.getParameter("department");
            
            // ok: java-sql-injection-ide
            SQLTemplate query = new SQLTemplate(Object.class, 
                "SELECT * FROM employees WHERE department = #bind($department)");
            query.setParams(Map.of("department", department));
            
            return context.performQuery(query);
        }
    }

    // Using ORMLite - secure version
    public class good_case_13 {
        private JdbcConnectionSource connectionSource;
        private Dao<Review, Integer> reviewDao;
        
        public good_case_13() throws SQLException {
            connectionSource = new JdbcConnectionSource(
                "jdbc:mysql://localhost:3306/mydb", "user", "password");
            reviewDao = DaoManager.createDao(connectionSource, Review.class);
        }
        
        public List<Review> getReviews(HttpServletRequest request) throws SQLException {
            String productId = request.getParameter("productId");
            
            // ok: java-sql-injection-ide
            QueryBuilder<Review, Integer> queryBuilder = reviewDao.queryBuilder();
            queryBuilder.where().eq("product_id", productId);
            PreparedQuery<Review> preparedQuery = queryBuilder.prepare();
            
            return reviewDao.query(preparedQuery);
        }
        
        // Simple entity class for the example
        public static class Review {
            private int id;
            private int rating;
            private String comment;
            private String productId;
            
            // Getters and setters omitted for brevity
        }
    }

    // Using jOOQ - secure version
    public class good_case_14 {
        private DSLContext create;
        
        public good_case_14() {
            Connection conn;
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
                create = DSL.using(conn, SQLDialect.MYSQL);
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        
        public String getProjectDetails(HttpServletRequest request) {
            String projectId = request.getParameter("id");
            
            // ok: java-sql-injection-ide
            Result<?> result = create.resultQuery("SELECT * FROM projects WHERE id = ?", projectId).fetch();
            
            StringBuilder sb = new StringBuilder();
            for (Record r : result) {
                sb.append(r.getValue("name")).append(": ").append(r.getValue("description")).append("\n");
            }
            
            return sb.toString();
        }
    }

    // Using Vert.x - secure version
    public class good_case_15 {
        private MySQLPool client;
        
        public void setupRoutes(Vertx vertx, Router router) {
            client = MySQLPool.pool(vertx, "jdbc:mysql://localhost:3306/mydb?user=user&password=password");
            
            router.get("/tasks").handler(this::getTasks);
        }
        
        private void getTasks(RoutingContext ctx) {
            String assignee = ctx.request().getParam("assignee");
            
            // ok: java-sql-injection-ide
            client.preparedQuery("SELECT * FROM tasks WHERE assignee = ?")
                .execute(Tuple.of(assignee), ar -> {
                    if (ar.succeeded()) {
                        RowSet<Row> rows = ar.result();
                        JsonArray result = new JsonArray();
                        for (Row row : rows) {
                            result.add(new JsonObject()
                                .put("id", row.getInteger(0))
                                .put("title", row.getString(1))
                                .put("assignee", row.getString(2)));
                        }
                        ctx.response().putHeader("content-type", "application/json")
                            .end(result.encode());
                    } else {
                        ctx.response().setStatusCode(500).end(ar.cause().getMessage());
                    }
                });
        }
    }
}
// {/fact}