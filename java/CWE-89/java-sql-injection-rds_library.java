import java.sql.*;
import javax.servlet.http.*;
import java.io.*;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.hibernate.*;
import org.hibernate.query.Query;
import com.amazonaws.services.rds.AmazonRDS;
import com.amazonaws.services.rds.AmazonRDSClientBuilder;
import com.amazonaws.services.rds.model.*;
import org.apache.commons.dbcp2.BasicDataSource;
import org.jooq.DSLContext;
import org.jooq.SQLDialect;
import org.jooq.impl.DSL;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.apache.ibatis.jdbc.SQL;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.core.statement.PreparedBatch;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.mysqlclient.MySQLPool;
import io.vertx.sqlclient.RowSet;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.Tuple;
import io.r2dbc.spi.ConnectionFactory;
import org.springframework.r2dbc.core.DatabaseClient;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.data.jdbc.runtime.JdbcOperations;
import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.SimpleStatement;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import com.querydsl.sql.SQLQueryFactory;
import com.querydsl.sql.Configuration;
import org.apache.cayenne.ObjectContext;
import org.apache.cayenne.query.ObjectSelect;
import org.apache.cayenne.query.SQLExec;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

// Security Issue: SQL Injection in Java Database Operations

// True Positive Examples (Vulnerable/Insecure Code)
public void bad_case_1(HttpServletRequest request) throws SQLException {
    // Standard JDBC vulnerable to SQL injection
    String username = request.getParameter("username");
    Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
    Statement stmt = conn.createStatement();
    
    // ruleid: java-sql-injection-rds
    ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
    
    while (rs.next()) {
        System.out.println(rs.getString("name"));
    }
    conn.close();
}

public void bad_case_2(HttpServletRequest request) {
    // Spring JDBC Template vulnerable to SQL injection
    String userId = request.getParameter("id");
    JdbcTemplate jdbcTemplate = new JdbcTemplate(getDataSource());
    
    // ruleid: java-sql-injection-rds
    List<Map<String, Object>> users = jdbcTemplate.queryForList("SELECT * FROM users WHERE id = " + userId);
    
    for (Map<String, Object> user : users) {
        System.out.println(user.get("username"));
    }
}

public void bad_case_3(HttpServletRequest request) {
    // Hibernate with raw SQL vulnerable to injection
    String category = request.getParameter("category");
    Session session = getHibernateSession();
    
    // ruleid: java-sql-injection-rds
    Query<Product> query = session.createNativeQuery(
        "SELECT * FROM products WHERE category = '" + category + "'", Product.class);
    
    List<Product> products = query.list();
    session.close();
}

public void bad_case_4(HttpServletRequest request) {
    // Apache DBCP with vulnerable SQL
    String searchTerm = request.getParameter("search");
    BasicDataSource dataSource = new BasicDataSource();
    dataSource.setUrl("jdbc:mysql://localhost:3306/mydb");
    dataSource.setUsername("user");
    dataSource.setPassword("password");
    
    try (Connection conn = dataSource.getConnection();
         Statement stmt = conn.createStatement()) {
        
        // ruleid: java-sql-injection-rds
        ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'");
        
        while (rs.next()) {
            System.out.println(rs.getString("name"));
        }
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request) {
    // jOOQ with SQL injection vulnerability
    String orderBy = request.getParameter("orderBy");
    DSLContext create = DSL.using(getConnection(), SQLDialect.MYSQL);
    
    // ruleid: java-sql-injection-rds
    Result<?> result = create.fetch("SELECT id, name FROM products ORDER BY " + orderBy);
    
    for (Record r : result) {
        System.out.println(r.getValue("name"));
    }
}

public void bad_case_6(HttpServletRequest request) {
    // HikariCP connection pool with SQL injection
    String price = request.getParameter("price");
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
    config.setUsername("user");
    config.setPassword("password");
    
    try (HikariDataSource ds = new HikariDataSource(config);
         Connection conn = ds.getConnection();
         Statement stmt = conn.createStatement()) {
        
        // ruleid: java-sql-injection-rds
        ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE price > " + price);
        
        while (rs.next()) {
            System.out.println(rs.getString("name"));
        }
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_7(HttpServletRequest request) {
    // MyBatis with SQL injection
    String status = request.getParameter("status");
    SqlSessionFactory sqlSessionFactory = getSqlSessionFactory();
    
    try (SqlSession session = sqlSessionFactory.openSession()) {
        // ruleid: java-sql-injection-rds
        List<Order> orders = session.selectList("selectOrdersByStatus", 
            "SELECT * FROM orders WHERE status = '" + status + "'");
        
        for (Order order : orders) {
            System.out.println(order.getId());
        }
    }
}

public void bad_case_8(HttpServletRequest request) {
    // JDBI with SQL injection
    String department = request.getParameter("dept");
    Jdbi jdbi = Jdbi.create("jdbc:mysql://localhost:3306/mydb", "user", "password");
    
    List<Employee> employees = jdbi.withHandle(handle -> {
        // ruleid: java-sql-injection-rds
        return handle.createQuery("SELECT * FROM employees WHERE department = '" + department + "'")
                    .mapToBean(Employee.class)
                    .list();
    });
    
    for (Employee emp : employees) {
        System.out.println(emp.getName());
    }
}

public void bad_case_9(HttpServletRequest request) {
    // Vert.x MySQL client with SQL injection
    String role = request.getParameter("role");
    MySQLPool client = getMySQLPool();
    
    // ruleid: java-sql-injection-rds
    client.query("SELECT * FROM users WHERE role = '" + role + "'")
        .execute(ar -> {
            if (ar.succeeded()) {
                RowSet<Row> rows = ar.result();
                for (Row row : rows) {
                    System.out.println(row.getString("username"));
                }
            } else {
                System.out.println("Query failed: " + ar.cause().getMessage());
            }
        });
}

public void bad_case_10(HttpServletRequest request) {
    // Spring R2DBC with SQL injection
    String country = request.getParameter("country");
    ConnectionFactory connectionFactory = getConnectionFactory();
    DatabaseClient client = DatabaseClient.create(connectionFactory);
    
    // ruleid: java-sql-injection-rds
    client.sql("SELECT * FROM customers WHERE country = '" + country + "'")
        .map((row, metadata) -> {
            return row.get("name", String.class);
        })
        .all()
        .subscribe(name -> System.out.println(name));
}

public void bad_case_11(HttpServletRequest request) {
    // Micronaut JDBC with SQL injection
    String city = request.getParameter("city");
    JdbcOperations jdbcOperations = getJdbcOperations();
    
    // ruleid: java-sql-injection-rds
    List<Map<String, Object>> results = jdbcOperations.prepareStatement(
        "SELECT * FROM addresses WHERE city = '" + city + "'",
        statement -> {
            ResultSet rs = statement.executeQuery();
            // Process result set and return data
            return processResultSet(rs);
        });
}

public void bad_case_12(HttpServletRequest request) {
    // Cassandra driver with CQL injection
    String email = request.getParameter("email");
    CqlSession session = getCqlSession();
    
    // ruleid: java-sql-injection-rds
    ResultSet rs = session.execute(
        "SELECT * FROM users WHERE email = '" + email + "'");
    
    for (Row row : rs) {
        System.out.println(row.getString("username"));
    }
}

public void bad_case_13(HttpServletRequest request) {
    // Spring Data JPA with @Query annotation and SQL injection
    String status = request.getParameter("status");
    OrderRepository orderRepo = getOrderRepository();
    
    // ruleid: java-sql-injection-rds
    List<Order> orders = orderRepo.findOrdersByStatusRaw("SELECT * FROM orders WHERE status = '" + status + "'");
    
    for (Order order : orders) {
        System.out.println(order.getId());
    }
}

public void bad_case_14(HttpServletRequest request) {
    // QueryDSL SQL with injection
    String category = request.getParameter("category");
    SQLQueryFactory queryFactory = getSqlQueryFactory();
    
    // ruleid: java-sql-injection-rds
    List<String> productNames = queryFactory
        .query()
        .select(Expressions.stringPath("name"))
        .from("products")
        .where("category = '" + category + "'")
        .fetch();
}

public void bad_case_15(HttpServletRequest request) {
    // Apache Cayenne with SQL injection
    String region = request.getParameter("region");
    ObjectContext context = getObjectContext();
    
    // ruleid: java-sql-injection-rds
    List<Map<String, Object>> results = SQLExec
        .query("SELECT * FROM stores WHERE region = '" + region + "'")
        .dataRows(context)
        .select();
    
    for (Map<String, Object> row : results) {
        System.out.println(row.get("name"));
    }
}

// True Negative Examples (Safe/Secure Code)
public void good_case_1(HttpServletRequest request) throws SQLException {
    // Standard JDBC with prepared statement to prevent SQL injection
    String username = request.getParameter("username");
    Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
    
    // ok: java-sql-injection-rds
    PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
    pstmt.setString(1, username);
    ResultSet rs = pstmt.executeQuery();
    
    while (rs.next()) {
        System.out.println(rs.getString("name"));
    }
    conn.close();
}

public void good_case_2(HttpServletRequest request) {
    // Spring JDBC Template with parameterized query
    String userId = request.getParameter("id");
    JdbcTemplate jdbcTemplate = new JdbcTemplate(getDataSource());
    
    // ok: java-sql-injection-rds
    List<Map<String, Object>> users = jdbcTemplate.queryForList(
        "SELECT * FROM users WHERE id = ?", userId);
    
    for (Map<String, Object> user : users) {
        System.out.println(user.get("username"));
    }
}

public void good_case_3(HttpServletRequest request) {
    // Hibernate with parameterized query
    String category = request.getParameter("category");
    Session session = getHibernateSession();
    
    // ok: java-sql-injection-rds
    Query<Product> query = session.createNativeQuery(
        "SELECT * FROM products WHERE category = :category", Product.class)
        .setParameter("category", category);
    
    List<Product> products = query.list();
    session.close();
}

public void good_case_4(HttpServletRequest request) {
    // Apache DBCP with prepared statement
    String searchTerm = request.getParameter("search");
    BasicDataSource dataSource = new BasicDataSource();
    dataSource.setUrl("jdbc:mysql://localhost:3306/mydb");
    dataSource.setUsername("user");
    dataSource.setPassword("password");
    
    try (Connection conn = dataSource.getConnection();
         PreparedStatement pstmt = conn.prepareStatement(
             "SELECT * FROM products WHERE name LIKE ?")) {
        
        // ok: java-sql-injection-rds
        pstmt.setString(1, "%" + searchTerm + "%");
        ResultSet rs = pstmt.executeQuery();
        
        while (rs.next()) {
            System.out.println(rs.getString("name"));
        }
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    // jOOQ with parameterized query
    String orderBy = request.getParameter("orderBy");
    DSLContext create = DSL.using(getConnection(), SQLDialect.MYSQL);
    
    // Validate input against allowed columns
    List<String> allowedColumns = List.of("id", "name", "price", "created_at");
    if (!allowedColumns.contains(orderBy)) {
        orderBy = "id"; // Default to safe value
    }
    
    // ok: java-sql-injection-rds
    Result<?> result = create.select()
        .from("products")
        .orderBy(DSL.field(orderBy))
        .fetch();
    
    for (Record r : result) {
        System.out.println(r.getValue("name"));
    }
}

public void good_case_6(HttpServletRequest request) {
    // HikariCP connection pool with prepared statement
    String price = request.getParameter("price");
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
    config.setUsername("user");
    config.setPassword("password");
    
    try (HikariDataSource ds = new HikariDataSource(config);
         Connection conn = ds.getConnection();
         PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM products WHERE price > ?")) {
        
        // ok: java-sql-injection-rds
        pstmt.setString(1, price);
        ResultSet rs = pstmt.executeQuery();
        
        while (rs.next()) {
            System.out.println(rs.getString("name"));
        }
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_7(HttpServletRequest request) {
    // MyBatis with parameterized query
    String status = request.getParameter("status");
    SqlSessionFactory sqlSessionFactory = getSqlSessionFactory();
    
    try (SqlSession session = sqlSessionFactory.openSession()) {
        Map<String, Object> params = new HashMap<>();
        params.put("status", status);
        
        // ok: java-sql-injection-rds
        List<Order> orders = session.selectList("selectOrdersByStatus", params);
        
        for (Order order : orders) {
            System.out.println(order.getId());
        }
    }
}

public void good_case_8(HttpServletRequest request) {
    // JDBI with parameterized query
    String department = request.getParameter("dept");
    Jdbi jdbi = Jdbi.create("jdbc:mysql://localhost:3306/mydb", "user", "password");
    
    List<Employee> employees = jdbi.withHandle(handle -> {
        // ok: java-sql-injection-rds
        return handle.createQuery("SELECT * FROM employees WHERE department = :dept")
                    .bind("dept", department)
                    .mapToBean(Employee.class)
                    .list();
    });
    
    for (Employee emp : employees) {
        System.out.println(emp.getName());
    }
}

public void good_case_9(HttpServletRequest request) {
    // Vert.x MySQL client with parameterized query
    String role = request.getParameter("role");
    MySQLPool client = getMySQLPool();
    
    // ok: java-sql-injection-rds
    client.preparedQuery("SELECT * FROM users WHERE role = ?")
        .execute(Tuple.of(role), ar -> {
            if (ar.succeeded()) {
                RowSet<Row> rows = ar.result();
                for (Row row : rows) {
                    System.out.println(row.getString("username"));
                }
            } else {
                System.out.println("Query failed: " + ar.cause().getMessage());
            }
        });
}

public void good_case_10(HttpServletRequest request) {
    // Spring R2DBC with parameterized query
    String country = request.getParameter("country");
    ConnectionFactory connectionFactory = getConnectionFactory();
    DatabaseClient client = DatabaseClient.create(connectionFactory);
    
    // ok: java-sql-injection-rds
    client.sql("SELECT * FROM customers WHERE country = :country")
        .bind("country", country)
        .map((row, metadata) -> {
            return row.get("name", String.class);
        })
        .all()
        .subscribe(name -> System.out.println(name));
}

public void good_case_11(HttpServletRequest request) {
    // Micronaut JDBC with parameterized query
    String city = request.getParameter("city");
    JdbcOperations jdbcOperations = getJdbcOperations();
    
    // ok: java-sql-injection-rds
    List<Map<String, Object>> results = jdbcOperations.prepareStatement(
        "SELECT * FROM addresses WHERE city = ?",
        statement -> {
            statement.setString(1, city);
            ResultSet rs = statement.executeQuery();
            // Process result set and return data
            return processResultSet(rs);
        });
}

public void good_case_12(HttpServletRequest request) {
    // Cassandra driver with parameterized query
    String email = request.getParameter("email");
    CqlSession session = getCqlSession();
    
    // ok: java-sql-injection-rds
    SimpleStatement statement = SimpleStatement.builder(
        "SELECT * FROM users WHERE email = ?")
        .addPositionalValue(email)
        .build();
    
    ResultSet rs = session.execute(statement);
    
    for (Row row : rs) {
        System.out.println(row.getString("username"));
    }
}

public void good_case_13(HttpServletRequest request) {
    // Spring Data JPA with @Query annotation and parameters
    String status = request.getParameter("status");
    OrderRepository orderRepo = getOrderRepository();
    
    // ok: java-sql-injection-rds
    List<Order> orders = orderRepo.findOrdersByStatus(status);
    
    for (Order order : orders) {
        System.out.println(order.getId());
    }
}

public void good_case_14(HttpServletRequest request) {
    // QueryDSL SQL with parameterized query
    String category = request.getParameter("category");
    SQLQueryFactory queryFactory = getSqlQueryFactory();
    
    // ok: java-sql-injection-rds
    List<String> productNames = queryFactory
        .query()
        .select(Expressions.stringPath("name"))
        .from("products")
        .where(Expressions.stringPath("category").eq(category))
        .fetch();
}

public void good_case_15(HttpServletRequest request) {
    // Apache Cayenne with parameterized query
    String region = request.getParameter("region");
    ObjectContext context = getObjectContext();
    
    // ok: java-sql-injection-rds
    List<Map<String, Object>> results = SQLExec
        .query("SELECT * FROM stores WHERE region = $region")
        .params(Map.of("region", region))
        .dataRows(context)
        .select();
    
    for (Map<String, Object> row : results) {
        System.out.println(row.get("name"));
    }
}

// Helper methods (would be implemented in a real application)
private DataSource getDataSource() {
    // Implementation would return a configured DataSource
    return null;
}

private Session getHibernateSession() {
    // Implementation would return a Hibernate Session
    return null;
}

private Connection getConnection() {
    // Implementation would return a JDBC Connection
    return null;
}

private SqlSessionFactory getSqlSessionFactory() {
    // Implementation would return a MyBatis SqlSessionFactory
    return null;
}

private MySQLPool getMySQLPool() {
    // Implementation would return a Vert.x MySQL client
    return null;
}

private ConnectionFactory getConnectionFactory() {
    // Implementation would return an R2DBC ConnectionFactory
    return null;
}

private JdbcOperations getJdbcOperations() {
    // Implementation would return Micronaut JdbcOperations
    return null;
}

private CqlSession getCqlSession() {
    // Implementation would return a Cassandra CqlSession
    return null;
}

private OrderRepository getOrderRepository() {
    // Implementation would return a Spring Data repository
    return null;
}

private SQLQueryFactory getSqlQueryFactory() {
    // Implementation would return a QueryDSL SQLQueryFactory
    return null;
}

private ObjectContext getObjectContext() {
    // Implementation would return a Cayenne ObjectContext
    return null;
}

private List<Map<String, Object>> processResultSet(ResultSet rs) throws SQLException {
    List<Map<String, Object>> results = new ArrayList<>();
    while (rs.next()) {
        Map<String, Object> row = new HashMap<>();
        for (int i = 1; i <= rs.getMetaData().getColumnCount(); i++) {
            row.put(rs.getMetaData().getColumnName(i), rs.getObject(i));
        }
        results.add(row);
    }
    return results;
}

// Example entity classes and interfaces
class Product {
    private Long id;
    private String name;
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}

class Order {
    private Long id;
    private String status;
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}

class Employee {
    private Long id;
    private String name;
    private String department;
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDepartment() { return department; }
    public void setDepartment(String department) { this.department = department; }
}

interface OrderRepository extends JpaRepository<Order, Long> {
    @Query(value = "SELECT * FROM orders WHERE status = :status", nativeQuery = true)
    List<Order> findOrdersByStatus(String status);
    
    @Query(nativeQuery = true)
    List<Order> findOrdersByStatusRaw(String query);
}