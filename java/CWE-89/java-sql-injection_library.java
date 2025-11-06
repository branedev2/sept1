import java.sql.*;
import javax.servlet.http.*;
import java.io.*;
import javax.servlet.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.hibernate.*;
import org.hibernate.query.Query;
import javax.persistence.*;
import org.apache.commons.dbutils.QueryRunner;
import org.jooq.DSLContext;
import org.jooq.impl.DSL;
import org.mybatis.spring.SqlSessionTemplate;
import org.apache.ibatis.session.SqlSession;
import com.querydsl.sql.SQLQueryFactory;
import com.querydsl.sql.SQLQuery;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import io.vertx.ext.web.RoutingContext;
import io.vertx.mysqlclient.MySQLPool;
import io.vertx.sqlclient.RowSet;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.Tuple;
import io.quarkus.hibernate.orm.panache.PanacheRepository;
import io.quarkus.hibernate.orm.panache.PanacheQuery;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import com.zaxxer.hikari.HikariDataSource;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.jdbi.v3.core.statement.StatementContext;
import org.springframework.r2dbc.core.DatabaseClient;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactory;
import reactor.core.publisher.Mono;
import org.apache.cayenne.ObjectContext;
import org.apache.cayenne.query.ObjectSelect;
import org.apache.cayenne.query.SQLTemplate;
import org.springframework.web.context.request.WebRequest;
import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Http;
import spark.Request;
import spark.Response;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Optional;

// Security Issue: SQL Injection vulnerabilities in Java applications

// True Positive Examples (Vulnerable/Insecure Code)

public class SqlInjectionExamples {

    // JDBC direct connection
// {fact rule=cross-site-scripting@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) throws SQLException {
        String username = request.getParameter("username");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        
        // ruleid: java-sql-injection
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
        
        while (rs.next()) {
            System.out.println(rs.getString("name"));
        }
        rs.close();
        stmt.close();
        conn.close();
    }

    // Spring JDBC Template
    public void bad_case_2(HttpServletRequest request, JdbcTemplate jdbcTemplate) {
        String userId = request.getParameter("id");
        
        // ruleid: java-sql-injection
        List<Map<String, Object>> users = jdbcTemplate.queryForList("SELECT * FROM users WHERE id = " + userId);
        
        for (Map<String, Object> user : users) {
            System.out.println(user.get("username"));
        }
    }

    // Hibernate Session with createQuery
    public void bad_case_3(HttpServletRequest request, Session session) {
        String department = request.getParameter("department");
        
        // ruleid: java-sql-injection
        Query<Employee> query = session.createQuery("FROM Employee WHERE department = '" + department + "'", Employee.class);
        
        List<Employee> employees = query.list();
        for (Employee emp : employees) {
            System.out.println(emp.getName());
        }
    }

    // JPA EntityManager with createNativeQuery
    public void bad_case_4(HttpServletRequest request, EntityManager entityManager) {
        String salary = request.getParameter("salary");
        
        // ruleid: java-sql-injection
        Query query = entityManager.createNativeQuery("SELECT * FROM employees WHERE salary > " + salary);
        
        List<Object[]> results = query.getResultList();
        for (Object[] result : results) {
            System.out.println(result[0]);
        }
    }

    // Apache DBUtils QueryRunner
    public void bad_case_5(HttpServletRequest request, QueryRunner queryRunner, Connection conn) throws SQLException {
        String category = request.getParameter("category");
        
        // ruleid: java-sql-injection
        List<Map<String, Object>> products = queryRunner.query(conn, 
            "SELECT * FROM products WHERE category = '" + category + "'", 
            new org.apache.commons.dbutils.handlers.MapListHandler());
        
        for (Map<String, Object> product : products) {
            System.out.println(product.get("name"));
        }
    }

    // JOOQ DSL Context
    public void bad_case_6(HttpServletRequest request, DSLContext create) {
        String status = request.getParameter("status");
        
        // ruleid: java-sql-injection
        Result<?> result = create.fetch("SELECT * FROM orders WHERE status = '" + status + "'");
        
        for (Record record : result) {
            System.out.println(record.get("order_id"));
        }
    }

    // MyBatis SqlSession
    public void bad_case_7(HttpServletRequest request, SqlSession sqlSession) {
        String region = request.getParameter("region");
        
        // ruleid: java-sql-injection
        List<Customer> customers = sqlSession.selectList("Customer.findByRegion", 
            "SELECT * FROM customers WHERE region = '" + region + "'");
        
        for (Customer customer : customers) {
            System.out.println(customer.getName());
        }
    }

    // QueryDSL SQLQueryFactory
    public void bad_case_8(HttpServletRequest request, SQLQueryFactory queryFactory) {
        String date = request.getParameter("date");
        
        // ruleid: java-sql-injection
        List<Tuple> results = queryFactory.query().fromQuery(
            "SELECT * FROM events WHERE event_date > '" + date + "'").fetch();
        
        for (Tuple result : results) {
            System.out.println(result.get(0, String.class));
        }
    }

    // Vert.x MySQL Client
    public void bad_case_9(RoutingContext routingContext, MySQLPool client) {
        String productId = routingContext.request().getParam("productId");
        
        // ruleid: java-sql-injection
        client.query("SELECT * FROM products WHERE id = " + productId)
            .execute(ar -> {
                if (ar.succeeded()) {
                    RowSet<Row> rows = ar.result();
                    for (Row row : rows) {
                        System.out.println(row.getString("name"));
                    }
                }
            });
    }

    // Quarkus Panache Repository
    public void bad_case_10(HttpServletRequest request, EntityManager em) {
        String price = request.getParameter("price");
        
        // ruleid: java-sql-injection
        PanacheQuery<Product> products = Product.find("price > " + price);
        
        List<Product> results = products.list();
        for (Product product : results) {
            System.out.println(product.name);
        }
    }

    // Micronaut HTTP Controller
    @Controller("/api")
    public class bad_case_11 {
        private final Connection connection;
        
        public bad_case_11(Connection connection) {
            this.connection = connection;
        }
        
        @Get("/users")
        public List<User> getUsers(HttpRequest<?> request) throws SQLException {
            String role = request.getParameters().get("role");
            Statement stmt = connection.createStatement();
            
            // ruleid: java-sql-injection
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE role = '" + role + "'");
            
            List<User> users = new ArrayList<>();
            while (rs.next()) {
                // Process results
                users.add(new User(rs.getString("name")));
            }
            return users;
        }
    }

    // HikariCP with JDBC
    public void bad_case_12(HttpServletRequest request, HikariDataSource dataSource) throws SQLException {
        String orderId = request.getParameter("orderId");
        Connection conn = dataSource.getConnection();
        Statement stmt = conn.createStatement();
        
        // ruleid: java-sql-injection
        ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = " + orderId);
        
        while (rs.next()) {
            System.out.println(rs.getString("customer_name"));
        }
        rs.close();
        stmt.close();
        conn.close();
    }

    // JDBI
    public void bad_case_13(HttpServletRequest request, Jdbi jdbi) {
        String city = request.getParameter("city");
        
        // ruleid: java-sql-injection
        List<Map<String, Object>> results = jdbi.withHandle(handle -> 
            handle.createQuery("SELECT * FROM addresses WHERE city = '" + city + "'")
                .mapToMap()
                .list());
        
        for (Map<String, Object> result : results) {
            System.out.println(result.get("street"));
        }
    }

    // Spring R2DBC
    public void bad_case_14(WebRequest request, DatabaseClient client) {
        String minAge = request.getParameter("minAge");
        
        // ruleid: java-sql-injection
        Mono<List<Map<String, Object>>> result = client.sql("SELECT * FROM users WHERE age > " + minAge)
            .fetch()
            .all()
            .collectList();
        
        result.subscribe(users -> {
            for (Map<String, Object> user : users) {
                System.out.println(user.get("name"));
            }
        });
    }

    // Apache Cayenne
    public void bad_case_15(HttpServletRequest request, ObjectContext context) {
        String status = request.getParameter("status");
        
        // ruleid: java-sql-injection
        SQLTemplate query = new SQLTemplate(Order.class, 
            "SELECT * FROM orders WHERE status = '" + status + "'");
        
        List<Order> orders = context.performQuery(query);
        for (Order order : orders) {
            System.out.println(order.getCustomerName());
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // JDBC with PreparedStatement
    public void good_case_1(HttpServletRequest request) throws SQLException {
        String username = request.getParameter("username");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // ok: java-sql-injection
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
        pstmt.setString(1, username);
        
        ResultSet rs = pstmt.executeQuery();
        while (rs.next()) {
            System.out.println(rs.getString("name"));
        }
        rs.close();
        pstmt.close();
        conn.close();
    }

    // Spring JDBC Template with parameterized query
    public void good_case_2(HttpServletRequest request, JdbcTemplate jdbcTemplate) {
        String userId = request.getParameter("id");
        
        // ok: java-sql-injection
        List<Map<String, Object>> users = jdbcTemplate.queryForList(
            "SELECT * FROM users WHERE id = ?", userId);
        
        for (Map<String, Object> user : users) {
            System.out.println(user.get("username"));
        }
    }

    // Hibernate Session with parameterized query
    public void good_case_3(HttpServletRequest request, Session session) {
        String department = request.getParameter("department");
        
        // ok: java-sql-injection
        Query<Employee> query = session.createQuery("FROM Employee WHERE department = :dept", Employee.class);
        query.setParameter("dept", department);
        
        List<Employee> employees = query.list();
        for (Employee emp : employees) {
            System.out.println(emp.getName());
        }
    }

    // JPA EntityManager with parameterized query
    public void good_case_4(HttpServletRequest request, EntityManager entityManager) {
        String salary = request.getParameter("salary");
        
        // ok: java-sql-injection
        Query query = entityManager.createNativeQuery("SELECT * FROM employees WHERE salary > ?");
        query.setParameter(1, Integer.parseInt(salary));
        
        List<Object[]> results = query.getResultList();
        for (Object[] result : results) {
            System.out.println(result[0]);
        }
    }

    // Apache DBUtils QueryRunner with parameters
    public void good_case_5(HttpServletRequest request, QueryRunner queryRunner, Connection conn) throws SQLException {
        String category = request.getParameter("category");
        
        // ok: java-sql-injection
        List<Map<String, Object>> products = queryRunner.query(conn, 
            "SELECT * FROM products WHERE category = ?", 
            new org.apache.commons.dbutils.handlers.MapListHandler(),
            category);
        
        for (Map<String, Object> product : products) {
            System.out.println(product.get("name"));
        }
    }

    // JOOQ DSL Context with bind values
    public void good_case_6(HttpServletRequest request, DSLContext create) {
        String status = request.getParameter("status");
        
        // ok: java-sql-injection
        Result<?> result = create.resultQuery("SELECT * FROM orders WHERE status = ?", status)
            .fetch();
        
        for (Record record : result) {
            System.out.println(record.get("order_id"));
        }
    }

    // MyBatis SqlSession with parameterized query
    public void good_case_7(HttpServletRequest request, SqlSessionTemplate sqlSession) {
        String region = request.getParameter("region");
        Map<String, Object> params = new HashMap<>();
        params.put("region", region);
        
        // ok: java-sql-injection
        List<Customer> customers = sqlSession.selectList("Customer.findByRegion", params);
        
        for (Customer customer : customers) {
            System.out.println(customer.getName());
        }
    }

    // QueryDSL SQLQueryFactory with parameters
    public void good_case_8(HttpServletRequest request, SQLQueryFactory queryFactory) {
        String date = request.getParameter("date");
        
        // ok: java-sql-injection
        List<Tuple> results = queryFactory.query().fromQuery(
            "SELECT * FROM events WHERE event_date > ?", date).fetch();
        
        for (Tuple result : results) {
            System.out.println(result.get(0, String.class));
        }
    }

    // Vert.x MySQL Client with parameters
    public void good_case_9(RoutingContext routingContext, MySQLPool client) {
        String productId = routingContext.request().getParam("productId");
        
        // ok: java-sql-injection
        client.preparedQuery("SELECT * FROM products WHERE id = ?")
            .execute(Tuple.of(productId), ar -> {
                if (ar.succeeded()) {
                    RowSet<Row> rows = ar.result();
                    for (Row row : rows) {
                        System.out.println(row.getString("name"));
                    }
                }
            });
    }

    // Quarkus Panache Repository with parameters
    public void good_case_10(HttpServletRequest request) {
        String price = request.getParameter("price");
        
        // ok: java-sql-injection
        PanacheQuery<Product> products = Product.find("price > ?1", Double.parseDouble(price));
        
        List<Product> results = products.list();
        for (Product product : results) {
            System.out.println(product.name);
        }
    }

    // Micronaut HTTP Controller with parameters
    @Controller("/api")
    public class good_case_11 {
        private final Connection connection;
        
        public good_case_11(Connection connection) {
            this.connection = connection;
        }
        
        @Get("/users")
        public List<User> getUsers(HttpRequest<?> request) throws SQLException {
            String role = request.getParameters().get("role");
            
            // ok: java-sql-injection
            PreparedStatement pstmt = connection.prepareStatement("SELECT * FROM users WHERE role = ?");
            pstmt.setString(1, role);
            
            ResultSet rs = pstmt.executeQuery();
            List<User> users = new ArrayList<>();
            while (rs.next()) {
                users.add(new User(rs.getString("name")));
            }
            return users;
        }
    }

    // HikariCP with JDBC PreparedStatement
    public void good_case_12(HttpServletRequest request, HikariDataSource dataSource) throws SQLException {
        String orderId = request.getParameter("orderId");
        Connection conn = dataSource.getConnection();
        
        // ok: java-sql-injection
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM orders WHERE id = ?");
        pstmt.setString(1, orderId);
        
        ResultSet rs = pstmt.executeQuery();
        while (rs.next()) {
            System.out.println(rs.getString("customer_name"));
        }
        rs.close();
        pstmt.close();
        conn.close();
    }

    // JDBI with bind parameters
    public void good_case_13(HttpServletRequest request, Jdbi jdbi) {
        String city = request.getParameter("city");
        
        // ok: java-sql-injection
        List<Map<String, Object>> results = jdbi.withHandle(handle -> 
            handle.createQuery("SELECT * FROM addresses WHERE city = :city")
                .bind("city", city)
                .mapToMap()
                .list());
        
        for (Map<String, Object> result : results) {
            System.out.println(result.get("street"));
        }
    }

    // Spring R2DBC with bind parameters
    public void good_case_14(WebRequest request, DatabaseClient client) {
        String minAge = request.getParameter("minAge");
        
        // ok: java-sql-injection
        Mono<List<Map<String, Object>>> result = client.sql("SELECT * FROM users WHERE age > :minAge")
            .bind("minAge", Integer.parseInt(minAge))
            .fetch()
            .all()
            .collectList();
        
        result.subscribe(users -> {
            for (Map<String, Object> user : users) {
                System.out.println(user.get("name"));
            }
        });
    }

    // Apache Cayenne with parameters
    public void good_case_15(HttpServletRequest request, ObjectContext context) {
        String status = request.getParameter("status");
        
        // ok: java-sql-injection
        SQLTemplate query = new SQLTemplate(Order.class, 
            "SELECT * FROM orders WHERE status = #bind($status)");
        query.setParams(Map.of("status", status));
        
        List<Order> orders = context.performQuery(query);
        for (Order order : orders) {
            System.out.println(order.getCustomerName());
        }
    }

    // Helper classes for examples
    private static class Employee {
        private String name;
        private String department;
        
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getDepartment() { return department; }
        public void setDepartment(String department) { this.department = department; }
    }
    
    private static class Customer {
        private String name;
        private String region;
        
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getRegion() { return region; }
        public void setRegion(String region) { this.region = region; }
    }
    
    private static class Product {
        public String name;
        public double price;
        public String category;
        
        public static PanacheQuery<Product> find(String query, Object... params) {
            return new PanacheQuery<>();
        }
    }
    
    private static class PanacheQuery<T> {
        public List<T> list() { return new ArrayList<>(); }
    }
    
    private static class User {
        private String name;
        
        public User(String name) {
            this.name = name;
        }
        
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
    }
    
    private static class Order {
        private String customerName;
        private String status;
        
        public String getCustomerName() { return customerName; }
        public void setCustomerName(String customerName) { this.customerName = customerName; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
    }
}
// {/fact}