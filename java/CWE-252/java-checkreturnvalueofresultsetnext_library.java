import java.sql.*;
import java.util.*;
import javax.servlet.http.*;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.query.Query;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.apache.commons.dbcp2.BasicDataSource;
import org.apache.tomcat.jdbc.pool.PoolProperties;
import org.jooq.DSLContext;
import org.jooq.SQLDialect;
import org.jooq.impl.DSL;
import com.mchange.v2.c3p0.ComboPooledDataSource;
import org.apache.commons.dbutils.QueryRunner;
import org.apache.commons.dbutils.handlers.MapListHandler;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.core.mapper.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.object.MappingSqlQuery;
import org.springframework.web.bind.annotation.*;
import io.vertx.core.Vertx;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.sql.ResultSet;
import org.apache.cayenne.ObjectContext;
import org.apache.cayenne.query.SQLTemplate;
import org.apache.cayenne.access.DataContext;
import org.mybatis.spring.SqlSessionTemplate;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.springframework.data.jdbc.core.JdbcAggregateTemplate;
import liquibase.database.jvm.JdbcConnection;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;

// Security Issue: Not checking the return value of ResultSet.next() can lead to NullPointerExceptions or incorrect data processing

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // Standard JDBC with no check on ResultSet.next()
    String userId = request.getParameter("userId");
    try {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
        // ruleid: java-checkreturnvalueofresultsetnext
        rs.next(); // Not checking return value
        String username = rs.getString("username"); // Potential NPE if no rows returned
        System.out.println("Username: " + username);
        rs.close();
        stmt.close();
        conn.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_2(HttpServletRequest request) {
    // Spring JdbcTemplate with raw ResultSet handling
    String productId = request.getParameter("productId");
    try {
        JdbcTemplate jdbcTemplate = new JdbcTemplate(new DriverManagerDataSource(
                "jdbc:postgresql://localhost:5432/products", "user", "password"));
        
        jdbcTemplate.query("SELECT * FROM products WHERE id = ?", new Object[]{productId}, 
            (ResultSet rs) -> {
                // ruleid: java-checkreturnvalueofresultsetnext
                rs.next(); // Not checking return value
                return rs.getString("product_name");
            });
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3(HttpServletRequest request) {
    // Hibernate with native SQL query and ResultSet
    String orderId = request.getParameter("orderId");
    try {
        SessionFactory sessionFactory = null; // Assume initialized elsewhere
        Session session = sessionFactory.openSession();
        
        Query query = session.createNativeQuery("SELECT * FROM orders WHERE id = :id")
                            .setParameter("id", orderId);
        
        ResultSet rs = (ResultSet) query.uniqueResult(); // This is simplified for example
        // ruleid: java-checkreturnvalueofresultsetnext
        rs.next(); // Not checking return value
        double amount = rs.getDouble("amount");
        System.out.println("Order amount: " + amount);
        session.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4(HttpServletRequest request) {
    // HikariCP connection pool with ResultSet
    String categoryId = request.getParameter("categoryId");
    try {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:mysql://localhost:3306/store");
        config.setUsername("user");
        config.setPassword("password");
        
        HikariDataSource dataSource = new HikariDataSource(config);
        Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM categories WHERE id = ?");
        pstmt.setString(1, categoryId);
        ResultSet rs = pstmt.executeQuery();
        
        // ruleid: java-checkreturnvalueofresultsetnext
        rs.next(); // Not checking return value
        String categoryName = rs.getString("name");
        System.out.println("Category: " + categoryName);
        
        rs.close();
        pstmt.close();
        conn.close();
        dataSource.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request) {
    // Apache DBCP with ResultSet
    String employeeId = request.getParameter("employeeId");
    try {
        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setUrl("jdbc:oracle:thin:@localhost:1521:HR");
        dataSource.setUsername("user");
        dataSource.setPassword("password");
        
        Connection conn = dataSource.getConnection();
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM employees WHERE id = " + employeeId);
        
        // ruleid: java-checkreturnvalueofresultsetnext
        rs.next(); // Not checking return value
        String name = rs.getString("name");
        double salary = rs.getDouble("salary");
        System.out.println("Employee: " + name + ", Salary: " + salary);
        
        rs.close();
        stmt.close();
        conn.close();
        dataSource.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_6(HttpServletRequest request) {
    // Tomcat JDBC Pool with ResultSet
    String customerId = request.getParameter("customerId");
    try {
        PoolProperties p = new PoolProperties();
        p.setUrl("jdbc:mysql://localhost:3306/customers");
        p.setDriverClassName("com.mysql.jdbc.Driver");
        p.setUsername("user");
        p.setPassword("password");
        
        org.apache.tomcat.jdbc.pool.DataSource dataSource = new org.apache.tomcat.jdbc.pool.DataSource();
        dataSource.setPoolProperties(p);
        
        Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM customers WHERE id = ?");
        pstmt.setString(1, customerId);
        ResultSet rs = pstmt.executeQuery();
        
        // ruleid: java-checkreturnvalueofresultsetnext
        rs.next(); // Not checking return value
        String email = rs.getString("email");
        System.out.println("Customer email: " + email);
        
        rs.close();
        pstmt.close();
        conn.close();
        dataSource.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_7(HttpServletRequest request) {
    // jOOQ with ResultSet
    String invoiceId = request.getParameter("invoiceId");
    try {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/invoices", "user", "password");
        DSLContext create = DSL.using(conn, SQLDialect.MYSQL);
        
        ResultSet rs = create.select().from("invoices").where("id = ?", invoiceId).fetchResultSet();
        
        // ruleid: java-checkreturnvalueofresultsetnext
        rs.next(); // Not checking return value
        double total = rs.getDouble("total");
        String client = rs.getString("client");
        System.out.println("Invoice for " + client + ": $" + total);
        
        rs.close();
        conn.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    // C3P0 connection pool with ResultSet
    String bookId = request.getParameter("bookId");
    try {
        ComboPooledDataSource cpds = new ComboPooledDataSource();
        cpds.setDriverClass("com.mysql.jdbc.Driver");
        cpds.setJdbcUrl("jdbc:mysql://localhost:3306/library");
        cpds.setUser("user");
        cpds.setPassword("password");
        
        Connection conn = cpds.getConnection();
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM books WHERE id = " + bookId);
        
        // ruleid: java-checkreturnvalueofresultsetnext
        rs.next(); // Not checking return value
        String title = rs.getString("title");
        String author = rs.getString("author");
        System.out.println("Book: " + title + " by " + author);
        
        rs.close();
        stmt.close();
        conn.close();
        cpds.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9(HttpServletRequest request) {
    // Apache DbUtils with ResultSet
    String projectId = request.getParameter("projectId");
    try {
        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setUrl("jdbc:postgresql://localhost:5432/projects");
        dataSource.setUsername("user");
        dataSource.setPassword("password");
        
        QueryRunner runner = new QueryRunner(dataSource);
        Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM projects WHERE id = ?");
        pstmt.setString(1, projectId);
        ResultSet rs = pstmt.executeQuery();
        
        // ruleid: java-checkreturnvalueofresultsetnext
        rs.next(); // Not checking return value
        String name = rs.getString("name");
        String client = rs.getString("client");
        System.out.println("Project: " + name + " for " + client);
        
        rs.close();
        pstmt.close();
        conn.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    // JDBI with ResultSet
    String userId = request.getParameter("userId");
    try {
        Jdbi jdbi = Jdbi.create("jdbc:h2:mem:test");
        
        jdbi.withHandle(handle -> {
            ResultSet rs = handle.createQuery("SELECT * FROM users WHERE id = ?")
                                .bind(0, userId)
                                .executeQuery()
                                .getResultSet();
            
            // ruleid: java-checkreturnvalueofresultsetnext
            rs.next(); // Not checking return value
            String username = rs.getString("username");
            String email = rs.getString("email");
            System.out.println("User: " + username + ", Email: " + email);
            
            return null;
        });
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11(HttpServletRequest request) {
    // Spring NamedParameterJdbcTemplate with ResultSet
    String productId = request.getParameter("productId");
    try {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:mysql://localhost:3306/inventory", "user", "password");
        NamedParameterJdbcTemplate namedTemplate = new NamedParameterJdbcTemplate(dataSource);
        
        MapSqlParameterSource params = new MapSqlParameterSource();
        params.addValue("id", productId);
        
        namedTemplate.query("SELECT * FROM products WHERE id = :id", params, 
            (ResultSet rs) -> {
                // ruleid: java-checkreturnvalueofresultsetnext
                rs.next(); // Not checking return value
                return rs.getString("product_name");
            });
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    // Spring MappingSqlQuery with ResultSet
    String orderId = request.getParameter("orderId");
    try {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:mysql://localhost:3306/orders", "user", "password");
        
        Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM orders WHERE id = ?");
        pstmt.setString(1, orderId);
        ResultSet rs = pstmt.executeQuery();
        
        // ruleid: java-checkreturnvalueofresultsetnext
        rs.next(); // Not checking return value
        double amount = rs.getDouble("amount");
        String customer = rs.getString("customer");
        System.out.println("Order for " + customer + ": $" + amount);
        
        rs.close();
        pstmt.close();
        conn.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_13(HttpServletRequest request) {
    // Vert.x JDBC Client with ResultSet
    String userId = request.getParameter("userId");
    try {
        // Simplified for example
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "user", "password");
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        pstmt.setString(1, userId);
        ResultSet rs = pstmt.executeQuery();
        
        // ruleid: java-checkreturnvalueofresultsetnext
        rs.next(); // Not checking return value
        String username = rs.getString("username");
        String role = rs.getString("role");
        System.out.println("User: " + username + ", Role: " + role);
        
        rs.close();
        pstmt.close();
        conn.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) {
    // Apache Cayenne with ResultSet
    String employeeId = request.getParameter("employeeId");
    try {
        // Simplified for example
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/hr", "user", "password");
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM employees WHERE id = ?");
        pstmt.setString(1, employeeId);
        ResultSet rs = pstmt.executeQuery();
        
        // ruleid: java-checkreturnvalueofresultsetnext
        rs.next(); // Not checking return value
        String name = rs.getString("name");
        String department = rs.getString("department");
        System.out.println("Employee: " + name + ", Department: " + department);
        
        rs.close();
        pstmt.close();
        conn.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    // Liquibase with ResultSet
    String tableId = request.getParameter("tableId");
    try {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/schema", "user", "password");
        JdbcConnection jdbcConnection = new JdbcConnection(conn);
        
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM database_tables WHERE id = " + tableId);
        
        // ruleid: java-checkreturnvalueofresultsetnext
        rs.next(); // Not checking return value
        String tableName = rs.getString("table_name");
        int rowCount = rs.getInt("row_count");
        System.out.println("Table: " + tableName + ", Rows: " + rowCount);
        
        rs.close();
        stmt.close();
        conn.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // Standard JDBC with proper check on ResultSet.next()
    String userId = request.getParameter("userId");
    try {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
        
        // ok: java-checkreturnvalueofresultsetnext
        if (rs.next()) {
            String username = rs.getString("username");
            System.out.println("Username: " + username);
        } else {
            System.out.println("User not found");
        }
        
        rs.close();
        stmt.close();
        conn.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_2(HttpServletRequest request) {
    // Spring JdbcTemplate with proper ResultSet handling
    String productId = request.getParameter("productId");
    try {
        JdbcTemplate jdbcTemplate = new JdbcTemplate(new DriverManagerDataSource(
                "jdbc:postgresql://localhost:5432/products", "user", "password"));
        
        jdbcTemplate.query("SELECT * FROM products WHERE id = ?", new Object[]{productId}, 
            (ResultSet rs) -> {
                // ok: java-checkreturnvalueofresultsetnext
                if (rs.next()) {
                    return rs.getString("product_name");
                }
                return "Product not found";
            });
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3(HttpServletRequest request) {
    // Hibernate with native SQL query and proper ResultSet handling
    String orderId = request.getParameter("orderId");
    try {
        SessionFactory sessionFactory = null; // Assume initialized elsewhere
        Session session = sessionFactory.openSession();
        
        Query query = session.createNativeQuery("SELECT * FROM orders WHERE id = :id")
                            .setParameter("id", orderId);
        
        ResultSet rs = (ResultSet) query.uniqueResult(); // This is simplified for example
        // ok: java-checkreturnvalueofresultsetnext
        if (rs.next()) {
            double amount = rs.getDouble("amount");
            System.out.println("Order amount: " + amount);
        } else {
            System.out.println("Order not found");
        }
        
        session.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4(HttpServletRequest request) {
    // HikariCP connection pool with proper ResultSet handling
    String categoryId = request.getParameter("categoryId");
    try {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:mysql://localhost:3306/store");
        config.setUsername("user");
        config.setPassword("password");
        
        HikariDataSource dataSource = new HikariDataSource(config);
        Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM categories WHERE id = ?");
        pstmt.setString(1, categoryId);
        ResultSet rs = pstmt.executeQuery();
        
        // ok: java-checkreturnvalueofresultsetnext
        if (rs.next()) {
            String categoryName = rs.getString("name");
            System.out.println("Category: " + categoryName);
        } else {
            System.out.println("Category not found");
        }
        
        rs.close();
        pstmt.close();
        conn.close();
        dataSource.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    // Apache DBCP with proper ResultSet handling
    String employeeId = request.getParameter("employeeId");
    try {
        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setUrl("jdbc:oracle:thin:@localhost:1521:HR");
        dataSource.setUsername("user");
        dataSource.setPassword("password");
        
        Connection conn = dataSource.getConnection();
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM employees WHERE id = " + employeeId);
        
        // ok: java-checkreturnvalueofresultsetnext
        if (rs.next()) {
            String name = rs.getString("name");
            double salary = rs.getDouble("salary");
            System.out.println("Employee: " + name + ", Salary: " + salary);
        } else {
            System.out.println("Employee not found");
        }
        
        rs.close();
        stmt.close();
        conn.close();
        dataSource.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_6(HttpServletRequest request) {
    // Tomcat JDBC Pool with proper ResultSet handling
    String customerId = request.getParameter("customerId");
    try {
        PoolProperties p = new PoolProperties();
        p.setUrl("jdbc:mysql://localhost:3306/customers");
        p.setDriverClassName("com.mysql.jdbc.Driver");
        p.setUsername("user");
        p.setPassword("password");
        
        org.apache.tomcat.jdbc.pool.DataSource dataSource = new org.apache.tomcat.jdbc.pool.DataSource();
        dataSource.setPoolProperties(p);
        
        Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM customers WHERE id = ?");
        pstmt.setString(1, customerId);
        ResultSet rs = pstmt.executeQuery();
        
        // ok: java-checkreturnvalueofresultsetnext
        boolean hasData = rs.next();
        if (hasData) {
            String email = rs.getString("email");
            System.out.println("Customer email: " + email);
        } else {
            System.out.println("Customer not found");
        }
        
        rs.close();
        pstmt.close();
        conn.close();
        dataSource.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_7(HttpServletRequest request) {
    // jOOQ with proper ResultSet handling
    String invoiceId = request.getParameter("invoiceId");
    try {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/invoices", "user", "password");
        DSLContext create = DSL.using(conn, SQLDialect.MYSQL);
        
        ResultSet rs = create.select().from("invoices").where("id = ?", invoiceId).fetchResultSet();
        
        // ok: java-checkreturnvalueofresultsetnext
        boolean found = rs.next();
        if (found) {
            double total = rs.getDouble("total");
            String client = rs.getString("client");
            System.out.println("Invoice for " + client + ": $" + total);
        } else {
            System.out.println("Invoice not found");
        }
        
        rs.close();
        conn.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    // C3P0 connection pool with proper ResultSet handling
    String bookId = request.getParameter("bookId");
    try {
        ComboPooledDataSource cpds = new ComboPooledDataSource();
        cpds.setDriverClass("com.mysql.jdbc.Driver");
        cpds.setJdbcUrl("jdbc:mysql://localhost:3306/library");
        cpds.setUser("user");
        cpds.setPassword("password");
        
        Connection conn = cpds.getConnection();
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM books WHERE id = " + bookId);
        
        // ok: java-checkreturnvalueofresultsetnext
        boolean hasBook = rs.next();
        if (hasBook) {
            String title = rs.getString("title");
            String author = rs.getString("author");
            System.out.println("Book: " + title + " by " + author);
        } else {
            System.out.println("Book not found");
        }
        
        rs.close();
        stmt.close();
        conn.close();
        cpds.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9(HttpServletRequest request) {
    // Apache DbUtils with proper ResultSet handling
    String projectId = request.getParameter("projectId");
    try {
        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setUrl("jdbc:postgresql://localhost:5432/projects");
        dataSource.setUsername("user");
        dataSource.setPassword("password");
        
        QueryRunner runner = new QueryRunner(dataSource);
        Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM projects WHERE id = ?");
        pstmt.setString(1, projectId);
        ResultSet rs = pstmt.executeQuery();
        
        // ok: java-checkreturnvalueofresultsetnext
        if (rs.next()) {
            String name = rs.getString("name");
            String client = rs.getString("client");
            System.out.println("Project: " + name + " for " + client);
        } else {
            System.out.println("Project not found");
        }
        
        rs.close();
        pstmt.close();
        conn.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    // JDBI with proper ResultSet handling
    String userId = request.getParameter("userId");
    try {
        Jdbi jdbi = Jdbi.create("jdbc:h2:mem:test");
        
        jdbi.withHandle(handle -> {
            ResultSet rs = handle.createQuery("SELECT * FROM users WHERE id = ?")
                                .bind(0, userId)
                                .executeQuery()
                                .getResultSet();
            
            // ok: java-checkreturnvalueofresultsetnext
            boolean userExists = rs.next();
            if (userExists) {
                String username = rs.getString("username");
                String email = rs.getString("email");
                System.out.println("User: " + username + ", Email: " + email);
            } else {
                System.out.println("User not found");
            }
            
            return null;
        });
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11(HttpServletRequest request) {
    // Spring NamedParameterJdbcTemplate with proper ResultSet handling
    String productId = request.getParameter("productId");
    try {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:mysql://localhost:3306/inventory", "user", "password");
        NamedParameterJdbcTemplate namedTemplate = new NamedParameterJdbcTemplate(dataSource);
        
        MapSqlParameterSource params = new MapSqlParameterSource();
        params.addValue("id", productId);
        
        namedTemplate.query("SELECT * FROM products WHERE id = :id", params, 
            (ResultSet rs) -> {
                // ok: java-checkreturnvalueofresultsetnext
                if (rs.next()) {
                    return rs.getString("product_name");
                } else {
                    return "Product not found";
                }
            });
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    // Spring MappingSqlQuery with proper ResultSet handling
    String orderId = request.getParameter("orderId");
    try {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:mysql://localhost:3306/orders", "user", "password");
        
        Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM orders WHERE id = ?");
        pstmt.setString(1, orderId);
        ResultSet rs = pstmt.executeQuery();
        
        // ok: java-checkreturnvalueofresultsetnext
        boolean orderFound = rs.next();
        if (orderFound) {
            double amount = rs.getDouble("amount");
            String customer = rs.getString("customer");
            System.out.println("Order for " + customer + ": $" + amount);
        } else {
            System.out.println("Order not found");
        }
        
        rs.close();
        pstmt.close();
        conn.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_13(HttpServletRequest request) {
    // Vert.x JDBC Client with proper ResultSet handling
    String userId = request.getParameter("userId");
    try {
        // Simplified for example
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "user", "password");
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        pstmt.setString(1, userId);
        ResultSet rs = pstmt.executeQuery();
        
        // ok: java-checkreturnvalueofresultsetnext
        boolean hasUser = rs.next();
        if (hasUser) {
            String username = rs.getString("username");
            String role = rs.getString("role");
            System.out.println("User: " + username + ", Role: " + role);
        } else {
            System.out.println("User not found");
        }
        
        rs.close();
        pstmt.close();
        conn.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) {
    // Apache Cayenne with proper ResultSet handling
    String employeeId = request.getParameter("employeeId");
    try {
        // Simplified for example
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/hr", "user", "password");
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM employees WHERE id = ?");
        pstmt.setString(1, employeeId);
        ResultSet rs = pstmt.executeQuery();
        
        // ok: java-checkreturnvalueofresultsetnext
        boolean found = rs.next();
        if (found) {
            String name = rs.getString("name");
            String department = rs.getString("department");
            System.out.println("Employee: " + name + ", Department: " + department);
        } else {
            System.out.println("Employee not found");
        }
        
        rs.close();
        pstmt.close();
        conn.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    // Liquibase with proper ResultSet handling
    String tableId = request.getParameter("tableId");
    try {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/schema", "user", "password");
        JdbcConnection jdbcConnection = new JdbcConnection(conn);
        
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM database_tables WHERE id = " + tableId);
        
        // ok: java-checkreturnvalueofresultsetnext
        if (rs.next()) {
            String tableName = rs.getString("table_name");
            int rowCount = rs.getInt("row_count");
            System.out.println("Table: " + tableName + ", Rows: " + rowCount);
        } else {
            System.out.println("Table not found");
        }
        
        rs.close();
        stmt.close();
        conn.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}