import java.sql.*;
import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.regex.Pattern;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.OracleCodec;
import java.util.UUID;
import java.util.Properties;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import java.util.HashMap;
import java.util.Map;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.query.Query;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

// True Positive Examples (Vulnerable Code)

public class SQLInjectionExamples extends HttpServlet {
    
    // Example 1: Basic SQL Injection in servlet
// {fact rule=cross-site-scripting@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        Connection conn = null;
        Statement stmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "user", "password");
            stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            // ruleid: java-sql-injection-rds
            ResultSet rs = stmt.executeQuery(query);
            
            // Process results
            while(rs.next()) {
                response.getWriter().println(rs.getString("username"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (stmt != null) stmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 2: SQL Injection with multiple parameters
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String productId = request.getParameter("productId");
        String category = request.getParameter("category");
        Connection conn = null;
        Statement stmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/products", "user", "password");
            stmt = conn.createStatement();
            String query = "SELECT * FROM products WHERE id = " + productId + " AND category = '" + category + "'";
            // ruleid: java-sql-injection-rds
            ResultSet rs = stmt.executeQuery(query);
            
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (stmt != null) stmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 3: SQL Injection in UPDATE statement
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        String newEmail = request.getParameter("email");
        Connection conn = null;
        Statement stmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/users", "admin", "admin123");
            stmt = conn.createStatement();
            String query = "UPDATE users SET email = '" + newEmail + "' WHERE id = " + userId;
            // ruleid: java-sql-injection-rds
            int rowsAffected = stmt.executeUpdate(query);
            
            response.getWriter().println("Updated " + rowsAffected + " rows");
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (stmt != null) stmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 4: SQL Injection with string concatenation in a loop
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String[] productIds = request.getParameterValues("productIds");
        Connection conn = null;
        Statement stmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/inventory", "user", "password");
            stmt = conn.createStatement();
            
            StringBuilder queryBuilder = new StringBuilder("SELECT * FROM products WHERE id IN (");
            for (int i = 0; i < productIds.length; i++) {
                if (i > 0) {
                    queryBuilder.append(",");
                }
                queryBuilder.append(productIds[i]);
            }
            queryBuilder.append(")");
            
            // ruleid: java-sql-injection-rds
            ResultSet rs = stmt.executeQuery(queryBuilder.toString());
            
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (stmt != null) stmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 5: SQL Injection with LIKE clause
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchTerm = request.getParameter("search");
        Connection conn = null;
        Statement stmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/library", "user", "password");
            stmt = conn.createStatement();
            String query = "SELECT * FROM books WHERE title LIKE '%" + searchTerm + "%'";
            // ruleid: java-sql-injection-rds
            ResultSet rs = stmt.executeQuery(query);
            
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (stmt != null) stmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 6: SQL Injection with ORDER BY clause
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String sortColumn = request.getParameter("sort");
        String sortOrder = request.getParameter("order");
        Connection conn = null;
        Statement stmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/employees", "user", "password");
            stmt = conn.createStatement();
            String query = "SELECT * FROM employees ORDER BY " + sortColumn + " " + sortOrder;
            // ruleid: java-sql-injection-rds
            ResultSet rs = stmt.executeQuery(query);
            
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (stmt != null) stmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 7: SQL Injection with header input
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userAgent = request.getHeader("User-Agent");
        Connection conn = null;
        Statement stmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/analytics", "user", "password");
            stmt = conn.createStatement();
            String query = "INSERT INTO user_agents (agent_string, visit_time) VALUES ('" + userAgent + "', NOW())";
            // ruleid: java-sql-injection-rds
            stmt.executeUpdate(query);
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (stmt != null) stmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 8: SQL Injection with cookie input
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Cookie[] cookies = request.getCookies();
        String trackingId = "";
        
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("trackingId")) {
                    trackingId = cookie.getValue();
                    break;
                }
            }
        }
        
        Connection conn = null;
        Statement stmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/tracking", "user", "password");
            stmt = conn.createStatement();
            String query = "SELECT * FROM sessions WHERE tracking_id = '" + trackingId + "'";
            // ruleid: java-sql-injection-rds
            ResultSet rs = stmt.executeQuery(query);
            
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (stmt != null) stmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 9: SQL Injection with minimal processing of input
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        // Minimal processing that doesn't prevent SQL injection
        userId = userId.trim().toLowerCase();
        
        Connection conn = null;
        Statement stmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "user", "password");
            stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE id = " + userId;
            // ruleid: java-sql-injection-rds
            ResultSet rs = stmt.executeQuery(query);
            
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (stmt != null) stmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 10: SQL Injection with Spring JDBC Template execute method
    @Controller
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("com.mysql.jdbc.Driver");
        dataSource.setUrl("jdbc:mysql://localhost:3306/users");
        dataSource.setUsername("user");
        dataSource.setPassword("password");
        
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        
        // ruleid: java-sql-injection-rds
        jdbcTemplate.execute(query);
    }
    
    // Example 11: SQL Injection with DELETE statement
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String commentId = request.getParameter("commentId");
        
        Connection conn = null;
        Statement stmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/blog", "user", "password");
            stmt = conn.createStatement();
            String query = "DELETE FROM comments WHERE id = " + commentId;
            // ruleid: java-sql-injection-rds
            int rowsDeleted = stmt.executeUpdate(query);
            
            response.getWriter().println("Deleted " + rowsDeleted + " comments");
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (stmt != null) stmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 12: SQL Injection with multiple inputs combined
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String minPrice = request.getParameter("minPrice");
        String maxPrice = request.getParameter("maxPrice");
        String category = request.getParameter("category");
        
        Connection conn = null;
        Statement stmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/store", "user", "password");
            stmt = conn.createStatement();
            String query = "SELECT * FROM products WHERE price BETWEEN " + minPrice + " AND " + maxPrice + 
                           " AND category = '" + category + "'";
            // ruleid: java-sql-injection-rds
            ResultSet rs = stmt.executeQuery(query);
            
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (stmt != null) stmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 13: SQL Injection with Hibernate createNativeQuery
    @PersistenceContext
    private EntityManager entityManager;
    
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String departmentName = request.getParameter("department");
        
        String query = "SELECT e FROM Employee e WHERE e.department = '" + departmentName + "'";
        
        // ruleid: java-sql-injection-rds
        entityManager.createNativeQuery(query).getResultList();
    }
    
    // Example 14: SQL Injection with Hibernate Session createSQLQuery
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response, SessionFactory sessionFactory) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        
        Session session = sessionFactory.openSession();
        try {
            String query = "SELECT * FROM users WHERE id = " + userId;
            
            // ruleid: java-sql-injection-rds
            session.createSQLQuery(query).list();
        } finally {
            session.close();
        }
    }
    
    // Example 15: SQL Injection with batch updates
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String[] userIds = request.getParameterValues("userIds");
        String newStatus = request.getParameter("status");
        
        Connection conn = null;
        Statement stmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "user", "password");
            stmt = conn.createStatement();
            
            for (String userId : userIds) {
                String query = "UPDATE users SET status = '" + newStatus + "' WHERE id = " + userId;
                stmt.addBatch(query);
            }
            
            // ruleid: java-sql-injection-rds
            stmt.executeBatch();
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (stmt != null) stmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // True Negative Examples (Secure Code)
    
    // Example 1: Using PreparedStatement for basic query
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        Connection conn = null;
        PreparedStatement pstmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "user", "password");
            // ok: java-sql-injection-rds
            pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            
            // Process results
            while(rs.next()) {
                response.getWriter().println(rs.getString("username"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (pstmt != null) pstmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 2: Using PreparedStatement with multiple parameters
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String productId = request.getParameter("productId");
        String category = request.getParameter("category");
        Connection conn = null;
        PreparedStatement pstmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/products", "user", "password");
            // ok: java-sql-injection-rds
            pstmt = conn.prepareStatement("SELECT * FROM products WHERE id = ? AND category = ?");
            pstmt.setString(1, productId);
            pstmt.setString(2, category);
            ResultSet rs = pstmt.executeQuery();
            
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (pstmt != null) pstmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 3: Using PreparedStatement for UPDATE
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        String newEmail = request.getParameter("email");
        Connection conn = null;
        PreparedStatement pstmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/users", "admin", "admin123");
            // ok: java-sql-injection-rds
            pstmt = conn.prepareStatement("UPDATE users SET email = ? WHERE id = ?");
            pstmt.setString(1, newEmail);
            pstmt.setString(2, userId);
            int rowsAffected = pstmt.executeUpdate();
            
            response.getWriter().println("Updated " + rowsAffected + " rows");
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (pstmt != null) pstmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 4: Using PreparedStatement with IN clause
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String[] productIds = request.getParameterValues("productIds");
        Connection conn = null;
        PreparedStatement pstmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/inventory", "user", "password");
            
            StringBuilder placeholders = new StringBuilder();
            for (int i = 0; i < productIds.length; i++) {
                if (i > 0) {
                    placeholders.append(",");
                }
                placeholders.append("?");
            }
            
            // ok: java-sql-injection-rds
            pstmt = conn.prepareStatement("SELECT * FROM products WHERE id IN (" + placeholders.toString() + ")");
            
            for (int i = 0; i < productIds.length; i++) {
                pstmt.setString(i + 1, productIds[i]);
            }
            
            ResultSet rs = pstmt.executeQuery();
            
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (pstmt != null) pstmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 5: Using PreparedStatement with LIKE clause
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchTerm = request.getParameter("search");
        Connection conn = null;
        PreparedStatement pstmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/library", "user", "password");
            // ok: java-sql-injection-rds
            pstmt = conn.prepareStatement("SELECT * FROM books WHERE title LIKE ?");
            pstmt.setString(1, "%" + searchTerm + "%");
            ResultSet rs = pstmt.executeQuery();
            
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (pstmt != null) pstmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 6: Using whitelist for ORDER BY clause
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String sortColumn = request.getParameter("sort");
        String sortOrder = request.getParameter("order");
        Connection conn = null;
        PreparedStatement pstmt = null;
        
        // Whitelist validation for column names
        Map<String, String> allowedColumns = new HashMap<>();
        allowedColumns.put("name", "name");
        allowedColumns.put("date", "hire_date");
        allowedColumns.put("salary", "salary");
        
        // Whitelist validation for sort order
        Map<String, String> allowedOrders = new HashMap<>();
        allowedOrders.put("asc", "ASC");
        allowedOrders.put("desc", "DESC");
        
        String validatedColumn = allowedColumns.getOrDefault(sortColumn, "name");
        String validatedOrder = allowedOrders.getOrDefault(sortOrder, "ASC");
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/employees", "user", "password");
            // ok: java-sql-injection-rds
            pstmt = conn.prepareStatement("SELECT * FROM employees ORDER BY " + validatedColumn + " " + validatedOrder);
            ResultSet rs = pstmt.executeQuery();
            
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (pstmt != null) pstmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 7: Using PreparedStatement with header input
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userAgent = request.getHeader("User-Agent");
        Connection conn = null;
        PreparedStatement pstmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/analytics", "user", "password");
            // ok: java-sql-injection-rds
            pstmt = conn.prepareStatement("INSERT INTO user_agents (agent_string, visit_time) VALUES (?, NOW())");
            pstmt.setString(1, userAgent);
            pstmt.executeUpdate();
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (pstmt != null) pstmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 8: Using PreparedStatement with cookie input
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Cookie[] cookies = request.getCookies();
        String trackingId = "";
        
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("trackingId")) {
                    trackingId = cookie.getValue();
                    break;
                }
            }
        }
        
        Connection conn = null;
        PreparedStatement pstmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/tracking", "user", "password");
            // ok: java-sql-injection-rds
            pstmt = conn.prepareStatement("SELECT * FROM sessions WHERE tracking_id = ?");
            pstmt.setString(1, trackingId);
            ResultSet rs = pstmt.executeQuery();
            
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (pstmt != null) pstmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 9: Using input validation with PreparedStatement
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        
        // Input validation
        if (!userId.matches("^[0-9]+$")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid user ID");
            return;
        }
        
        Connection conn = null;
        PreparedStatement pstmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "user", "password");
            // ok: java-sql-injection-rds
            pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
            pstmt.setString(1, userId);
            ResultSet rs = pstmt.executeQuery();
            
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (pstmt != null) pstmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 10: Using Spring JDBC Template with parameterized query
    @Controller
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("com.mysql.jdbc.Driver");
        dataSource.setUrl("jdbc:mysql://localhost:3306/users");
        dataSource.setUsername("user");
        dataSource.setPassword("password");
        
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        
        // ok: java-sql-injection-rds
        jdbcTemplate.queryForList("SELECT * FROM users WHERE username = ?", username);
    }
    
    // Example 11: Using PreparedStatement with DELETE statement
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String commentId = request.getParameter("commentId");
        
        Connection conn = null;
        PreparedStatement pstmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/blog", "user", "password");
            // ok: java-sql-injection-rds
            pstmt = conn.prepareStatement("DELETE FROM comments WHERE id = ?");
            pstmt.setString(1, commentId);
            int rowsDeleted = pstmt.executeUpdate();
            
            response.getWriter().println("Deleted " + rowsDeleted + " comments");
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (pstmt != null) pstmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 12: Using PreparedStatement with multiple inputs
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String minPrice = request.getParameter("minPrice");
        String maxPrice = request.getParameter("maxPrice");
        String category = request.getParameter("category");
        
        Connection conn = null;
        PreparedStatement pstmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/store", "user", "password");
            // ok: java-sql-injection-rds
            pstmt = conn.prepareStatement("SELECT * FROM products WHERE price BETWEEN ? AND ? AND category = ?");
            pstmt.setString(1, minPrice);
            pstmt.setString(2, maxPrice);
            pstmt.setString(3, category);
            ResultSet rs = pstmt.executeQuery();
            
            // Process results
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (pstmt != null) pstmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
    
    // Example 13: Using Hibernate with parameterized query
    @PersistenceContext
    private EntityManager entityManager2;
    
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String departmentName = request.getParameter("department");
        
        // ok: java-sql-injection-rds
        entityManager2.createNativeQuery("SELECT e FROM Employee e WHERE e.department = ?")
            .setParameter(1, departmentName)
            .getResultList();
    }
    
    // Example 14: Using Hibernate Session with parameterized query
    public void good_case_14(HttpServletRequest request, HttpServletResponse response, SessionFactory sessionFactory) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        
        Session session = sessionFactory.openSession();
        try {
            // ok: java-sql-injection-rds
            Query query = session.createSQLQuery("SELECT * FROM users WHERE id = :userId")
                .setParameter("userId", userId);
            
            query.list();
        } finally {
            session.close();
        }
    }
    
    // Example 15: Using PreparedStatement with batch updates
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String[] userIds = request.getParameterValues("userIds");
        String newStatus = request.getParameter("status");
        
        Connection conn = null;
        PreparedStatement pstmt = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "user", "password");
            // ok: java-sql-injection-rds
            pstmt = conn.prepareStatement("UPDATE users SET status = ? WHERE id = ?");
            
            for (String userId : userIds) {
                pstmt.setString(1, newStatus);
                pstmt.setString(2, userId);
                pstmt.addBatch();
            }
            
            pstmt.executeBatch();
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (pstmt != null) pstmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
}
// {/fact}