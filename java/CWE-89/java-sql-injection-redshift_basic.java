import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.Properties;
import org.apache.commons.lang3.StringEscapeUtils;
import org.owasp.esapi.ESAPI;
import java.util.regex.Pattern;

public class RedshiftSQLInjectionExamples {
    
    private static Connection getRedshiftConnection() throws SQLException {
        String url = "jdbc:redshift://redshift-cluster.example.region.redshift.amazonaws.com:5439/dev";
        String user = "username";
        String password = "password";
        return DriverManager.getConnection(url, user, password);
    }
    
    // True Positive Examples (Vulnerable Code)
    
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String userId = request.getParameter("id");
        Connection conn = getRedshiftConnection();
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE user_id = " + userId;
        // ruleid: java-sql-injection-redshift
        ResultSet rs = stmt.executeQuery(query);
        // Process results...
        rs.close();
        stmt.close();
        conn.close();
    }
    
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String username = request.getParameter("username");
        Connection conn = getRedshiftConnection();
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM customers WHERE name LIKE '%" + username + "%'";
        // ruleid: java-sql-injection-redshift
        ResultSet rs = stmt.executeQuery(query);
        // Process results...
        rs.close();
        stmt.close();
        conn.close();
    }
    
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String sortColumn = request.getParameter("sort");
        Connection conn = getRedshiftConnection();
        Statement stmt = conn.createStatement();
        String query = "SELECT product_id, product_name, price FROM products ORDER BY " + sortColumn;
        // ruleid: java-sql-injection-redshift
        ResultSet rs = stmt.executeQuery(query);
        // Process results...
        rs.close();
        stmt.close();
        conn.close();
    }
    
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws SQLException, IOException {
        String tableName = request.getParameter("table");
        Connection conn = getRedshiftConnection();
        Statement stmt = conn.createStatement();
        String query = "SELECT COUNT(*) FROM " + tableName;
        // ruleid: java-sql-injection-redshift
        ResultSet rs = stmt.executeQuery(query);
        if (rs.next()) {
            response.getWriter().println("Count: " + rs.getInt(1));
        }
        rs.close();
        stmt.close();
        conn.close();
    }
    
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String category = request.getParameter("category");
        String minPrice = request.getParameter("minPrice");
        Connection conn = getRedshiftConnection();
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM products WHERE category = '" + category + 
                       "' AND price > " + minPrice;
        // ruleid: java-sql-injection-redshift
        ResultSet rs = stmt.executeQuery(query);
        // Process results...
        rs.close();
        stmt.close();
        conn.close();
    }
    
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String[] ids = request.getParameterValues("ids");
        StringBuilder idList = new StringBuilder();
        for (String id : ids) {
            if (idList.length() > 0) {
                idList.append(",");
            }
            idList.append(id);
        }
        
        Connection conn = getRedshiftConnection();
        Statement stmt = conn.createStatement();
        String query = "DELETE FROM orders WHERE order_id IN (" + idList.toString() + ")";
        // ruleid: java-sql-injection-redshift
        stmt.executeUpdate(query);
        stmt.close();
        conn.close();
    }
    
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String searchTerm = request.getParameter("search");
        Connection conn = getRedshiftConnection();
        Statement stmt = conn.createStatement();
        
        // Using concatenation in a more complex query
        String query = "SELECT p.product_name, c.category_name " +
                       "FROM products p " +
                       "JOIN categories c ON p.category_id = c.id " +
                       "WHERE p.product_name LIKE '%" + searchTerm + "%' OR " +
                       "c.category_name LIKE '%" + searchTerm + "%'";
        
        // ruleid: java-sql-injection-redshift
        ResultSet rs = stmt.executeQuery(query);
        // Process results...
        rs.close();
        stmt.close();
        conn.close();
    }
    
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String userId = request.getParameter("userId");
        String newStatus = request.getParameter("status");
        
        Connection conn = getRedshiftConnection();
        Statement stmt = conn.createStatement();
        String query = "UPDATE users SET status = '" + newStatus + "' WHERE user_id = " + userId;
        // ruleid: java-sql-injection-redshift
        stmt.executeUpdate(query);
        stmt.close();
        conn.close();
    }
    
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String dateFrom = request.getParameter("dateFrom");
        String dateTo = request.getParameter("dateTo");
        
        Connection conn = getRedshiftConnection();
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM transactions WHERE transaction_date BETWEEN '" + 
                       dateFrom + "' AND '" + dateTo + "'";
        // ruleid: java-sql-injection-redshift
        ResultSet rs = stmt.executeQuery(query);
        // Process results...
        rs.close();
        stmt.close();
        conn.close();
    }
    
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String groupBy = request.getParameter("groupBy");
        
        Connection conn = getRedshiftConnection();
        Statement stmt = conn.createStatement();
        String query = "SELECT " + groupBy + ", SUM(amount) FROM sales GROUP BY " + groupBy;
        // ruleid: java-sql-injection-redshift
        ResultSet rs = stmt.executeQuery(query);
        // Process results...
        rs.close();
        stmt.close();
        conn.close();
    }
    
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String userInput = request.getParameter("query");
        
        Connection conn = getRedshiftConnection();
        Statement stmt = conn.createStatement();
        // Direct execution of user input
        // ruleid: java-sql-injection-redshift
        ResultSet rs = stmt.executeQuery(userInput);
        // Process results...
        rs.close();
        stmt.close();
        conn.close();
    }
    
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String tableName = request.getParameter("table");
        String columnName = request.getParameter("column");
        String value = request.getParameter("value");
        
        Connection conn = getRedshiftConnection();
        Statement stmt = conn.createStatement();
        String query = "INSERT INTO " + tableName + " (" + columnName + ") VALUES ('" + value + "')";
        // ruleid: java-sql-injection-redshift
        stmt.executeUpdate(query);
        stmt.close();
        conn.close();
    }
    
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String header = request.getHeader("X-Sort-Column");
        String direction = request.getParameter("direction");
        
        Connection conn = getRedshiftConnection();
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM products ORDER BY " + header + " " + direction;
        // ruleid: java-sql-injection-redshift
        ResultSet rs = stmt.executeQuery(query);
        // Process results...
        rs.close();
        stmt.close();
        conn.close();
    }
    
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String userId = request.getParameter("userId");
        // Attempting to sanitize but still vulnerable
        userId = userId.replace("'", "''");
        
        Connection conn = getRedshiftConnection();
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE user_id = " + userId; // Still injectable with numeric attacks
        // ruleid: java-sql-injection-redshift
        ResultSet rs = stmt.executeQuery(query);
        // Process results...
        rs.close();
        stmt.close();
        conn.close();
    }
    
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String limit = request.getParameter("limit");
        String offset = request.getParameter("offset");
        
        Connection conn = getRedshiftConnection();
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM products LIMIT " + limit + " OFFSET " + offset;
        // ruleid: java-sql-injection-redshift
        ResultSet rs = stmt.executeQuery(query);
        // Process results...
        rs.close();
        stmt.close();
        conn.close();
    }
    
    // True Negative Examples (Secure Code)
    
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String userId = request.getParameter("id");
        Connection conn = getRedshiftConnection();
        // ok: java-sql-injection-redshift
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE user_id = ?");
        pstmt.setString(1, userId);
        ResultSet rs = pstmt.executeQuery();
        // Process results...
        rs.close();
        pstmt.close();
        conn.close();
    }
    
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String username = request.getParameter("username");
        Connection conn = getRedshiftConnection();
        // ok: java-sql-injection-redshift
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM customers WHERE name LIKE ?");
        pstmt.setString(1, "%" + username + "%");
        ResultSet rs = pstmt.executeQuery();
        // Process results...
        rs.close();
        pstmt.close();
        conn.close();
    }
    
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String sortColumn = request.getParameter("sort");
        // Validate against a whitelist of allowed columns
        String[] allowedColumns = {"product_id", "product_name", "price", "created_date"};
        boolean isValid = false;
        for (String allowed : allowedColumns) {
            if (allowed.equals(sortColumn)) {
                isValid = true;
                break;
            }
        }
        
        if (!isValid) {
            sortColumn = "product_id"; // Default safe value
        }
        
        Connection conn = getRedshiftConnection();
        // ok: java-sql-injection-redshift
        Statement stmt = conn.createStatement();
        String query = "SELECT product_id, product_name, price FROM products ORDER BY " + sortColumn;
        ResultSet rs = stmt.executeQuery(query);
        // Process results...
        rs.close();
        stmt.close();
        conn.close();
    }
    
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws SQLException, IOException {
        String tableName = request.getParameter("table");
        // Validate table name against whitelist
        String[] allowedTables = {"products", "customers", "orders"};
        boolean isValid = false;
        for (String allowed : allowedTables) {
            if (allowed.equals(tableName)) {
                isValid = true;
                break;
            }
        }
        
        if (!isValid) {
            response.getWriter().println("Invalid table name");
            return;
        }
        
        Connection conn = getRedshiftConnection();
        // ok: java-sql-injection-redshift
        Statement stmt = conn.createStatement();
        String query = "SELECT COUNT(*) FROM " + tableName;
        ResultSet rs = stmt.executeQuery(query);
        if (rs.next()) {
            response.getWriter().println("Count: " + rs.getInt(1));
        }
        rs.close();
        stmt.close();
        conn.close();
    }
    
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String category = request.getParameter("category");
        String minPrice = request.getParameter("minPrice");
        Connection conn = getRedshiftConnection();
        // ok: java-sql-injection-redshift
        PreparedStatement pstmt = conn.prepareStatement(
            "SELECT * FROM products WHERE category = ? AND price > ?");
        pstmt.setString(1, category);
        pstmt.setDouble(2, Double.parseDouble(minPrice));
        ResultSet rs = pstmt.executeQuery();
        // Process results...
        rs.close();
        pstmt.close();
        conn.close();
    }
    
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String[] ids = request.getParameterValues("ids");
        Connection conn = getRedshiftConnection();
        
        // Using a prepared statement with batch updates
        // ok: java-sql-injection-redshift
        PreparedStatement pstmt = conn.prepareStatement("DELETE FROM orders WHERE order_id = ?");
        for (String id : ids) {
            pstmt.setInt(1, Integer.parseInt(id));
            pstmt.addBatch();
        }
        pstmt.executeBatch();
        pstmt.close();
        conn.close();
    }
    
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String searchTerm = request.getParameter("search");
        Connection conn = getRedshiftConnection();
        
        // ok: java-sql-injection-redshift
        PreparedStatement pstmt = conn.prepareStatement(
            "SELECT p.product_name, c.category_name " +
            "FROM products p " +
            "JOIN categories c ON p.category_id = c.id " +
            "WHERE p.product_name LIKE ? OR c.category_name LIKE ?");
        
        String searchPattern = "%" + searchTerm + "%";
        pstmt.setString(1, searchPattern);
        pstmt.setString(2, searchPattern);
        
        ResultSet rs = pstmt.executeQuery();
        // Process results...
        rs.close();
        pstmt.close();
        conn.close();
    }
    
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String userId = request.getParameter("userId");
        String newStatus = request.getParameter("status");
        
        // Validate status against allowed values
        String[] allowedStatuses = {"active", "inactive", "pending"};
        boolean isValidStatus = false;
        for (String status : allowedStatuses) {
            if (status.equals(newStatus)) {
                isValidStatus = true;
                break;
            }
        }
        
        if (!isValidStatus) {
            return; // Invalid status
        }
        
        Connection conn = getRedshiftConnection();
        // ok: java-sql-injection-redshift
        PreparedStatement pstmt = conn.prepareStatement(
            "UPDATE users SET status = ? WHERE user_id = ?");
        pstmt.setString(1, newStatus);
        pstmt.setInt(2, Integer.parseInt(userId));
        pstmt.executeUpdate();
        pstmt.close();
        conn.close();
    }
    
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String dateFrom = request.getParameter("dateFrom");
        String dateTo = request.getParameter("dateTo");
        
        // Validate date format
        Pattern datePattern = Pattern.compile("\\d{4}-\\d{2}-\\d{2}");
        if (!datePattern.matcher(dateFrom).matches() || !datePattern.matcher(dateTo).matches()) {
            return; // Invalid date format
        }
        
        Connection conn = getRedshiftConnection();
        // ok: java-sql-injection-redshift
        PreparedStatement pstmt = conn.prepareStatement(
            "SELECT * FROM transactions WHERE transaction_date BETWEEN ? AND ?");
        pstmt.setString(1, dateFrom);
        pstmt.setString(2, dateTo);
        ResultSet rs = pstmt.executeQuery();
        // Process results...
        rs.close();
        pstmt.close();
        conn.close();
    }
    
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String groupBy = request.getParameter("groupBy");
        
        // Whitelist validation
        String[] allowedColumns = {"region", "product_category", "customer_type", "year", "month"};
        boolean isValid = false;
        for (String allowed : allowedColumns) {
            if (allowed.equals(groupBy)) {
                isValid = true;
                break;
            }
        }
        
        if (!isValid) {
            groupBy = "region"; // Default safe value
        }
        
        Connection conn = getRedshiftConnection();
        // ok: java-sql-injection-redshift
        Statement stmt = conn.createStatement();
        String query = "SELECT " + groupBy + ", SUM(amount) FROM sales GROUP BY " + groupBy;
        ResultSet rs = stmt.executeQuery(query);
        // Process results...
        rs.close();
        stmt.close();
        conn.close();
    }
    
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        // Instead of executing user input directly, use a predefined query with parameters
        String productId = request.getParameter("productId");
        
        Connection conn = getRedshiftConnection();
        // ok: java-sql-injection-redshift
        PreparedStatement pstmt = conn.prepareStatement(
            "SELECT * FROM products WHERE product_id = ?");
        pstmt.setString(1, productId);
        ResultSet rs = pstmt.executeQuery();
        // Process results...
        rs.close();
        pstmt.close();
        conn.close();
    }
    
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String value = request.getParameter("value");
        
        Connection conn = getRedshiftConnection();
        // Using a fixed table and column name with parameterized value
        // ok: java-sql-injection-redshift
        PreparedStatement pstmt = conn.prepareStatement(
            "INSERT INTO products (product_name) VALUES (?)");
        pstmt.setString(1, value);
        pstmt.executeUpdate();
        pstmt.close();
        conn.close();
    }
    
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String header = request.getHeader("X-Sort-Column");
        String direction = request.getParameter("direction");
        
        // Validate sort column
        String[] validColumns = {"product_id", "name", "price", "created_at"};
        boolean isValidColumn = false;
        for (String col : validColumns) {
            if (col.equals(header)) {
                isValidColumn = true;
                break;
            }
        }
        
        // Validate direction
        String[] validDirections = {"ASC", "DESC"};
        boolean isValidDirection = false;
        for (String dir : validDirections) {
            if (dir.equalsIgnoreCase(direction)) {
                isValidDirection = true;
                break;
            }
        }
        
        if (!isValidColumn || !isValidDirection) {
            header = "product_id";
            direction = "ASC";
        }
        
        Connection conn = getRedshiftConnection();
        // ok: java-sql-injection-redshift
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM products ORDER BY " + header + " " + direction;
        ResultSet rs = stmt.executeQuery(query);
        // Process results...
        rs.close();
        stmt.close();
        conn.close();
    }
    
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String userId = request.getParameter("userId");
        
        // Proper input validation
        if (!userId.matches("\\d+")) {
            return; // Invalid input
        }
        
        Connection conn = getRedshiftConnection();
        // ok: java-sql-injection-redshift
        PreparedStatement pstmt = conn.prepareStatement(
            "SELECT * FROM users WHERE user_id = ?");
        pstmt.setInt(1, Integer.parseInt(userId));
        ResultSet rs = pstmt.executeQuery();
        // Process results...
        rs.close();
        pstmt.close();
        conn.close();
    }
    
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String limitStr = request.getParameter("limit");
        String offsetStr = request.getParameter("offset");
        
        // Parse and validate numeric values
        int limit, offset;
        try {
            limit = Integer.parseInt(limitStr);
            offset = Integer.parseInt(offsetStr);
            
            if (limit <= 0 || limit > 100 || offset < 0) {
                limit = 10;  // Default safe values
                offset = 0;
            }
        } catch (NumberFormatException e) {
            limit = 10;  // Default safe values
            offset = 0;
        }
        
        Connection conn = getRedshiftConnection();
        // ok: java-sql-injection-redshift
        PreparedStatement pstmt = conn.prepareStatement(
            "SELECT * FROM products LIMIT ? OFFSET ?");
        pstmt.setInt(1, limit);
        pstmt.setInt(2, offset);
        ResultSet rs = pstmt.executeQuery();
        // Process results...
        rs.close();
        pstmt.close();
        conn.close();
    }
}