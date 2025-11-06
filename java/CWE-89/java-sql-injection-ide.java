import java.sql.*;
import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.Properties;
import java.util.regex.Pattern;
import java.util.UUID;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.OracleCodec;

public class SQLInjectionExamples extends HttpServlet {

    // True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
    protected void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            // ruleid: java-sql-injection-ide
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
            
            // Process results
            while (rs.next()) {
                response.getWriter().println("User found: " + rs.getString("name"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String productId = request.getParameter("productId");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            // ruleid: java-sql-injection-ide
            int count = stmt.executeUpdate("UPDATE products SET views = views + 1 WHERE id = " + productId);
            
            response.getWriter().println("Updated " + count + " records");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchTerm = request.getParameter("search");
        String category = request.getParameter("category");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + 
                           "%' AND category = '" + category + "'";
            // ruleid: java-sql-injection-ide
            ResultSet rs = stmt.executeQuery(query);
            
            while (rs.next()) {
                response.getWriter().println(rs.getString("name"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("id");
        String role = request.getParameter("role");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            StringBuilder queryBuilder = new StringBuilder();
            queryBuilder.append("SELECT * FROM users WHERE id = ");
            queryBuilder.append(userId);
            queryBuilder.append(" AND role = '");
            queryBuilder.append(role);
            queryBuilder.append("'");
            
            // ruleid: java-sql-injection-ide
            ResultSet rs = stmt.executeQuery(queryBuilder.toString());
            
            while (rs.next()) {
                response.getWriter().println("Found user: " + rs.getString("username"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String sortColumn = request.getParameter("sort");
        String sortOrder = request.getParameter("order");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM products ORDER BY " + sortColumn + " " + sortOrder;
            
            // ruleid: java-sql-injection-ide
            ResultSet rs = stmt.executeQuery(query);
            
            while (rs.next()) {
                response.getWriter().println(rs.getString("name"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String tableName = request.getParameter("table");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            
            // ruleid: java-sql-injection-ide
            ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM " + tableName);
            
            if (rs.next()) {
                response.getWriter().println("Count: " + rs.getInt(1));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        String action = request.getParameter("action");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            
            if ("delete".equals(action)) {
                // ruleid: java-sql-injection-ide
                stmt.executeUpdate("DELETE FROM users WHERE id = " + userId);
                response.getWriter().println("User deleted");
            } else if ("activate".equals(action)) {
                // ruleid: java-sql-injection-ide
                stmt.executeUpdate("UPDATE users SET active = true WHERE id = " + userId);
                response.getWriter().println("User activated");
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            
            // ruleid: java-sql-injection-ide
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + 
                                           "' AND password = '" + password + "'");
            
            if (rs.next()) {
                response.getWriter().println("Login successful");
            } else {
                response.getWriter().println("Login failed");
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String minPrice = request.getParameter("minPrice");
        String maxPrice = request.getParameter("maxPrice");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            
            String query = "SELECT * FROM products WHERE price BETWEEN " + minPrice + " AND " + maxPrice;
            
            // ruleid: java-sql-injection-ide
            ResultSet rs = stmt.executeQuery(query);
            
            while (rs.next()) {
                response.getWriter().println(rs.getString("name") + ": $" + rs.getDouble("price"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String[] selectedIds = request.getParameterValues("selected");
        
        if (selectedIds != null && selectedIds.length > 0) {
            try {
                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
                Statement stmt = conn.createStatement();
                
                StringBuilder idList = new StringBuilder();
                for (String id : selectedIds) {
                    if (idList.length() > 0) {
                        idList.append(",");
                    }
                    idList.append(id);
                }
                
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE id IN (" + idList.toString() + ")");
                
                while (rs.next()) {
                    response.getWriter().println(rs.getString("name"));
                }
                conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    protected void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String dateFilter = request.getParameter("date");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            
            // ruleid: java-sql-injection-ide
            ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE order_date " + dateFilter);
            
            while (rs.next()) {
                response.getWriter().println("Order #" + rs.getString("id"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchQuery = request.getParameter("q");
        String limit = request.getParameter("limit");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            
            // ruleid: java-sql-injection-ide
            ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE name LIKE '%" + searchQuery + 
                                           "%' OR description LIKE '%" + searchQuery + "%' LIMIT " + limit);
            
            while (rs.next()) {
                response.getWriter().println(rs.getString("name"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        String newEmail = request.getParameter("email");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            
            // ruleid: java-sql-injection-ide
            int updated = stmt.executeUpdate("UPDATE users SET email = '" + newEmail + "' WHERE id = " + userId);
            
            response.getWriter().println("Updated " + updated + " users");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String categoryId = request.getParameter("categoryId");
        String offset = request.getParameter("offset");
        String limit = request.getParameter("limit");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            
            String query = "SELECT * FROM products WHERE category_id = " + categoryId + 
                           " ORDER BY name LIMIT " + limit + " OFFSET " + offset;
            
            // ruleid: java-sql-injection-ide
            ResultSet rs = stmt.executeQuery(query);
            
            while (rs.next()) {
                response.getWriter().println(rs.getString("name"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String customQuery = request.getParameter("query");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            
            // ruleid: java-sql-injection-ide
            ResultSet rs = stmt.executeQuery(customQuery);
            
            while (rs.next()) {
                response.getWriter().println("Result found");
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe Code)

    protected void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            // ok: java-sql-injection-ide
            PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                response.getWriter().println("User found: " + rs.getString("name"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String productId = request.getParameter("productId");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            // ok: java-sql-injection-ide
            PreparedStatement pstmt = conn.prepareStatement("UPDATE products SET views = views + 1 WHERE id = ?");
            pstmt.setInt(1, Integer.parseInt(productId));
            int count = pstmt.executeUpdate();
            
            response.getWriter().println("Updated " + count + " records");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (NumberFormatException e) {
            response.getWriter().println("Invalid product ID");
        }
    }

    protected void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchTerm = request.getParameter("search");
        String category = request.getParameter("category");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            // ok: java-sql-injection-ide
            PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM products WHERE name LIKE ? AND category = ?");
            pstmt.setString(1, "%" + searchTerm + "%");
            pstmt.setString(2, category);
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                response.getWriter().println(rs.getString("name"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("id");
        String role = request.getParameter("role");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            // ok: java-sql-injection-ide
            PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ? AND role = ?");
            pstmt.setInt(1, Integer.parseInt(userId));
            pstmt.setString(2, role);
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                response.getWriter().println("Found user: " + rs.getString("username"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (NumberFormatException e) {
            response.getWriter().println("Invalid user ID");
        }
    }

    protected void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String sortColumn = request.getParameter("sort");
        String sortOrder = request.getParameter("order");
        
        // Validate sort column against allowed values
        String[] allowedColumns = {"name", "price", "date_added", "stock"};
        boolean validColumn = false;
        for (String allowed : allowedColumns) {
            if (allowed.equals(sortColumn)) {
                validColumn = true;
                break;
            }
        }
        
        // Validate sort order
        if (!"ASC".equalsIgnoreCase(sortOrder) && !"DESC".equalsIgnoreCase(sortOrder)) {
            sortOrder = "ASC"; // Default to ascending if invalid
        }
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            
            if (validColumn) {
                // ok: java-sql-injection-ide
                PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM products ORDER BY " + sortColumn + " " + sortOrder);
                ResultSet rs = pstmt.executeQuery();
                
                while (rs.next()) {
                    response.getWriter().println(rs.getString("name"));
                }
            } else {
                response.getWriter().println("Invalid sort column");
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String tableName = request.getParameter("table");
        
        // Whitelist approach for table names
        Map<String, String> allowedTables = new HashMap<>();
        allowedTables.put("products", "products");
        allowedTables.put("users", "users");
        allowedTables.put("orders", "orders");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            
            String validTableName = allowedTables.get(tableName);
            if (validTableName != null) {
                // ok: java-sql-injection-ide
                PreparedStatement pstmt = conn.prepareStatement("SELECT COUNT(*) FROM " + validTableName);
                ResultSet rs = pstmt.executeQuery();
                
                if (rs.next()) {
                    response.getWriter().println("Count: " + rs.getInt(1));
                }
            } else {
                response.getWriter().println("Invalid table name");
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        String action = request.getParameter("action");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            
            if ("delete".equals(action)) {
                // ok: java-sql-injection-ide
                PreparedStatement pstmt = conn.prepareStatement("DELETE FROM users WHERE id = ?");
                pstmt.setInt(1, Integer.parseInt(userId));
                pstmt.executeUpdate();
                response.getWriter().println("User deleted");
            } else if ("activate".equals(action)) {
                // ok: java-sql-injection-ide
                PreparedStatement pstmt = conn.prepareStatement("UPDATE users SET active = true WHERE id = ?");
                pstmt.setInt(1, Integer.parseInt(userId));
                pstmt.executeUpdate();
                response.getWriter().println("User activated");
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (NumberFormatException e) {
            response.getWriter().println("Invalid user ID");
        }
    }

    protected void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            
            // ok: java-sql-injection-ide
            PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ? AND password = ?");
            pstmt.setString(1, username);
            pstmt.setString(2, password);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                response.getWriter().println("Login successful");
            } else {
                response.getWriter().println("Login failed");
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String minPriceStr = request.getParameter("minPrice");
        String maxPriceStr = request.getParameter("maxPrice");
        
        try {
            double minPrice = Double.parseDouble(minPriceStr);
            double maxPrice = Double.parseDouble(maxPriceStr);
            
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            
            // ok: java-sql-injection-ide
            PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM products WHERE price BETWEEN ? AND ?");
            pstmt.setDouble(1, minPrice);
            pstmt.setDouble(2, maxPrice);
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                response.getWriter().println(rs.getString("name") + ": $" + rs.getDouble("price"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (NumberFormatException e) {
            response.getWriter().println("Invalid price values");
        }
    }

    protected void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String[] selectedIds = request.getParameterValues("selected");
        
        if (selectedIds != null && selectedIds.length > 0) {
            try {
                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
                
                StringBuilder placeholders = new StringBuilder();
                for (int i = 0; i < selectedIds.length; i++) {
                    if (i > 0) {
                        placeholders.append(",");
                    }
                    placeholders.append("?");
                }
                
                // ok: java-sql-injection-ide
                PreparedStatement pstmt = conn.prepareStatement(
                    "SELECT * FROM products WHERE id IN (" + placeholders.toString() + ")");
                
                for (int i = 0; i < selectedIds.length; i++) {
                    pstmt.setInt(i + 1, Integer.parseInt(selectedIds[i]));
                }
                
                ResultSet rs = pstmt.executeQuery();
                
                while (rs.next()) {
                    response.getWriter().println(rs.getString("name"));
                }
                conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            } catch (NumberFormatException e) {
                response.getWriter().println("Invalid ID format");
            }
        }
    }

    protected void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String dateFilter = request.getParameter("date");
        
        // Validate date filter against allowed values
        Map<String, String> allowedFilters = new HashMap<>();
        allowedFilters.put("today", "= CURRENT_DATE");
        allowedFilters.put("yesterday", "= CURRENT_DATE - INTERVAL 1 DAY");
        allowedFilters.put("last_week", ">= CURRENT_DATE - INTERVAL 7 DAY");
        allowedFilters.put("last_month", ">= CURRENT_DATE - INTERVAL 1 MONTH");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            
            String validFilter = allowedFilters.get(dateFilter);
            if (validFilter != null) {
                // ok: java-sql-injection-ide
                PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM orders WHERE order_date " + validFilter);
                ResultSet rs = pstmt.executeQuery();
                
                while (rs.next()) {
                    response.getWriter().println("Order #" + rs.getString("id"));
                }
            } else {
                response.getWriter().println("Invalid date filter");
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    protected void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchQuery = request.getParameter("q");
        String limitStr = request.getParameter("limit");
        
        try {
            int limit = Integer.parseInt(limitStr);
            if (limit <= 0 || limit > 100) {
                limit = 20; // Default limit if invalid
            }
            
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            
            // ok: java-sql-injection-ide
            PreparedStatement pstmt = conn.prepareStatement(
                "SELECT * FROM products WHERE name LIKE ? OR description LIKE ? LIMIT ?");
            pstmt.setString(1, "%" + searchQuery + "%");
            pstmt.setString(2, "%" + searchQuery + "%");
            pstmt.setInt(3, limit);
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                response.getWriter().println(rs.getString("name"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (NumberFormatException e) {
            response.getWriter().println("Invalid limit value");
        }
    }

    protected void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        String newEmail = request.getParameter("email");
        
        // Validate email format
        if (!Pattern.matches("^[A-Za-z0-9+_.-]+@(.+)$", newEmail)) {
            response.getWriter().println("Invalid email format");
            return;
        }
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            
            // ok: java-sql-injection-ide
            PreparedStatement pstmt = conn.prepareStatement("UPDATE users SET email = ? WHERE id = ?");
            pstmt.setString(1, newEmail);
            pstmt.setInt(2, Integer.parseInt(userId));
            int updated = pstmt.executeUpdate();
            
            response.getWriter().println("Updated " + updated + " users");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (NumberFormatException e) {
            response.getWriter().println("Invalid user ID");
        }
    }

    protected void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String categoryIdStr = request.getParameter("categoryId");
        String offsetStr = request.getParameter("offset");
        String limitStr = request.getParameter("limit");
        
        try {
            int categoryId = Integer.parseInt(categoryIdStr);
            int offset = Integer.parseInt(offsetStr);
            int limit = Integer.parseInt(limitStr);
            
            // Validate pagination parameters
            if (offset < 0) offset = 0;
            if (limit <= 0 || limit > 100) limit = 20;
            
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            
            // ok: java-sql-injection-ide
            PreparedStatement pstmt = conn.prepareStatement(
                "SELECT * FROM products WHERE category_id = ? ORDER BY name LIMIT ? OFFSET ?");
            pstmt.setInt(1, categoryId);
            pstmt.setInt(2, limit);
            pstmt.setInt(3, offset);
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                response.getWriter().println(rs.getString("name"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (NumberFormatException e) {
            response.getWriter().println("Invalid numeric parameters");
        }
    }

    protected void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Instead of allowing arbitrary queries, provide specific functionality
        String reportType = request.getParameter("reportType");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            PreparedStatement pstmt = null;
            
            switch (reportType) {
                case "daily_sales":
                    // ok: java-sql-injection-ide
                    pstmt = conn.prepareStatement(
                        "SELECT SUM(amount) FROM sales WHERE sale_date = CURRENT_DATE");
                    break;
                case "top_products":
                    // ok: java-sql-injection-ide
                    pstmt = conn.prepareStatement(
                        "SELECT product_name, SUM(quantity) as total FROM sales " +
                        "GROUP BY product_name ORDER BY total DESC LIMIT 10");
                    break;
                case "low_stock":
                    // ok: java-sql-injection-ide
                    pstmt = conn.prepareStatement(
                        "SELECT * FROM products WHERE stock < 10 ORDER BY stock ASC");
                    break;
                default:
                    response.getWriter().println("Invalid report type");
                    conn.close();
                    return;
            }
            
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                response.getWriter().println("Report data found");
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
// {/fact}