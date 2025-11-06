import java.sql.*;
import javax.servlet.http.*;
import java.io.*;
import javax.servlet.*;
import java.util.*;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.OracleCodec;
import java.security.SecureRandom;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import org.apache.commons.text.StringEscapeUtils;
import java.util.logging.Logger;
import java.util.logging.Level;

public class SQLInjectionTestCases extends HttpServlet {
    private static final Logger logger = Logger.getLogger(SQLInjectionTestCases.class.getName());
    private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
    private static final String DB_USER = "user";
    private static final String DB_PASSWORD = "password";

    // True Positive Cases (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
    protected void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            
            // ruleid: java-sql-injection
            ResultSet rs = stmt.executeQuery(query);
            
            // Process results
            while (rs.next()) {
                response.getWriter().println("User found: " + rs.getString("username"));
            }
            
            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String productId = request.getParameter("productId");
        String category = request.getParameter("category");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM products WHERE id = " + productId + " AND category = '" + category + "'";
            
            // ruleid: java-sql-injection
            ResultSet rs = stmt.executeQuery(query);
            
            // Process results
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Product: " + rs.getString("name"));
            }
            
            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getHeader("X-User-Id");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            
            // ruleid: java-sql-injection
            stmt.executeUpdate("UPDATE users SET last_login = NOW() WHERE id = " + userId);
            
            stmt.close();
            conn.close();
            response.getWriter().println("User login time updated");
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchTerm = request.getParameter("search");
        String sortOrder = request.getParameter("sort");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%' ORDER BY price " + sortOrder;
            
            // ruleid: java-sql-injection
            ResultSet rs = stmt.executeQuery(query);
            
            // Process results
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Product: " + rs.getString("name") + " - $" + rs.getDouble("price"));
            }
            
            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String[] selectedIds = request.getParameterValues("selected");
        
        if (selectedIds != null && selectedIds.length > 0) {
            StringBuilder idList = new StringBuilder();
            for (String id : selectedIds) {
                if (idList.length() > 0) {
                    idList.append(",");
                }
                idList.append(id);
            }
            
            try {
                Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                Statement stmt = conn.createStatement();
                
                // ruleid: java-sql-injection
                stmt.executeUpdate("DELETE FROM cart_items WHERE id IN (" + idList.toString() + ")");
                
                stmt.close();
                conn.close();
                response.getWriter().println("Items removed from cart");
            } catch (SQLException e) {
                logger.log(Level.SEVERE, "Database error", e);
            }
        }
    }

    protected void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String tableName = request.getParameter("table");
        String column = request.getParameter("column");
        String value = request.getParameter("value");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM " + tableName + " WHERE " + column + " = '" + value + "'";
            
            // ruleid: java-sql-injection
            ResultSet rs = stmt.executeQuery(query);
            
            // Process results
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Result: " + rs.getString(1));
            }
            
            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Cookie[] cookies = request.getCookies();
        String userId = null;
        
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("user_id".equals(cookie.getName())) {
                    userId = cookie.getValue();
                    break;
                }
            }
        }
        
        if (userId != null) {
            try {
                Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                Statement stmt = conn.createStatement();
                
                // ruleid: java-sql-injection
                ResultSet rs = stmt.executeQuery("SELECT * FROM user_preferences WHERE user_id = " + userId);
                
                // Process results
                PrintWriter out = response.getWriter();
                while (rs.next()) {
                    out.println("Preference: " + rs.getString("preference_name") + " = " + rs.getString("preference_value"));
                }
                
                rs.close();
                stmt.close();
                conn.close();
            } catch (SQLException e) {
                logger.log(Level.SEVERE, "Database error", e);
            }
        }
    }

    protected void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            
            // ruleid: java-sql-injection
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'");
            
            if (rs.next()) {
                response.getWriter().println("Login successful");
            } else {
                response.getWriter().println("Login failed");
            }
            
            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String email = request.getParameter("email");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            
            // Concatenate user input directly into SQL query
            String query = "SELECT * FROM subscribers WHERE email LIKE '%" + email + "%'";
            
            // ruleid: java-sql-injection
            ResultSet rs = stmt.executeQuery(query);
            
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Subscriber: " + rs.getString("email"));
            }
            
            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String orderId = request.getParameter("orderId");
        String action = request.getParameter("action");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            
            String query = "UPDATE orders SET status = '" + action + "' WHERE id = " + orderId;
            
            // ruleid: java-sql-injection
            int rowsAffected = stmt.executeUpdate(query);
            
            response.getWriter().println("Updated " + rowsAffected + " orders");
            
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting multiple parameters and using them in a complex query
        String minPrice = request.getParameter("minPrice");
        String maxPrice = request.getParameter("maxPrice");
        String category = request.getParameter("category");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            
            String query = "SELECT * FROM products WHERE price BETWEEN " + minPrice + " AND " + maxPrice + 
                           " AND category = '" + category + "' ORDER BY price ASC";
            
            // ruleid: java-sql-injection
            ResultSet rs = stmt.executeQuery(query);
            
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Product: " + rs.getString("name") + " - $" + rs.getDouble("price"));
            }
            
            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using request attributes which could be set by another component
        String userId = (String) request.getAttribute("userId");
        
        if (userId == null) {
            userId = request.getParameter("userId");
        }
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            
            // ruleid: java-sql-injection
            ResultSet rs = stmt.executeQuery("SELECT * FROM user_roles WHERE user_id = " + userId);
            
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Role: " + rs.getString("role_name"));
            }
            
            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a StringBuilder to construct a query with user input
        String productName = request.getParameter("productName");
        String brand = request.getParameter("brand");
        
        StringBuilder queryBuilder = new StringBuilder("SELECT * FROM products WHERE 1=1");
        
        if (productName != null && !productName.isEmpty()) {
            queryBuilder.append(" AND product_name LIKE '%").append(productName).append("%'");
        }
        
        if (brand != null && !brand.isEmpty()) {
            queryBuilder.append(" AND brand = '").append(brand).append("'");
        }
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            
            // ruleid: java-sql-injection
            ResultSet rs = stmt.executeQuery(queryBuilder.toString());
            
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Product: " + rs.getString("product_name") + " by " + rs.getString("brand"));
            }
            
            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using string concatenation with a ternary operator
        String sortField = request.getParameter("sortField");
        String sortOrder = request.getParameter("sortOrder");
        
        // Default values if parameters are not provided
        sortField = (sortField != null) ? sortField : "name";
        sortOrder = (sortOrder != null && sortOrder.equalsIgnoreCase("DESC")) ? "DESC" : "ASC";
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            
            String query = "SELECT * FROM products ORDER BY " + sortField + " " + sortOrder;
            
            // ruleid: java-sql-injection
            ResultSet rs = stmt.executeQuery(query);
            
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Product: " + rs.getString("name"));
            }
            
            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using string formatting
        String userId = request.getParameter("userId");
        String limit = request.getParameter("limit");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            
            String query = String.format("SELECT * FROM user_orders WHERE user_id = %s ORDER BY order_date DESC LIMIT %s", userId, limit);
            
            // ruleid: java-sql-injection
            ResultSet rs = stmt.executeQuery(query);
            
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Order #" + rs.getString("order_id") + " - " + rs.getDate("order_date"));
            }
            
            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    // True Negative Cases (Safe Code)

    protected void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // ok: java-sql-injection
            PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
            pstmt.setString(1, username);
            
            ResultSet rs = pstmt.executeQuery();
            
            // Process results
            while (rs.next()) {
                response.getWriter().println("User found: " + rs.getString("username"));
            }
            
            rs.close();
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String productId = request.getParameter("productId");
        String category = request.getParameter("category");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // ok: java-sql-injection
            PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM products WHERE id = ? AND category = ?");
            pstmt.setString(1, productId);
            pstmt.setString(2, category);
            
            ResultSet rs = pstmt.executeQuery();
            
            // Process results
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Product: " + rs.getString("name"));
            }
            
            rs.close();
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getHeader("X-User-Id");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // ok: java-sql-injection
            PreparedStatement pstmt = conn.prepareStatement("UPDATE users SET last_login = NOW() WHERE id = ?");
            pstmt.setString(1, userId);
            
            pstmt.executeUpdate();
            
            pstmt.close();
            conn.close();
            response.getWriter().println("User login time updated");
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchTerm = request.getParameter("search");
        String sortOrder = request.getParameter("sort");
        
        // Validate sort order parameter
        if (!"ASC".equalsIgnoreCase(sortOrder) && !"DESC".equalsIgnoreCase(sortOrder)) {
            sortOrder = "ASC"; // Default to ascending if invalid
        }
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // ok: java-sql-injection
            PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM products WHERE name LIKE ? ORDER BY price " + sortOrder);
            pstmt.setString(1, "%" + searchTerm + "%");
            
            ResultSet rs = pstmt.executeQuery();
            
            // Process results
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Product: " + rs.getString("name") + " - $" + rs.getDouble("price"));
            }
            
            rs.close();
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String[] selectedIds = request.getParameterValues("selected");
        
        if (selectedIds != null && selectedIds.length > 0) {
            try {
                Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                
                // Create a prepared statement with the right number of placeholders
                StringBuilder placeholders = new StringBuilder();
                for (int i = 0; i < selectedIds.length; i++) {
                    if (i > 0) {
                        placeholders.append(",");
                    }
                    placeholders.append("?");
                }
                
                // ok: java-sql-injection
                PreparedStatement pstmt = conn.prepareStatement("DELETE FROM cart_items WHERE id IN (" + placeholders.toString() + ")");
                
                // Set all the parameters
                for (int i = 0; i < selectedIds.length; i++) {
                    pstmt.setString(i + 1, selectedIds[i]);
                }
                
                pstmt.executeUpdate();
                
                pstmt.close();
                conn.close();
                response.getWriter().println("Items removed from cart");
            } catch (SQLException e) {
                logger.log(Level.SEVERE, "Database error", e);
            }
        }
    }

    protected void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String tableName = request.getParameter("table");
        String column = request.getParameter("column");
        String value = request.getParameter("value");
        
        // Whitelist validation for table name and column
        Map<String, List<String>> allowedTables = new HashMap<>();
        allowedTables.put("products", Arrays.asList("id", "name", "category", "price"));
        allowedTables.put("categories", Arrays.asList("id", "name", "parent_id"));
        
        if (!allowedTables.containsKey(tableName) || !allowedTables.get(tableName).contains(column)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid table or column name");
            return;
        }
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // ok: java-sql-injection
            PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM " + tableName + " WHERE " + column + " = ?");
            pstmt.setString(1, value);
            
            ResultSet rs = pstmt.executeQuery();
            
            // Process results
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Result: " + rs.getString(1));
            }
            
            rs.close();
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Cookie[] cookies = request.getCookies();
        String userId = null;
        
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("user_id".equals(cookie.getName())) {
                    userId = cookie.getValue();
                    break;
                }
            }
        }
        
        if (userId != null) {
            try {
                Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                
                // ok: java-sql-injection
                PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM user_preferences WHERE user_id = ?");
                pstmt.setString(1, userId);
                
                ResultSet rs = pstmt.executeQuery();
                
                // Process results
                PrintWriter out = response.getWriter();
                while (rs.next()) {
                    out.println("Preference: " + rs.getString("preference_name") + " = " + rs.getString("preference_value"));
                }
                
                rs.close();
                pstmt.close();
                conn.close();
            } catch (SQLException e) {
                logger.log(Level.SEVERE, "Database error", e);
            }
        }
    }

    protected void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // ok: java-sql-injection
            PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ? AND password = ?");
            pstmt.setString(1, username);
            pstmt.setString(2, password); // Note: In a real app, passwords should be hashed
            
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                response.getWriter().println("Login successful");
            } else {
                response.getWriter().println("Login failed");
            }
            
            rs.close();
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String email = request.getParameter("email");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // ok: java-sql-injection
            PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM subscribers WHERE email LIKE ?");
            pstmt.setString(1, "%" + email + "%");
            
            ResultSet rs = pstmt.executeQuery();
            
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Subscriber: " + rs.getString("email"));
            }
            
            rs.close();
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String orderId = request.getParameter("orderId");
        String action = request.getParameter("action");
        
        // Validate action parameter
        List<String> validActions = Arrays.asList("processing", "shipped", "delivered", "cancelled");
        if (!validActions.contains(action)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid action");
            return;
        }
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // ok: java-sql-injection
            PreparedStatement pstmt = conn.prepareStatement("UPDATE orders SET status = ? WHERE id = ?");
            pstmt.setString(1, action);
            pstmt.setString(2, orderId);
            
            int rowsAffected = pstmt.executeUpdate();
            
            response.getWriter().println("Updated " + rowsAffected + " orders");
            
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting multiple parameters and using them in a complex query
        String minPrice = request.getParameter("minPrice");
        String maxPrice = request.getParameter("maxPrice");
        String category = request.getParameter("category");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // ok: java-sql-injection
            PreparedStatement pstmt = conn.prepareStatement(
                "SELECT * FROM products WHERE price BETWEEN ? AND ? AND category = ? ORDER BY price ASC");
            
            // Parse and validate numeric inputs
            double minPriceValue = 0.0;
            double maxPriceValue = Double.MAX_VALUE;
            
            try {
                if (minPrice != null && !minPrice.isEmpty()) {
                    minPriceValue = Double.parseDouble(minPrice);
                }
                if (maxPrice != null && !maxPrice.isEmpty()) {
                    maxPriceValue = Double.parseDouble(maxPrice);
                }
            } catch (NumberFormatException e) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid price values");
                return;
            }
            
            pstmt.setDouble(1, minPriceValue);
            pstmt.setDouble(2, maxPriceValue);
            pstmt.setString(3, category);
            
            ResultSet rs = pstmt.executeQuery();
            
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Product: " + rs.getString("name") + " - $" + rs.getDouble("price"));
            }
            
            rs.close();
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using request attributes which could be set by another component
        String userId = (String) request.getAttribute("userId");
        
        if (userId == null) {
            userId = request.getParameter("userId");
        }
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // ok: java-sql-injection
            PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM user_roles WHERE user_id = ?");
            pstmt.setString(1, userId);
            
            ResultSet rs = pstmt.executeQuery();
            
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Role: " + rs.getString("role_name"));
            }
            
            rs.close();
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using a StringBuilder to construct a query with user input but properly parameterized
        String productName = request.getParameter("productName");
        String brand = request.getParameter("brand");
        
        StringBuilder queryBuilder = new StringBuilder("SELECT * FROM products WHERE 1=1");
        List<Object> params = new ArrayList<>();
        
        if (productName != null && !productName.isEmpty()) {
            queryBuilder.append(" AND product_name LIKE ?");
            params.add("%" + productName + "%");
        }
        
        if (brand != null && !brand.isEmpty()) {
            queryBuilder.append(" AND brand = ?");
            params.add(brand);
        }
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // ok: java-sql-injection
            PreparedStatement pstmt = conn.prepareStatement(queryBuilder.toString());
            
            // Set all parameters
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            
            ResultSet rs = pstmt.executeQuery();
            
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Product: " + rs.getString("product_name") + " by " + rs.getString("brand"));
            }
            
            rs.close();
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using string concatenation with a ternary operator but with validation
        String sortField = request.getParameter("sortField");
        String sortOrder = request.getParameter("sortOrder");
        
        // Whitelist validation for sort field
        List<String> validSortFields = Arrays.asList("name", "price", "created_date", "category");
        if (sortField == null || !validSortFields.contains(sortField)) {
            sortField = "name"; // Default to name if invalid
        }
        
        // Validate sort order
        if (sortOrder == null || (!sortOrder.equalsIgnoreCase("ASC") && !sortOrder.equalsIgnoreCase("DESC"))) {
            sortOrder = "ASC"; // Default to ascending if invalid
        }
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // ok: java-sql-injection
            PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM products ORDER BY " + sortField + " " + sortOrder);
            
            ResultSet rs = pstmt.executeQuery();
            
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Product: " + rs.getString("name"));
            }
            
            rs.close();
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }

    protected void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using string formatting but with proper parameterization
        String userId = request.getParameter("userId");
        String limitStr = request.getParameter("limit");
        
        // Validate and parse limit
        int limit = 10; // Default value
        if (limitStr != null && !limitStr.isEmpty()) {
            try {
                limit = Integer.parseInt(limitStr);
                if (limit <= 0) {
                    limit = 10;
                } else if (limit > 100) {
                    limit = 100; // Cap the maximum limit
                }
            } catch (NumberFormatException e) {
                // Use default if parsing fails
            }
        }
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // ok: java-sql-injection
            PreparedStatement pstmt = conn.prepareStatement(
                "SELECT * FROM user_orders WHERE user_id = ? ORDER BY order_date DESC LIMIT ?");
            pstmt.setString(1, userId);
            pstmt.setInt(2, limit);
            
            ResultSet rs = pstmt.executeQuery();
            
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("Order #" + rs.getString("order_id") + " - " + rs.getDate("order_date"));
            }
            
            rs.close();
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
        }
    }
}
// {/fact}