import java.sql.*;
import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.regex.Pattern;
import java.util.UUID;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.OracleCodec;
import org.apache.commons.lang3.StringEscapeUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import javax.sql.DataSource;
import java.util.Properties;
import java.util.Map;
import java.util.HashMap;

public class SQLInjectionExamples extends HttpServlet {

    // True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String userId = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        
        // ruleid: java-sql-injection-exp
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("username"));
        }
        conn.close();
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String username = request.getParameter("username");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // ruleid: java-sql-injection-exp
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE username LIKE '%" + username + "%'");
        ResultSet rs = ps.executeQuery();
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("email"));
        }
        conn.close();
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String category = request.getParameter("category");
        String minPrice = request.getParameter("minPrice");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        
        String query = "SELECT * FROM products WHERE category = '" + category + "'";
        if (minPrice != null && !minPrice.isEmpty()) {
            query += " AND price > " + minPrice;
        }
        
        // ruleid: java-sql-injection-exp
        ResultSet rs = stmt.executeQuery(query);
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("name"));
        }
        conn.close();
    }

    @RequestMapping("/search")
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String searchTerm = request.getHeader("X-Search-Term");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        
        // ruleid: java-sql-injection-exp
        ResultSet rs = stmt.executeQuery("SELECT * FROM articles WHERE title LIKE '%" + searchTerm + "%' OR content LIKE '%" + searchTerm + "%'");
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("title"));
        }
        conn.close();
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String[] ids = request.getParameterValues("ids");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        
        StringBuilder query = new StringBuilder("SELECT * FROM products WHERE id IN (");
        for (int i = 0; i < ids.length; i++) {
            query.append(ids[i]);
            if (i < ids.length - 1) {
                query.append(",");
            }
        }
        query.append(")");
        
        // ruleid: java-sql-injection-exp
        ResultSet rs = stmt.executeQuery(query.toString());
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("name"));
        }
        conn.close();
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String sortColumn = request.getParameter("sort");
        String sortOrder = request.getParameter("order");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        
        // ruleid: java-sql-injection-exp
        ResultSet rs = stmt.executeQuery("SELECT * FROM products ORDER BY " + sortColumn + " " + sortOrder);
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("name"));
        }
        conn.close();
    }

    @PostMapping("/filter")
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String dateFrom = request.getParameter("dateFrom");
        String dateTo = request.getParameter("dateTo");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        
        // ruleid: java-sql-injection-exp
        ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE order_date BETWEEN '" + dateFrom + "' AND '" + dateTo + "'");
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("order_id"));
        }
        conn.close();
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String userId = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        String query = "SELECT * FROM users WHERE id = " + userId;
        Statement stmt = conn.createStatement();
        
        // ruleid: java-sql-injection-exp
        stmt.execute(query);
        ResultSet rs = stmt.getResultSet();
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("username"));
        }
        conn.close();
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        Cookie[] cookies = request.getCookies();
        String userFilter = null;
        
        for (Cookie cookie : cookies) {
            if ("userFilter".equals(cookie.getName())) {
                userFilter = cookie.getValue();
                break;
            }
        }
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        
        // ruleid: java-sql-injection-exp
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE role = '" + userFilter + "'");
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("username"));
        }
        conn.close();
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String tableName = request.getParameter("table");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        
        // ruleid: java-sql-injection-exp
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM " + tableName);
        
        if (rs.next()) {
            response.getWriter().println("Count: " + rs.getInt(1));
        }
        conn.close();
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String userId = request.getParameter("id");
        DataSource dataSource = getDataSource(); // Assume this method returns a DataSource
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        
        // ruleid: java-sql-injection-exp
        Map<String, Object> result = jdbcTemplate.queryForMap("SELECT * FROM users WHERE id = " + userId);
        
        response.getWriter().println("Username: " + result.get("username"));
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String searchTerm = request.getParameter("search");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        String processedTerm = searchTerm.replace("'", "''"); // Incomplete sanitization
        
        // ruleid: java-sql-injection-exp
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM products WHERE description LIKE '%" + processedTerm + "%'");
        ResultSet rs = ps.executeQuery();
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("name"));
        }
        conn.close();
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String userId = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        try {
            int id = Integer.parseInt(userId); // Attempt to sanitize, but doesn't use the sanitized value
        } catch (NumberFormatException e) {
            // Log error
        }
        
        // ruleid: java-sql-injection-exp
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("username"));
        }
        conn.close();
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        Map<String, String[]> paramMap = request.getParameterMap();
        String[] categoryValues = paramMap.get("category");
        String category = categoryValues != null && categoryValues.length > 0 ? categoryValues[0] : "";
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        
        // ruleid: java-sql-injection-exp
        ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE category = '" + category + "'");
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("name"));
        }
        conn.close();
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String limit = request.getParameter("limit");
        String offset = request.getParameter("offset");
        
        if (limit == null || limit.isEmpty()) {
            limit = "10"; // Default value
        }
        
        if (offset == null || offset.isEmpty()) {
            offset = "0"; // Default value
        }
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        
        // ruleid: java-sql-injection-exp
        ResultSet rs = stmt.executeQuery("SELECT * FROM products LIMIT " + limit + " OFFSET " + offset);
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("name"));
        }
        conn.close();
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String userId = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // ok: java-sql-injection-exp
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, userId);
        ResultSet rs = ps.executeQuery();
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("username"));
        }
        conn.close();
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String username = request.getParameter("username");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // ok: java-sql-injection-exp
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE username LIKE ?");
        ps.setString(1, "%" + username + "%");
        ResultSet rs = ps.executeQuery();
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("email"));
        }
        conn.close();
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String category = request.getParameter("category");
        String minPriceStr = request.getParameter("minPrice");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        StringBuilder queryBuilder = new StringBuilder("SELECT * FROM products WHERE category = ?");
        if (minPriceStr != null && !minPriceStr.isEmpty()) {
            queryBuilder.append(" AND price > ?");
        }
        
        // ok: java-sql-injection-exp
        PreparedStatement ps = conn.prepareStatement(queryBuilder.toString());
        ps.setString(1, category);
        
        if (minPriceStr != null && !minPriceStr.isEmpty()) {
            try {
                double minPrice = Double.parseDouble(minPriceStr);
                ps.setDouble(2, minPrice);
            } catch (NumberFormatException e) {
                ps.setDouble(2, 0.0);
            }
        }
        
        ResultSet rs = ps.executeQuery();
        while (rs.next()) {
            response.getWriter().println(rs.getString("name"));
        }
        conn.close();
    }

    @RequestMapping("/search")
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String searchTerm = request.getHeader("X-Search-Term");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // ok: java-sql-injection-exp
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM articles WHERE title LIKE ? OR content LIKE ?");
        ps.setString(1, "%" + searchTerm + "%");
        ps.setString(2, "%" + searchTerm + "%");
        ResultSet rs = ps.executeQuery();
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("title"));
        }
        conn.close();
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String[] idStrings = request.getParameterValues("ids");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        StringBuilder placeholders = new StringBuilder();
        for (int i = 0; i < idStrings.length; i++) {
            placeholders.append("?");
            if (i < idStrings.length - 1) {
                placeholders.append(",");
            }
        }
        
        // ok: java-sql-injection-exp
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM products WHERE id IN (" + placeholders.toString() + ")");
        
        for (int i = 0; i < idStrings.length; i++) {
            try {
                int id = Integer.parseInt(idStrings[i]);
                ps.setInt(i + 1, id);
            } catch (NumberFormatException e) {
                ps.setInt(i + 1, 0);
            }
        }
        
        ResultSet rs = ps.executeQuery();
        while (rs.next()) {
            response.getWriter().println(rs.getString("name"));
        }
        conn.close();
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String sortColumn = request.getParameter("sort");
        String sortOrder = request.getParameter("order");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // Validate sort column against allowed values
        Map<String, String> allowedColumns = new HashMap<>();
        allowedColumns.put("name", "name");
        allowedColumns.put("price", "price");
        allowedColumns.put("date", "creation_date");
        
        String validatedColumn = allowedColumns.getOrDefault(sortColumn, "name");
        
        // Validate sort order
        String validatedOrder = "ASC";
        if ("DESC".equalsIgnoreCase(sortOrder)) {
            validatedOrder = "DESC";
        }
        
        // ok: java-sql-injection-exp
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM products ORDER BY " + validatedColumn + " " + validatedOrder);
        ResultSet rs = ps.executeQuery();
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("name"));
        }
        conn.close();
    }

    @PostMapping("/filter")
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String dateFrom = request.getParameter("dateFrom");
        String dateTo = request.getParameter("dateTo");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // ok: java-sql-injection-exp
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM orders WHERE order_date BETWEEN ? AND ?");
        ps.setString(1, dateFrom);
        ps.setString(2, dateTo);
        ResultSet rs = ps.executeQuery();
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("order_id"));
        }
        conn.close();
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String userId = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        try {
            int id = Integer.parseInt(userId);
            
            // ok: java-sql-injection-exp
            PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
            ps.setInt(1, id);
            ResultSet rs = ps.executeQuery();
            
            while (rs.next()) {
                response.getWriter().println(rs.getString("username"));
            }
        } catch (NumberFormatException e) {
            response.getWriter().println("Invalid ID format");
        } finally {
            conn.close();
        }
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        Cookie[] cookies = request.getCookies();
        String userFilter = null;
        
        for (Cookie cookie : cookies) {
            if ("userFilter".equals(cookie.getName())) {
                userFilter = cookie.getValue();
                break;
            }
        }
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // Validate against allowed values
        String[] allowedRoles = {"admin", "user", "guest"};
        boolean isValidRole = false;
        for (String role : allowedRoles) {
            if (role.equals(userFilter)) {
                isValidRole = true;
                break;
            }
        }
        
        if (!isValidRole) {
            userFilter = "guest"; // Default to safe value
        }
        
        // ok: java-sql-injection-exp
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE role = ?");
        ps.setString(1, userFilter);
        ResultSet rs = ps.executeQuery();
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("username"));
        }
        conn.close();
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String tableName = request.getParameter("table");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // Whitelist validation
        Map<String, String> allowedTables = new HashMap<>();
        allowedTables.put("products", "products");
        allowedTables.put("users", "users");
        allowedTables.put("orders", "orders");
        
        String validatedTable = allowedTables.get(tableName);
        if (validatedTable == null) {
            response.getWriter().println("Invalid table name");
            conn.close();
            return;
        }
        
        // ok: java-sql-injection-exp
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM " + validatedTable);
        
        if (rs.next()) {
            response.getWriter().println("Count: " + rs.getInt(1));
        }
        conn.close();
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String userId = request.getParameter("id");
        DataSource dataSource = getDataSource(); // Assume this method returns a DataSource
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        
        // ok: java-sql-injection-exp
        Map<String, Object> result = jdbcTemplate.queryForMap("SELECT * FROM users WHERE id = ?", userId);
        
        response.getWriter().println("Username: " + result.get("username"));
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String searchTerm = request.getParameter("search");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // Using ESAPI for proper escaping
        String escapedTerm = ESAPI.encoder().encodeForSQL(new OracleCodec(), searchTerm);
        
        // ok: java-sql-injection-exp
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE description LIKE '%" + escapedTerm + "%'");
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("name"));
        }
        conn.close();
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String userId = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // Input validation with regex pattern
        Pattern pattern = Pattern.compile("^[0-9]+$");
        if (!pattern.matcher(userId).matches()) {
            response.getWriter().println("Invalid ID format");
            conn.close();
            return;
        }
        
        // ok: java-sql-injection-exp
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("username"));
        }
        conn.close();
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        Map<String, String[]> paramMap = request.getParameterMap();
        String[] categoryValues = paramMap.get("category");
        String category = categoryValues != null && categoryValues.length > 0 ? categoryValues[0] : "";
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // ok: java-sql-injection-exp
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM products WHERE category = ?");
        ps.setString(1, category);
        ResultSet rs = ps.executeQuery();
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("name"));
        }
        conn.close();
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, SQLException {
        String limitStr = request.getParameter("limit");
        String offsetStr = request.getParameter("offset");
        
        int limit = 10; // Default value
        int offset = 0; // Default value
        
        try {
            if (limitStr != null && !limitStr.isEmpty()) {
                limit = Integer.parseInt(limitStr);
                if (limit < 0 || limit > 100) {
                    limit = 10; // Enforce reasonable limits
                }
            }
            
            if (offsetStr != null && !offsetStr.isEmpty()) {
                offset = Integer.parseInt(offsetStr);
                if (offset < 0) {
                    offset = 0;
                }
            }
        } catch (NumberFormatException e) {
            // Use default values
        }
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // ok: java-sql-injection-exp
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM products LIMIT ? OFFSET ?");
        ps.setInt(1, limit);
        ps.setInt(2, offset);
        ResultSet rs = ps.executeQuery();
        
        while (rs.next()) {
            response.getWriter().println(rs.getString("name"));
        }
        conn.close();
    }

    // Helper method
    private DataSource getDataSource() {
        // Implementation would return a properly configured DataSource
        return null;
    }
}
// {/fact}