import java.sql.*;
import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.annotation.WebServlet;
import java.util.regex.Pattern;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.OracleCodec;
import java.util.UUID;
import java.util.HashMap;
import java.util.Map;

public class SQLInjectionExamples {

    // True Positive Examples (Vulnerable Code)

    @WebServlet("/bad1")
    public class BadCase1 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userId = request.getParameter("id");
            Connection conn = null;
            Statement stmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "username", "password");
                stmt = conn.createStatement();
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("username"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/bad2")
    public class BadCase2 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String username = request.getParameter("username");
            Connection conn = null;
            Statement stmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "username", "password");
                stmt = conn.createStatement();
                String query = "SELECT * FROM users WHERE username = '" + username + "'";
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery(query);
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("email"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/bad3")
    public class BadCase3 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String sortColumn = request.getParameter("sort");
            Connection conn = null;
            Statement stmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/products", "username", "password");
                stmt = conn.createStatement();
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery("SELECT * FROM products ORDER BY " + sortColumn);
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("name"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/bad4")
    public class BadCase4 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String searchTerm = request.getParameter("search");
            Connection conn = null;
            Statement stmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/products", "username", "password");
                stmt = conn.createStatement();
                String query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery(query);
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("name"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/bad5")
    public class BadCase5 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String category = request.getParameter("category");
            String minPrice = request.getParameter("minPrice");
            Connection conn = null;
            Statement stmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/products", "username", "password");
                stmt = conn.createStatement();
                String query = "SELECT * FROM products WHERE category = '" + category + "' AND price > " + minPrice;
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery(query);
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("name"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/bad6")
    public class BadCase6 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userId = request.getParameter("userId");
            String newEmail = request.getParameter("email");
            Connection conn = null;
            Statement stmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "username", "password");
                stmt = conn.createStatement();
                String query = "UPDATE users SET email = '" + newEmail + "' WHERE id = " + userId;
                // ruleid: java-sql-injection-ide
                int rowsAffected = stmt.executeUpdate(query);
                
                response.getWriter().println(rowsAffected + " rows updated");
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/bad7")
    public class BadCase7 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String table = request.getParameter("table");
            Connection conn = null;
            Statement stmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/database", "username", "password");
                stmt = conn.createStatement();
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM " + table);
                
                if (rs.next()) {
                    response.getWriter().println("Count: " + rs.getInt(1));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/bad8")
    public class BadCase8 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String productId = request.getParameter("productId");
            String userId = request.getParameter("userId");
            Connection conn = null;
            Statement stmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/shop", "username", "password");
                stmt = conn.createStatement();
                String query = "INSERT INTO cart (user_id, product_id) VALUES (" + userId + ", " + productId + ")";
                // ruleid: java-sql-injection-ide
                int rowsAffected = stmt.executeUpdate(query);
                
                response.getWriter().println(rowsAffected + " product added to cart");
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/bad9")
    public class BadCase9 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String header = request.getHeader("X-User-ID");
            Connection conn = null;
            Statement stmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "username", "password");
                stmt = conn.createStatement();
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + header);
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("username"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/bad10")
    public class BadCase10 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String cookie = request.getCookies()[0].getValue();
            Connection conn = null;
            Statement stmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/sessions", "username", "password");
                stmt = conn.createStatement();
                String query = "SELECT * FROM sessions WHERE token = '" + cookie + "'";
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery(query);
                
                // Process results
                if (rs.next()) {
                    response.getWriter().println("Session found");
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/bad11")
    public class BadCase11 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String[] ids = request.getParameterValues("ids");
            StringBuilder idList = new StringBuilder();
            
            for (String id : ids) {
                if (idList.length() > 0) {
                    idList.append(",");
                }
                idList.append(id);
            }
            
            Connection conn = null;
            Statement stmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/products", "username", "password");
                stmt = conn.createStatement();
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE id IN (" + idList.toString() + ")");
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("name"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/bad12")
    public class BadCase12 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String tableName = request.getParameter("table");
            String columnName = request.getParameter("column");
            String value = request.getParameter("value");
            
            Connection conn = null;
            Statement stmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/database", "username", "password");
                stmt = conn.createStatement();
                String query = "SELECT * FROM " + tableName + " WHERE " + columnName + " = '" + value + "'";
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery(query);
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println("Record found");
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/bad13")
    public class BadCase13 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userId = request.getParameter("id");
            String role = request.getParameter("role");
            
            Connection conn = null;
            Statement stmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "username", "password");
                stmt = conn.createStatement();
                
                // Attempt to sanitize by checking role, but still vulnerable
                if (role.equals("admin") || role.equals("user")) {
                    String query = "SELECT * FROM users WHERE id = " + userId + " AND role = '" + role + "'";
                    // ruleid: java-sql-injection-ide
                    ResultSet rs = stmt.executeQuery(query);
                    
                    // Process results
                    while (rs.next()) {
                        response.getWriter().println(rs.getString("username"));
                    }
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/bad14")
    public class BadCase14 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            Map<String, String[]> paramMap = request.getParameterMap();
            String username = paramMap.get("username")[0];
            
            Connection conn = null;
            Statement stmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "username", "password");
                stmt = conn.createStatement();
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("email"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/bad15")
    public class BadCase15 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String query = request.getQueryString();
            String[] parts = query.split("=");
            String userId = parts.length > 1 ? parts[1] : "";
            
            Connection conn = null;
            Statement stmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "username", "password");
                stmt = conn.createStatement();
                // ruleid: java-sql-injection-ide
                ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("username"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    // True Negative Examples (Safe Code)

    @WebServlet("/good1")
    public class GoodCase1 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userId = request.getParameter("id");
            Connection conn = null;
            PreparedStatement pstmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "username", "password");
                // ok: java-sql-injection-ide
                pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
                pstmt.setString(1, userId);
                ResultSet rs = pstmt.executeQuery();
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("username"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/good2")
    public class GoodCase2 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String username = request.getParameter("username");
            Connection conn = null;
            PreparedStatement pstmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "username", "password");
                // ok: java-sql-injection-ide
                pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
                pstmt.setString(1, username);
                ResultSet rs = pstmt.executeQuery();
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("email"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/good3")
    public class GoodCase3 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String sortColumn = request.getParameter("sort");
            Connection conn = null;
            PreparedStatement pstmt = null;
            
            // Validate input against a whitelist of allowed columns
            Map<String, String> allowedColumns = new HashMap<>();
            allowedColumns.put("name", "name");
            allowedColumns.put("price", "price");
            allowedColumns.put("date", "created_date");
            
            String actualColumn = allowedColumns.getOrDefault(sortColumn, "name");
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/products", "username", "password");
                // ok: java-sql-injection-ide
                pstmt = conn.prepareStatement("SELECT * FROM products ORDER BY " + actualColumn);
                ResultSet rs = pstmt.executeQuery();
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("name"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/good4")
    public class GoodCase4 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String searchTerm = request.getParameter("search");
            Connection conn = null;
            PreparedStatement pstmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/products", "username", "password");
                // ok: java-sql-injection-ide
                pstmt = conn.prepareStatement("SELECT * FROM products WHERE name LIKE ?");
                pstmt.setString(1, "%" + searchTerm + "%");
                ResultSet rs = pstmt.executeQuery();
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("name"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/good5")
    public class GoodCase5 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String category = request.getParameter("category");
            String minPriceStr = request.getParameter("minPrice");
            double minPrice = 0.0;
            
            try {
                minPrice = Double.parseDouble(minPriceStr);
            } catch (NumberFormatException e) {
                // Default to 0 if not a valid number
                minPrice = 0.0;
            }
            
            Connection conn = null;
            PreparedStatement pstmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/products", "username", "password");
                // ok: java-sql-injection-ide
                pstmt = conn.prepareStatement("SELECT * FROM products WHERE category = ? AND price > ?");
                pstmt.setString(1, category);
                pstmt.setDouble(2, minPrice);
                ResultSet rs = pstmt.executeQuery();
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("name"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/good6")
    public class GoodCase6 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userIdStr = request.getParameter("userId");
            String newEmail = request.getParameter("email");
            int userId = 0;
            
            try {
                userId = Integer.parseInt(userIdStr);
            } catch (NumberFormatException e) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid user ID");
                return;
            }
            
            Connection conn = null;
            PreparedStatement pstmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "username", "password");
                // ok: java-sql-injection-ide
                pstmt = conn.prepareStatement("UPDATE users SET email = ? WHERE id = ?");
                pstmt.setString(1, newEmail);
                pstmt.setInt(2, userId);
                int rowsAffected = pstmt.executeUpdate();
                
                response.getWriter().println(rowsAffected + " rows updated");
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/good7")
    public class GoodCase7 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String table = request.getParameter("table");
            
            // Whitelist validation for table names
            Map<String, String> allowedTables = new HashMap<>();
            allowedTables.put("users", "users");
            allowedTables.put("products", "products");
            allowedTables.put("orders", "orders");
            
            if (!allowedTables.containsKey(table)) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid table name");
                return;
            }
            
            String actualTable = allowedTables.get(table);
            Connection conn = null;
            PreparedStatement pstmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/database", "username", "password");
                // ok: java-sql-injection-ide
                pstmt = conn.prepareStatement("SELECT COUNT(*) FROM " + actualTable);
                ResultSet rs = pstmt.executeQuery();
                
                if (rs.next()) {
                    response.getWriter().println("Count: " + rs.getInt(1));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/good8")
    public class GoodCase8 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String productIdStr = request.getParameter("productId");
            String userIdStr = request.getParameter("userId");
            int productId = 0;
            int userId = 0;
            
            try {
                productId = Integer.parseInt(productIdStr);
                userId = Integer.parseInt(userIdStr);
            } catch (NumberFormatException e) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid ID format");
                return;
            }
            
            Connection conn = null;
            PreparedStatement pstmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/shop", "username", "password");
                // ok: java-sql-injection-ide
                pstmt = conn.prepareStatement("INSERT INTO cart (user_id, product_id) VALUES (?, ?)");
                pstmt.setInt(1, userId);
                pstmt.setInt(2, productId);
                int rowsAffected = pstmt.executeUpdate();
                
                response.getWriter().println(rowsAffected + " product added to cart");
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/good9")
    public class GoodCase9 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String header = request.getHeader("X-User-ID");
            int userId = 0;
            
            try {
                userId = Integer.parseInt(header);
            } catch (NumberFormatException e) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid user ID in header");
                return;
            }
            
            Connection conn = null;
            PreparedStatement pstmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "username", "password");
                // ok: java-sql-injection-ide
                pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
                pstmt.setInt(1, userId);
                ResultSet rs = pstmt.executeQuery();
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("username"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/good10")
    public class GoodCase10 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            Cookie[] cookies = request.getCookies();
            String cookieValue = "";
            
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("sessionToken".equals(cookie.getName())) {
                        cookieValue = cookie.getValue();
                        break;
                    }
                }
            }
            
            Connection conn = null;
            PreparedStatement pstmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/sessions", "username", "password");
                // ok: java-sql-injection-ide
                pstmt = conn.prepareStatement("SELECT * FROM sessions WHERE token = ?");
                pstmt.setString(1, cookieValue);
                ResultSet rs = pstmt.executeQuery();
                
                // Process results
                if (rs.next()) {
                    response.getWriter().println("Session found");
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/good11")
    public class GoodCase11 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String[] ids = request.getParameterValues("ids");
            Connection conn = null;
            PreparedStatement pstmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/products", "username", "password");
                
                // Create a prepared statement with the right number of placeholders
                StringBuilder placeholders = new StringBuilder();
                for (int i = 0; i < ids.length; i++) {
                    if (i > 0) {
                        placeholders.append(",");
                    }
                    placeholders.append("?");
                }
                
                // ok: java-sql-injection-ide
                pstmt = conn.prepareStatement("SELECT * FROM products WHERE id IN (" + placeholders.toString() + ")");
                
                // Set all parameters
                for (int i = 0; i < ids.length; i++) {
                    pstmt.setString(i + 1, ids[i]);
                }
                
                ResultSet rs = pstmt.executeQuery();
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("name"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/good12")
    public class GoodCase12 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String tableName = request.getParameter("table");
            String columnName = request.getParameter("column");
            String value = request.getParameter("value");
            
            // Whitelist validation for table and column names
            Map<String, String[]> allowedTablesAndColumns = new HashMap<>();
            allowedTablesAndColumns.put("users", new String[]{"id", "username", "email"});
            allowedTablesAndColumns.put("products", new String[]{"id", "name", "price"});
            
            if (!allowedTablesAndColumns.containsKey(tableName)) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid table name");
                return;
            }
            
            boolean validColumn = false;
            for (String col : allowedTablesAndColumns.get(tableName)) {
                if (col.equals(columnName)) {
                    validColumn = true;
                    break;
                }
            }
            
            if (!validColumn) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid column name");
                return;
            }
            
            Connection conn = null;
            PreparedStatement pstmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/database", "username", "password");
                // ok: java-sql-injection-ide
                pstmt = conn.prepareStatement("SELECT * FROM " + tableName + " WHERE " + columnName + " = ?");
                pstmt.setString(1, value);
                ResultSet rs = pstmt.executeQuery();
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println("Record found");
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/good13")
    public class GoodCase13 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userIdStr = request.getParameter("id");
            String role = request.getParameter("role");
            int userId = 0;
            
            try {
                userId = Integer.parseInt(userIdStr);
            } catch (NumberFormatException e) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid user ID");
                return;
            }
            
            // Validate role input
            if (!"admin".equals(role) && !"user".equals(role)) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid role");
                return;
            }
            
            Connection conn = null;
            PreparedStatement pstmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "username", "password");
                // ok: java-sql-injection-ide
                pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ? AND role = ?");
                pstmt.setInt(1, userId);
                pstmt.setString(2, role);
                ResultSet rs = pstmt.executeQuery();
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("username"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/good14")
    public class GoodCase14 extends HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            Map<String, String[]> paramMap = request.getParameterMap();
            String username = "";
            
            if (paramMap.containsKey("username") && paramMap.get("username").length > 0) {
                username = paramMap.get("username")[0];
            }
            
            Connection conn = null;
            PreparedStatement pstmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "username", "password");
                // ok: java-sql-injection-ide
                pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
                pstmt.setString(1, username);
                ResultSet rs = pstmt.executeQuery();
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("email"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }

    @WebServlet("/good15")
    public class GoodCase15 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String query = request.getQueryString();
            String userId = "";
            
            if (query != null && query.startsWith("id=")) {
                userId = query.substring(3);
            }
            
            // Validate userId is numeric
            if (!userId.matches("^\\d+$")) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid user ID");
                return;
            }
            
            Connection conn = null;
            PreparedStatement pstmt = null;
            
            try {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "username", "password");
                // ok: java-sql-injection-ide
                pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
                pstmt.setString(1, userId);
                ResultSet rs = pstmt.executeQuery();
                
                // Process results
                while (rs.next()) {
                    response.getWriter().println(rs.getString("username"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            } finally {
                try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
                try { if (conn != null) conn.close(); } catch (SQLException e) {}
            }
        }
    }
}