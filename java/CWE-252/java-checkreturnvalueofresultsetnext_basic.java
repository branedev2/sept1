import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class ResultSetNextCheckExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
    public void bad_case_1() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT username FROM users");
            
            // ruleid: java-checkreturnvalueofresultsetnext
            rs.next(); // Not checking return value
            String username = rs.getString("username"); // Potential NPE if no rows
            System.out.println("Username: " + username);
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void bad_case_2() {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            pstmt = conn.prepareStatement("SELECT id, name FROM products WHERE category = ?");
            pstmt.setString(1, "electronics");
            rs = pstmt.executeQuery();
            
            // ruleid: java-checkreturnvalueofresultsetnext
            rs.next(); // Not checking return value
            int id = rs.getInt("id");
            String name = rs.getString("name");
            System.out.println("Product: " + id + " - " + name);
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void bad_case_3() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT COUNT(*) as count FROM orders");
            
            // ruleid: java-checkreturnvalueofresultsetnext
            rs.next(); // Not checking return value
            int count = rs.getInt("count");
            System.out.println("Total orders: " + count);
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public List<String> bad_case_4() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        List<String> emails = new ArrayList<>();
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT email FROM subscribers");
            
            while (true) {
                // ruleid: java-checkreturnvalueofresultsetnext
                rs.next(); // Not checking return value in loop
                String email = rs.getString("email");
                emails.add(email);
            }
            
        } catch (SQLException e) {
            // Catching exception when no more rows
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
        
        return emails;
    }
    
    public void bad_case_5() {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            pstmt = conn.prepareStatement("SELECT balance FROM accounts WHERE user_id = ?");
            pstmt.setInt(1, 123);
            rs = pstmt.executeQuery();
            
            // ruleid: java-checkreturnvalueofresultsetnext
            rs.next(); // Not checking return value
            double balance = rs.getDouble("balance");
            if (balance > 1000) {
                System.out.println("High balance account");
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void bad_case_6() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT first_name, last_name FROM employees");
            
            for (int i = 0; i < 5; i++) {
                // ruleid: java-checkreturnvalueofresultsetnext
                rs.next(); // Not checking return value in fixed loop
                String firstName = rs.getString("first_name");
                String lastName = rs.getString("last_name");
                System.out.println(firstName + " " + lastName);
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void bad_case_7() {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            pstmt = conn.prepareStatement("SELECT * FROM logs WHERE timestamp > ?");
            pstmt.setLong(1, System.currentTimeMillis() - 86400000); // Last 24 hours
            rs = pstmt.executeQuery();
            
            do {
                // ruleid: java-checkreturnvalueofresultsetnext
                rs.next(); // Not checking return value in do-while loop
                String logEntry = rs.getString("message");
                System.out.println(logEntry);
            } while (!rs.isLast());
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void bad_case_8() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT product_name, price FROM products WHERE price > 100");
            
            // ruleid: java-checkreturnvalueofresultsetnext
            rs.next(); // Not checking return value
            String product = rs.getString(1); // Using column index instead of name
            double price = rs.getDouble(2);
            System.out.println("Expensive product: " + product + " costs $" + price);
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void bad_case_9() {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            pstmt = conn.prepareStatement("SELECT username, password FROM users WHERE id = ?");
            pstmt.setInt(1, 42);
            rs = pstmt.executeQuery();
            
            // ruleid: java-checkreturnvalueofresultsetnext
            rs.next(); // Not checking return value
            String username = rs.getString("username");
            String password = rs.getString("password");
            authenticateUser(username, password);
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void bad_case_10() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT config_value FROM system_config WHERE config_key = 'api_key'");
            
            // ruleid: java-checkreturnvalueofresultsetnext
            rs.next(); // Not checking return value
            String apiKey = rs.getString("config_value");
            initializeApiClient(apiKey);
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void bad_case_11() {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            pstmt = conn.prepareStatement("SELECT address FROM customers WHERE customer_id = ?");
            pstmt.setInt(1, 1001);
            rs = pstmt.executeQuery();
            
            // ruleid: java-checkreturnvalueofresultsetnext
            rs.next(); // Not checking return value
            String address = rs.getString("address");
            sendMailTo(address);
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void bad_case_12() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT permission FROM user_roles WHERE role_id = 5");
            
            // ruleid: java-checkreturnvalueofresultsetnext
            rs.next(); // Not checking return value
            boolean hasAdminAccess = rs.getBoolean("permission");
            grantAccess(hasAdminAccess);
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void bad_case_13() {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            pstmt = conn.prepareStatement("SELECT file_path FROM documents WHERE doc_id = ?");
            pstmt.setInt(1, 500);
            rs = pstmt.executeQuery();
            
            // ruleid: java-checkreturnvalueofresultsetnext
            rs.next(); // Not checking return value
            String filePath = rs.getString("file_path");
            loadDocument(filePath);
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void bad_case_14() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT url FROM redirects WHERE short_code = 'abc123'");
            
            // ruleid: java-checkreturnvalueofresultsetnext
            rs.next(); // Not checking return value
            String redirectUrl = rs.getString("url");
            performRedirect(redirectUrl);
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void bad_case_15() {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            pstmt = conn.prepareStatement("SELECT token FROM api_tokens WHERE app_id = ?");
            pstmt.setString(1, "my-app");
            rs = pstmt.executeQuery();
            
            // ruleid: java-checkreturnvalueofresultsetnext
            rs.next(); // Not checking return value
            String token = rs.getString("token");
            validateToken(token);
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    // True Negative Examples (Secure Code)
    
    public void good_case_1() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT username FROM users");
            
            // ok: java-checkreturnvalueofresultsetnext
            if (rs.next()) {
                String username = rs.getString("username");
                System.out.println("Username: " + username);
            } else {
                System.out.println("No users found");
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void good_case_2() {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            pstmt = conn.prepareStatement("SELECT id, name FROM products WHERE category = ?");
            pstmt.setString(1, "electronics");
            rs = pstmt.executeQuery();
            
            // ok: java-checkreturnvalueofresultsetnext
            while (rs.next()) {
                int id = rs.getInt("id");
                String name = rs.getString("name");
                System.out.println("Product: " + id + " - " + name);
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void good_case_3() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT COUNT(*) as count FROM orders");
            
            // ok: java-checkreturnvalueofresultsetnext
            if (rs.next()) {
                int count = rs.getInt("count");
                System.out.println("Total orders: " + count);
            } else {
                System.out.println("Error retrieving count");
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public List<String> good_case_4() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        List<String> emails = new ArrayList<>();
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT email FROM subscribers");
            
            // ok: java-checkreturnvalueofresultsetnext
            while (rs.next()) {
                String email = rs.getString("email");
                emails.add(email);
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
        
        return emails;
    }
    
    public void good_case_5() {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            pstmt = conn.prepareStatement("SELECT balance FROM accounts WHERE user_id = ?");
            pstmt.setInt(1, 123);
            rs = pstmt.executeQuery();
            
            // ok: java-checkreturnvalueofresultsetnext
            boolean hasResult = rs.next();
            if (hasResult) {
                double balance = rs.getDouble("balance");
                if (balance > 1000) {
                    System.out.println("High balance account");
                }
            } else {
                System.out.println("Account not found");
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void good_case_6() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT first_name, last_name FROM employees");
            
            int count = 0;
            // ok: java-checkreturnvalueofresultsetnext
            while (rs.next() && count < 5) {
                String firstName = rs.getString("first_name");
                String lastName = rs.getString("last_name");
                System.out.println(firstName + " " + lastName);
                count++;
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void good_case_7() {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            pstmt = conn.prepareStatement("SELECT * FROM logs WHERE timestamp > ?");
            pstmt.setLong(1, System.currentTimeMillis() - 86400000); // Last 24 hours
            rs = pstmt.executeQuery();
            
            // ok: java-checkreturnvalueofresultsetnext
            boolean hasMore = rs.next();
            while (hasMore) {
                String logEntry = rs.getString("message");
                System.out.println(logEntry);
                hasMore = rs.next();
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void good_case_8() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT product_name, price FROM products WHERE price > 100");
            
            // ok: java-checkreturnvalueofresultsetnext
            if (rs.next()) {
                String product = rs.getString(1); // Using column index instead of name
                double price = rs.getDouble(2);
                System.out.println("Expensive product: " + product + " costs $" + price);
            } else {
                System.out.println("No expensive products found");
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void good_case_9() {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            pstmt = conn.prepareStatement("SELECT username, password FROM users WHERE id = ?");
            pstmt.setInt(1, 42);
            rs = pstmt.executeQuery();
            
            // ok: java-checkreturnvalueofresultsetnext
            if (rs.next()) {
                String username = rs.getString("username");
                String password = rs.getString("password");
                authenticateUser(username, password);
            } else {
                System.out.println("User not found");
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void good_case_10() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT config_value FROM system_config WHERE config_key = 'api_key'");
            
            // ok: java-checkreturnvalueofresultsetnext
            boolean found = rs.next();
            if (found) {
                String apiKey = rs.getString("config_value");
                initializeApiClient(apiKey);
            } else {
                System.out.println("API key not configured");
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void good_case_11() {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            pstmt = conn.prepareStatement("SELECT address FROM customers WHERE customer_id = ?");
            pstmt.setInt(1, 1001);
            rs = pstmt.executeQuery();
            
            // ok: java-checkreturnvalueofresultsetnext
            boolean customerExists = rs.next();
            if (customerExists) {
                String address = rs.getString("address");
                sendMailTo(address);
            } else {
                System.out.println("Customer not found");
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void good_case_12() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT permission FROM user_roles WHERE role_id = 5");
            
            // ok: java-checkreturnvalueofresultsetnext
            if (rs.next()) {
                boolean hasAdminAccess = rs.getBoolean("permission");
                grantAccess(hasAdminAccess);
            } else {
                grantAccess(false); // Default to no access
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void good_case_13() {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            pstmt = conn.prepareStatement("SELECT file_path FROM documents WHERE doc_id = ?");
            pstmt.setInt(1, 500);
            rs = pstmt.executeQuery();
            
            // ok: java-checkreturnvalueofresultsetnext
            boolean documentExists = rs.next();
            if (documentExists) {
                String filePath = rs.getString("file_path");
                loadDocument(filePath);
            } else {
                System.out.println("Document not found");
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void good_case_14() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT url FROM redirects WHERE short_code = 'abc123'");
            
            // ok: java-checkreturnvalueofresultsetnext
            if (rs.next()) {
                String redirectUrl = rs.getString("url");
                performRedirect(redirectUrl);
            } else {
                System.out.println("Redirect not found");
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void good_case_15() {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            pstmt = conn.prepareStatement("SELECT token FROM api_tokens WHERE app_id = ?");
            pstmt.setString(1, "my-app");
            rs = pstmt.executeQuery();
            
            // ok: java-checkreturnvalueofresultsetnext
            boolean hasToken = rs.next();
            if (hasToken) {
                String token = rs.getString("token");
                validateToken(token);
            } else {
                System.out.println("No token found for application");
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (pstmt != null) pstmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    // Helper methods to make the examples compile
    private void authenticateUser(String username, String password) {
        // Authentication logic
    }
    
    private void initializeApiClient(String apiKey) {
        // API client initialization
    }
    
    private void sendMailTo(String address) {
        // Mail sending logic
    }
    
    private void grantAccess(boolean hasAccess) {
        // Access control logic
    }
    
    private void loadDocument(String filePath) {
        // Document loading logic
    }
    
    private void performRedirect(String url) {
        // Redirection logic
    }
    
    private void validateToken(String token) {
        // Token validation logic
    }
}
// {/fact}