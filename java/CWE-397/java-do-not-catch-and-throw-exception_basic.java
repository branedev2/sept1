import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Logger;
import java.util.logging.Level;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URL;
import java.net.HttpURLConnection;
import java.util.Properties;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.Message;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.InternetAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CatchAndThrowExceptionExamples {
    private static final Logger logger = Logger.getLogger(CatchAndThrowExceptionExamples.class.getName());
    
    // TRUE POSITIVES - Vulnerable code examples
    
// {fact rule=do-not-catch-and-throw-exception@v1.0 defects=1}
    public void bad_case_1() {
        try {
            FileInputStream fis = new FileInputStream("config.properties");
            // Some file operations
            fis.close();
        } catch (IOException e) {
            // ruleid: java-do-not-catch-and-throw-exception
            throw e; // Simply re-throwing the exception without any additional operations
        }
    }
    
    public void bad_case_2() {
        Connection conn = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "password");
            // Database operations
        } catch (SQLException e) {
            // ruleid: java-do-not-catch-and-throw-exception
            throw e; // Re-throwing without adding context or handling
        } finally {
            try {
                if (conn != null) conn.close();
            } catch (SQLException e) {
                // Ignored
            }
        }
    }
    
    public void bad_case_3(HttpServletRequest request) {
        try {
            String username = request.getParameter("username");
            validateUser(username);
        } catch (IllegalArgumentException e) {
            // ruleid: java-do-not-catch-and-throw-exception
            throw e; // Simply re-throwing the caught exception
        }
    }
    
    public void bad_case_4() {
        try {
            URL url = new URL("https://api.example.com/data");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            // Process response
        } catch (IOException e) {
            // ruleid: java-do-not-catch-and-throw-exception
            throw e; // Re-throwing without any additional information
        }
    }
    
    public void bad_case_5() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // Hash operations
        } catch (NoSuchAlgorithmException e) {
            // ruleid: java-do-not-catch-and-throw-exception
            throw e; // Simply re-throwing
        }
    }
    
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) {
        try {
            String action = request.getParameter("action");
            if ("delete".equals(action)) {
                deleteUser(request.getParameter("userId"));
            }
        } catch (Exception e) {
            // ruleid: java-do-not-catch-and-throw-exception
            throw e; // Re-throwing a generic exception without context
        }
    }
    
    public void bad_case_7() {
        try {
            Properties props = new Properties();
            props.put("mail.smtp.host", "smtp.example.com");
            Session session = Session.getDefaultInstance(props, null);
            // Email operations
        } catch (Exception e) {
            // ruleid: java-do-not-catch-and-throw-exception
            throw e; // Simply re-throwing the exception
        }
    }
    
    public void bad_case_8() {
        try {
            String content = new String(Files.readAllBytes(Paths.get("sensitive.txt")));
            processContent(content);
        } catch (IOException e) {
            // ruleid: java-do-not-catch-and-throw-exception
            throw e; // Re-throwing without adding context
        }
    }
    
    public void bad_case_9(HttpServletRequest request) {
        try {
            String query = "SELECT * FROM users WHERE id = " + request.getParameter("id");
            executeQuery(query);
        } catch (SQLException e) {
            // ruleid: java-do-not-catch-and-throw-exception
            throw e; // Simply re-throwing SQL exception
        }
    }
    
    public void bad_case_10() {
        try {
            // Some complex operation
            performComplexCalculation();
        } catch (ArithmeticException e) {
            // ruleid: java-do-not-catch-and-throw-exception
            throw e; // Re-throwing without any additional context
        }
    }
    
    public void bad_case_11() {
        try {
            // Parse configuration
            parseConfiguration("config.xml");
        } catch (Exception e) {
            try {
                // Try alternative configuration
                parseConfiguration("backup-config.xml");
            } catch (Exception inner) {
                // ruleid: java-do-not-catch-and-throw-exception
                throw inner; // Simply re-throwing the inner exception
            }
        }
    }
    
    public void bad_case_12(HttpServletRequest request) {
        String filename = null;
        try {
            filename = request.getParameter("file");
            readFile(filename);
        } catch (IOException e) {
            // ruleid: java-do-not-catch-and-throw-exception
            throw e; // Re-throwing without adding context about the filename
        }
    }
    
    public void bad_case_13() {
        Connection conn = null;
        Statement stmt = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
            stmt = conn.createStatement();
            stmt.executeUpdate("UPDATE users SET status = 'active'");
        } catch (SQLException e) {
            // ruleid: java-do-not-catch-and-throw-exception
            throw e; // Simply re-throwing SQL exception
        } finally {
            // Close resources
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }
    
    public void bad_case_14() {
        try {
            // Authentication operation
            authenticateUser("username", "password");
        } catch (SecurityException e) {
            // ruleid: java-do-not-catch-and-throw-exception
            throw e; // Re-throwing without logging or adding context
        }
    }
    
    public void bad_case_15(HttpServletRequest request) {
        try {
            int value = Integer.parseInt(request.getParameter("value"));
            if (value < 0) {
                throw new IllegalArgumentException("Value cannot be negative");
            }
        } catch (IllegalArgumentException e) {
            // ruleid: java-do-not-catch-and-throw-exception
            throw e; // Simply re-throwing the exception
        }
    }
    
    // TRUE NEGATIVES - Secure code examples
    
    public void good_case_1() {
        try {
            FileInputStream fis = new FileInputStream("config.properties");
            // Some file operations
            fis.close();
        } catch (IOException e) {
            // ok: java-do-not-catch-and-throw-exception
            logger.log(Level.SEVERE, "Error processing config file", e);
            throw new RuntimeException("Configuration error", e);
        }
    }
    
    public void good_case_2() {
        Connection conn = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "password");
            // Database operations
        } catch (SQLException e) {
            // ok: java-do-not-catch-and-throw-exception
            logger.log(Level.SEVERE, "Database connection failed", e);
            throw new DatabaseException("Failed to connect to database", e);
        } finally {
            try {
                if (conn != null) conn.close();
            } catch (SQLException e) {
                logger.log(Level.WARNING, "Failed to close connection", e);
            }
        }
    }
    
    public void good_case_3(HttpServletRequest request) {
        try {
            String username = request.getParameter("username");
            validateUser(username);
        } catch (IllegalArgumentException e) {
            // ok: java-do-not-catch-and-throw-exception
            logger.log(Level.WARNING, "Invalid username: " + request.getParameter("username"), e);
            throw new ValidationException("Username validation failed", e);
        }
    }
    
    public void good_case_4() {
        try {
            URL url = new URL("https://api.example.com/data");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            // Process response
        } catch (IOException e) {
            // ok: java-do-not-catch-and-throw-exception
            logger.log(Level.SEVERE, "API connection failed", e);
            throw new ServiceUnavailableException("Failed to connect to external API", e);
        }
    }
    
    public void good_case_5() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // Hash operations
        } catch (NoSuchAlgorithmException e) {
            // ok: java-do-not-catch-and-throw-exception
            logger.log(Level.SEVERE, "Cryptographic algorithm not available", e);
            throw new CryptoException("Required cryptographic algorithm not available", e);
        }
    }
    
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) {
        try {
            String action = request.getParameter("action");
            if ("delete".equals(action)) {
                deleteUser(request.getParameter("userId"));
            }
        } catch (Exception e) {
            // ok: java-do-not-catch-and-throw-exception
            String userId = request.getParameter("userId");
            logger.log(Level.SEVERE, "Error processing user deletion for ID: " + userId, e);
            throw new UserOperationException("Failed to delete user: " + userId, e);
        }
    }
    
    public void good_case_7() {
        try {
            Properties props = new Properties();
            props.put("mail.smtp.host", "smtp.example.com");
            Session session = Session.getDefaultInstance(props, null);
            // Email operations
        } catch (Exception e) {
            // ok: java-do-not-catch-and-throw-exception
            logger.log(Level.SEVERE, "Email configuration error", e);
            throw new CommunicationException("Failed to configure email service", e);
        }
    }
    
    public void good_case_8() {
        try {
            String content = new String(Files.readAllBytes(Paths.get("sensitive.txt")));
            processContent(content);
        } catch (IOException e) {
            // ok: java-do-not-catch-and-throw-exception
            logger.log(Level.SEVERE, "Failed to read sensitive file", e);
            throw new FileAccessException("Could not access required configuration file", e);
        }
    }
    
    public void good_case_9(HttpServletRequest request) {
        try {
            String id = request.getParameter("id");
            String query = "SELECT * FROM users WHERE id = ?";
            executeParameterizedQuery(query, id);
        } catch (SQLException e) {
            // ok: java-do-not-catch-and-throw-exception
            String id = request.getParameter("id");
            logger.log(Level.SEVERE, "Database query failed for ID: " + id, e);
            throw new DatabaseQueryException("Failed to retrieve user data", e);
        }
    }
    
    public void good_case_10() {
        try {
            // Some complex operation
            performComplexCalculation();
        } catch (ArithmeticException e) {
            // ok: java-do-not-catch-and-throw-exception
            logger.log(Level.SEVERE, "Calculation error occurred", e);
            throw new CalculationException("Error in complex calculation routine", e);
        }
    }
    
    public void good_case_11() {
        try {
            // Parse configuration
            parseConfiguration("config.xml");
        } catch (Exception e) {
            try {
                // Try alternative configuration
                parseConfiguration("backup-config.xml");
            } catch (Exception inner) {
                // ok: java-do-not-catch-and-throw-exception
                logger.log(Level.SEVERE, "Both primary and backup configurations failed", inner);
                throw new ConfigurationException("Failed to load any configuration file", inner);
            }
        }
    }
    
    public void good_case_12(HttpServletRequest request) {
        String filename = null;
        try {
            filename = request.getParameter("file");
            readFile(filename);
        } catch (IOException e) {
            // ok: java-do-not-catch-and-throw-exception
            logger.log(Level.SEVERE, "Failed to read file: " + filename, e);
            throw new FileReadException("Could not read requested file: " + filename, e);
        }
    }
    
    public void good_case_13() {
        Connection conn = null;
        Statement stmt = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
            stmt = conn.createStatement();
            stmt.executeUpdate("UPDATE users SET status = 'active'");
        } catch (SQLException e) {
            // ok: java-do-not-catch-and-throw-exception
            logger.log(Level.SEVERE, "Failed to update user status", e);
            throw new DatabaseUpdateException("Could not activate users", e);
        } finally {
            // Close resources
            try { if (stmt != null) stmt.close(); } catch (SQLException e) { logger.log(Level.WARNING, "Failed to close statement", e); }
            try { if (conn != null) conn.close(); } catch (SQLException e) { logger.log(Level.WARNING, "Failed to close connection", e); }
        }
    }
    
    public void good_case_14() {
        try {
            // Authentication operation
            authenticateUser("username", "password");
        } catch (SecurityException e) {
            // ok: java-do-not-catch-and-throw-exception
            logger.log(Level.WARNING, "Authentication failed for user: username", e);
            throw new AuthenticationException("User authentication failed", e);
        }
    }
    
    public void good_case_15(HttpServletRequest request) {
        try {
            int value = Integer.parseInt(request.getParameter("value"));
            if (value < 0) {
                throw new IllegalArgumentException("Value cannot be negative");
            }
        } catch (IllegalArgumentException e) {
            // ok: java-do-not-catch-and-throw-exception
            String inputValue = request.getParameter("value");
            logger.log(Level.WARNING, "Invalid input value: " + inputValue, e);
            throw new ValidationException("Input validation failed: " + inputValue, e);
        }
    }
    
    // Helper methods to support the examples
    private void validateUser(String username) throws IllegalArgumentException {
        if (username == null || username.isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty");
        }
    }
    
    private void deleteUser(String userId) throws Exception {
        // Implementation for user deletion
    }
    
    private void processContent(String content) {
        // Process file content
    }
    
    private void executeQuery(String query) throws SQLException {
        // Execute SQL query
    }
    
    private void executeParameterizedQuery(String query, String param) throws SQLException {
        // Execute parameterized SQL query
    }
    
    private void performComplexCalculation() throws ArithmeticException {
        // Complex calculation that might throw ArithmeticException
    }
    
    private void parseConfiguration(String filename) throws Exception {
        // Parse configuration file
    }
    
    private void readFile(String filename) throws IOException {
        // Read file content
    }
    
    private void authenticateUser(String username, String password) throws SecurityException {
        // Authentication logic
    }
    
    // Custom exception classes
    private static class DatabaseException extends RuntimeException {
        public DatabaseException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    private static class ValidationException extends RuntimeException {
        public ValidationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    private static class ServiceUnavailableException extends RuntimeException {
        public ServiceUnavailableException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    private static class CryptoException extends RuntimeException {
        public CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    private static class UserOperationException extends RuntimeException {
        public UserOperationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    private static class CommunicationException extends RuntimeException {
        public CommunicationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    private static class FileAccessException extends RuntimeException {
        public FileAccessException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    private static class DatabaseQueryException extends RuntimeException {
        public DatabaseQueryException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    private static class CalculationException extends RuntimeException {
        public CalculationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    private static class ConfigurationException extends RuntimeException {
        public ConfigurationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    private static class FileReadException extends RuntimeException {
        public FileReadException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    private static class DatabaseUpdateException extends RuntimeException {
        public DatabaseUpdateException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    private static class AuthenticationException extends RuntimeException {
        public AuthenticationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
// {/fact}