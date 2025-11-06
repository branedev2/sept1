import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import org.json.JSONException;
import org.json.JSONObject;
import java.net.HttpURLConnection;
import java.net.URL;

public class ExceptionHandlingExamples {
    private static final Logger logger = Logger.getLogger(ExceptionHandlingExamples.class.getName());

    // True Positive Examples (Bad Cases)

// {fact rule=inconsistent-exception-handling@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        try {
            String userId = request.getParameter("userId");
            if (userId == null) {
                throw new IllegalArgumentException("User ID cannot be null");
            }
            // Process user ID
        } catch (Exception e) {
            try {
                // ruleid: java-throw-exception-with-stack-trace
                throw new RuntimeException("Error processing user ID");
            } catch (RuntimeException re) {
                logger.log(Level.SEVERE, "Error occurred", re);
            }
        }
    }

    public void bad_case_2() {
        try {
            File file = new File("important.txt");
            FileInputStream fis = new FileInputStream(file);
            // Process file
            fis.close();
        } catch (FileNotFoundException e) {
            // ruleid: java-throw-exception-with-stack-trace
            throw new RuntimeException("File not found");
        } catch (IOException e) {
            // ruleid: java-throw-exception-with-stack-trace
            throw new RuntimeException("IO error occurred");
        }
    }

    public void bad_case_3(String jsonString) {
        try {
            JSONObject jsonObject = new JSONObject(jsonString);
            // Process JSON
        } catch (JSONException e) {
            // ruleid: java-throw-exception-with-stack-trace
            throw new IllegalArgumentException("Invalid JSON format");
        }
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Process request
            if (request.getParameter("action") == null) {
                throw new ServletException("Action parameter is required");
            }
        } catch (ServletException e) {
            try {
                // ruleid: java-throw-exception-with-stack-trace
                throw new IllegalStateException("Invalid request");
            } catch (Exception ex) {
                logger.log(Level.SEVERE, "Error in request processing", ex);
            }
        }
    }

    public void bad_case_5() {
        Connection conn = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "password");
            // Database operations
        } catch (SQLException e) {
            // ruleid: java-throw-exception-with-stack-trace
            throw new RuntimeException("Database connection failed");
        } finally {
            try {
                if (conn != null) conn.close();
            } catch (SQLException e) {
                // Ignore
            }
        }
    }

    public void bad_case_6(String apiUrl) {
        try {
            URL url = new URL(apiUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            // Process response
        } catch (IOException e) {
            // ruleid: java-throw-exception-with-stack-trace
            throw new IllegalStateException("API call failed");
        }
    }

    public void bad_case_7() {
        try {
            int result = 10 / 0; // Will throw ArithmeticException
        } catch (ArithmeticException e) {
            try {
                // ruleid: java-throw-exception-with-stack-trace
                throw new RuntimeException("Calculation error");
            } catch (RuntimeException re) {
                logger.log(Level.SEVERE, "Runtime error", re);
            }
        }
    }

    public void bad_case_8(HttpServletRequest request) {
        String fileName = null;
        try {
            fileName = request.getParameter("fileName");
            if (fileName == null) {
                throw new IllegalArgumentException("File name is required");
            }
            // Process file name
        } catch (Exception e) {
            // ruleid: java-throw-exception-with-stack-trace
            throw new NullPointerException("Error with file: " + fileName);
        }
    }

    public void bad_case_9() {
        try {
            // Some complex operation
            complexOperation();
        } catch (Exception e) {
            // ruleid: java-throw-exception-with-stack-trace
            Exception newException = new Exception("Complex operation failed");
            throw newException;
        }
    }

    public void bad_case_10(String input) {
        try {
            if (input == null || input.isEmpty()) {
                throw new IllegalArgumentException("Input cannot be empty");
            }
            // Process input
        } catch (IllegalArgumentException e) {
            // ruleid: java-throw-exception-with-stack-trace
            RuntimeException re = new RuntimeException();
            re.initCause(new Exception("Invalid input provided"));
            throw re;
        }
    }

    public void bad_case_11() {
        try {
            // Some operation that might throw an exception
            riskyOperation();
        } catch (Exception original) {
            try {
                // Another operation that might throw an exception
                anotherRiskyOperation();
            } catch (Exception e) {
                // ruleid: java-throw-exception-with-stack-trace
                throw new RuntimeException("Multiple errors occurred");
            }
        }
    }

    public void bad_case_12(HttpServletRequest request) {
        try {
            String value = request.getParameter("value");
            int intValue = Integer.parseInt(value);
            // Process integer value
        } catch (NumberFormatException e) {
            // ruleid: java-throw-exception-with-stack-trace
            throw new IllegalArgumentException("Invalid number format");
        }
    }

    public void bad_case_13() {
        try {
            // Some code that might throw different exceptions
            multiExceptionOperation();
        } catch (IOException e) {
            // ruleid: java-throw-exception-with-stack-trace
            throw new RuntimeException("IO error");
        } catch (SQLException e) {
            // ruleid: java-throw-exception-with-stack-trace
            throw new RuntimeException("SQL error");
        } catch (Exception e) {
            // ruleid: java-throw-exception-with-stack-trace
            throw new RuntimeException("General error");
        }
    }

    public void bad_case_14(String configPath) {
        try {
            // Load configuration from file
            loadConfiguration(configPath);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to load configuration", e);
            // ruleid: java-throw-exception-with-stack-trace
            throw new IllegalStateException("Configuration error");
        }
    }

    public void bad_case_15() {
        try {
            // Some operation that might fail
            if (!performCriticalOperation()) {
                throw new Exception("Critical operation failed");
            }
        } catch (Exception e) {
            // Log the original exception
            logger.log(Level.SEVERE, "Operation failed", e);
            
            // ruleid: java-throw-exception-with-stack-trace
            throw new RuntimeException("System is in an inconsistent state");
        }
    }

    // True Negative Examples (Good Cases)

    public void good_case_1(HttpServletRequest request) {
        try {
            String userId = request.getParameter("userId");
            if (userId == null) {
                throw new IllegalArgumentException("User ID cannot be null");
            }
            // Process user ID
        } catch (Exception e) {
            try {
                // ok: java-throw-exception-with-stack-trace
                throw new RuntimeException("Error processing user ID", e);
            } catch (RuntimeException re) {
                logger.log(Level.SEVERE, "Error occurred", re);
            }
        }
    }

    public void good_case_2() {
        try {
            File file = new File("important.txt");
            FileInputStream fis = new FileInputStream(file);
            // Process file
            fis.close();
        } catch (FileNotFoundException e) {
            // ok: java-throw-exception-with-stack-trace
            throw new RuntimeException("File not found", e);
        } catch (IOException e) {
            // ok: java-throw-exception-with-stack-trace
            throw new RuntimeException("IO error occurred", e);
        }
    }

    public void good_case_3(String jsonString) {
        try {
            JSONObject jsonObject = new JSONObject(jsonString);
            // Process JSON
        } catch (JSONException e) {
            // ok: java-throw-exception-with-stack-trace
            throw new IllegalArgumentException("Invalid JSON format", e);
        }
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Process request
            if (request.getParameter("action") == null) {
                throw new ServletException("Action parameter is required");
            }
        } catch (ServletException e) {
            try {
                // ok: java-throw-exception-with-stack-trace
                throw new IllegalStateException("Invalid request", e);
            } catch (Exception ex) {
                logger.log(Level.SEVERE, "Error in request processing", ex);
            }
        }
    }

    public void good_case_5() {
        Connection conn = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "password");
            // Database operations
        } catch (SQLException e) {
            // ok: java-throw-exception-with-stack-trace
            throw new RuntimeException("Database connection failed", e);
        } finally {
            try {
                if (conn != null) conn.close();
            } catch (SQLException e) {
                // Ignore
            }
        }
    }

    public void good_case_6(String apiUrl) {
        try {
            URL url = new URL(apiUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            // Process response
        } catch (IOException e) {
            // ok: java-throw-exception-with-stack-trace
            throw new IllegalStateException("API call failed", e);
        }
    }

    public void good_case_7() {
        try {
            int result = 10 / 0; // Will throw ArithmeticException
        } catch (ArithmeticException e) {
            try {
                // ok: java-throw-exception-with-stack-trace
                throw new RuntimeException("Calculation error", e);
            } catch (RuntimeException re) {
                logger.log(Level.SEVERE, "Runtime error", re);
            }
        }
    }

    public void good_case_8(HttpServletRequest request) {
        String fileName = null;
        try {
            fileName = request.getParameter("fileName");
            if (fileName == null) {
                throw new IllegalArgumentException("File name is required");
            }
            // Process file name
        } catch (Exception e) {
            // ok: java-throw-exception-with-stack-trace
            throw new NullPointerException("Error with file: " + fileName) {{ initCause(e); }};
        }
    }

    public void good_case_9() {
        try {
            // Some complex operation
            complexOperation();
        } catch (Exception e) {
            // ok: java-throw-exception-with-stack-trace
            Exception newException = new Exception("Complex operation failed", e);
            throw newException;
        }
    }

    public void good_case_10(String input) {
        try {
            if (input == null || input.isEmpty()) {
                throw new IllegalArgumentException("Input cannot be empty");
            }
            // Process input
        } catch (IllegalArgumentException e) {
            // ok: java-throw-exception-with-stack-trace
            RuntimeException re = new RuntimeException("Invalid input provided", e);
            throw re;
        }
    }

    public void good_case_11() {
        try {
            // Some operation that might throw an exception
            riskyOperation();
        } catch (Exception original) {
            try {
                // Another operation that might throw an exception
                anotherRiskyOperation();
            } catch (Exception e) {
                // ok: java-throw-exception-with-stack-trace
                Exception combined = new Exception("Multiple errors occurred", original);
                combined.addSuppressed(e);
                throw combined;
            }
        }
    }

    public void good_case_12(HttpServletRequest request) {
        try {
            String value = request.getParameter("value");
            int intValue = Integer.parseInt(value);
            // Process integer value
        } catch (NumberFormatException e) {
            // ok: java-throw-exception-with-stack-trace
            throw new IllegalArgumentException("Invalid number format: " + value, e);
        }
    }

    public void good_case_13() {
        try {
            // Some code that might throw different exceptions
            multiExceptionOperation();
        } catch (IOException e) {
            // ok: java-throw-exception-with-stack-trace
            throw new RuntimeException("IO error", e);
        } catch (SQLException e) {
            // ok: java-throw-exception-with-stack-trace
            throw new RuntimeException("SQL error", e);
        } catch (Exception e) {
            // ok: java-throw-exception-with-stack-trace
            throw new RuntimeException("General error", e);
        }
    }

    public void good_case_14(String configPath) {
        try {
            // Load configuration from file
            loadConfiguration(configPath);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to load configuration", e);
            // ok: java-throw-exception-with-stack-trace
            throw new IllegalStateException("Configuration error: " + configPath, e);
        }
    }

    public void good_case_15() {
        try {
            // Some operation that might fail
            if (!performCriticalOperation()) {
                throw new Exception("Critical operation failed");
            }
        } catch (Exception e) {
            // Log the original exception
            logger.log(Level.SEVERE, "Operation failed", e);
            
            // ok: java-throw-exception-with-stack-trace
            RuntimeException runtimeException = new RuntimeException("System is in an inconsistent state");
            runtimeException.initCause(e);
            throw runtimeException;
        }
    }

    // Helper methods to make the examples compile
    private void complexOperation() throws Exception {
        // Implementation not important for the examples
    }

    private void riskyOperation() throws Exception {
        // Implementation not important for the examples
    }

    private void anotherRiskyOperation() throws Exception {
        // Implementation not important for the examples
    }

    private void multiExceptionOperation() throws IOException, SQLException {
        // Implementation not important for the examples
    }

    private void loadConfiguration(String path) throws Exception {
        // Implementation not important for the examples
    }

    private boolean performCriticalOperation() throws Exception {
        // Implementation not important for the examples
        return true;
    }
}
// {/fact}