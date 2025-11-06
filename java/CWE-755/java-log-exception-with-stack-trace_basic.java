import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.slf4j.LoggerFactory;
import org.apache.logging.log4j.LogManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ExceptionLoggingExamples {
    private static final Logger javaLogger = Logger.getLogger(ExceptionLoggingExamples.class.getName());
    private static final org.slf4j.Logger slf4jLogger = LoggerFactory.getLogger(ExceptionLoggingExamples.class);
    private static final org.apache.logging.log4j.Logger log4jLogger = LogManager.getLogger(ExceptionLoggingExamples.class);
    
    // True Positive Examples (Vulnerable code)
    
// {fact rule=inconsistent-exception-handling@v1.0 defects=1}
    public void bad_case_1() {
        try {
            // Some code that might throw an exception
            int result = 10 / 0;
        } catch (Exception e) {
            // ruleid: java-log-exception-with-stack-trace
            javaLogger.log(Level.SEVERE, "Division error occurred");
            // No stack trace logged
        }
    }
    
    public void bad_case_2() {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
        } catch (SQLException e) {
            // ruleid: java-log-exception-with-stack-trace
            System.out.println("Database connection failed: " + e.getMessage());
            // Only message is logged, not the stack trace
        }
    }
    
    public void bad_case_3() {
        try {
            String filename = null;
            filename.length(); // Will throw NullPointerException
        } catch (NullPointerException e) {
            // ruleid: java-log-exception-with-stack-trace
            slf4jLogger.error("Null pointer error");
            // No stack trace logged
        }
    }
    
    public void bad_case_4(HttpServletRequest request) {
        try {
            String param = request.getParameter("id");
            Integer.parseInt(param); // Might throw NumberFormatException
        } catch (NumberFormatException e) {
            // ruleid: java-log-exception-with-stack-trace
            log4jLogger.error("Invalid number format in request parameter");
            // No exception details logged
        }
    }
    
    public void bad_case_5() {
        try {
            // Some code that might throw an exception
            throw new RuntimeException("Test exception");
        } catch (RuntimeException e) {
            // ruleid: java-log-exception-with-stack-trace
            slf4jLogger.error("Runtime error: {}", e.getMessage());
            // Only message is logged, not the stack trace
        }
    }
    
    public void bad_case_6() {
        try {
            // Some code that might throw an exception
            Class.forName("non.existent.Driver");
        } catch (ClassNotFoundException e) {
            // ruleid: java-log-exception-with-stack-trace
            System.err.println("Driver not found: " + e);
            // toString() doesn't include full stack trace
        }
    }
    
    public void bad_case_7() {
        try {
            // Some code that might throw an exception
            throw new IllegalArgumentException("Invalid argument");
        } catch (Exception e) {
            // ruleid: java-log-exception-with-stack-trace
            javaLogger.log(Level.WARNING, "An error occurred: " + e.getMessage());
            // Only message is logged
        }
    }
    
    public void bad_case_8() {
        try {
            // Some code that might throw an exception
            throw new IOException("File not found");
        } catch (IOException e) {
            // ruleid: java-log-exception-with-stack-trace
            log4jLogger.warn("IO problem: {}", e.getMessage());
            // Only message is logged, not the stack trace
        }
    }
    
    public void bad_case_9() {
        Exception savedEx = null;
        try {
            // Some code that might throw an exception
            throw new Exception("Test exception");
        } catch (Exception e) {
            savedEx = e;
        }
        
        if (savedEx != null) {
            // ruleid: java-log-exception-with-stack-trace
            slf4jLogger.error("Error occurred: {}", savedEx.getMessage());
            // Only message is logged, not the stack trace
        }
    }
    
    public void bad_case_10(HttpServletResponse response) {
        try {
            // Some code that might throw an exception
            throw new RuntimeException("Error in processing");
        } catch (RuntimeException e) {
            // ruleid: java-log-exception-with-stack-trace
            log4jLogger.error("Failed to process request");
            // No exception details logged at all
            response.setStatus(500);
        }
    }
    
    public void bad_case_11() {
        try {
            // Some code that might throw multiple exceptions
            throw new IllegalStateException("Invalid state");
        } catch (IllegalArgumentException e) {
            // ruleid: java-log-exception-with-stack-trace
            slf4jLogger.error("Argument error");
        } catch (IllegalStateException e) {
            // ruleid: java-log-exception-with-stack-trace
            slf4jLogger.error("State error: " + e.getMessage());
            // Only message is logged, not the stack trace
        }
    }
    
    public void bad_case_12() {
        try {
            // Some code that might throw an exception
            throw new SecurityException("Access denied");
        } catch (SecurityException e) {
            // Log to custom destination
            // ruleid: java-log-exception-with-stack-trace
            logToCustomDestination("Security violation: " + e.getMessage());
            // Only message is logged, not the stack trace
        }
    }
    
    private void logToCustomDestination(String message) {
        // Custom logging implementation
        System.out.println("[CUSTOM LOG] " + message);
    }
    
    public void bad_case_13() {
        try {
            // Some code that might throw an exception
            throw new UnsupportedOperationException("Operation not supported");
        } catch (UnsupportedOperationException e) {
            // ruleid: java-log-exception-with-stack-trace
            javaLogger.log(Level.SEVERE, e.toString());
            // toString() doesn't include full stack trace
        }
    }
    
    public void bad_case_14() {
        Exception ex = null;
        try {
            // Some code that might throw an exception
            throw new Exception("Test exception");
        } catch (Exception e) {
            ex = e;
        } finally {
            if (ex != null) {
                // ruleid: java-log-exception-with-stack-trace
                log4jLogger.error("Operation failed with error: " + ex.getMessage());
                // Only message is logged, not the stack trace
            }
        }
    }
    
    public void bad_case_15() {
        try {
            // Some code that might throw an exception
            throw new RuntimeException("Critical error");
        } catch (Exception e) {
            // Custom formatting without stack trace
            StringBuilder sb = new StringBuilder();
            sb.append("Error type: ").append(e.getClass().getName());
            sb.append(", Message: ").append(e.getMessage());
            
            // ruleid: java-log-exception-with-stack-trace
            slf4jLogger.error(sb.toString());
            // No stack trace in custom formatting
        }
    }
    
    // True Negative Examples (Secure code)
    
    public void good_case_1() {
        try {
            // Some code that might throw an exception
            int result = 10 / 0;
        } catch (Exception e) {
            // ok: java-log-exception-with-stack-trace
            javaLogger.log(Level.SEVERE, "Division error occurred", e);
            // Stack trace is properly logged
        }
    }
    
    public void good_case_2() {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
        } catch (SQLException e) {
            // ok: java-log-exception-with-stack-trace
            slf4jLogger.error("Database connection failed", e);
            // Stack trace is properly logged
        }
    }
    
    public void good_case_3() {
        try {
            String filename = null;
            filename.length(); // Will throw NullPointerException
        } catch (NullPointerException e) {
            // ok: java-log-exception-with-stack-trace
            log4jLogger.error("Null pointer error", e);
            // Stack trace is properly logged
        }
    }
    
    public void good_case_4(HttpServletRequest request) {
        try {
            String param = request.getParameter("id");
            Integer.parseInt(param); // Might throw NumberFormatException
        } catch (NumberFormatException e) {
            // ok: java-log-exception-with-stack-trace
            javaLogger.log(Level.WARNING, "Invalid number format in request parameter", e);
            // Stack trace is properly logged
        }
    }
    
    public void good_case_5() {
        try {
            // Some code that might throw an exception
            throw new RuntimeException("Test exception");
        } catch (RuntimeException e) {
            // ok: java-log-exception-with-stack-trace
            e.printStackTrace(); // This prints the full stack trace
        }
    }
    
    public void good_case_6() {
        try {
            // Some code that might throw an exception
            Class.forName("non.existent.Driver");
        } catch (ClassNotFoundException e) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            String stackTrace = sw.toString();
            
            // ok: java-log-exception-with-stack-trace
            System.err.println("Driver not found: " + stackTrace);
            // Full stack trace is logged
        }
    }
    
    public void good_case_7() {
        try {
            // Some code that might throw an exception
            throw new IllegalArgumentException("Invalid argument");
        } catch (Exception e) {
            // ok: java-log-exception-with-stack-trace
            slf4jLogger.error("An error occurred", e);
            // Stack trace is properly logged
        }
    }
    
    public void good_case_8() {
        try {
            // Some code that might throw an exception
            throw new IOException("File not found");
        } catch (IOException e) {
            // ok: java-log-exception-with-stack-trace
            log4jLogger.warn("IO problem", e);
            // Stack trace is properly logged
        }
    }
    
    public void good_case_9() {
        Exception savedEx = null;
        try {
            // Some code that might throw an exception
            throw new Exception("Test exception");
        } catch (Exception e) {
            savedEx = e;
        }
        
        if (savedEx != null) {
            // ok: java-log-exception-with-stack-trace
            javaLogger.log(Level.SEVERE, "Error occurred", savedEx);
            // Stack trace is properly logged
        }
    }
    
    public void good_case_10(HttpServletResponse response) {
        try {
            // Some code that might throw an exception
            throw new RuntimeException("Error in processing");
        } catch (RuntimeException e) {
            // ok: java-log-exception-with-stack-trace
            slf4jLogger.error("Failed to process request", e);
            // Stack trace is properly logged
            response.setStatus(500);
        }
    }
    
    public void good_case_11() {
        try {
            // Some code that might throw multiple exceptions
            throw new IllegalStateException("Invalid state");
        } catch (IllegalArgumentException e) {
            // ok: java-log-exception-with-stack-trace
            log4jLogger.error("Argument error", e);
            // Stack trace is properly logged
        } catch (IllegalStateException e) {
            // ok: java-log-exception-with-stack-trace
            log4jLogger.error("State error", e);
            // Stack trace is properly logged
        }
    }
    
    public void good_case_12() {
        try {
            // Some code that might throw an exception
            throw new SecurityException("Access denied");
        } catch (SecurityException e) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            String stackTrace = sw.toString();
            
            // ok: java-log-exception-with-stack-trace
            logToCustomDestination("Security violation: " + stackTrace);
            // Full stack trace is logged
        }
    }
    
    public void good_case_13() {
        try {
            // Some code that might throw an exception
            throw new UnsupportedOperationException("Operation not supported");
        } catch (UnsupportedOperationException e) {
            // ok: java-log-exception-with-stack-trace
            slf4jLogger.error("Unsupported operation: {}", e.getMessage(), e);
            // Both message and stack trace are logged
        }
    }
    
    public void good_case_14() {
        Exception ex = null;
        try {
            // Some code that might throw an exception
            throw new Exception("Test exception");
        } catch (Exception e) {
            ex = e;
        } finally {
            if (ex != null) {
                // ok: java-log-exception-with-stack-trace
                log4jLogger.error("Operation failed", ex);
                // Stack trace is properly logged
            }
        }
    }
    
    public void good_case_15() {
        try {
            // Some code that might throw an exception
            throw new RuntimeException("Critical error");
        } catch (Exception e) {
            // Using try-with-resources for proper stack trace handling
            try (StringWriter sw = new StringWriter();
                 PrintWriter pw = new PrintWriter(sw)) {
                
                e.printStackTrace(pw);
                String stackTrace = sw.toString();
                
                // ok: java-log-exception-with-stack-trace
                javaLogger.log(Level.SEVERE, "Critical error occurred: " + stackTrace);
                // Full stack trace is logged
            } catch (IOException ioe) {
                // Handle StringWriter exception
                javaLogger.log(Level.SEVERE, "Error while logging exception", ioe);
            }
        }
    }
}
// {/fact}