import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.logging.log4j.LogManager;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;

public class LoggingPracticeExamples {
    // Logger instances for good examples
    private static final Logger javaLogger = Logger.getLogger(LoggingPracticeExamples.class.getName());
    private static final org.apache.logging.log4j.Logger log4jLogger = LogManager.getLogger(LoggingPracticeExamples.class);
    private static final org.slf4j.Logger slf4jLogger = LoggerFactory.getLogger(LoggingPracticeExamples.class);

    // Bad case 1: Using println for error logging
// {fact rule=seven-pk-code-quality@v1.0 defects=1}
    public void bad_case_1() {
        try {
            int result = 10 / 0;
        } catch (ArithmeticException e) {
            // ruleid: java-poor-logging-practice
            System.out.println("Error occurred: " + e.getMessage());
        }
    }

    // Bad case 2: Using println for authentication logging
    public boolean bad_case_2(String username, String password) {
        // ruleid: java-poor-logging-practice
        System.out.println("User attempting to login: " + username);
        
        if (username.equals("admin") && password.equals("password123")) {
            // ruleid: java-poor-logging-practice
            System.out.println("Login successful for user: " + username);
            return true;
        } else {
            // ruleid: java-poor-logging-practice
            System.out.println("Login failed for user: " + username);
            return false;
        }
    }

    // Bad case 3: Using println in a servlet
    @WebServlet("/badLogging")
    public static class BadLoggingServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String ipAddress = request.getRemoteAddr();
            // ruleid: java-poor-logging-practice
            System.out.println("Request received from IP: " + ipAddress);
            
            response.getWriter().println("Hello, World!");
        }
    }

    // Bad case 4: Using println for database operations
    public void bad_case_4() {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            // ruleid: java-poor-logging-practice
            System.out.println("Database connection established successfully");
        } catch (SQLException e) {
            // ruleid: java-poor-logging-practice
            System.out.println("Database connection failed: " + e.getMessage());
        }
    }

    // Bad case 5: Using println for application startup
    public void bad_case_5() {
        // ruleid: java-poor-logging-practice
        System.out.println("Application starting up...");
        
        // Initialize some resources
        
        // ruleid: java-poor-logging-practice
        System.out.println("Application started successfully");
    }

    // Bad case 6: Using println in a multi-threaded context
    public void bad_case_6() {
        Thread thread = new Thread(() -> {
            // ruleid: java-poor-logging-practice
            System.out.println("Thread " + Thread.currentThread().getId() + " is running");
            
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                // ruleid: java-poor-logging-practice
                System.out.println("Thread was interrupted: " + e.getMessage());
            }
        });
        thread.start();
    }

    // Bad case 7: Using System.err.println for error logging
    public void bad_case_7() {
        try {
            // Some code that might throw an exception
            String str = null;
            str.length();
        } catch (NullPointerException e) {
            // ruleid: java-poor-logging-practice
            System.err.println("Caught exception: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Bad case 8: Using println in a loop
    public void bad_case_8(String[] items) {
        for (int i = 0; i < items.length; i++) {
            // Process each item
            // ruleid: java-poor-logging-practice
            System.out.println("Processing item " + i + ": " + items[i]);
        }
    }

    // Bad case 9: Using println in a conditional block
    public void bad_case_9(int status) {
        if (status >= 400) {
            // ruleid: java-poor-logging-practice
            System.out.println("Error status code: " + status);
        } else if (status >= 300) {
            // ruleid: java-poor-logging-practice
            System.out.println("Redirection status code: " + status);
        } else {
            // ruleid: java-poor-logging-practice
            System.out.println("Success status code: " + status);
        }
    }

    // Bad case 10: Using println in exception handling with try-with-resources
    public void bad_case_10() {
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")) {
            // Database operations
        } catch (SQLException e) {
            // ruleid: java-poor-logging-practice
            System.out.println("Database error: " + e.getMessage());
            for (Throwable t : e) {
                // ruleid: java-poor-logging-practice
                System.out.println("Caused by: " + t.getMessage());
            }
        }
    }

    // Bad case 11: Using println in a switch statement
    public void bad_case_11(String eventType) {
        switch (eventType) {
            case "INFO":
                // ruleid: java-poor-logging-practice
                System.out.println("Information event occurred");
                break;
            case "WARNING":
                // ruleid: java-poor-logging-practice
                System.out.println("Warning event occurred");
                break;
            case "ERROR":
                // ruleid: java-poor-logging-practice
                System.out.println("Error event occurred");
                break;
            default:
                // ruleid: java-poor-logging-practice
                System.out.println("Unknown event type: " + eventType);
        }
    }

    // Bad case 12: Using println in a method with lambda expressions
    public void bad_case_12() {
        Runnable task = () -> {
            // ruleid: java-poor-logging-practice
            System.out.println("Task is running in thread: " + Thread.currentThread().getName());
        };
        
        new Thread(task).start();
    }

    // Bad case 13: Using println with string concatenation
    public void bad_case_13(String username, String action) {
        // ruleid: java-poor-logging-practice
        System.out.println("User " + username + " performed action: " + action + " at time: " + System.currentTimeMillis());
    }

    // Bad case 14: Using println in a nested try-catch
    public void bad_case_14() {
        try {
            // Outer operation
            try {
                // Inner operation that might fail
                int[] arr = new int[5];
                arr[10] = 25; // Array index out of bounds
            } catch (ArrayIndexOutOfBoundsException e) {
                // ruleid: java-poor-logging-practice
                System.out.println("Inner operation failed: " + e.getMessage());
            }
        } catch (Exception e) {
            // ruleid: java-poor-logging-practice
            System.out.println("Outer operation failed: " + e.getMessage());
        }
    }

    // Bad case 15: Using println in a finally block
    public void bad_case_15() {
        try {
            // Some operation
        } catch (Exception e) {
            throw e; // Re-throw the exception
        } finally {
            // ruleid: java-poor-logging-practice
            System.out.println("Operation completed at: " + System.currentTimeMillis());
        }
    }

    // Good case 1: Using java.util.logging for error logging
    public void good_case_1() {
        try {
            int result = 10 / 0;
        } catch (ArithmeticException e) {
            // ok: java-poor-logging-practice
            javaLogger.log(Level.SEVERE, "Error occurred", e);
        }
    }

    // Good case 2: Using java.util.logging for authentication logging
    public boolean good_case_2(String username, String password) {
        // ok: java-poor-logging-practice
        javaLogger.info("User attempting to login: " + username);
        
        if (username.equals("admin") && password.equals("password123")) {
            // ok: java-poor-logging-practice
            javaLogger.info("Login successful for user: " + username);
            return true;
        } else {
            // ok: java-poor-logging-practice
            javaLogger.warning("Login failed for user: " + username);
            return false;
        }
    }

    // Good case 3: Using Log4j in a servlet
    @WebServlet("/goodLogging")
    public static class GoodLoggingServlet extends HttpServlet {
        private static final org.apache.logging.log4j.Logger logger = LogManager.getLogger(GoodLoggingServlet.class);
        
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String ipAddress = request.getRemoteAddr();
            // ok: java-poor-logging-practice
            logger.info("Request received from IP: {}", ipAddress);
            
            response.getWriter().println("Hello, World!");
        }
    }

    // Good case 4: Using SLF4J for database operations
    public void good_case_4() {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            // ok: java-poor-logging-practice
            slf4jLogger.info("Database connection established successfully");
        } catch (SQLException e) {
            // ok: java-poor-logging-practice
            slf4jLogger.error("Database connection failed: {}", e.getMessage(), e);
        }
    }

    // Good case 5: Using Log4j for application startup
    public void good_case_5() {
        // ok: java-poor-logging-practice
        log4jLogger.info("Application starting up...");
        
        // Initialize some resources
        
        // ok: java-poor-logging-practice
        log4jLogger.info("Application started successfully");
    }

    // Good case 6: Using SLF4J in a multi-threaded context
    public void good_case_6() {
        Thread thread = new Thread(() -> {
            // ok: java-poor-logging-practice
            slf4jLogger.info("Thread {} is running", Thread.currentThread().getId());
            
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                // ok: java-poor-logging-practice
                slf4jLogger.warn("Thread was interrupted: {}", e.getMessage(), e);
            }
        });
        thread.start();
    }

    // Good case 7: Using java.util.logging for error logging instead of System.err
    public void good_case_7() {
        try {
            // Some code that might throw an exception
            String str = null;
            str.length();
        } catch (NullPointerException e) {
            // ok: java-poor-logging-practice
            javaLogger.log(Level.SEVERE, "Caught exception", e);
        }
    }

    // Good case 8: Using Log4j in a loop
    public void good_case_8(String[] items) {
        for (int i = 0; i < items.length; i++) {
            // Process each item
            // ok: java-poor-logging-practice
            log4jLogger.debug("Processing item {}: {}", i, items[i]);
        }
    }

    // Good case 9: Using SLF4J in a conditional block
    public void good_case_9(int status) {
        if (status >= 400) {
            // ok: java-poor-logging-practice
            slf4jLogger.error("Error status code: {}", status);
        } else if (status >= 300) {
            // ok: java-poor-logging-practice
            slf4jLogger.warn("Redirection status code: {}", status);
        } else {
            // ok: java-poor-logging-practice
            slf4jLogger.info("Success status code: {}", status);
        }
    }

    // Good case 10: Using Log4j in exception handling with try-with-resources
    public void good_case_10() {
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")) {
            // Database operations
        } catch (SQLException e) {
            // ok: java-poor-logging-practice
            log4jLogger.error("Database error: {}", e.getMessage(), e);
            for (Throwable t : e) {
                // ok: java-poor-logging-practice
                log4jLogger.error("Caused by: {}", t.getMessage(), t);
            }
        }
    }

    // Good case 11: Using java.util.logging in a switch statement
    public void good_case_11(String eventType) {
        switch (eventType) {
            case "INFO":
                // ok: java-poor-logging-practice
                javaLogger.info("Information event occurred");
                break;
            case "WARNING":
                // ok: java-poor-logging-practice
                javaLogger.warning("Warning event occurred");
                break;
            case "ERROR":
                // ok: java-poor-logging-practice
                javaLogger.severe("Error event occurred");
                break;
            default:
                // ok: java-poor-logging-practice
                javaLogger.warning("Unknown event type: " + eventType);
        }
    }

    // Good case 12: Using SLF4J in a method with lambda expressions
    public void good_case_12() {
        Runnable task = () -> {
            // ok: java-poor-logging-practice
            slf4jLogger.info("Task is running in thread: {}", Thread.currentThread().getName());
        };
        
        new Thread(task).start();
    }

    // Good case 13: Using Log4j with parameter substitution instead of string concatenation
    public void good_case_13(String username, String action) {
        // ok: java-poor-logging-practice
        log4jLogger.info("User {} performed action: {} at time: {}", username, action, System.currentTimeMillis());
    }

    // Good case 14: Using SLF4J in a nested try-catch
    public void good_case_14() {
        try {
            // Outer operation
            try {
                // Inner operation that might fail
                int[] arr = new int[5];
                arr[10] = 25; // Array index out of bounds
            } catch (ArrayIndexOutOfBoundsException e) {
                // ok: java-poor-logging-practice
                slf4jLogger.error("Inner operation failed: {}", e.getMessage(), e);
            }
        } catch (Exception e) {
            // ok: java-poor-logging-practice
            slf4jLogger.error("Outer operation failed: {}", e.getMessage(), e);
        }
    }

    // Good case 15: Using java.util.logging in a finally block
    public void good_case_15() {
        try {
            // Some operation
        } catch (Exception e) {
            throw e; // Re-throw the exception
        } finally {
            // ok: java-poor-logging-practice
            javaLogger.info("Operation completed at: " + System.currentTimeMillis());
        }
    }
}
// {/fact}