import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import java.net.URL;
import java.net.HttpURLConnection;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ExceptionHandlingExamples {
    private static final Logger logger = Logger.getLogger(ExceptionHandlingExamples.class.getName());

    // TRUE POSITIVES - Bad exception handling patterns

// {fact rule=unhandled-exceptions@v1.0 defects=1}
    public void bad_case_1() {
        try {
            File file = new File("nonexistent.txt");
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[100];
            fis.read(data);
            fis.close();
        } catch (IOException e) {
            // ruleid: java-do-not-swallow-exceptions
            // Exception is caught but not logged or re-thrown
        }
    }

    public String bad_case_2(HttpServletRequest request) {
        String userId = request.getParameter("id");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            Statement stmt = conn.createStatement();
            stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
            conn.close();
            return "Success";
        } catch (SQLException e) {
            // ruleid: java-do-not-swallow-exceptions
            // Exception swallowed, only returning an error message
            return "Database error";
        }
    }

    public void bad_case_3() {
        try {
            URL url = new URL("https://example.com/api");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            int responseCode = conn.getResponseCode();
            System.out.println("Response code: " + responseCode);
        } catch (IOException e) {
            // ruleid: java-do-not-swallow-exceptions
            System.out.println("Error occurred"); // Only printing generic message, not logging the exception
        }
    }

    public int bad_case_4() {
        try {
            String content = new String(Files.readAllBytes(Paths.get("config.json")));
            return content.length();
        } catch (IOException e) {
            // ruleid: java-do-not-swallow-exceptions
            return -1; // Exception swallowed, only returning error code
        }
    }

    public void bad_case_5() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<String> future = executor.submit(new Callable<String>() {
            @Override
            public String call() throws Exception {
                Thread.sleep(1000);
                return "Task completed";
            }
        });
        
        try {
            String result = future.get();
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
            // ruleid: java-do-not-swallow-exceptions
            // Exception completely swallowed
        } finally {
            executor.shutdown();
        }
    }

    public void bad_case_6() {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // Use cipher for encryption/decryption
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // ruleid: java-do-not-swallow-exceptions
            System.out.println("Encryption error"); // Generic message, exception swallowed
        }
    }

    public boolean bad_case_7(String filePath) {
        try {
            File file = new File(filePath);
            if (file.delete()) {
                return true;
            } else {
                return false;
            }
        } catch (SecurityException e) {
            // ruleid: java-do-not-swallow-exceptions
            return false; // Exception swallowed
        }
    }

    public void bad_case_8() {
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    // ruleid: java-do-not-swallow-exceptions
                    // Exception completely swallowed
                }
            }
        });
        thread.start();
    }

    public int bad_case_9(String[] args) {
        try {
            return Integer.parseInt(args[0]);
        } catch (NumberFormatException | ArrayIndexOutOfBoundsException e) {
            // ruleid: java-do-not-swallow-exceptions
            return 0; // Exception swallowed, default value returned
        }
    }

    public void bad_case_10(HttpServletRequest request) {
        try {
            String action = request.getParameter("action");
            if ("delete".equals(action)) {
                // Perform deletion
                throw new IllegalStateException("Deletion failed");
            }
        } catch (IllegalStateException e) {
            // ruleid: java-do-not-swallow-exceptions
            // Exception completely swallowed
        }
    }

    public void bad_case_11() {
        try {
            Class.forName("com.mysql.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            // ruleid: java-do-not-swallow-exceptions
            // Exception completely swallowed
        }
    }

    public String bad_case_12() {
        try {
            Process process = Runtime.getRuntime().exec("ls -la");
            return "Process started";
        } catch (IOException e) {
            // ruleid: java-do-not-swallow-exceptions
            return "Error starting process"; // Exception swallowed
        }
    }

    public void bad_case_13() {
        try {
            String[] array = new String[3];
            System.out.println(array[5]); // This will throw ArrayIndexOutOfBoundsException
        } catch (ArrayIndexOutOfBoundsException e) {
            // ruleid: java-do-not-swallow-exceptions
            // Exception completely swallowed
        }
    }

    public Object bad_case_14() {
        try {
            String str = null;
            return str.length(); // This will throw NullPointerException
        } catch (NullPointerException e) {
            // ruleid: java-do-not-swallow-exceptions
            return -1; // Exception swallowed
        }
    }

    public void bad_case_15() {
        try {
            double result = 10 / 0; // This will throw ArithmeticException
            System.out.println("Result: " + result);
        } catch (ArithmeticException e) {
            // ruleid: java-do-not-swallow-exceptions
            System.out.println("Error in calculation"); // Exception details swallowed
        }
    }

    // TRUE NEGATIVES - Good exception handling patterns

    public void good_case_1() {
        try {
            File file = new File("nonexistent.txt");
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[100];
            fis.read(data);
            fis.close();
        } catch (IOException e) {
            // ok: java-do-not-swallow-exceptions
            logger.log(Level.SEVERE, "Error reading file", e);
        }
    }

    public String good_case_2(HttpServletRequest request) {
        String userId = request.getParameter("id");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password");
            Statement stmt = conn.createStatement();
            stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
            conn.close();
            return "Success";
        } catch (SQLException e) {
            // ok: java-do-not-swallow-exceptions
            logger.log(Level.SEVERE, "Database error", e);
            return "Database error";
        }
    }

    public void good_case_3() {
        try {
            URL url = new URL("https://example.com/api");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            int responseCode = conn.getResponseCode();
            System.out.println("Response code: " + responseCode);
        } catch (IOException e) {
            // ok: java-do-not-swallow-exceptions
            logger.log(Level.WARNING, "Error connecting to API", e);
        }
    }

    public int good_case_4() {
        try {
            String content = new String(Files.readAllBytes(Paths.get("config.json")));
            return content.length();
        } catch (IOException e) {
            // ok: java-do-not-swallow-exceptions
            logger.log(Level.SEVERE, "Error reading config file", e);
            return -1;
        }
    }

    public void good_case_5() throws InterruptedException, ExecutionException {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<String> future = executor.submit(new Callable<String>() {
            @Override
            public String call() throws Exception {
                Thread.sleep(1000);
                return "Task completed";
            }
        });
        
        try {
            String result = future.get();
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
            // ok: java-do-not-swallow-exceptions
            throw e; // Re-throwing the exception
        } finally {
            executor.shutdown();
        }
    }

    public void good_case_6() {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // Use cipher for encryption/decryption
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // ok: java-do-not-swallow-exceptions
            logger.log(Level.SEVERE, "Encryption error", e);
        }
    }

    public boolean good_case_7(String filePath) {
        try {
            File file = new File(filePath);
            if (file.delete()) {
                return true;
            } else {
                return false;
            }
        } catch (SecurityException e) {
            // ok: java-do-not-swallow-exceptions
            logger.log(Level.WARNING, "Security exception when deleting file", e);
            return false;
        }
    }

    public void good_case_8() {
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    // ok: java-do-not-swallow-exceptions
                    Thread.currentThread().interrupt(); // Restore interrupted status
                    logger.log(Level.INFO, "Thread interrupted", e);
                }
            }
        });
        thread.start();
    }

    public int good_case_9(String[] args) {
        try {
            return Integer.parseInt(args[0]);
        } catch (NumberFormatException | ArrayIndexOutOfBoundsException e) {
            // ok: java-do-not-swallow-exceptions
            logger.log(Level.WARNING, "Error parsing argument", e);
            return 0;
        }
    }

    public void good_case_10(HttpServletRequest request) throws IllegalStateException {
        try {
            String action = request.getParameter("action");
            if ("delete".equals(action)) {
                // Perform deletion
                throw new IllegalStateException("Deletion failed");
            }
        } catch (IllegalStateException e) {
            // ok: java-do-not-swallow-exceptions
            throw e; // Re-throwing the exception
        }
    }

    public void good_case_11() {
        try {
            Class.forName("com.mysql.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            // ok: java-do-not-swallow-exceptions
            logger.log(Level.SEVERE, "JDBC Driver not found", e);
        }
    }

    public String good_case_12() {
        try {
            Process process = Runtime.getRuntime().exec("ls -la");
            return "Process started";
        } catch (IOException e) {
            // ok: java-do-not-swallow-exceptions
            logger.log(Level.SEVERE, "Error executing process", e);
            return "Error starting process";
        }
    }

    public void good_case_13() {
        try {
            String[] array = new String[3];
            System.out.println(array[5]); // This will throw ArrayIndexOutOfBoundsException
        } catch (ArrayIndexOutOfBoundsException e) {
            // ok: java-do-not-swallow-exceptions
            logger.log(Level.WARNING, "Array index out of bounds", e);
        }
    }

    public Object good_case_14() {
        try {
            String str = null;
            return str.length(); // This will throw NullPointerException
        } catch (NullPointerException e) {
            // ok: java-do-not-swallow-exceptions
            logger.log(Level.SEVERE, "Null pointer encountered", e);
            return -1;
        }
    }

    public void good_case_15() {
        try {
            double result = 10 / 0; // This will throw ArithmeticException
            System.out.println("Result: " + result);
        } catch (ArithmeticException e) {
            // ok: java-do-not-swallow-exceptions
            logger.log(Level.SEVERE, "Division by zero", e);
        }
    }
}
// {/fact}