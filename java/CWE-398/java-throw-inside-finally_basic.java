import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Logger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class ThrowInsideFinallyExamples {
    private static final Logger logger = Logger.getLogger(ThrowInsideFinallyExamples.class.getName());

    // True Positive Examples (Bad Cases)

// {fact rule=seven-pk-code-quality@v1.0 defects=1}
    public void bad_case_1() {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream("config.properties");
            // Process file
        } catch (IOException e) {
            logger.severe("Error reading file: " + e.getMessage());
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
            } catch (IOException e) {
                // ruleid: java-throw-inside-finally
                throw new RuntimeException("Failed to close file", e);
            }
        }
    }

    public void bad_case_2() {
        Connection conn = null;
        Statement stmt = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            stmt = conn.createStatement();
            stmt.executeUpdate("UPDATE users SET status = 'active' WHERE id = 1");
        } catch (SQLException e) {
            logger.severe("Database error: " + e.getMessage());
        } finally {
            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException e) {
                    logger.warning("Error closing statement");
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    // ruleid: java-throw-inside-finally
                    throw new IllegalStateException("Could not close database connection", e);
                }
            }
        }
    }

    public void bad_case_3() {
        Lock lock = new ReentrantLock();
        try {
            lock.lock();
            // Critical section
            performOperation();
        } catch (Exception e) {
            logger.severe("Operation failed: " + e.getMessage());
        } finally {
            // ruleid: java-throw-inside-finally
            if (!lock.tryLock()) {
                throw new IllegalStateException("Lock state is inconsistent");
            }
            lock.unlock();
        }
    }

    public void bad_case_4() {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader("data.txt"));
            String line;
            while ((line = reader.readLine()) != null) {
                processLine(line);
            }
        } catch (IOException e) {
            logger.warning("Error reading file: " + e.getMessage());
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                    // ruleid: java-throw-inside-finally
                    throw new RuntimeException("Testing exception in finally");
                } catch (IOException e) {
                    logger.severe("Failed to close reader");
                }
            }
        }
    }

    public void bad_case_5() {
        InputStream is = null;
        OutputStream os = null;
        try {
            is = new FileInputStream("source.dat");
            os = new FileOutputStream("destination.dat");
            byte[] buffer = new byte[1024];
            int length;
            while ((length = is.read(buffer)) > 0) {
                os.write(buffer, 0, length);
            }
        } catch (IOException e) {
            logger.severe("Copy failed: " + e.getMessage());
        } finally {
            try {
                if (is != null) is.close();
                if (os != null) {
                    os.close();
                    // ruleid: java-throw-inside-finally
                    throw new IllegalStateException("Output stream closed but with error");
                }
            } catch (IOException e) {
                logger.warning("Error closing streams");
            }
        }
    }

    public void bad_case_6() {
        SecretKey key = null;
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            key = keyGen.generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // Use cipher for encryption/decryption
        } catch (Exception e) {
            logger.severe("Encryption error: " + e.getMessage());
        } finally {
            if (key != null) {
                // ruleid: java-throw-inside-finally
                throw new SecurityException("Key needs to be destroyed properly");
            }
        }
    }

    public void bad_case_7() {
        Socket socket = null;
        try {
            socket = new Socket("localhost", 8080);
            // Communicate with server
        } catch (IOException e) {
            logger.severe("Network error: " + e.getMessage());
        } finally {
            if (socket != null && !socket.isClosed()) {
                try {
                    socket.close();
                } catch (IOException e) {
                    // ruleid: java-throw-inside-finally
                    throw new RuntimeException("Failed to close socket properly", e);
                }
            }
        }
    }

    public void bad_case_8() {
        List<String> resources = new ArrayList<>();
        try {
            resources.add("Resource1");
            resources.add("Resource2");
            // Use resources
        } catch (Exception e) {
            logger.severe("Error using resources: " + e.getMessage());
        } finally {
            for (String resource : resources) {
                if (resource.equals("Resource1")) {
                    // Clean up Resource1
                } else {
                    // ruleid: java-throw-inside-finally
                    throw new IllegalArgumentException("Unknown resource: " + resource);
                }
            }
        }
    }

    public void bad_case_9() {
        Thread worker = new Thread(() -> {
            // Do background work
        });
        
        try {
            worker.start();
            worker.join(1000);
        } catch (InterruptedException e) {
            logger.warning("Worker thread interrupted");
        } finally {
            if (worker.isAlive()) {
                worker.interrupt();
                // ruleid: java-throw-inside-finally
                throw new IllegalThreadStateException("Thread did not terminate properly");
            }
        }
    }

    public void bad_case_10() {
        Object lock = new Object();
        boolean locked = false;
        
        try {
            synchronized(lock) {
                locked = true;
                // Critical section
            }
        } catch (Exception e) {
            logger.severe("Error in critical section: " + e.getMessage());
        } finally {
            if (locked) {
                // Some cleanup
                // ruleid: java-throw-inside-finally
                throw new RuntimeException("Cleanup failed");
            }
        }
    }

    public void bad_case_11() {
        FileInputStream fis1 = null;
        FileInputStream fis2 = null;
        
        try {
            fis1 = new FileInputStream("file1.txt");
            fis2 = new FileInputStream("file2.txt");
            // Process files
        } catch (IOException e) {
            logger.severe("File processing error: " + e.getMessage());
        } finally {
            try {
                if (fis1 != null) fis1.close();
            } catch (IOException e) {
                logger.warning("Error closing first file");
            }
            
            try {
                if (fis2 != null) fis2.close();
            } catch (IOException e) {
                // ruleid: java-throw-inside-finally
                throw new RuntimeException("Error closing second file", e);
            }
        }
    }

    public void bad_case_12() {
        Connection conn = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            boolean autoCommit = conn.getAutoCommit();
            conn.setAutoCommit(false);
            
            // Database operations
            conn.commit();
        } catch (SQLException e) {
            try {
                if (conn != null) conn.rollback();
            } catch (SQLException rollbackEx) {
                logger.severe("Rollback failed: " + rollbackEx.getMessage());
            }
        } finally {
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    // ruleid: java-throw-inside-finally
                    throw new RuntimeException("Database connection couldn't be closed", e);
                }
            }
        }
    }

    public void bad_case_13() {
        try {
            // Some operation
            int result = 10 / 0; // Will throw ArithmeticException
        } catch (ArithmeticException e) {
            logger.warning("Division by zero");
        } finally {
            // ruleid: java-throw-inside-finally
            if (System.currentTimeMillis() % 2 == 0) {
                throw new RuntimeException("Random failure in cleanup");
            }
        }
    }

    public void bad_case_14() {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream("output.log");
            fos.write("Log message".getBytes());
        } catch (IOException e) {
            logger.severe("Failed to write to log: " + e.getMessage());
        } finally {
            if (fos != null) {
                try {
                    fos.flush();
                    fos.close();
                } catch (IOException e) {
                    // ruleid: java-throw-inside-finally
                    throw new IllegalStateException("Failed to flush and close log file", e);
                }
            }
        }
    }

    public void bad_case_15() {
        ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
        ClassLoader tempClassLoader = new ClassLoader() {};
        
        try {
            Thread.currentThread().setContextClassLoader(tempClassLoader);
            // Perform operations with temporary class loader
        } catch (Exception e) {
            logger.severe("Class loading error: " + e.getMessage());
        } finally {
            // ruleid: java-throw-inside-finally
            if (Thread.currentThread().getContextClassLoader() != tempClassLoader) {
                throw new IllegalStateException("ClassLoader was unexpectedly changed");
            }
            Thread.currentThread().setContextClassLoader(originalClassLoader);
        }
    }

    // True Negative Examples (Good Cases)

    public void good_case_1() {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream("config.properties");
            // Process file
        } catch (IOException e) {
            logger.severe("Error reading file: " + e.getMessage());
        } finally {
            try {
                // ok: java-throw-inside-finally
                if (fis != null) {
                    fis.close();
                }
            } catch (IOException e) {
                logger.severe("Failed to close file: " + e.getMessage());
            }
        }
    }

    public void good_case_2() {
        Connection conn = null;
        Statement stmt = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            stmt = conn.createStatement();
            stmt.executeUpdate("UPDATE users SET status = 'active' WHERE id = 1");
        } catch (SQLException e) {
            logger.severe("Database error: " + e.getMessage());
        } finally {
            // ok: java-throw-inside-finally
            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException e) {
                    logger.warning("Error closing statement: " + e.getMessage());
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    logger.warning("Error closing connection: " + e.getMessage());
                }
            }
        }
    }

    public void good_case_3() {
        Lock lock = new ReentrantLock();
        try {
            lock.lock();
            // Critical section
            performOperation();
        } catch (Exception e) {
            logger.severe("Operation failed: " + e.getMessage());
            throw e; // Re-throwing from catch is fine
        } finally {
            // ok: java-throw-inside-finally
            if (lock.isHeldByCurrentThread()) {
                lock.unlock();
            }
        }
    }

    public void good_case_4() {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader("data.txt"));
            String line;
            while ((line = reader.readLine()) != null) {
                processLine(line);
            }
        } catch (IOException e) {
            logger.warning("Error reading file: " + e.getMessage());
            throw new RuntimeException("File processing failed", e); // Re-throwing from catch is fine
        } finally {
            // ok: java-throw-inside-finally
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    logger.severe("Failed to close reader: " + e.getMessage());
                }
            }
        }
    }

    public void good_case_5() {
        InputStream is = null;
        OutputStream os = null;
        try {
            is = new FileInputStream("source.dat");
            os = new FileOutputStream("destination.dat");
            byte[] buffer = new byte[1024];
            int length;
            while ((length = is.read(buffer)) > 0) {
                os.write(buffer, 0, length);
            }
        } catch (IOException e) {
            logger.severe("Copy failed: " + e.getMessage());
        } finally {
            // ok: java-throw-inside-finally
            closeQuietly(is);
            closeQuietly(os);
        }
    }

    private void closeQuietly(AutoCloseable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (Exception e) {
                logger.warning("Error during resource closing: " + e.getMessage());
            }
        }
    }

    public void good_case_6() {
        SecretKey key = null;
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            key = keyGen.generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // Use cipher for encryption/decryption
        } catch (Exception e) {
            logger.severe("Encryption error: " + e.getMessage());
            throw new SecurityException("Encryption failed", e); // Re-throwing from catch is fine
        } finally {
            // ok: java-throw-inside-finally
            // Proper cleanup without throwing
            if (key != null) {
                // Secure key cleanup would go here
                logger.info("Key cleanup completed");
            }
        }
    }

    public void good_case_7() {
        Socket socket = null;
        try {
            socket = new Socket("localhost", 8080);
            // Communicate with server
        } catch (IOException e) {
            logger.severe("Network error: " + e.getMessage());
        } finally {
            // ok: java-throw-inside-finally
            if (socket != null && !socket.isClosed()) {
                try {
                    socket.close();
                } catch (IOException e) {
                    logger.warning("Failed to close socket: " + e.getMessage());
                }
            }
        }
    }

    public void good_case_8() {
        List<String> resources = new ArrayList<>();
        try {
            resources.add("Resource1");
            resources.add("Resource2");
            // Use resources
        } catch (Exception e) {
            logger.severe("Error using resources: " + e.getMessage());
        } finally {
            // ok: java-throw-inside-finally
            for (String resource : resources) {
                try {
                    // Clean up resource
                    logger.info("Cleaning up: " + resource);
                } catch (Exception e) {
                    logger.warning("Failed to clean up " + resource + ": " + e.getMessage());
                }
            }
        }
    }

    public void good_case_9() {
        Thread worker = new Thread(() -> {
            // Do background work
        });
        
        try {
            worker.start();
            worker.join(1000);
        } catch (InterruptedException e) {
            logger.warning("Worker thread interrupted");
            Thread.currentThread().interrupt(); // Restore interrupt status
        } finally {
            // ok: java-throw-inside-finally
            if (worker.isAlive()) {
                worker.interrupt();
                logger.warning("Thread did not terminate within timeout");
            }
        }
    }

    public void good_case_10() {
        Object lock = new Object();
        boolean locked = false;
        
        try {
            synchronized(lock) {
                locked = true;
                // Critical section
            }
        } catch (Exception e) {
            logger.severe("Error in critical section: " + e.getMessage());
            throw e; // Re-throwing from catch is fine
        } finally {
            // ok: java-throw-inside-finally
            if (locked) {
                // Some cleanup
                logger.info("Cleanup completed");
            }
        }
    }

    public void good_case_11() {
        FileInputStream fis1 = null;
        FileInputStream fis2 = null;
        
        try {
            fis1 = new FileInputStream("file1.txt");
            fis2 = new FileInputStream("file2.txt");
            // Process files
        } catch (IOException e) {
            logger.severe("File processing error: " + e.getMessage());
        } finally {
            // ok: java-throw-inside-finally
            try {
                if (fis1 != null) fis1.close();
            } catch (IOException e) {
                logger.warning("Error closing first file: " + e.getMessage());
            }
            
            try {
                if (fis2 != null) fis2.close();
            } catch (IOException e) {
                logger.warning("Error closing second file: " + e.getMessage());
            }
        }
    }

    public void good_case_12() {
        Connection conn = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            boolean autoCommit = conn.getAutoCommit();
            conn.setAutoCommit(false);
            
            // Database operations
            conn.commit();
        } catch (SQLException e) {
            try {
                if (conn != null) conn.rollback();
            } catch (SQLException rollbackEx) {
                logger.severe("Rollback failed: " + rollbackEx.getMessage());
            }
            throw new RuntimeException("Database operation failed", e); // Re-throwing from catch is fine
        } finally {
            // ok: java-throw-inside-finally
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    logger.warning("Database connection couldn't be closed: " + e.getMessage());
                }
            }
        }
    }

    public void good_case_13() {
        boolean cleanupFailed = false;
        Exception cleanupException = null;
        
        try {
            // Some operation
            int result = 10 / 0; // Will throw ArithmeticException
        } catch (ArithmeticException e) {
            logger.warning("Division by zero");
        } finally {
            // ok: java-throw-inside-finally
            try {
                // Cleanup code that might fail
                if (System.currentTimeMillis() % 2 == 0) {
                    throw new IOException("Simulated cleanup failure");
                }
            } catch (Exception e) {
                cleanupFailed = true;
                cleanupException = e;
                logger.warning("Cleanup failed: " + e.getMessage());
            }
        }
        
        // Handle cleanup failure outside finally
        if (cleanupFailed) {
            throw new RuntimeException("Cleanup failed", cleanupException);
        }
    }

    public void good_case_14() {
        FileOutputStream fos = null;
        boolean closeError = false;
        Exception closeException = null;
        
        try {
            fos = new FileOutputStream("output.log");
            fos.write("Log message".getBytes());
        } catch (IOException e) {
            logger.severe("Failed to write to log: " + e.getMessage());
        } finally {
            // ok: java-throw-inside-finally
            if (fos != null) {
                try {
                    fos.flush();
                    fos.close();
                } catch (IOException e) {
                    closeError = true;
                    closeException = e;
                    logger.warning("Failed to flush and close log file: " + e.getMessage());
                }
            }
        }
        
        // Handle close error outside finally
        if (closeError) {
            throw new IllegalStateException("Failed to close resources properly", closeException);
        }
    }

    public void good_case_15() {
        ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
        ClassLoader tempClassLoader = new ClassLoader() {};
        
        try {
            Thread.currentThread().setContextClassLoader(tempClassLoader);
            // Perform operations with temporary class loader
        } catch (Exception e) {
            logger.severe("Class loading error: " + e.getMessage());
            throw e; // Re-throwing from catch is fine
        } finally {
            // ok: java-throw-inside-finally
            Thread.currentThread().setContextClassLoader(originalClassLoader);
            logger.info("ClassLoader restored");
        }
    }

    // Helper methods
    private void performOperation() {
        // Implementation
    }
    
    private void processLine(String line) {
        // Implementation
    }
}
// {/fact}