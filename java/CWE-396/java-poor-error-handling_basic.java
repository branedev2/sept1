import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public class PoorErrorHandlingExamples {

    // True Positive Examples (Bad Cases)

// {fact rule=do-not-catch-and-throw-exception@v1.0 defects=1}
    public void bad_case_1(String filename) {
        try {
            FileInputStream fis = new FileInputStream(filename);
            byte[] data = new byte[1024];
            fis.read(data);
            fis.close();
            // Process data...
        } catch (Exception e) {
            // ruleid: java-poor-error-handling
            System.out.println("Error: " + e.getMessage());
        }
    }

    public void bad_case_2(HttpServletRequest request) {
        Connection conn = null;
        try {
            String username = request.getParameter("username");
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            // Process results...
            conn.close();
        } catch (Exception e) {
            // ruleid: java-poor-error-handling
            e.printStackTrace();
        }
    }

    public void bad_case_3(String url) {
        try {
            URL apiUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            // Process response...
        } catch (Exception e) {
            // ruleid: java-poor-error-handling
            System.err.println("Failed to connect: " + e.getMessage());
        }
    }

    public void bad_case_4() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // Use cipher...
        } catch (Exception e) {
            // ruleid: java-poor-error-handling
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) {
        try {
            String action = request.getParameter("action");
            if ("delete".equals(action)) {
                // Delete user account
            } else if ("update".equals(action)) {
                // Update user account
            }
            response.sendRedirect("/dashboard");
        } catch (Exception e) {
            // ruleid: java-poor-error-handling
            response.setStatus(500);
        }
    }

    public List<String> bad_case_6(String directoryPath) {
        List<String> fileNames = new ArrayList<>();
        try {
            File directory = new File(directoryPath);
            File[] files = directory.listFiles();
            for (File file : files) {
                fileNames.add(file.getName());
            }
        } catch (Exception e) {
            // ruleid: java-poor-error-handling
            System.out.println("Error listing files: " + e.getMessage());
        }
        return fileNames;
    }

    public void bad_case_7(String configFile) {
        Properties props = new Properties();
        try {
            FileInputStream fis = new FileInputStream(configFile);
            props.load(fis);
            fis.close();
            // Use properties...
        } catch (Exception e) {
            // ruleid: java-poor-error-handling
            System.err.println("Configuration error");
        }
    }

    public void bad_case_8(String algorithm) {
        try {
            SSLContext sslContext = SSLContext.getInstance(algorithm);
            sslContext.init(null, null, null);
            // Use SSL context...
        } catch (Exception e) {
            // ruleid: java-poor-error-handling
            System.out.println("SSL error occurred: " + e);
        }
    }

    public void bad_case_9(HttpServletRequest request) {
        try {
            String userId = request.getParameter("id");
            int id = Integer.parseInt(userId);
            // Use id...
        } catch (Exception e) {
            // ruleid: java-poor-error-handling
            System.out.println("Invalid input");
        }
    }

    public void bad_case_10(String[] fileNames) {
        for (String fileName : fileNames) {
            try {
                FileInputStream fis = new FileInputStream(fileName);
                // Process file...
                fis.close();
            } catch (Exception e) {
                // ruleid: java-poor-error-handling
                continue; // Silently skip and continue with next file
            }
        }
    }

    public void bad_case_11(Connection conn, String query) {
        try {
            PreparedStatement stmt = conn.prepareStatement(query);
            ResultSet rs = stmt.executeQuery();
            // Process results...
        } catch (Exception e) {
            // ruleid: java-poor-error-handling
            // Empty catch block completely ignores the error
        }
    }

    public void bad_case_12(String url) {
        try {
            URL apiUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            // Send data...
            int responseCode = connection.getResponseCode();
        } catch (Exception e) {
            // ruleid: java-poor-error-handling
            System.out.println("Error: " + e.getClass().getName());
            // No specific handling for different exception types
        }
    }

    public void bad_case_13() {
        try {
            // Multiple operations that could fail for different reasons
            File file = new File("config.txt");
            FileInputStream fis = new FileInputStream(file);
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            // More operations...
        } catch (Exception e) {
            // ruleid: java-poor-error-handling
            System.err.println("Operation failed");
            // No way to distinguish between file error and database error
        }
    }

    public void bad_case_14(HttpServletRequest request) {
        try {
            String value = request.getParameter("value");
            double number = Double.parseDouble(value);
            if (number < 0) {
                throw new IllegalArgumentException("Value must be positive");
            }
            // Use number...
        } catch (Exception e) {
            // ruleid: java-poor-error-handling
            // Cannot distinguish between parsing error and validation error
            System.out.println("Invalid input: " + e.getMessage());
        }
    }

    public void bad_case_15(String filename) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(filename);
            // Process file...
        } catch (Exception e) {
            // ruleid: java-poor-error-handling
            System.err.println("Error processing file");
        } finally {
            try {
                if (fis != null) fis.close();
            } catch (Exception e) {
                // Another overly broad catch
                System.err.println("Error closing file");
            }
        }
    }

    // True Negative Examples (Good Cases)

    public void good_case_1(String filename) {
        try {
            FileInputStream fis = new FileInputStream(filename);
            byte[] data = new byte[1024];
            fis.read(data);
            fis.close();
            // Process data...
        } catch (FileNotFoundException e) {
            // ok: java-poor-error-handling
            System.out.println("File not found: " + filename);
        } catch (IOException e) {
            // ok: java-poor-error-handling
            System.out.println("Error reading file: " + e.getMessage());
        }
    }

    public void good_case_2(HttpServletRequest request) {
        Connection conn = null;
        try {
            String username = request.getParameter("username");
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            // Process results...
        } catch (SQLException e) {
            // ok: java-poor-error-handling
            System.err.println("Database error: " + e.getMessage());
        } finally {
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    System.err.println("Error closing connection: " + e.getMessage());
                }
            }
        }
    }

    public void good_case_3(String url) {
        try {
            URL apiUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            // Process response...
        } catch (IOException e) {
            // ok: java-poor-error-handling
            System.err.println("Network error: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            // ok: java-poor-error-handling
            System.err.println("Invalid URL format: " + e.getMessage());
        }
    }

    public void good_case_4() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // Use cipher...
        } catch (NoSuchAlgorithmException e) {
            // ok: java-poor-error-handling
            throw new RuntimeException("Algorithm not supported", e);
        } catch (NoSuchPaddingException e) {
            // ok: java-poor-error-handling
            throw new RuntimeException("Padding not supported", e);
        }
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) {
        try {
            String action = request.getParameter("action");
            if ("delete".equals(action)) {
                // Delete user account
            } else if ("update".equals(action)) {
                // Update user account
            }
            response.sendRedirect("/dashboard");
        } catch (IOException e) {
            // ok: java-poor-error-handling
            System.err.println("Error redirecting: " + e.getMessage());
            try {
                response.setStatus(500);
                response.getWriter().write("Internal server error");
            } catch (IOException ex) {
                System.err.println("Failed to send error response: " + ex.getMessage());
            }
        }
    }

    public List<String> good_case_6(String directoryPath) {
        List<String> fileNames = new ArrayList<>();
        try {
            File directory = new File(directoryPath);
            File[] files = directory.listFiles();
            if (files == null) {
                System.err.println("Not a directory or I/O error: " + directoryPath);
                return fileNames;
            }
            for (File file : files) {
                fileNames.add(file.getName());
            }
        } catch (SecurityException e) {
            // ok: java-poor-error-handling
            System.err.println("Access denied to directory: " + e.getMessage());
        } catch (NullPointerException e) {
            // ok: java-poor-error-handling
            System.err.println("Directory path is null");
        }
        return fileNames;
    }

    public void good_case_7(String configFile) {
        Properties props = new Properties();
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(configFile);
            props.load(fis);
            // Use properties...
        } catch (FileNotFoundException e) {
            // ok: java-poor-error-handling
            System.err.println("Configuration file not found: " + configFile);
        } catch (IOException e) {
            // ok: java-poor-error-handling
            System.err.println("Error reading configuration: " + e.getMessage());
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    System.err.println("Error closing file: " + e.getMessage());
                }
            }
        }
    }

    public void good_case_8(String algorithm) {
        try {
            SSLContext sslContext = SSLContext.getInstance(algorithm);
            sslContext.init(null, null, null);
            // Use SSL context...
        } catch (NoSuchAlgorithmException e) {
            // ok: java-poor-error-handling
            System.err.println("SSL algorithm not supported: " + algorithm);
        } catch (KeyManagementException e) {
            // ok: java-poor-error-handling
            System.err.println("SSL key management error: " + e.getMessage());
        }
    }

    public void good_case_9(HttpServletRequest request) {
        try {
            String userId = request.getParameter("id");
            int id = Integer.parseInt(userId);
            // Use id...
        } catch (NumberFormatException e) {
            // ok: java-poor-error-handling
            System.out.println("Invalid user ID format: " + e.getMessage());
        } catch (NullPointerException e) {
            // ok: java-poor-error-handling
            System.out.println("User ID parameter is missing");
        }
    }

    public void good_case_10(String[] fileNames) {
        for (String fileName : fileNames) {
            FileInputStream fis = null;
            try {
                fis = new FileInputStream(fileName);
                // Process file...
            } catch (FileNotFoundException e) {
                // ok: java-poor-error-handling
                System.err.println("File not found: " + fileName);
                continue;
            } catch (IOException e) {
                // ok: java-poor-error-handling
                System.err.println("Error reading file " + fileName + ": " + e.getMessage());
                continue;
            } finally {
                if (fis != null) {
                    try {
                        fis.close();
                    } catch (IOException e) {
                        System.err.println("Error closing file: " + e.getMessage());
                    }
                }
            }
        }
    }

    public void good_case_11(Connection conn, String query) {
        try {
            PreparedStatement stmt = conn.prepareStatement(query);
            ResultSet rs = stmt.executeQuery();
            // Process results...
        } catch (SQLException e) {
            // ok: java-poor-error-handling
            if (e.getErrorCode() == 1064) {
                System.err.println("SQL syntax error: " + e.getMessage());
            } else if (e.getErrorCode() == 1146) {
                System.err.println("Table doesn't exist: " + e.getMessage());
            } else {
                System.err.println("Database error: " + e.getMessage());
            }
        }
    }

    public void good_case_12(String url) {
        try {
            URL apiUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            // Send data...
            int responseCode = connection.getResponseCode();
        } catch (IOException e) {
            // ok: java-poor-error-handling
            if (e instanceof SSLHandshakeException) {
                System.err.println("SSL certificate error: " + e.getMessage());
            } else {
                System.err.println("Network error: " + e.getMessage());
            }
        } catch (IllegalArgumentException e) {
            // ok: java-poor-error-handling
            System.err.println("Invalid URL: " + e.getMessage());
        }
    }

    public void good_case_13() {
        // Handle file operations
        FileInputStream fis = null;
        Connection conn = null;
        try {
            File file = new File("config.txt");
            fis = new FileInputStream(file);
            // File operations...
        } catch (FileNotFoundException e) {
            // ok: java-poor-error-handling
            System.err.println("Config file not found: " + e.getMessage());
            return;
        } catch (IOException e) {
            // ok: java-poor-error-handling
            System.err.println("Error reading config file: " + e.getMessage());
            return;
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    System.err.println("Error closing file: " + e.getMessage());
                }
            }
        }
        
        // Handle database operations separately
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            // Database operations...
        } catch (SQLException e) {
            // ok: java-poor-error-handling
            System.err.println("Database error: " + e.getMessage());
        } finally {
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    System.err.println("Error closing connection: " + e.getMessage());
                }
            }
        }
    }

    public void good_case_14(HttpServletRequest request) {
        String value = request.getParameter("value");
        
        // First handle parsing errors
        double number;
        try {
            number = Double.parseDouble(value);
        } catch (NumberFormatException e) {
            // ok: java-poor-error-handling
            System.out.println("Invalid number format: " + e.getMessage());
            return;
        } catch (NullPointerException e) {
            // ok: java-poor-error-handling
            System.out.println("Value parameter is missing");
            return;
        }
        
        // Then handle validation errors
        try {
            if (number < 0) {
                throw new IllegalArgumentException("Value must be positive");
            }
            // Use number...
        } catch (IllegalArgumentException e) {
            // ok: java-poor-error-handling
            System.out.println("Validation error: " + e.getMessage());
        }
    }

    public void good_case_15(String filename) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(filename);
            // Process file...
        } catch (FileNotFoundException e) {
            // ok: java-poor-error-handling
            System.err.println("File not found: " + filename);
        } catch (SecurityException e) {
            // ok: java-poor-error-handling
            System.err.println("Access denied: " + e.getMessage());
        } catch (IOException e) {
            // ok: java-poor-error-handling
            System.err.println("I/O error: " + e.getMessage());
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    System.err.println("Error closing file: " + e.getMessage());
                }
            }
        }
    }
}
// {/fact}