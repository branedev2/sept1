import java.io.*;
import java.sql.*;
import java.net.*;
import java.util.*;
import java.nio.file.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.apache.http.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import com.mongodb.*;
import redis.clients.jedis.*;
import org.springframework.web.client.*;
import org.apache.commons.io.*;
import org.apache.commons.net.ftp.*;
import javax.jms.*;
import org.hibernate.*;
import com.fasterxml.jackson.databind.*;
import com.google.cloud.storage.*;

// Security Issue: Throwing exceptions inside finally blocks can prevent proper cleanup and lead to resource leaks

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    // JDBC connection with throw inside finally
    Connection conn = null;
    Statement stmt = null;
    try {
        conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users");
    } catch (SQLException e) {
        e.printStackTrace();
    } finally {
        try {
            if (stmt != null) stmt.close();
            if (conn != null) conn.close();
        } catch (SQLException e) {
            // ruleid: java-throw-inside-finally
            throw new RuntimeException("Failed to close database resources", e);
        }
    }
}

public void bad_case_2() {
    // File handling with Apache Commons IO
    FileInputStream fis = null;
    try {
        fis = new FileInputStream("config.properties");
        Properties props = new Properties();
        props.load(fis);
    } catch (IOException e) {
        System.err.println("Error loading properties: " + e.getMessage());
    } finally {
        if (fis != null) {
            try {
                fis.close();
            } catch (IOException e) {
                // ruleid: java-throw-inside-finally
                throw new IllegalStateException("Could not close file stream", e);
            }
        }
    }
}

public void bad_case_3(HttpServletRequest request) {
    // Spring RestTemplate with throw in finally
    RestTemplate restTemplate = new RestTemplate();
    String url = request.getParameter("apiUrl");
    InputStream responseStream = null;
    
    try {
        responseStream = restTemplate.execute(url, HttpMethod.GET, null, response -> {
            return response.getBody();
        });
        // Process the response stream
    } catch (Exception e) {
        System.err.println("API request failed: " + e.getMessage());
    } finally {
        try {
            if (responseStream != null) {
                responseStream.close();
            }
        } catch (IOException e) {
            // ruleid: java-throw-inside-finally
            throw new RuntimeException("Failed to close response stream", e);
        }
    }
}

public void bad_case_4() {
    // MongoDB connection with throw in finally
    MongoClient mongoClient = null;
    try {
        mongoClient = new MongoClient("localhost", 27017);
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("users");
        // Perform operations
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        try {
            if (mongoClient != null) {
                mongoClient.close();
                System.out.println("MongoDB connection closed");
            }
        } catch (Exception e) {
            // ruleid: java-throw-inside-finally
            throw new RuntimeException("Failed to close MongoDB client", e);
        }
    }
}

public void bad_case_5() {
    // Redis connection with throw in finally
    Jedis jedis = null;
    try {
        jedis = new Jedis("localhost");
        jedis.set("key", "value");
    } catch (Exception e) {
        System.err.println("Redis operation failed: " + e.getMessage());
    } finally {
        try {
            if (jedis != null) {
                jedis.close();
            }
        } catch (Exception e) {
            // ruleid: java-throw-inside-finally
            throw new IllegalStateException("Failed to close Redis connection", e);
        }
    }
}

public void bad_case_6(HttpServletRequest request) {
    // AWS S3 client with throw in finally
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String bucketName = request.getParameter("bucket");
    InputStream inputStream = null;
    
    try {
        S3Object s3Object = s3Client.getObject(bucketName, "file.txt");
        inputStream = s3Object.getObjectContent();
        // Process the input stream
    } catch (Exception e) {
        System.err.println("S3 operation failed: " + e.getMessage());
    } finally {
        try {
            if (inputStream != null) {
                inputStream.close();
            }
        } catch (IOException e) {
            // ruleid: java-throw-inside-finally
            throw new RuntimeException("Failed to close S3 input stream", e);
        }
    }
}

public void bad_case_7() {
    // FTP client with throw in finally
    FTPClient ftpClient = new FTPClient();
    try {
        ftpClient.connect("ftp.example.com");
        ftpClient.login("username", "password");
        ftpClient.retrieveFile("remote.txt", new FileOutputStream("local.txt"));
    } catch (IOException e) {
        System.err.println("FTP operation failed: " + e.getMessage());
    } finally {
        try {
            if (ftpClient.isConnected()) {
                ftpClient.disconnect();
            }
        } catch (IOException e) {
            // ruleid: java-throw-inside-finally
            throw new RuntimeException("Failed to disconnect FTP client", e);
        }
    }
}

public void bad_case_8() {
    // JMS connection with throw in finally
    Connection connection = null;
    Session session = null;
    
    try {
        ConnectionFactory factory = new ActiveMQConnectionFactory("tcp://localhost:61616");
        connection = factory.createConnection();
        session = connection.createSession(false, Session.AUTO_AC_REDACTED_TWILIO_ID);
        // Perform JMS operations
    } catch (JMSException e) {
        System.err.println("JMS operation failed: " + e.getMessage());
    } finally {
        try {
            if (session != null) session.close();
            if (connection != null) connection.close();
        } catch (JMSException e) {
            // ruleid: java-throw-inside-finally
            throw new RuntimeException("Failed to close JMS resources", e);
        }
    }
}

public void bad_case_9() {
    // Hibernate session with throw in finally
    Session session = null;
    Transaction tx = null;
    
    try {
        session = HibernateUtil.getSessionFactory().openSession();
        tx = session.beginTransaction();
        // Perform database operations
        tx.commit();
    } catch (Exception e) {
        if (tx != null) tx.rollback();
        System.err.println("Hibernate operation failed: " + e.getMessage());
    } finally {
        try {
            if (session != null) {
                session.close();
            }
        } catch (Exception e) {
            // ruleid: java-throw-inside-finally
            throw new RuntimeException("Failed to close Hibernate session", e);
        }
    }
}

public void bad_case_10(HttpServletRequest request) {
    // Jackson ObjectMapper with throw in finally
    InputStream inputStream = null;
    try {
        String fileName = request.getParameter("configFile");
        inputStream = new FileInputStream(fileName);
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> data = mapper.readValue(inputStream, Map.class);
        // Process the data
    } catch (IOException e) {
        System.err.println("JSON parsing failed: " + e.getMessage());
    } finally {
        try {
            if (inputStream != null) {
                inputStream.close();
            }
        } catch (IOException e) {
            // ruleid: java-throw-inside-finally
            throw new RuntimeException("Failed to close input stream", e);
        }
    }
}

public void bad_case_11() {
    // Google Cloud Storage with throw in finally
    Storage storage = StorageOptions.getDefaultInstance().getService();
    ReadChannel reader = null;
    
    try {
        reader = storage.reader("bucket-name", "object-name");
        ByteBuffer bytes = ByteBuffer.allocate(64 * 1024);
        reader.read(bytes);
        // Process bytes
    } catch (IOException e) {
        System.err.println("GCS operation failed: " + e.getMessage());
    } finally {
        try {
            if (reader != null) {
                reader.close();
            }
        } catch (IOException e) {
            // ruleid: java-throw-inside-finally
            throw new RuntimeException("Failed to close GCS reader", e);
        }
    }
}

public void bad_case_12(HttpServletRequest request) {
    // Apache HttpClient with throw in finally
    CloseableHttpClient httpClient = HttpClients.createDefault();
    CloseableHttpResponse response = null;
    
    try {
        String url = request.getParameter("url");
        HttpGet httpGet = new HttpGet(url);
        response = httpClient.execute(httpGet);
        // Process response
    } catch (IOException e) {
        System.err.println("HTTP request failed: " + e.getMessage());
    } finally {
        try {
            if (response != null) {
                response.close();
            }
            httpClient.close();
        } catch (IOException e) {
            // ruleid: java-throw-inside-finally
            throw new RuntimeException("Failed to close HTTP resources", e);
        }
    }
}

public void bad_case_13() {
    // NIO Path operations with throw in finally
    DirectoryStream<Path> directoryStream = null;
    try {
        directoryStream = Files.newDirectoryStream(Paths.get("/tmp"));
        for (Path path : directoryStream) {
            // Process each file
            System.out.println(path);
        }
    } catch (IOException e) {
        System.err.println("Directory listing failed: " + e.getMessage());
    } finally {
        try {
            if (directoryStream != null) {
                directoryStream.close();
            }
        } catch (IOException e) {
            // ruleid: java-throw-inside-finally
            throw new RuntimeException("Failed to close directory stream", e);
        }
    }
}

public void bad_case_14(HttpServletRequest request, HttpServletResponse response) {
    // Servlet output stream with throw in finally
    OutputStream outputStream = null;
    try {
        outputStream = response.getOutputStream();
        String message = request.getParameter("message");
        outputStream.write(message.getBytes());
    } catch (IOException e) {
        System.err.println("Failed to write to output stream: " + e.getMessage());
    } finally {
        try {
            if (outputStream != null) {
                outputStream.close();
            }
        } catch (IOException e) {
            // ruleid: java-throw-inside-finally
            throw new RuntimeException("Failed to close servlet output stream", e);
        }
    }
}

public void bad_case_15() {
    // URL connection with throw in finally
    URLConnection connection = null;
    InputStream inputStream = null;
    
    try {
        URL url = new URL("https://example.com");
        connection = url.openConnection();
        inputStream = connection.getInputStream();
        // Process the input stream
    } catch (IOException e) {
        System.err.println("URL connection failed: " + e.getMessage());
    } finally {
        try {
            if (inputStream != null) {
                inputStream.close();
            }
        } catch (IOException e) {
            // ruleid: java-throw-inside-finally
            throw new RuntimeException("Failed to close URL connection", e);
        }
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    // JDBC connection without throw inside finally
    Connection conn = null;
    Statement stmt = null;
    try {
        conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users");
    } catch (SQLException e) {
        e.printStackTrace();
    } finally {
        try {
            if (stmt != null) stmt.close();
            if (conn != null) conn.close();
        } catch (SQLException e) {
            // ok: java-throw-inside-finally
            System.err.println("Failed to close database resources: " + e.getMessage());
            // Log the error but don't throw
        }
    }
}

public void good_case_2() {
    // File handling with Apache Commons IO - safe approach
    FileInputStream fis = null;
    try {
        fis = new FileInputStream("config.properties");
        Properties props = new Properties();
        props.load(fis);
    } catch (IOException e) {
        System.err.println("Error loading properties: " + e.getMessage());
    } finally {
        if (fis != null) {
            try {
                fis.close();
            } catch (IOException e) {
                // ok: java-throw-inside-finally
                System.err.println("Could not close file stream: " + e.getMessage());
            }
        }
    }
}

public void good_case_3(HttpServletRequest request) {
    // Spring RestTemplate with safe finally block
    RestTemplate restTemplate = new RestTemplate();
    String url = request.getParameter("apiUrl");
    InputStream responseStream = null;
    
    try {
        responseStream = restTemplate.execute(url, HttpMethod.GET, null, response -> {
            return response.getBody();
        });
        // Process the response stream
    } catch (Exception e) {
        System.err.println("API request failed: " + e.getMessage());
    } finally {
        try {
            if (responseStream != null) {
                responseStream.close();
            }
        } catch (IOException e) {
            // ok: java-throw-inside-finally
            System.err.println("Failed to close response stream: " + e.getMessage());
        }
    }
}

public void good_case_4() {
    // MongoDB connection with safe finally
    MongoClient mongoClient = null;
    try {
        mongoClient = new MongoClient("localhost", 27017);
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("users");
        // Perform operations
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        try {
            if (mongoClient != null) {
                mongoClient.close();
            }
        } catch (Exception e) {
            // ok: java-throw-inside-finally
            System.err.println("Failed to close MongoDB client: " + e.getMessage());
        }
    }
}

public void good_case_5() {
    // Redis connection with safe finally
    Jedis jedis = null;
    try {
        jedis = new Jedis("localhost");
        jedis.set("key", "value");
    } catch (Exception e) {
        System.err.println("Redis operation failed: " + e.getMessage());
    } finally {
        try {
            if (jedis != null) {
                jedis.close();
            }
        } catch (Exception e) {
            // ok: java-throw-inside-finally
            System.err.println("Failed to close Redis connection: " + e.getMessage());
        }
    }
}

public void good_case_6(HttpServletRequest request) {
    // AWS S3 client with safe finally
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String bucketName = request.getParameter("bucket");
    InputStream inputStream = null;
    
    try {
        S3Object s3Object = s3Client.getObject(bucketName, "file.txt");
        inputStream = s3Object.getObjectContent();
        // Process the input stream
    } catch (Exception e) {
        System.err.println("S3 operation failed: " + e.getMessage());
    } finally {
        try {
            if (inputStream != null) {
                inputStream.close();
            }
        } catch (IOException e) {
            // ok: java-throw-inside-finally
            System.err.println("Failed to close S3 input stream: " + e.getMessage());
        }
    }
}

public void good_case_7() {
    // FTP client with safe finally
    FTPClient ftpClient = new FTPClient();
    try {
        ftpClient.connect("ftp.example.com");
        ftpClient.login("username", "password");
        ftpClient.retrieveFile("remote.txt", new FileOutputStream("local.txt"));
    } catch (IOException e) {
        System.err.println("FTP operation failed: " + e.getMessage());
    } finally {
        try {
            if (ftpClient.isConnected()) {
                ftpClient.disconnect();
            }
        } catch (IOException e) {
            // ok: java-throw-inside-finally
            System.err.println("Failed to disconnect FTP client: " + e.getMessage());
        }
    }
}

public void good_case_8() {
    // JMS connection with safe finally
    Connection connection = null;
    Session session = null;
    
    try {
        ConnectionFactory factory = new ActiveMQConnectionFactory("tcp://localhost:61616");
        connection = factory.createConnection();
        session = connection.createSession(false, Session.AUTO_AC_REDACTED_TWILIO_ID);
        // Perform JMS operations
    } catch (JMSException e) {
        System.err.println("JMS operation failed: " + e.getMessage());
    } finally {
        try {
            if (session != null) session.close();
        } catch (JMSException e) {
            // ok: java-throw-inside-finally
            System.err.println("Failed to close JMS session: " + e.getMessage());
        }
        try {
            if (connection != null) connection.close();
        } catch (JMSException e) {
            // ok: java-throw-inside-finally
            System.err.println("Failed to close JMS connection: " + e.getMessage());
        }
    }
}

public void good_case_9() {
    // Hibernate session with safe finally
    Session session = null;
    Transaction tx = null;
    
    try {
        session = HibernateUtil.getSessionFactory().openSession();
        tx = session.beginTransaction();
        // Perform database operations
        tx.commit();
    } catch (Exception e) {
        if (tx != null) tx.rollback();
        System.err.println("Hibernate operation failed: " + e.getMessage());
    } finally {
        try {
            if (session != null) {
                session.close();
            }
        } catch (Exception e) {
            // ok: java-throw-inside-finally
            System.err.println("Failed to close Hibernate session: " + e.getMessage());
        }
    }
}

public void good_case_10(HttpServletRequest request) {
    // Jackson ObjectMapper with safe finally
    InputStream inputStream = null;
    try {
        String fileName = request.getParameter("configFile");
        inputStream = new FileInputStream(fileName);
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> data = mapper.readValue(inputStream, Map.class);
        // Process the data
    } catch (IOException e) {
        System.err.println("JSON parsing failed: " + e.getMessage());
    } finally {
        try {
            if (inputStream != null) {
                inputStream.close();
            }
        } catch (IOException e) {
            // ok: java-throw-inside-finally
            System.err.println("Failed to close input stream: " + e.getMessage());
        }
    }
}

public void good_case_11() {
    // Google Cloud Storage with safe finally
    Storage storage = StorageOptions.getDefaultInstance().getService();
    ReadChannel reader = null;
    
    try {
        reader = storage.reader("bucket-name", "object-name");
        ByteBuffer bytes = ByteBuffer.allocate(64 * 1024);
        reader.read(bytes);
        // Process bytes
    } catch (IOException e) {
        System.err.println("GCS operation failed: " + e.getMessage());
    } finally {
        try {
            if (reader != null) {
                reader.close();
            }
        } catch (IOException e) {
            // ok: java-throw-inside-finally
            System.err.println("Failed to close GCS reader: " + e.getMessage());
        }
    }
}

public void good_case_12(HttpServletRequest request) {
    // Apache HttpClient with safe finally using try-with-resources
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
        String url = request.getParameter("url");
        HttpGet httpGet = new HttpGet(url);
        
        try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
            // Process response
        }
        // ok: java-throw-inside-finally
        // No need for explicit finally block with try-with-resources
    } catch (IOException e) {
        System.err.println("HTTP request failed: " + e.getMessage());
    }
}

public void good_case_13() {
    // NIO Path operations with safe finally using try-with-resources
    try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(Paths.get("/tmp"))) {
        for (Path path : directoryStream) {
            // Process each file
            System.out.println(path);
        }
        // ok: java-throw-inside-finally
        // No need for explicit finally block with try-with-resources
    } catch (IOException e) {
        System.err.println("Directory listing failed: " + e.getMessage());
    }
}

public void good_case_14(HttpServletRequest request, HttpServletResponse response) {
    // Servlet output stream with safe finally
    OutputStream outputStream = null;
    try {
        outputStream = response.getOutputStream();
        String message = request.getParameter("message");
        outputStream.write(message.getBytes());
    } catch (IOException e) {
        System.err.println("Failed to write to output stream: " + e.getMessage());
    } finally {
        try {
            if (outputStream != null) {
                outputStream.flush();
                // Note: In servlets, the container manages closing the stream
            }
        } catch (IOException e) {
            // ok: java-throw-inside-finally
            System.err.println("Failed to flush servlet output stream: " + e.getMessage());
        }
    }
}

public void good_case_15() {
    // URL connection with safe finally
    InputStream inputStream = null;
    
    try {
        URL url = new URL("https://example.com");
        URLConnection connection = url.openConnection();
        inputStream = connection.getInputStream();
        // Process the input stream
    } catch (IOException e) {
        System.err.println("URL connection failed: " + e.getMessage());
    } finally {
        if (inputStream != null) {
            try {
                inputStream.close();
            } catch (IOException e) {
                // ok: java-throw-inside-finally
                System.err.println("Failed to close URL connection: " + e.getMessage());
            }
        }
    }
}