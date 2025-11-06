import java.io.IOException;
import java.sql.SQLException;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.AmazonServiceException;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Retrofit;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.query.Query;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import org.bson.Document;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobContainerClient;
import redis.clients.jedis.Jedis;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import org.apache.commons.io.FileUtils;
import java.io.File;
import org.apache.commons.lang3.StringUtils;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import javax.jms.JMSException;
import javax.jms.MessageProducer;
import javax.jms.Queue;
import javax.jms.Session;
import javax.jms.TextMessage;
import org.apache.commons.net.ftp.FTPClient;

// Security Issue: Catching and re-throwing an exception without any additional operations

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // Spring MVC web framework example
    try {
        String userId = request.getParameter("userId");
        // Some processing with userId
    } catch (Exception e) {
        // ruleid: java-do-not-catch-and-throw-exception
        throw e; // Simply re-throwing the exception without any additional information
    }
}

public void bad_case_2() {
    // Apache HttpClient example
    CloseableHttpClient httpClient = HttpClients.createDefault();
    try {
        HttpGet request = new HttpGet("https://api.example.com/data");
        httpClient.execute(request);
    } catch (IOException e) {
        // ruleid: java-do-not-catch-and-throw-exception
        throw e; // Re-throwing without adding context
    }
}

public void bad_case_3() {
    // AWS SDK example
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    try {
        s3Client.getObject("bucket-name", "object-key");
    } catch (AmazonServiceException e) {
        // ruleid: java-do-not-catch-and-throw-exception
        throw e; // Simply re-throwing AWS exception
    }
}

public void bad_case_4() {
    // OkHttp client example
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
        .url("https://api.example.com/data")
        .build();
    try {
        Response response = client.newCall(request).execute();
    } catch (IOException e) {
        // ruleid: java-do-not-catch-and-throw-exception
        throw e; // Re-throwing without context
    }
}

public void bad_case_5() {
    // Apache Commons Exec example
    CommandLine cmdLine = CommandLine.parse("ls -la");
    DefaultExecutor executor = new DefaultExecutor();
    try {
        executor.execute(cmdLine);
    } catch (IOException e) {
        // ruleid: java-do-not-catch-and-throw-exception
        throw e; // Re-throwing command execution exception
    }
}

public void bad_case_6() {
    // Retrofit API client example
    Retrofit retrofit = new Retrofit.Builder()
        .baseUrl("https://api.example.com/")
        .build();
    
    try {
        // Some retrofit API call
    } catch (Exception e) {
        // ruleid: java-do-not-catch-and-throw-exception
        throw e; // Re-throwing without additional context
    }
}

public void bad_case_7() {
    // Hibernate ORM example
    Session session = null;
    try {
        session = sessionFactory.openSession();
        Query<User> query = session.createQuery("FROM User", User.class);
    } catch (Exception e) {
        // ruleid: java-do-not-catch-and-throw-exception
        throw e; // Re-throwing Hibernate exception
    }
}

public void bad_case_8() {
    // Jackson JSON parsing example
    ObjectMapper mapper = new ObjectMapper();
    try {
        User user = mapper.readValue(jsonString, User.class);
    } catch (IOException e) {
        // ruleid: java-do-not-catch-and-throw-exception
        throw e; // Re-throwing parsing exception
    }
}

public void bad_case_9() {
    // Kafka producer example
    KafkaProducer<String, String> producer = new KafkaProducer<>(properties);
    try {
        producer.send(new ProducerRecord<>("topic", "key", "value"));
    } catch (Exception e) {
        // ruleid: java-do-not-catch-and-throw-exception
        throw e; // Re-throwing Kafka exception
    }
}

public void bad_case_10() {
    // MongoDB client example
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    try {
        MongoCollection<Document> collection = mongoClient.getDatabase("test").getCollection("users");
        collection.insertOne(new Document("name", "John Doe"));
    } catch (Exception e) {
        // ruleid: java-do-not-catch-and-throw-exception
        throw e; // Re-throwing MongoDB exception
    }
}

public void bad_case_11() {
    // Azure Blob Storage example
    BlobContainerClient containerClient = new BlobContainerClient("connection-string", "container-name");
    try {
        BlobClient blobClient = containerClient.getBlobClient("blob-name");
        blobClient.downloadToFile("downloaded-file.txt");
    } catch (Exception e) {
        // ruleid: java-do-not-catch-and-throw-exception
        throw e; // Re-throwing Azure SDK exception
    }
}

public void bad_case_12() {
    // Redis Jedis client example
    Jedis jedis = new Jedis("localhost");
    try {
        jedis.set("key", "value");
    } catch (Exception e) {
        // ruleid: java-do-not-catch-and-throw-exception
        throw e; // Re-throwing Redis exception
    }
}

public void bad_case_13() {
    // RabbitMQ client example
    ConnectionFactory factory = new ConnectionFactory();
    try {
        Connection connection = factory.newConnection();
        Channel channel = connection.createChannel();
        channel.queueDeclare("queue-name", false, false, false, null);
    } catch (Exception e) {
        // ruleid: java-do-not-catch-and-throw-exception
        throw e; // Re-throwing RabbitMQ exception
    }
}

public void bad_case_14() {
    // JSoup HTML parsing example
    try {
        Document doc = Jsoup.connect("https://example.com").get();
    } catch (IOException e) {
        // ruleid: java-do-not-catch-and-throw-exception
        throw e; // Re-throwing JSoup exception
    }
}

public void bad_case_15() {
    // Apache Commons Net FTP client example
    FTPClient ftpClient = new FTPClient();
    try {
        ftpClient.connect("ftp.example.com");
        ftpClient.login("username", "password");
    } catch (IOException e) {
        // ruleid: java-do-not-catch-and-throw-exception
        throw e; // Re-throwing FTP exception
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // Spring MVC web framework example with proper exception handling
    try {
        String userId = request.getParameter("userId");
        // Some processing with userId
    } catch (Exception e) {
        // ok: java-do-not-catch-and-throw-exception
        throw new ServiceException("Error processing user ID: " + e.getMessage(), e);
    }
}

public void good_case_2() {
    // Apache HttpClient example with proper exception handling
    CloseableHttpClient httpClient = HttpClients.createDefault();
    try {
        HttpGet request = new HttpGet("https://api.example.com/data");
        httpClient.execute(request);
    } catch (IOException e) {
        // ok: java-do-not-catch-and-throw-exception
        throw new ApiConnectionException("Failed to connect to API endpoint", e);
    }
}

public void good_case_3() {
    // AWS SDK example with proper exception handling
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    try {
        s3Client.getObject("bucket-name", "object-key");
    } catch (AmazonServiceException e) {
        // ok: java-do-not-catch-and-throw-exception
        throw new StorageException("Failed to retrieve object from S3: " + e.getMessage(), e);
    }
}

public void good_case_4() {
    // OkHttp client example with proper exception handling
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
        .url("https://api.example.com/data")
        .build();
    try {
        Response response = client.newCall(request).execute();
    } catch (IOException e) {
        // ok: java-do-not-catch-and-throw-exception
        Logger logger = LogManager.getLogger(getClass());
        logger.error("HTTP request failed", e);
        throw new HttpClientException("Failed to execute HTTP request", e);
    }
}

public void good_case_5() {
    // Apache Commons Exec example with proper exception handling
    CommandLine cmdLine = CommandLine.parse("ls -la");
    DefaultExecutor executor = new DefaultExecutor();
    try {
        executor.execute(cmdLine);
    } catch (IOException e) {
        // ok: java-do-not-catch-and-throw-exception
        System.err.println("Command execution failed: " + e.getMessage());
        throw new CommandExecutionException("Failed to execute command", e);
    }
}

public void good_case_6() {
    // Retrofit API client example with proper exception handling
    Retrofit retrofit = new Retrofit.Builder()
        .baseUrl("https://api.example.com/")
        .build();
    
    try {
        // Some retrofit API call
    } catch (Exception e) {
        // ok: java-do-not-catch-and-throw-exception
        logError("API call failed", e);
        throw new ApiException("Failed to call external API", e);
    }
}

public void good_case_7() {
    // Hibernate ORM example with proper exception handling
    Session session = null;
    try {
        session = sessionFactory.openSession();
        Query<User> query = session.createQuery("FROM User", User.class);
    } catch (Exception e) {
        // ok: java-do-not-catch-and-throw-exception
        if (session != null) {
            session.close();
        }
        throw new DatabaseException("Database query failed", e);
    }
}

public void good_case_8() {
    // Jackson JSON parsing example with proper exception handling
    ObjectMapper mapper = new ObjectMapper();
    try {
        User user = mapper.readValue(jsonString, User.class);
    } catch (IOException e) {
        // ok: java-do-not-catch-and-throw-exception
        throw new DataParsingException("Failed to parse JSON data: " + jsonString.substring(0, 20) + "...", e);
    }
}

public void good_case_9() {
    // Kafka producer example with proper exception handling
    KafkaProducer<String, String> producer = new KafkaProducer<>(properties);
    try {
        producer.send(new ProducerRecord<>("topic", "key", "value"));
    } catch (Exception e) {
        // ok: java-do-not-catch-and-throw-exception
        producer.close();
        throw new MessagePublishException("Failed to publish message to Kafka", e);
    }
}

public void good_case_10() {
    // MongoDB client example with proper exception handling
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    try {
        MongoCollection<Document> collection = mongoClient.getDatabase("test").getCollection("users");
        collection.insertOne(new Document("name", "John Doe"));
    } catch (Exception e) {
        // ok: java-do-not-catch-and-throw-exception
        mongoClient.close();
        throw new DatabaseOperationException("Failed to insert document into MongoDB", e);
    }
}

public void good_case_11() {
    // Azure Blob Storage example with proper exception handling
    BlobContainerClient containerClient = new BlobContainerClient("connection-string", "container-name");
    try {
        BlobClient blobClient = containerClient.getBlobClient("blob-name");
        blobClient.downloadToFile("downloaded-file.txt");
    } catch (Exception e) {
        // ok: java-do-not-catch-and-throw-exception
        Logger logger = LogManager.getLogger(getClass());
        logger.error("Azure blob download failed for blob: blob-name", e);
        throw new CloudStorageException("Failed to download blob from Azure storage", e);
    }
}

public void good_case_12() {
    // Redis Jedis client example with proper exception handling
    Jedis jedis = new Jedis("localhost");
    try {
        jedis.set("key", "value");
    } catch (Exception e) {
        // ok: java-do-not-catch-and-throw-exception
        jedis.close();
        throw new CacheException("Failed to set value in Redis cache", e);
    }
}

public void good_case_13() {
    // RabbitMQ client example with proper exception handling
    ConnectionFactory factory = new ConnectionFactory();
    Connection connection = null;
    Channel channel = null;
    try {
        connection = factory.newConnection();
        channel = connection.createChannel();
        channel.queueDeclare("queue-name", false, false, false, null);
    } catch (Exception e) {
        // ok: java-do-not-catch-and-throw-exception
        if (channel != null) {
            try { channel.close(); } catch (Exception ex) {}
        }
        if (connection != null) {
            try { connection.close(); } catch (Exception ex) {}
        }
        throw new MessageQueueException("Failed to set up RabbitMQ queue", e);
    }
}

public void good_case_14() {
    // JSoup HTML parsing example with proper exception handling
    try {
        Document doc = Jsoup.connect("https://example.com").get();
    } catch (IOException e) {
        // ok: java-do-not-catch-and-throw-exception
        String errorMsg = "Failed to fetch and parse HTML from example.com";
        Logger logger = LogManager.getLogger(getClass());
        logger.error(errorMsg, e);
        throw new WebScrapingException(errorMsg, e);
    }
}

public void good_case_15() {
    // Apache Commons Net FTP client example with proper exception handling
    FTPClient ftpClient = new FTPClient();
    try {
        ftpClient.connect("ftp.example.com");
        ftpClient.login("username", "password");
    } catch (IOException e) {
        // ok: java-do-not-catch-and-throw-exception
        try { ftpClient.disconnect(); } catch (IOException ex) {}
        throw new FileTransferException("Failed to connect to FTP server", e);
    }
}

// Custom exception classes for the examples
class ServiceException extends RuntimeException {
    public ServiceException(String message, Throwable cause) {
        super(message, cause);
    }
}

class ApiConnectionException extends RuntimeException {
    public ApiConnectionException(String message, Throwable cause) {
        super(message, cause);
    }
}

class StorageException extends RuntimeException {
    public StorageException(String message, Throwable cause) {
        super(message, cause);
    }
}

class HttpClientException extends RuntimeException {
    public HttpClientException(String message, Throwable cause) {
        super(message, cause);
    }
}

class CommandExecutionException extends RuntimeException {
    public CommandExecutionException(String message, Throwable cause) {
        super(message, cause);
    }
}

class ApiException extends RuntimeException {
    public ApiException(String message, Throwable cause) {
        super(message, cause);
    }
}

class DatabaseException extends RuntimeException {
    public DatabaseException(String message, Throwable cause) {
        super(message, cause);
    }
}

class DataParsingException extends RuntimeException {
    public DataParsingException(String message, Throwable cause) {
        super(message, cause);
    }
}

class MessagePublishException extends RuntimeException {
    public MessagePublishException(String message, Throwable cause) {
        super(message, cause);
    }
}

class DatabaseOperationException extends RuntimeException {
    public DatabaseOperationException(String message, Throwable cause) {
        super(message, cause);
    }
}

class CloudStorageException extends RuntimeException {
    public CloudStorageException(String message, Throwable cause) {
        super(message, cause);
    }
}

class CacheException extends RuntimeException {
    public CacheException(String message, Throwable cause) {
        super(message, cause);
    }
}

class MessageQueueException extends RuntimeException {
    public MessageQueueException(String message, Throwable cause) {
        super(message, cause);
    }
}

class WebScrapingException extends RuntimeException {
    public WebScrapingException(String message, Throwable cause) {
        super(message, cause);
    }
}

class FileTransferException extends RuntimeException {
    public FileTransferException(String message, Throwable cause) {
        super(message, cause);
    }
}

// Helper method for logging
private void logError(String message, Exception e) {
    Logger logger = LogManager.getLogger(getClass());
    logger.error(message, e);
}

// User class for examples
class User {
    private String name;
    private String email;
    
    // Getters and setters
}