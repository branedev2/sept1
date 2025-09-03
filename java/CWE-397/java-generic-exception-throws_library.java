import java.io.IOException;
import java.sql.SQLException;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.io.FileUtils;
import com.google.firebase.FirebaseApp;
import com.google.firebase.database.DatabaseReference;
import com.google.firebase.database.FirebaseDatabase;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import redis.clients.jedis.Jedis;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import org.bson.Document;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import org.apache.commons.net.ftp.FTPClient;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import org.apache.http.HttpHost;

// Security Issue: Methods throwing general exceptions instead of specific exceptions

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    try {
        // Spring Framework - Web MVC
        validateUser(userId);
    } catch (Exception e) {
        // ruleid: java-generic-exception-throws
        throw new Exception("Error validating user: " + e.getMessage());
    }
}

public void bad_case_2(HttpServletRequest request) {
    String url = request.getParameter("url");
    // Apache HttpClient
    CloseableHttpClient httpClient = HttpClients.createDefault();
    try {
        HttpGet httpGet = new HttpGet(url);
        httpClient.execute(httpGet);
    } catch (IOException e) {
        // ruleid: java-generic-exception-throws
        throw new Exception("HTTP client error: " + e.getMessage());
    }
}

public void bad_case_3(HttpServletRequest request) {
    String bucketName = request.getParameter("bucket");
    // AWS SDK - S3
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    try {
        s3Client.listObjects(bucketName);
    } catch (RuntimeException e) {
        // ruleid: java-generic-exception-throws
        throw new Exception("S3 error: " + e.getMessage());
    }
}

public void bad_case_4(HttpServletRequest request) {
    String json = request.getParameter("data");
    // Jackson JSON Library
    ObjectMapper mapper = new ObjectMapper();
    try {
        mapper.readTree(json);
    } catch (IOException e) {
        // ruleid: java-generic-exception-throws
        throw new Exception("JSON parsing error: " + e.getMessage());
    }
}

public void bad_case_5(HttpServletRequest request) {
    String query = request.getParameter("query");
    // Hibernate ORM
    SessionFactory sessionFactory = null; // Assume initialized
    try (Session session = sessionFactory.openSession()) {
        session.createQuery(query).list();
    } catch (RuntimeException e) {
        // ruleid: java-generic-exception-throws
        throw new Exception("Database query error: " + e.getMessage());
    }
}

public void bad_case_6(HttpServletRequest request) {
    String apiUrl = request.getParameter("apiUrl");
    // OkHttp Client
    OkHttpClient client = new OkHttpClient();
    try {
        Request okRequest = new Request.Builder().url(apiUrl).build();
        client.newCall(okRequest).execute();
    } catch (IOException e) {
        // ruleid: java-generic-exception-throws
        throw new Exception("OkHttp request error: " + e.getMessage());
    }
}

public void bad_case_7(HttpServletRequest request) {
    String baseUrl = request.getParameter("baseUrl");
    // Retrofit API Client
    try {
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl(baseUrl)
            .addConverterFactory(GsonConverterFactory.create())
            .build();
        // Use retrofit
    } catch (IllegalArgumentException e) {
        // ruleid: java-generic-exception-throws
        throw new Exception("Retrofit configuration error: " + e.getMessage());
    }
}

public void bad_case_8(HttpServletRequest request) {
    String command = request.getParameter("command");
    // Apache Commons Exec
    try {
        CommandLine cmdLine = CommandLine.parse(command);
        DefaultExecutor executor = new DefaultExecutor();
        executor.execute(cmdLine);
    } catch (IOException e) {
        // ruleid: java-generic-exception-throws
        throw new Exception("Command execution error: " + e.getMessage());
    }
}

public void bad_case_9(HttpServletRequest request) {
    String path = request.getParameter("path");
    // Apache Commons IO
    try {
        FileUtils.forceDelete(new java.io.File(path));
    } catch (IOException e) {
        // ruleid: java-generic-exception-throws
        throw new Exception("File operation error: " + e.getMessage());
    }
}

public void bad_case_10(HttpServletRequest request) {
    String dbPath = request.getParameter("dbPath");
    // Firebase Realtime Database
    try {
        DatabaseReference ref = FirebaseDatabase.getInstance().getReference(dbPath);
        // Use ref
    } catch (RuntimeException e) {
        // ruleid: java-generic-exception-throws
        throw new Exception("Firebase database error: " + e.getMessage());
    }
}

public void bad_case_11(HttpServletRequest request) {
    String topic = request.getParameter("topic");
    String message = request.getParameter("message");
    // Kafka Producer
    KafkaProducer<String, String> producer = null; // Assume initialized
    try {
        producer.send(new ProducerRecord<>(topic, message));
    } catch (RuntimeException e) {
        // ruleid: java-generic-exception-throws
        throw new Exception("Kafka producer error: " + e.getMessage());
    }
}

public void bad_case_12(HttpServletRequest request) {
    String key = request.getParameter("key");
    // Redis/Jedis Client
    Jedis jedis = new Jedis("localhost");
    try {
        jedis.get(key);
    } catch (RuntimeException e) {
        // ruleid: java-generic-exception-throws
        throw new Exception("Redis operation error: " + e.getMessage());
    }
}

public void bad_case_13(HttpServletRequest request) {
    String collection = request.getParameter("collection");
    // MongoDB Java Driver
    MongoClient mongoClient = new MongoClient();
    try {
        MongoCollection<Document> coll = mongoClient.getDatabase("test").getCollection(collection);
        // Use collection
    } catch (RuntimeException e) {
        // ruleid: java-generic-exception-throws
        throw new Exception("MongoDB error: " + e.getMessage());
    }
}

public void bad_case_14(HttpServletRequest request) {
    String containerName = request.getParameter("container");
    // Azure Storage SDK
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder().connectionString("connection-string").buildClient();
    try {
        blobServiceClient.getBlobContainerClient(containerName).create();
    } catch (RuntimeException e) {
        // ruleid: java-generic-exception-throws
        throw new Exception("Azure storage error: " + e.getMessage());
    }
}

public void bad_case_15(HttpServletRequest request) {
    String server = request.getParameter("server");
    // Apache Commons Net FTP
    FTPClient ftpClient = new FTPClient();
    try {
        ftpClient.connect(server);
    } catch (IOException e) {
        // ruleid: java-generic-exception-throws
        throw new Exception("FTP connection error: " + e.getMessage());
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    try {
        // Spring Framework - Web MVC
        validateUser(userId);
    } catch (Exception e) {
        // ok: java-generic-exception-throws
        throw new IllegalArgumentException("Error validating user: " + e.getMessage());
    }
}

public void good_case_2(HttpServletRequest request) {
    String url = request.getParameter("url");
    // Apache HttpClient
    CloseableHttpClient httpClient = HttpClients.createDefault();
    try {
        HttpGet httpGet = new HttpGet(url);
        httpClient.execute(httpGet);
    } catch (IOException e) {
        // ok: java-generic-exception-throws
        throw new IOException("HTTP client error: " + e.getMessage(), e);
    }
}

public void good_case_3(HttpServletRequest request) {
    String bucketName = request.getParameter("bucket");
    // AWS SDK - S3
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    try {
        s3Client.listObjects(bucketName);
    } catch (RuntimeException e) {
        // ok: java-generic-exception-throws
        throw new IllegalStateException("S3 error: " + e.getMessage(), e);
    }
}

public void good_case_4(HttpServletRequest request) {
    String json = request.getParameter("data");
    // Jackson JSON Library
    ObjectMapper mapper = new ObjectMapper();
    try {
        mapper.readTree(json);
    } catch (IOException e) {
        // ok: java-generic-exception-throws
        throw new IOException("JSON parsing error: " + e.getMessage(), e);
    }
}

public void good_case_5(HttpServletRequest request) {
    String query = request.getParameter("query");
    // Hibernate ORM
    SessionFactory sessionFactory = null; // Assume initialized
    try (Session session = sessionFactory.openSession()) {
        session.createQuery(query).list();
    } catch (RuntimeException e) {
        // ok: java-generic-exception-throws
        throw new IllegalStateException("Database query error: " + e.getMessage(), e);
    }
}

public void good_case_6(HttpServletRequest request) {
    String apiUrl = request.getParameter("apiUrl");
    // OkHttp Client
    OkHttpClient client = new OkHttpClient();
    try {
        Request okRequest = new Request.Builder().url(apiUrl).build();
        client.newCall(okRequest).execute();
    } catch (IOException e) {
        // ok: java-generic-exception-throws
        throw new IOException("OkHttp request error: " + e.getMessage(), e);
    }
}

public void good_case_7(HttpServletRequest request) {
    String baseUrl = request.getParameter("baseUrl");
    // Retrofit API Client
    try {
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl(baseUrl)
            .addConverterFactory(GsonConverterFactory.create())
            .build();
        // Use retrofit
    } catch (IllegalArgumentException e) {
        // ok: java-generic-exception-throws
        throw new IllegalArgumentException("Retrofit configuration error: " + e.getMessage(), e);
    }
}

public void good_case_8(HttpServletRequest request) {
    String command = request.getParameter("command");
    // Apache Commons Exec
    try {
        CommandLine cmdLine = CommandLine.parse(command);
        DefaultExecutor executor = new DefaultExecutor();
        executor.execute(cmdLine);
    } catch (IOException e) {
        // ok: java-generic-exception-throws
        throw new IOException("Command execution error: " + e.getMessage(), e);
    }
}

public void good_case_9(HttpServletRequest request) {
    String path = request.getParameter("path");
    // Apache Commons IO
    try {
        FileUtils.forceDelete(new java.io.File(path));
    } catch (IOException e) {
        // ok: java-generic-exception-throws
        throw new IOException("File operation error: " + e.getMessage(), e);
    }
}

public void good_case_10(HttpServletRequest request) {
    String dbPath = request.getParameter("dbPath");
    // Firebase Realtime Database
    try {
        DatabaseReference ref = FirebaseDatabase.getInstance().getReference(dbPath);
        // Use ref
    } catch (RuntimeException e) {
        // ok: java-generic-exception-throws
        throw new IllegalStateException("Firebase database error: " + e.getMessage(), e);
    }
}

public void good_case_11(HttpServletRequest request) {
    String topic = request.getParameter("topic");
    String message = request.getParameter("message");
    // Kafka Producer
    KafkaProducer<String, String> producer = null; // Assume initialized
    try {
        producer.send(new ProducerRecord<>(topic, message));
    } catch (RuntimeException e) {
        // ok: java-generic-exception-throws
        throw new IllegalStateException("Kafka producer error: " + e.getMessage(), e);
    }
}

public void good_case_12(HttpServletRequest request) {
    String key = request.getParameter("key");
    // Redis/Jedis Client
    Jedis jedis = new Jedis("localhost");
    try {
        jedis.get(key);
    } catch (RuntimeException e) {
        // ok: java-generic-exception-throws
        throw new IllegalStateException("Redis operation error: " + e.getMessage(), e);
    }
}

public void good_case_13(HttpServletRequest request) {
    String collection = request.getParameter("collection");
    // MongoDB Java Driver
    MongoClient mongoClient = new MongoClient();
    try {
        MongoCollection<Document> coll = mongoClient.getDatabase("test").getCollection(collection);
        // Use collection
    } catch (RuntimeException e) {
        // ok: java-generic-exception-throws
        throw new IllegalStateException("MongoDB error: " + e.getMessage(), e);
    }
}

public void good_case_14(HttpServletRequest request) {
    String containerName = request.getParameter("container");
    // Azure Storage SDK
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder().connectionString("connection-string").buildClient();
    try {
        blobServiceClient.getBlobContainerClient(containerName).create();
    } catch (RuntimeException e) {
        // ok: java-generic-exception-throws
        throw new IllegalStateException("Azure storage error: " + e.getMessage(), e);
    }
}

public void good_case_15(HttpServletRequest request) {
    String server = request.getParameter("server");
    // Apache Commons Net FTP
    FTPClient ftpClient = new FTPClient();
    try {
        ftpClient.connect(server);
    } catch (IOException e) {
        // ok: java-generic-exception-throws
        throw new IOException("FTP connection error: " + e.getMessage(), e);
    }
}

// Helper method for examples
private void validateUser(String userId) throws Exception {
    // Implementation not important for this example
}