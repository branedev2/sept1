import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.ExecutionException;
import java.util.logging.Logger;
import java.util.logging.Level;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.AmazonServiceException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mongodb.MongoClient;
import com.mongodb.MongoException;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import retrofit2.Retrofit;
import retrofit2.Call;
import retrofit2.Response;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.errors.TimeoutException;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.exceptions.JedisConnectionException;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.ElasticsearchException;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseException;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPConnectionClosedException;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.AlreadyClosedException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import java.net.HttpURLConnection;
import java.net.URL;

// Security Issue: Catching exceptions without re-throwing or logging them can lead to information loss,
// making it difficult to diagnose and fix issues, potentially resulting in application crashes or security vulnerabilities.

public class ExceptionHandlingExamples {
    private static final Logger LOGGER = Logger.getLogger(ExceptionHandlingExamples.class.getName());

    // True Positive Examples (Vulnerable/Insecure Code)
    
    // Spring Framework - REST Controller
    @RestController
    public static class BadSpringController {
// {fact rule=unhandled-exceptions@v1.0 defects=1}
        public void bad_case_1(HttpServletRequest request) {
            String userId = request.getParameter("userId");
            try {
                // Some database operation with userId
                if (userId == null) {
                    throw new IllegalArgumentException("User ID cannot be null");
                }
                // More processing...
            } catch (IllegalArgumentException e) {
                // ruleid: java-do-not-swallow-exceptions
                // Exception is caught but not logged or re-thrown
            }
        }
    }
// {/fact}
    
    // Apache HttpClient
// {fact rule=unhandled-exceptions@v1.0 defects=1}
    public static void bad_case_2(HttpServletRequest request) {
        String url = request.getParameter("url");
        HttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(url);
        
        try {
            httpClient.execute(httpGet);
        } catch (IOException e) {
            // ruleid: java-do-not-swallow-exceptions
            // Exception is caught but not logged or re-thrown
        }
    }
    
    // AWS SDK - S3 Client
    public static void bad_case_3(HttpServletRequest request) {
        String bucketName = request.getParameter("bucket");
        String key = request.getParameter("key");
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        try {
            s3Client.getObject(bucketName, key);
        } catch (AmazonServiceException e) {
            // ruleid: java-do-not-swallow-exceptions
            // AWS exception is caught but not logged or re-thrown
        }
    }
    
    // Jackson ObjectMapper
    public static void bad_case_4(HttpServletRequest request) {
        String json = request.getParameter("data");
        ObjectMapper mapper = new ObjectMapper();
        try {
            Object jsonObject = mapper.readValue(json, Object.class);
        } catch (IOException e) {
            // ruleid: java-do-not-swallow-exceptions
            // JSON parsing exception is caught but not logged or re-thrown
        }
    }
    
    // MongoDB Client
    public static void bad_case_5(HttpServletRequest request) {
        String dbName = request.getParameter("db");
        try (MongoClient mongoClient = new MongoClient()) {
            try {
                mongoClient.getDatabase(dbName).listCollectionNames();
            } catch (MongoException e) {
                // ruleid: java-do-not-swallow-exceptions
                // MongoDB exception is caught but not logged or re-thrown
            }
        }
    }
    
    // Apache Commons Exec
    public static void bad_case_6(HttpServletRequest request) {
        String command = request.getParameter("cmd");
        CommandLine cmdLine = CommandLine.parse(command);
        DefaultExecutor executor = new DefaultExecutor();
        try {
            executor.execute(cmdLine);
        } catch (ExecuteException e) {
            // ruleid: java-do-not-swallow-exceptions
            // Command execution exception is caught but not logged or re-thrown
        } catch (IOException e) {
            // ruleid: java-do-not-swallow-exceptions
            // IO exception is caught but not logged or re-thrown
        }
    }
    
    // OkHttp Client
    public static void bad_case_7(HttpServletRequest request) {
        String url = request.getParameter("url");
        OkHttpClient client = new OkHttpClient();
        Request okRequest = new Request.Builder()
            .url(url)
            .build();
            
        try {
            client.newCall(okRequest).execute();
        } catch (IOException e) {
            // ruleid: java-do-not-swallow-exceptions
            // HTTP client exception is caught but not logged or re-thrown
        }
    }
    
    // Retrofit API Client
    public static void bad_case_8(HttpServletRequest request) {
        String baseUrl = request.getParameter("apiUrl");
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl(baseUrl)
            .build();
            
        ApiService service = retrofit.create(ApiService.class);
        Call<Object> call = service.getData();
        
        try {
            Response<Object> response = call.execute();
        } catch (IOException e) {
            // ruleid: java-do-not-swallow-exceptions
            // Retrofit exception is caught but not logged or re-thrown
        }
    }
    
    // Kafka Producer
    public static void bad_case_9(HttpServletRequest request) {
        String topic = request.getParameter("topic");
        String message = request.getParameter("message");
        
        KafkaProducer<String, String> producer = new KafkaProducer<>(new java.util.Properties());
        try {
            producer.send(new ProducerRecord<>(topic, message));
        } catch (TimeoutException e) {
            // ruleid: java-do-not-swallow-exceptions
            // Kafka exception is caught but not logged or re-thrown
        } finally {
            producer.close();
        }
    }
    
    // Redis Jedis Client
    public static void bad_case_10(HttpServletRequest request) {
        String key = request.getParameter("key");
        Jedis jedis = new Jedis("localhost");
        try {
            jedis.get(key);
        } catch (JedisConnectionException e) {
            // ruleid: java-do-not-swallow-exceptions
            // Redis exception is caught but not logged or re-thrown
        } finally {
            jedis.close();
        }
    }
    
    // Elasticsearch Client
    public static void bad_case_11(HttpServletRequest request) {
        String indexName = request.getParameter("index");
        RestHighLevelClient client = new RestHighLevelClient(RestClient.builder(new org.apache.http.HttpHost("localhost", 9200)));
        try {
            client.indices().exists(new org.elasticsearch.client.indices.GetIndexRequest(indexName), org.elasticsearch.client.RequestOptions.DEFAULT);
        } catch (ElasticsearchException e) {
            // ruleid: java-do-not-swallow-exceptions
            // Elasticsearch exception is caught but not logged or re-thrown
        } catch (IOException e) {
            // ruleid: java-do-not-swallow-exceptions
            // IO exception is caught but not logged or re-thrown
        }
    }
    
    // Firebase SDK
    public static void bad_case_12(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        try {
            FirebaseApp.getInstance().get(userId);
        } catch (FirebaseException e) {
            // ruleid: java-do-not-swallow-exceptions
            // Firebase exception is caught but not logged or re-thrown
        }
    }
    
    // Google Cloud Storage
    public static void bad_case_13(HttpServletRequest request) {
        String bucketName = request.getParameter("bucket");
        Storage storage = com.google.cloud.storage.StorageOptions.getDefaultInstance().getService();
        try {
            storage.get(bucketName);
        } catch (StorageException e) {
            // ruleid: java-do-not-swallow-exceptions
            // Google Cloud Storage exception is caught but not logged or re-thrown
        }
    }
    
    // Apache Commons IO
    public static void bad_case_14(HttpServletRequest request) {
        String filePath = request.getParameter("file");
        try {
            FileUtils.readFileToString(new java.io.File(filePath), "UTF-8");
        } catch (IOException e) {
            // ruleid: java-do-not-swallow-exceptions
            // File IO exception is caught but not logged or re-thrown
        }
    }
    
    // Apache Commons Net FTP
    public static void bad_case_15(HttpServletRequest request) {
        String server = request.getParameter("server");
        FTPClient ftpClient = new FTPClient();
        try {
            ftpClient.connect(server);
            ftpClient.login("username", "password");
        } catch (FTPConnectionClosedException e) {
            // ruleid: java-do-not-swallow-exceptions
            // FTP exception is caught but not logged or re-thrown
        } catch (IOException e) {
            // ruleid: java-do-not-swallow-exceptions
            // IO exception is caught but not logged or re-thrown
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    // Spring Framework - REST Controller
    @RestController
    public static class GoodSpringController {
        public void good_case_1(HttpServletRequest request) {
            String userId = request.getParameter("userId");
            try {
                // Some database operation with userId
                if (userId == null) {
                    throw new IllegalArgumentException("User ID cannot be null");
                }
                // More processing...
            } catch (IllegalArgumentException e) {
                // ok: java-do-not-swallow-exceptions
                LOGGER.log(Level.SEVERE, "Invalid user ID provided", e);
                throw new RuntimeException("Invalid user input", e);
            }
        }
    }
    
    // Apache HttpClient
    public static void good_case_2(HttpServletRequest request) {
        String url = request.getParameter("url");
        HttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(url);
        
        try {
            httpClient.execute(httpGet);
        } catch (IOException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.SEVERE, "Failed to execute HTTP request", e);
            throw new RuntimeException("HTTP request failed", e);
        }
    }
    
    // AWS SDK - S3 Client
    public static void good_case_3(HttpServletRequest request) {
        String bucketName = request.getParameter("bucket");
        String key = request.getParameter("key");
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        try {
            s3Client.getObject(bucketName, key);
        } catch (AmazonServiceException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.SEVERE, "AWS S3 operation failed", e);
            throw e;
        }
    }
    
    // Jackson ObjectMapper
    public static void good_case_4(HttpServletRequest request) {
        String json = request.getParameter("data");
        ObjectMapper mapper = new ObjectMapper();
        try {
            Object jsonObject = mapper.readValue(json, Object.class);
        } catch (IOException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.WARNING, "Failed to parse JSON data", e);
            throw new IllegalArgumentException("Invalid JSON format", e);
        }
    }
    
    // MongoDB Client
    public static void good_case_5(HttpServletRequest request) {
        String dbName = request.getParameter("db");
        try (MongoClient mongoClient = new MongoClient()) {
            try {
                mongoClient.getDatabase(dbName).listCollectionNames();
            } catch (MongoException e) {
                // ok: java-do-not-swallow-exceptions
                LOGGER.log(Level.SEVERE, "MongoDB operation failed", e);
                throw new RuntimeException("Database operation failed", e);
            }
        }
    }
    
    // Apache Commons Exec
    public static void good_case_6(HttpServletRequest request) {
        String command = request.getParameter("cmd");
        CommandLine cmdLine = CommandLine.parse(command);
        DefaultExecutor executor = new DefaultExecutor();
        try {
            executor.execute(cmdLine);
        } catch (ExecuteException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.SEVERE, "Command execution failed with exit code: " + e.getExitValue(), e);
            throw e;
        } catch (IOException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.SEVERE, "IO error during command execution", e);
            throw new RuntimeException("Command execution failed", e);
        }
    }
    
    // OkHttp Client
    public static void good_case_7(HttpServletRequest request) {
        String url = request.getParameter("url");
        OkHttpClient client = new OkHttpClient();
        Request okRequest = new Request.Builder()
            .url(url)
            .build();
            
        try {
            client.newCall(okRequest).execute();
        } catch (IOException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.SEVERE, "OkHttp request failed: " + url, e);
            throw new RuntimeException("Failed to fetch data from URL", e);
        }
    }
    
    // Retrofit API Client
    public static void good_case_8(HttpServletRequest request) {
        String baseUrl = request.getParameter("apiUrl");
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl(baseUrl)
            .build();
            
        ApiService service = retrofit.create(ApiService.class);
        Call<Object> call = service.getData();
        
        try {
            Response<Object> response = call.execute();
        } catch (IOException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.SEVERE, "Retrofit API call failed", e);
            throw new RuntimeException("API request failed", e);
        }
    }
    
    // Kafka Producer
    public static void good_case_9(HttpServletRequest request) {
        String topic = request.getParameter("topic");
        String message = request.getParameter("message");
        
        KafkaProducer<String, String> producer = new KafkaProducer<>(new java.util.Properties());
        try {
            producer.send(new ProducerRecord<>(topic, message));
        } catch (TimeoutException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.SEVERE, "Kafka message send timed out", e);
            throw e;
        } finally {
            producer.close();
        }
    }
    
    // Redis Jedis Client
    public static void good_case_10(HttpServletRequest request) {
        String key = request.getParameter("key");
        Jedis jedis = new Jedis("localhost");
        try {
            jedis.get(key);
        } catch (JedisConnectionException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.SEVERE, "Redis connection failed", e);
            throw new RuntimeException("Failed to connect to Redis", e);
        } finally {
            jedis.close();
        }
    }
    
    // Elasticsearch Client
    public static void good_case_11(HttpServletRequest request) {
        String indexName = request.getParameter("index");
        RestHighLevelClient client = new RestHighLevelClient(RestClient.builder(new org.apache.http.HttpHost("localhost", 9200)));
        try {
            client.indices().exists(new org.elasticsearch.client.indices.GetIndexRequest(indexName), org.elasticsearch.client.RequestOptions.DEFAULT);
        } catch (ElasticsearchException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.SEVERE, "Elasticsearch operation failed", e);
            throw e;
        } catch (IOException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.SEVERE, "IO error during Elasticsearch operation", e);
            throw new RuntimeException("Elasticsearch operation failed", e);
        }
    }
    
    // Firebase SDK
    public static void good_case_12(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        try {
            FirebaseApp.getInstance().get(userId);
        } catch (FirebaseException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.SEVERE, "Firebase operation failed for user: " + userId, e);
            throw new RuntimeException("Firebase operation failed", e);
        }
    }
    
    // Google Cloud Storage
    public static void good_case_13(HttpServletRequest request) {
        String bucketName = request.getParameter("bucket");
        Storage storage = com.google.cloud.storage.StorageOptions.getDefaultInstance().getService();
        try {
            storage.get(bucketName);
        } catch (StorageException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.SEVERE, "Google Cloud Storage operation failed for bucket: " + bucketName, e);
            throw e;
        }
    }
    
    // Apache Commons IO
    public static void good_case_14(HttpServletRequest request) {
        String filePath = request.getParameter("file");
        try {
            FileUtils.readFileToString(new java.io.File(filePath), "UTF-8");
        } catch (IOException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.SEVERE, "Failed to read file: " + filePath, e);
            throw new RuntimeException("File read operation failed", e);
        }
    }
    
    // Apache Commons Net FTP
    public static void good_case_15(HttpServletRequest request) {
        String server = request.getParameter("server");
        FTPClient ftpClient = new FTPClient();
        try {
            ftpClient.connect(server);
            ftpClient.login("username", "password");
        } catch (FTPConnectionClosedException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.SEVERE, "FTP connection closed unexpectedly", e);
            throw new RuntimeException("FTP connection failed", e);
        } catch (IOException e) {
            // ok: java-do-not-swallow-exceptions
            LOGGER.log(Level.SEVERE, "IO error during FTP operation", e);
            throw new RuntimeException("FTP operation failed", e);
        }
    }
    
    // Interface for Retrofit example
    interface ApiService {
        Call<Object> getData();
    }
}
// {/fact}