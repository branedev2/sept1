import java.io.IOException;
import java.sql.SQLException;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.S3Object;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import redis.clients.jedis.Jedis;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import org.bson.Document;
import com.google.firebase.FirebaseApp;
import com.google.firebase.database.FirebaseDatabase;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

// Security Issue: Failing to re-throw exceptions with their original stack traces can lead to loss of critical debugging information

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request, HttpServletResponse response) {
    try {
        String url = request.getParameter("url");
        URL requestUrl = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) requestUrl.openConnection();
        connection.getInputStream();
    } catch (IOException e) {
        try {
            // ruleid: java-throw-exception-with-stack-trace
            throw new RuntimeException("Error processing URL connection");
        } catch (Exception ex) {
            response.setStatus(500);
        }
    }
}

public void bad_case_2(HttpServletRequest request) {
    RestTemplate restTemplate = new RestTemplate();
    String apiUrl = request.getParameter("api");
    
    try {
        restTemplate.getForObject(apiUrl, String.class);
    } catch (Exception e) {
        // ruleid: java-throw-exception-with-stack-trace
        throw new IllegalStateException("Failed to call external API");
    }
}

public void bad_case_3(HttpServletRequest request) {
    String bucketName = request.getParameter("bucket");
    String objectKey = request.getParameter("key");
    
    try {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        S3Object object = s3Client.getObject(bucketName, objectKey);
    } catch (Exception e) {
        // ruleid: java-throw-exception-with-stack-trace
        throw new RuntimeException("Error retrieving object from S3");
    }
}

public void bad_case_4(HttpServletRequest request) {
    ObjectMapper mapper = new ObjectMapper();
    String json = request.getParameter("data");
    
    try {
        Object data = mapper.readValue(json, Object.class);
    } catch (IOException e) {
        // ruleid: java-throw-exception-with-stack-trace
        throw new IllegalArgumentException("Invalid JSON format");
    }
}

public void bad_case_5(HttpServletRequest request, SessionFactory sessionFactory) {
    String userId = request.getParameter("userId");
    
    try {
        Session session = sessionFactory.openSession();
        session.get(User.class, userId);
    } catch (Exception e) {
        // ruleid: java-throw-exception-with-stack-trace
        throw new RuntimeException("Database error occurred");
    }
}

public void bad_case_6(HttpServletRequest request) {
    OkHttpClient client = new OkHttpClient();
    String url = request.getParameter("endpoint");
    
    try {
        Request okRequest = new Request.Builder().url(url).build();
        client.newCall(okRequest).execute();
    } catch (IOException e) {
        // ruleid: java-throw-exception-with-stack-trace
        throw new RuntimeException("HTTP request failed");
    }
}

public void bad_case_7(HttpServletRequest request) {
    String apiBaseUrl = request.getParameter("apiUrl");
    
    try {
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl(apiBaseUrl)
            .addConverterFactory(GsonConverterFactory.create())
            .build();
        
        ApiService service = retrofit.create(ApiService.class);
        service.getData().execute();
    } catch (Exception e) {
        // ruleid: java-throw-exception-with-stack-trace
        throw new IllegalStateException("API service error");
    }
}

public void bad_case_8(HttpServletRequest request, KafkaProducer<String, String> producer) {
    String topic = request.getParameter("topic");
    String message = request.getParameter("message");
    
    try {
        producer.send(new ProducerRecord<>(topic, message));
    } catch (Exception e) {
        // ruleid: java-throw-exception-with-stack-trace
        throw new RuntimeException("Failed to send message to Kafka");
    }
}

public void bad_case_9(HttpServletRequest request) {
    String redisKey = request.getParameter("key");
    
    try (Jedis jedis = new Jedis("localhost")) {
        jedis.get(redisKey);
    } catch (Exception e) {
        // ruleid: java-throw-exception-with-stack-trace
        throw new RuntimeException("Redis operation failed");
    }
}

public void bad_case_10(HttpServletRequest request) {
    String collection = request.getParameter("collection");
    
    try (MongoClient mongoClient = new MongoClient()) {
        MongoCollection<Document> coll = mongoClient.getDatabase("test").getCollection(collection);
        coll.find().first();
    } catch (Exception e) {
        // ruleid: java-throw-exception-with-stack-trace
        throw new IllegalStateException("MongoDB query failed");
    }
}

public void bad_case_11(HttpServletRequest request) {
    String path = request.getParameter("path");
    
    try {
        FirebaseDatabase database = FirebaseDatabase.getInstance();
        database.getReference(path).get();
    } catch (Exception e) {
        // ruleid: java-throw-exception-with-stack-trace
        throw new RuntimeException("Firebase database error");
    }
}

public void bad_case_12(HttpServletRequest request, Vertx vertx) {
    String endpoint = request.getParameter("endpoint");
    
    try {
        Router router = Router.router(vertx);
        router.get(endpoint).handler(this::handleRequest);
        vertx.createHttpServer().requestHandler(router).listen(8080);
    } catch (Exception e) {
        // ruleid: java-throw-exception-with-stack-trace
        throw new IllegalStateException("Vert.x server error");
    }
}

public void bad_case_13(HttpServletRequest request) {
    String command = request.getParameter("command");
    
    try {
        CommandLine cmdLine = CommandLine.parse(command);
        DefaultExecutor executor = new DefaultExecutor();
        executor.execute(cmdLine);
    } catch (IOException e) {
        // ruleid: java-throw-exception-with-stack-trace
        throw new RuntimeException("Command execution failed");
    }
}

public void bad_case_14(HttpServletRequest request) {
    String host = request.getParameter("host");
    
    try {
        JSch jsch = new JSch();
        com.jcraft.jsch.Session session = jsch.getSession("user", host, 22);
        session.connect();
        Channel channel = session.openChannel("exec");
        ((ChannelExec)channel).setCommand("ls");
        channel.connect();
    } catch (Exception e) {
        // ruleid: java-throw-exception-with-stack-trace
        throw new RuntimeException("SSH connection failed");
    }
}

public void bad_case_15(HttpServletRequest request) {
    String containerName = request.getParameter("container");
    
    try {
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString("connection-string")
            .buildClient();
        blobServiceClient.getBlobContainerClient(containerName).listBlobs();
    } catch (Exception e) {
        // ruleid: java-throw-exception-with-stack-trace
        throw new IllegalStateException("Azure blob storage error");
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request, HttpServletResponse response) {
    try {
        String url = request.getParameter("url");
        URL requestUrl = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) requestUrl.openConnection();
        connection.getInputStream();
    } catch (IOException e) {
        try {
            // ok: java-throw-exception-with-stack-trace
            throw new RuntimeException("Error processing URL connection", e);
        } catch (Exception ex) {
            response.setStatus(500);
        }
    }
}

public void good_case_2(HttpServletRequest request) {
    RestTemplate restTemplate = new RestTemplate();
    String apiUrl = request.getParameter("api");
    
    try {
        restTemplate.getForObject(apiUrl, String.class);
    } catch (Exception e) {
        // ok: java-throw-exception-with-stack-trace
        throw new IllegalStateException("Failed to call external API", e);
    }
}

public void good_case_3(HttpServletRequest request) {
    String bucketName = request.getParameter("bucket");
    String objectKey = request.getParameter("key");
    
    try {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        S3Object object = s3Client.getObject(bucketName, objectKey);
    } catch (Exception e) {
        // ok: java-throw-exception-with-stack-trace
        throw new RuntimeException("Error retrieving object from S3", e);
    }
}

public void good_case_4(HttpServletRequest request) {
    ObjectMapper mapper = new ObjectMapper();
    String json = request.getParameter("data");
    
    try {
        Object data = mapper.readValue(json, Object.class);
    } catch (IOException e) {
        // ok: java-throw-exception-with-stack-trace
        throw new IllegalArgumentException("Invalid JSON format", e);
    }
}

public void good_case_5(HttpServletRequest request, SessionFactory sessionFactory) {
    String userId = request.getParameter("userId");
    
    try {
        Session session = sessionFactory.openSession();
        session.get(User.class, userId);
    } catch (Exception e) {
        // ok: java-throw-exception-with-stack-trace
        throw new RuntimeException("Database error occurred", e);
    }
}

public void good_case_6(HttpServletRequest request) {
    OkHttpClient client = new OkHttpClient();
    String url = request.getParameter("endpoint");
    
    try {
        Request okRequest = new Request.Builder().url(url).build();
        client.newCall(okRequest).execute();
    } catch (IOException e) {
        // ok: java-throw-exception-with-stack-trace
        throw new RuntimeException("HTTP request failed", e);
    }
}

public void good_case_7(HttpServletRequest request) {
    String apiBaseUrl = request.getParameter("apiUrl");
    
    try {
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl(apiBaseUrl)
            .addConverterFactory(GsonConverterFactory.create())
            .build();
        
        ApiService service = retrofit.create(ApiService.class);
        service.getData().execute();
    } catch (Exception e) {
        // ok: java-throw-exception-with-stack-trace
        throw new IllegalStateException("API service error", e);
    }
}

public void good_case_8(HttpServletRequest request, KafkaProducer<String, String> producer) {
    String topic = request.getParameter("topic");
    String message = request.getParameter("message");
    
    try {
        producer.send(new ProducerRecord<>(topic, message));
    } catch (Exception e) {
        // ok: java-throw-exception-with-stack-trace
        throw new RuntimeException("Failed to send message to Kafka", e);
    }
}

public void good_case_9(HttpServletRequest request) {
    String redisKey = request.getParameter("key");
    
    try (Jedis jedis = new Jedis("localhost")) {
        jedis.get(redisKey);
    } catch (Exception e) {
        // ok: java-throw-exception-with-stack-trace
        throw new RuntimeException("Redis operation failed", e);
    }
}

public void good_case_10(HttpServletRequest request) {
    String collection = request.getParameter("collection");
    
    try (MongoClient mongoClient = new MongoClient()) {
        MongoCollection<Document> coll = mongoClient.getDatabase("test").getCollection(collection);
        coll.find().first();
    } catch (Exception e) {
        // ok: java-throw-exception-with-stack-trace
        throw new IllegalStateException("MongoDB query failed", e);
    }
}

public void good_case_11(HttpServletRequest request) {
    String path = request.getParameter("path");
    
    try {
        FirebaseDatabase database = FirebaseDatabase.getInstance();
        database.getReference(path).get();
    } catch (Exception e) {
        // ok: java-throw-exception-with-stack-trace
        throw new RuntimeException("Firebase database error", e);
    }
}

public void good_case_12(HttpServletRequest request, Vertx vertx) {
    String endpoint = request.getParameter("endpoint");
    
    try {
        Router router = Router.router(vertx);
        router.get(endpoint).handler(this::handleRequest);
        vertx.createHttpServer().requestHandler(router).listen(8080);
    } catch (Exception e) {
        // ok: java-throw-exception-with-stack-trace
        throw new IllegalStateException("Vert.x server error", e);
    }
}

public void good_case_13(HttpServletRequest request) {
    String command = request.getParameter("command");
    
    try {
        CommandLine cmdLine = CommandLine.parse(command);
        DefaultExecutor executor = new DefaultExecutor();
        executor.execute(cmdLine);
    } catch (IOException e) {
        // ok: java-throw-exception-with-stack-trace
        throw new RuntimeException("Command execution failed", e);
    }
}

public void good_case_14(HttpServletRequest request) {
    String host = request.getParameter("host");
    
    try {
        JSch jsch = new JSch();
        com.jcraft.jsch.Session session = jsch.getSession("user", host, 22);
        session.connect();
        Channel channel = session.openChannel("exec");
        ((ChannelExec)channel).setCommand("ls");
        channel.connect();
    } catch (Exception e) {
        // ok: java-throw-exception-with-stack-trace
        throw new RuntimeException("SSH connection failed", e);
    }
}

public void good_case_15(HttpServletRequest request) {
    String containerName = request.getParameter("container");
    
    try {
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString("connection-string")
            .buildClient();
        blobServiceClient.getBlobContainerClient(containerName).listBlobs();
    } catch (Exception e) {
        // ok: java-throw-exception-with-stack-trace
        throw new IllegalStateException("Azure blob storage error", e);
    }
}

// Helper class for examples
class User {
    private String id;
    private String name;
    
    public String getId() {
        return id;
    }
    
    public void setId(String id) {
        this.id = id;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
}

// Helper interface for Retrofit example
interface ApiService {
    retrofit2.Call<Object> getData();
}

// Helper method for Vert.x example
private void handleRequest(RoutingContext context) {
    context.response().end("Hello");
}