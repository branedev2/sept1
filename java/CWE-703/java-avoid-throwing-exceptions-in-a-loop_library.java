import java.util.*;
import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.concurrent.*;
import java.util.stream.*;
import java.util.logging.*;
import java.nio.file.*;
import javax.servlet.http.*;
import javax.servlet.*;
import org.apache.http.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.*;
import org.springframework.http.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import com.fasterxml.jackson.databind.*;
import com.google.gson.*;
import okhttp3.*;
import retrofit2.*;
import retrofit2.http.*;
import org.apache.commons.io.*;
import org.apache.commons.exec.*;
import org.apache.commons.lang3.*;
import com.jcraft.jsch.*;
import com.azure.storage.blob.*;
import com.azure.storage.blob.models.*;
import org.apache.kafka.clients.producer.*;
import org.apache.kafka.clients.consumer.*;
import org.hibernate.*;
import javax.persistence.*;
import com.mongodb.*;
import redis.clients.jedis.*;
import org.elasticsearch.client.*;
import org.apache.logging.log4j.*;
import org.slf4j.*;

// Security Issue: Throwing exceptions in a loop can degrade application performance by introducing significant overhead

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // Spring RestTemplate example with exception throwing in a loop
    RestTemplate restTemplate = new RestTemplate();
    String[] endpoints = request.getParameterValues("endpoints");
    
    for (int i = 0; i < endpoints.length; i++) {
        try {
            String url = "https://api.example.com/" + endpoints[i];
            // ruleid: java-avoid-throwing-exceptions-in-a-loop
            throw new IllegalArgumentException("Invalid endpoint: " + endpoints[i]);
        } catch (Exception e) {
            System.out.println("Error processing endpoint: " + e.getMessage());
        }
    }
}

public void bad_case_2(HttpServletRequest request) {
    // Apache HttpClient example with exception throwing in a loop
    CloseableHttpClient httpClient = HttpClients.createDefault();
    String[] userIds = request.getParameterValues("userIds");
    
    for (String userId : userIds) {
        HttpGet httpGet = new HttpGet("https://api.example.com/users/" + userId);
        if (!userId.matches("\\d+")) {
            // ruleid: java-avoid-throwing-exceptions-in-a-loop
            throw new IllegalArgumentException("Invalid user ID format: " + userId);
        }
    }
}

public void bad_case_3(HttpServletRequest request) {
    // AWS SDK S3 example with exception throwing in a loop
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String[] bucketNames = request.getParameterValues("buckets");
    
    for (String bucket : bucketNames) {
        if (bucket.length() < 3) {
            // ruleid: java-avoid-throwing-exceptions-in-a-loop
            throw new IllegalArgumentException("Bucket name too short: " + bucket);
        }
        // Process bucket
    }
}

public void bad_case_4(HttpServletRequest request) {
    // OkHttp client example with exception throwing in a loop
    OkHttpClient client = new OkHttpClient();
    String[] urls = request.getParameterValues("urls");
    
    for (int i = 0; i < urls.length; i++) {
        if (!urls[i].startsWith("https://")) {
            // ruleid: java-avoid-throwing-exceptions-in-a-loop
            throw new SecurityException("Non-HTTPS URL not allowed: " + urls[i]);
        }
        // Process URL
    }
}

public void bad_case_5(HttpServletRequest request) {
    // Jackson JSON processing with exception throwing in a loop
    ObjectMapper mapper = new ObjectMapper();
    String[] jsonInputs = request.getParameterValues("jsonData");
    
    for (String json : jsonInputs) {
        try {
            if (json.contains("<script>")) {
                // ruleid: java-avoid-throwing-exceptions-in-a-loop
                throw new SecurityException("Potential XSS in JSON: " + json);
            }
            // Process JSON
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

public void bad_case_6(HttpServletRequest request) {
    // JDBC database connection with exception throwing in a loop
    String[] sqlQueries = request.getParameterValues("queries");
    Connection conn = null;
    
    try {
        conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        for (String query : sqlQueries) {
            if (query.toLowerCase().contains("drop table")) {
                // ruleid: java-avoid-throwing-exceptions-in-a-loop
                throw new SQLException("Potentially harmful SQL detected: " + query);
            }
            // Execute query
        }
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_7(HttpServletRequest request) {
    // Apache Commons Exec with exception throwing in a loop
    String[] commands = request.getParameterValues("commands");
    
    for (String cmd : commands) {
        CommandLine commandLine = CommandLine.parse(cmd);
        if (cmd.contains("rm -rf")) {
            // ruleid: java-avoid-throwing-exceptions-in-a-loop
            throw new IllegalArgumentException("Dangerous command detected: " + cmd);
        }
        // Execute command
    }
}

public void bad_case_8(HttpServletRequest request) {
    // JSch SSH library with exception throwing in a loop
    String[] servers = request.getParameterValues("servers");
    
    for (String server : servers) {
        JSch jsch = new JSch();
        if (!server.matches("^[a-zA-Z0-9.-]+$")) {
            // ruleid: java-avoid-throwing-exceptions-in-a-loop
            throw new JSchException("Invalid server name format: " + server);
        }
        // Connect to server
    }
}

public void bad_case_9(HttpServletRequest request) {
    // Azure Blob Storage with exception throwing in a loop
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder().connectionString("connection-string").buildClient();
    String[] containerNames = request.getParameterValues("containers");
    
    for (String container : containerNames) {
        if (container.length() < 3 || container.length() > 63) {
            // ruleid: java-avoid-throwing-exceptions-in-a-loop
            throw new IllegalArgumentException("Invalid container name length: " + container);
        }
        // Process container
    }
}

public void bad_case_10(HttpServletRequest request) {
    // Kafka Producer with exception throwing in a loop
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    Producer<String, String> producer = new KafkaProducer<>(props);
    
    String[] messages = request.getParameterValues("messages");
    for (String message : messages) {
        if (message.length() > 1000000) {
            // ruleid: java-avoid-throwing-exceptions-in-a-loop
            throw new IllegalArgumentException("Message too large: " + message.length() + " bytes");
        }
        // Send message
    }
}

public void bad_case_11(HttpServletRequest request) {
    // Hibernate ORM with exception throwing in a loop
    SessionFactory sessionFactory = new Configuration().configure().buildSessionFactory();
    Session session = sessionFactory.openSession();
    
    String[] entityIds = request.getParameterValues("entityIds");
    for (String id : entityIds) {
        if (!id.matches("\\d+")) {
            // ruleid: java-avoid-throwing-exceptions-in-a-loop
            throw new IllegalArgumentException("Invalid entity ID format: " + id);
        }
        // Process entity
    }
}

public void bad_case_12(HttpServletRequest request) {
    // MongoDB client with exception throwing in a loop
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    String[] collectionNames = request.getParameterValues("collections");
    
    for (String collection : collectionNames) {
        if (collection.startsWith("system.")) {
            // ruleid: java-avoid-throwing-exceptions-in-a-loop
            throw new IllegalArgumentException("Access to system collection not allowed: " + collection);
        }
        // Process collection
    }
}

public void bad_case_13(HttpServletRequest request) {
    // Redis Jedis client with exception throwing in a loop
    Jedis jedis = new Jedis("localhost");
    String[] keys = request.getParameterValues("keys");
    
    for (String key : keys) {
        if (key.contains("*")) {
            // ruleid: java-avoid-throwing-exceptions-in-a-loop
            throw new IllegalArgumentException("Wildcard not allowed in key: " + key);
        }
        // Process key
    }
}

public void bad_case_14(HttpServletRequest request) {
    // Elasticsearch client with exception throwing in a loop
    RestClient restClient = RestClient.builder(new HttpHost("localhost", 9200, "http")).build();
    String[] indices = request.getParameterValues("indices");
    
    for (String index : indices) {
        if (index.equals("_all")) {
            // ruleid: java-avoid-throwing-exceptions-in-a-loop
            throw new IllegalArgumentException("_all index not allowed for this operation");
        }
        // Process index
    }
}

public void bad_case_15(HttpServletRequest request) {
    // Retrofit API client with exception throwing in a loop
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .build();
    
    String[] endpoints = request.getParameterValues("apiEndpoints");
    for (String endpoint : endpoints) {
        if (!endpoint.startsWith("/v1/")) {
            // ruleid: java-avoid-throwing-exceptions-in-a-loop
            throw new IllegalArgumentException("Only v1 API endpoints are supported: " + endpoint);
        }
        // Call API endpoint
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // Spring RestTemplate example with proper exception handling in a loop
    RestTemplate restTemplate = new RestTemplate();
    String[] endpoints = request.getParameterValues("endpoints");
    List<String> invalidEndpoints = new ArrayList<>();
    
    for (int i = 0; i < endpoints.length; i++) {
        try {
            String url = "https://api.example.com/" + endpoints[i];
            if (!endpoints[i].matches("[a-zA-Z0-9-_/]+")) {
                // ok: java-avoid-throwing-exceptions-in-a-loop
                invalidEndpoints.add("Invalid endpoint: " + endpoints[i]);
            }
        } catch (Exception e) {
            System.out.println("Error processing endpoint: " + e.getMessage());
        }
    }
    
    if (!invalidEndpoints.isEmpty()) {
        throw new IllegalArgumentException("Found invalid endpoints: " + String.join(", ", invalidEndpoints));
    }
}

public void good_case_2(HttpServletRequest request) {
    // Apache HttpClient example with proper exception handling in a loop
    CloseableHttpClient httpClient = HttpClients.createDefault();
    String[] userIds = request.getParameterValues("userIds");
    List<String> invalidUserIds = new ArrayList<>();
    
    for (String userId : userIds) {
        HttpGet httpGet = new HttpGet("https://api.example.com/users/" + userId);
        if (!userId.matches("\\d+")) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            invalidUserIds.add(userId);
        }
    }
    
    if (!invalidUserIds.isEmpty()) {
        throw new IllegalArgumentException("Invalid user ID formats: " + String.join(", ", invalidUserIds));
    }
}

public void good_case_3(HttpServletRequest request) {
    // AWS SDK S3 example with proper exception handling in a loop
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String[] bucketNames = request.getParameterValues("buckets");
    List<String> invalidBuckets = new ArrayList<>();
    
    for (String bucket : bucketNames) {
        if (bucket.length() < 3) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            invalidBuckets.add(bucket);
        }
        // Process valid bucket
    }
    
    if (!invalidBuckets.isEmpty()) {
        throw new IllegalArgumentException("Bucket names too short: " + String.join(", ", invalidBuckets));
    }
}

public void good_case_4(HttpServletRequest request) {
    // OkHttp client example with proper exception handling in a loop
    OkHttpClient client = new OkHttpClient();
    String[] urls = request.getParameterValues("urls");
    List<String> nonHttpsUrls = new ArrayList<>();
    
    for (int i = 0; i < urls.length; i++) {
        if (!urls[i].startsWith("https://")) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            nonHttpsUrls.add(urls[i]);
        } else {
            // Process HTTPS URL
        }
    }
    
    if (!nonHttpsUrls.isEmpty()) {
        throw new SecurityException("Non-HTTPS URLs not allowed: " + String.join(", ", nonHttpsUrls));
    }
}

public void good_case_5(HttpServletRequest request) {
    // Jackson JSON processing with proper exception handling in a loop
    ObjectMapper mapper = new ObjectMapper();
    String[] jsonInputs = request.getParameterValues("jsonData");
    List<String> suspiciousInputs = new ArrayList<>();
    
    for (String json : jsonInputs) {
        try {
            if (json.contains("<script>")) {
                // ok: java-avoid-throwing-exceptions-in-a-loop
                suspiciousInputs.add(json);
            } else {
                // Process safe JSON
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    if (!suspiciousInputs.isEmpty()) {
        throw new SecurityException("Potential XSS in JSON inputs detected");
    }
}

public void good_case_6(HttpServletRequest request) {
    // JDBC database connection with proper exception handling in a loop
    String[] sqlQueries = request.getParameterValues("queries");
    List<String> dangerousQueries = new ArrayList<>();
    Connection conn = null;
    
    try {
        conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        for (String query : sqlQueries) {
            if (query.toLowerCase().contains("drop table")) {
                // ok: java-avoid-throwing-exceptions-in-a-loop
                dangerousQueries.add(query);
            } else {
                // Execute safe query
            }
        }
        
        if (!dangerousQueries.isEmpty()) {
            throw new SQLException("Potentially harmful SQL detected in " + dangerousQueries.size() + " queries");
        }
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_7(HttpServletRequest request) {
    // Apache Commons Exec with proper exception handling in a loop
    String[] commands = request.getParameterValues("commands");
    List<String> dangerousCommands = new ArrayList<>();
    
    for (String cmd : commands) {
        CommandLine commandLine = CommandLine.parse(cmd);
        if (cmd.contains("rm -rf")) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            dangerousCommands.add(cmd);
        } else {
            // Execute safe command
        }
    }
    
    if (!dangerousCommands.isEmpty()) {
        throw new IllegalArgumentException("Dangerous commands detected: " + String.join(", ", dangerousCommands));
    }
}

public void good_case_8(HttpServletRequest request) {
    // JSch SSH library with proper exception handling in a loop
    String[] servers = request.getParameterValues("servers");
    List<String> invalidServers = new ArrayList<>();
    
    for (String server : servers) {
        JSch jsch = new JSch();
        if (!server.matches("^[a-zA-Z0-9.-]+$")) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            invalidServers.add(server);
        } else {
            // Connect to valid server
        }
    }
    
    if (!invalidServers.isEmpty()) {
        throw new IllegalArgumentException("Invalid server name formats: " + String.join(", ", invalidServers));
    }
}

public void good_case_9(HttpServletRequest request) {
    // Azure Blob Storage with proper exception handling in a loop
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder().connectionString("connection-string").buildClient();
    String[] containerNames = request.getParameterValues("containers");
    List<String> invalidContainers = new ArrayList<>();
    
    for (String container : containerNames) {
        if (container.length() < 3 || container.length() > 63) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            invalidContainers.add(container);
        } else {
            // Process valid container
        }
    }
    
    if (!invalidContainers.isEmpty()) {
        throw new IllegalArgumentException("Invalid container name lengths: " + String.join(", ", invalidContainers));
    }
}

public void good_case_10(HttpServletRequest request) {
    // Kafka Producer with proper exception handling in a loop
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    Producer<String, String> producer = new KafkaProducer<>(props);
    
    String[] messages = request.getParameterValues("messages");
    List<Integer> oversizedMessages = new ArrayList<>();
    
    for (int i = 0; i < messages.length; i++) {
        if (messages[i].length() > 1000000) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            oversizedMessages.add(i);
        } else {
            // Send valid message
        }
    }
    
    if (!oversizedMessages.isEmpty()) {
        throw new IllegalArgumentException("Messages too large at indices: " + oversizedMessages);
    }
}

public void good_case_11(HttpServletRequest request) {
    // Hibernate ORM with proper exception handling in a loop
    SessionFactory sessionFactory = new Configuration().configure().buildSessionFactory();
    Session session = sessionFactory.openSession();
    
    String[] entityIds = request.getParameterValues("entityIds");
    List<String> invalidIds = new ArrayList<>();
    
    for (String id : entityIds) {
        if (!id.matches("\\d+")) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            invalidIds.add(id);
        } else {
            // Process valid entity
        }
    }
    
    if (!invalidIds.isEmpty()) {
        throw new IllegalArgumentException("Invalid entity ID formats: " + String.join(", ", invalidIds));
    }
}

public void good_case_12(HttpServletRequest request) {
    // MongoDB client with proper exception handling in a loop
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    String[] collectionNames = request.getParameterValues("collections");
    List<String> systemCollections = new ArrayList<>();
    
    for (String collection : collectionNames) {
        if (collection.startsWith("system.")) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            systemCollections.add(collection);
        } else {
            // Process regular collection
        }
    }
    
    if (!systemCollections.isEmpty()) {
        throw new IllegalArgumentException("Access to system collections not allowed: " + String.join(", ", systemCollections));
    }
}

public void good_case_13(HttpServletRequest request) {
    // Redis Jedis client with proper exception handling in a loop
    Jedis jedis = new Jedis("localhost");
    String[] keys = request.getParameterValues("keys");
    List<String> wildcardKeys = new ArrayList<>();
    
    for (String key : keys) {
        if (key.contains("*")) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            wildcardKeys.add(key);
        } else {
            // Process valid key
        }
    }
    
    if (!wildcardKeys.isEmpty()) {
        throw new IllegalArgumentException("Wildcards not allowed in keys: " + String.join(", ", wildcardKeys));
    }
}

public void good_case_14(HttpServletRequest request) {
    // Elasticsearch client with proper exception handling in a loop
    RestClient restClient = RestClient.builder(new HttpHost("localhost", 9200, "http")).build();
    String[] indices = request.getParameterValues("indices");
    boolean hasAllIndex = false;
    
    for (String index : indices) {
        if (index.equals("_all")) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            hasAllIndex = true;
        } else {
            // Process regular index
        }
    }
    
    if (hasAllIndex) {
        throw new IllegalArgumentException("_all index not allowed for this operation");
    }
}

public void good_case_15(HttpServletRequest request) {
    // Retrofit API client with proper exception handling in a loop
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .build();
    
    String[] endpoints = request.getParameterValues("apiEndpoints");
    List<String> invalidEndpoints = new ArrayList<>();
    
    for (String endpoint : endpoints) {
        if (!endpoint.startsWith("/v1/")) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            invalidEndpoints.add(endpoint);
        } else {
            // Call valid API endpoint
        }
    }
    
    if (!invalidEndpoints.isEmpty()) {
        throw new IllegalArgumentException("Only v1 API endpoints are supported. Invalid endpoints: " + 
                                          String.join(", ", invalidEndpoints));
    }
}