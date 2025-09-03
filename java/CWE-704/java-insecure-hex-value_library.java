import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.HttpGet;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import retrofit2.Retrofit;
import retrofit2.http.GET;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.google.common.hash.Hashing;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import redis.clients.jedis.Jedis;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import org.bson.Document;
import com.google.firebase.FirebaseApp;
import com.google.firebase.database.FirebaseDatabase;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

// Security Issue: Using Integer.toHexString for hash value computation introduces more collisions
// and weakens the security of hash values. String.format should be used instead.

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // Spring Web MVC - Creating a token with insecure hex representation
    String username = request.getParameter("username");
    try {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(username.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            // ruleid: java-insecure-hex-value
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        System.out.println("Generated token: " + hexString.toString());
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void bad_case_2(OkHttpClient client, String url) {
    // OkHttp - Generating a checksum for request validation
    Request request = new Request.Builder().url(url).build();
    try {
        okhttp3.Response response = client.newCall(request).execute();
        String responseBody = response.body().string();
        
        MessageDigest digest = MessageDigest.getInstance("MD5");
        byte[] hashBytes = digest.digest(responseBody.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            // ruleid: java-insecure-hex-value
            sb.append(Integer.toHexString(0xff & b));
        }
        System.out.println("Response checksum: " + sb.toString());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3(AmazonS3 s3Client, String bucketName, String objectKey) {
    // AWS SDK - Creating a content hash for S3 object metadata
    try {
        byte[] content = s3Client.getObjectAsBytes(bucketName, objectKey).getObjectContent().readAllBytes();
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(content);
        
        StringBuilder hexDigest = new StringBuilder();
        for (byte b : digest) {
            // ruleid: java-insecure-hex-value
            hexDigest.append(Integer.toHexString((b & 0xff)));
        }
        
        Map<String, String> metadata = new HashMap<>();
        metadata.put("content-hash", hexDigest.toString());
        s3Client.copyObject(bucketName, objectKey, bucketName, objectKey, metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4(MongoClient mongoClient, HttpServletRequest request) {
    // MongoDB - Storing user password hash
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashedPassword = md.digest(password.getBytes(StandardCharsets.UTF_8));
        
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashedPassword) {
            // ruleid: java-insecure-hex-value
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        
        MongoCollection<Document> collection = mongoClient.getDatabase("users").getCollection("credentials");
        Document doc = new Document("username", username)
                .append("password_hash", hexString.toString());
        collection.insertOne(doc);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void bad_case_5(Jedis jedis, HttpServletRequest request) {
    // Redis - Generating a cache key based on request parameters
    String userId = request.getParameter("userId");
    String action = request.getParameter("action");
    String combined = userId + ":" + action;
    
    try {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(combined.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ruleid: java-insecure-hex-value
            sb.append(Integer.toHexString(0xff & b));
        }
        String cacheKey = "action:" + sb.toString();
        jedis.set(cacheKey, "true");
        jedis.expire(cacheKey, 3600);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void bad_case_6(HttpServletRequest request, Session hibernateSession) {
    // Hibernate - Creating a unique identifier for database record
    String data = request.getParameter("data");
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            // ruleid: java-insecure-hex-value
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        
        Map<String, Object> entity = new HashMap<>();
        entity.put("id", hexString.toString());
        entity.put("data", data);
        hibernateSession.save("DataEntity", entity);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void bad_case_7(FirebaseDatabase database, HttpServletRequest request) {
    // Firebase SDK - Creating a unique path for storing user data
    String userId = request.getParameter("userId");
    String data = request.getParameter("data");
    
    try {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(userId.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ruleid: java-insecure-hex-value
            sb.append(Integer.toHexString(b & 0xff));
        }
        
        String path = "users/" + sb.toString();
        database.getReference(path).setValue(data);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void bad_case_8(RoutingContext routingContext, Vertx vertx) {
    // Vert.x - Creating a session ID
    String ip = routingContext.request().remoteAddress().host();
    String userAgent = routingContext.request().getHeader("User-Agent");
    String combined = ip + ":" + userAgent + ":" + System.currentTimeMillis();
    
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(combined.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            // ruleid: java-insecure-hex-value
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        
        routingContext.session().put("sessionId", hexString.toString());
        routingContext.response().end("Session created");
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void bad_case_9(KafkaProducer<String, String> producer, HttpServletRequest request) {
    // Kafka - Creating a message key based on request data
    String topic = "user-events";
    String userId = request.getParameter("userId");
    String eventType = request.getParameter("eventType");
    String eventData = request.getParameter("data");
    
    try {
        String combined = userId + ":" + eventType;
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(combined.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ruleid: java-insecure-hex-value
            sb.append(Integer.toHexString(0xff & b));
        }
        
        String key = sb.toString();
        ProducerRecord<String, String> record = new ProducerRecord<>(topic, key, eventData);
        producer.send(record);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    // JWT Token - Creating a token ID
    String username = request.getParameter("username");
    
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(username.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            // ruleid: java-insecure-hex-value
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        
        String jwtId = hexString.toString();
        String token = Jwts.builder()
                .setId(jwtId)
                .setSubject(username)
                .signWith(SignatureAlgorithm.HS256, "secret".getBytes())
                .compact();
        
        System.out.println("Generated JWT: " + token);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void bad_case_11(BlobServiceClient blobServiceClient, HttpServletRequest request) {
    // Azure Storage SDK - Creating a blob name based on content hash
    String containerName = "user-uploads";
    String content = request.getParameter("content");
    
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(content.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ruleid: java-insecure-hex-value
            sb.append(Integer.toHexString(0xff & b));
        }
        
        String blobName = sb.toString() + ".txt";
        blobServiceClient.getBlobContainerClient(containerName)
                .getBlobClient(blobName)
                .getBlockBlobClient()
                .upload(content.getBytes(StandardCharsets.UTF_8), content.length());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    // Apache Commons IO - Creating a unique filename for temporary file
    String content = request.getParameter("content");
    
    try {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(content.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ruleid: java-insecure-hex-value
            sb.append(Integer.toHexString(0xff & b));
        }
        
        String filename = "temp_" + sb.toString() + ".txt";
        File tempFile = new File(System.getProperty("java.io.tmpdir"), filename);
        FileUtils.writeStringToFile(tempFile, content, StandardCharsets.UTF_8);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13(ObjectMapper mapper, HttpServletRequest request) {
    // Jackson - Creating a unique ID for JSON object
    String data = request.getParameter("data");
    
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ruleid: java-insecure-hex-value
            sb.append(Integer.toHexString(0xff & b));
        }
        
        Map<String, Object> jsonObject = new HashMap<>();
        jsonObject.put("id", sb.toString());
        jsonObject.put("data", data);
        jsonObject.put("timestamp", System.currentTimeMillis());
        
        String json = mapper.writeValueAsString(jsonObject);
        System.out.println("JSON: " + json);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) {
    // Java NIO - Creating a unique directory name
    String userId = request.getParameter("userId");
    
    try {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(userId.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ruleid: java-insecure-hex-value
            sb.append(Integer.toHexString(0xff & b));
        }
        
        String dirName = "user_" + sb.toString();
        Files.createDirectories(Paths.get(System.getProperty("java.io.tmpdir"), dirName));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    // Java Base64 - Creating a filename-safe hash
    String data = request.getParameter("data");
    
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ruleid: java-insecure-hex-value
            sb.append(Integer.toHexString(0xff & b));
        }
        
        String encoded = Base64.getEncoder().encodeToString(sb.toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("Encoded hash: " + encoded);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // Spring Web MVC - Creating a token with secure hex representation
    String username = request.getParameter("username");
    try {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(username.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            // ok: java-insecure-hex-value
            String hex = String.format("%02x", b & 0xff);
            hexString.append(hex);
        }
        System.out.println("Generated token: " + hexString.toString());
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void good_case_2(OkHttpClient client, String url) {
    // OkHttp - Generating a checksum for request validation
    Request request = new Request.Builder().url(url).build();
    try {
        okhttp3.Response response = client.newCall(request).execute();
        String responseBody = response.body().string();
        
        MessageDigest digest = MessageDigest.getInstance("MD5");
        byte[] hashBytes = digest.digest(responseBody.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            // ok: java-insecure-hex-value
            sb.append(String.format("%02x", b & 0xff));
        }
        System.out.println("Response checksum: " + sb.toString());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3(AmazonS3 s3Client, String bucketName, String objectKey) {
    // AWS SDK - Creating a content hash for S3 object metadata
    try {
        byte[] content = s3Client.getObjectAsBytes(bucketName, objectKey).getObjectContent().readAllBytes();
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(content);
        
        StringBuilder hexDigest = new StringBuilder();
        for (byte b : digest) {
            // ok: java-insecure-hex-value
            hexDigest.append(String.format("%02x", b & 0xff));
        }
        
        Map<String, String> metadata = new HashMap<>();
        metadata.put("content-hash", hexDigest.toString());
        s3Client.copyObject(bucketName, objectKey, bucketName, objectKey, metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4(MongoClient mongoClient, HttpServletRequest request) {
    // MongoDB - Storing user password hash
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashedPassword = md.digest(password.getBytes(StandardCharsets.UTF_8));
        
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashedPassword) {
            // ok: java-insecure-hex-value
            hexString.append(String.format("%02x", b & 0xff));
        }
        
        MongoCollection<Document> collection = mongoClient.getDatabase("users").getCollection("credentials");
        Document doc = new Document("username", username)
                .append("password_hash", hexString.toString());
        collection.insertOne(doc);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void good_case_5(Jedis jedis, HttpServletRequest request) {
    // Redis - Generating a cache key based on request parameters
    String userId = request.getParameter("userId");
    String action = request.getParameter("action");
    String combined = userId + ":" + action;
    
    try {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(combined.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ok: java-insecure-hex-value
            sb.append(String.format("%02x", b & 0xff));
        }
        String cacheKey = "action:" + sb.toString();
        jedis.set(cacheKey, "true");
        jedis.expire(cacheKey, 3600);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void good_case_6(HttpServletRequest request, Session hibernateSession) {
    // Hibernate - Creating a unique identifier for database record
    String data = request.getParameter("data");
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            // ok: java-insecure-hex-value
            hexString.append(String.format("%02x", b & 0xff));
        }
        
        Map<String, Object> entity = new HashMap<>();
        entity.put("id", hexString.toString());
        entity.put("data", data);
        hibernateSession.save("DataEntity", entity);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void good_case_7(FirebaseDatabase database, HttpServletRequest request) {
    // Firebase SDK - Creating a unique path for storing user data
    String userId = request.getParameter("userId");
    String data = request.getParameter("data");
    
    try {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(userId.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ok: java-insecure-hex-value
            sb.append(String.format("%02x", b & 0xff));
        }
        
        String path = "users/" + sb.toString();
        database.getReference(path).setValue(data);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void good_case_8(RoutingContext routingContext, Vertx vertx) {
    // Vert.x - Creating a session ID
    String ip = routingContext.request().remoteAddress().host();
    String userAgent = routingContext.request().getHeader("User-Agent");
    String combined = ip + ":" + userAgent + ":" + System.currentTimeMillis();
    
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(combined.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            // ok: java-insecure-hex-value
            hexString.append(String.format("%02x", b & 0xff));
        }
        
        routingContext.session().put("sessionId", hexString.toString());
        routingContext.response().end("Session created");
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void good_case_9(KafkaProducer<String, String> producer, HttpServletRequest request) {
    // Kafka - Creating a message key based on request data
    String topic = "user-events";
    String userId = request.getParameter("userId");
    String eventType = request.getParameter("eventType");
    String eventData = request.getParameter("data");
    
    try {
        String combined = userId + ":" + eventType;
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(combined.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ok: java-insecure-hex-value
            sb.append(String.format("%02x", b & 0xff));
        }
        
        String key = sb.toString();
        ProducerRecord<String, String> record = new ProducerRecord<>(topic, key, eventData);
        producer.send(record);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    // JWT Token - Creating a token ID
    String username = request.getParameter("username");
    
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(username.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            // ok: java-insecure-hex-value
            hexString.append(String.format("%02x", b & 0xff));
        }
        
        String jwtId = hexString.toString();
        String token = Jwts.builder()
                .setId(jwtId)
                .setSubject(username)
                .signWith(SignatureAlgorithm.HS256, "secret".getBytes())
                .compact();
        
        System.out.println("Generated JWT: " + token);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void good_case_11(BlobServiceClient blobServiceClient, HttpServletRequest request) {
    // Azure Storage SDK - Creating a blob name based on content hash
    String containerName = "user-uploads";
    String content = request.getParameter("content");
    
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(content.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ok: java-insecure-hex-value
            sb.append(String.format("%02x", b & 0xff));
        }
        
        String blobName = sb.toString() + ".txt";
        blobServiceClient.getBlobContainerClient(containerName)
                .getBlobClient(blobName)
                .getBlockBlobClient()
                .upload(content.getBytes(StandardCharsets.UTF_8), content.length());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    // Apache Commons IO - Creating a unique filename for temporary file
    String content = request.getParameter("content");
    
    try {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(content.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ok: java-insecure-hex-value
            sb.append(String.format("%02x", b & 0xff));
        }
        
        String filename = "temp_" + sb.toString() + ".txt";
        File tempFile = new File(System.getProperty("java.io.tmpdir"), filename);
        FileUtils.writeStringToFile(tempFile, content, StandardCharsets.UTF_8);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13(ObjectMapper mapper, HttpServletRequest request) {
    // Jackson - Creating a unique ID for JSON object
    String data = request.getParameter("data");
    
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ok: java-insecure-hex-value
            sb.append(String.format("%02x", b & 0xff));
        }
        
        Map<String, Object> jsonObject = new HashMap<>();
        jsonObject.put("id", sb.toString());
        jsonObject.put("data", data);
        jsonObject.put("timestamp", System.currentTimeMillis());
        
        String json = mapper.writeValueAsString(jsonObject);
        System.out.println("JSON: " + json);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) {
    // Java NIO - Creating a unique directory name
    String userId = request.getParameter("userId");
    
    try {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(userId.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ok: java-insecure-hex-value
            sb.append(String.format("%02x", b & 0xff));
        }
        
        String dirName = "user_" + sb.toString();
        Files.createDirectories(Paths.get(System.getProperty("java.io.tmpdir"), dirName));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    // Java Base64 - Creating a filename-safe hash
    String data = request.getParameter("data");
    
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            // ok: java-insecure-hex-value
            sb.append(String.format("%02x", b & 0xff));
        }
        
        String encoded = Base64.getEncoder().encodeToString(sb.toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("Encoded hash: " + encoded);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}