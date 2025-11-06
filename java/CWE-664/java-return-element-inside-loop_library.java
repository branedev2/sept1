import java.util.*;
import java.io.*;
import java.net.*;
import java.sql.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import org.apache.http.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import com.google.api.client.http.*;
import com.google.api.client.http.javanet.*;
import com.google.api.services.drive.*;
import com.google.api.services.drive.model.*;
import org.apache.commons.io.*;
import okhttp3.*;
import retrofit2.*;
import retrofit2.http.*;
import org.apache.commons.exec.*;
import com.jcraft.jsch.*;
import org.apache.commons.net.ftp.*;
import software.amazon.awssdk.services.ec2.*;
import software.amazon.awssdk.services.ec2.model.*;
import com.azure.storage.blob.*;
import com.azure.storage.blob.models.*;
import com.mongodb.*;
import org.elasticsearch.client.*;
import org.elasticsearch.action.search.*;
import org.elasticsearch.search.*;
import redis.clients.jedis.*;
import com.rabbitmq.client.*;
import org.apache.kafka.clients.consumer.*;
import org.apache.kafka.clients.producer.*;
import com.fasterxml.jackson.databind.*;

// Security Issue: Returning elements inside loops can lead to inconsistent results or security issues
// when multiple elements might match a condition, especially when dealing with sensitive data or identifiers.

// True Positive Examples (Vulnerable/Insecure Code)

// Spring Framework - User Authentication
public User bad_case_1(@RequestParam String username) {
    List<User> users = userRepository.findAll();
    
    for (User user : users) {
        if (user.getUsername().equals(username)) {
            // ruleid: java-return-element-inside-loop
            return user; // Returns first matching user without checking if multiple users have the same username
        }
    }
    return null;
}

// Apache HttpClient - Finding specific HTTP response header
public String bad_case_2() throws IOException {
    HttpClient httpClient = HttpClients.createDefault();
    HttpGet request = new HttpGet("https://api.example.com/data");
    HttpResponse response = httpClient.execute(request);
    
    Header[] headers = response.getAllHeaders();
    for (Header header : headers) {
        if (header.getName().equalsIgnoreCase("X-API-Key")) {
            // ruleid: java-return-element-inside-loop
            return header.getValue(); // Returns first matching header without checking for duplicates
        }
    }
    return null;
}

// AWS SDK - S3 Object Search
public S3Object bad_case_3(AmazonS3 s3Client, String bucketName, String filePrefix) {
    ObjectListing objectListing = s3Client.listObjects(bucketName);
    
    for (S3ObjectSummary objectSummary : objectListing.getObjectSummaries()) {
        if (objectSummary.getKey().startsWith(filePrefix)) {
            // ruleid: java-return-element-inside-loop
            return s3Client.getObject(bucketName, objectSummary.getKey()); // Returns first matching S3 object
        }
    }
    return null;
}

// Google Drive API - File Search
public File bad_case_4(Drive driveService, String fileName) throws IOException {
    FileList result = driveService.files().list()
            .setPageSize(100)
            .execute();
    
    for (File file : result.getFiles()) {
        if (file.getName().equals(fileName)) {
            // ruleid: java-return-element-inside-loop
            return file; // Returns first matching file without checking for duplicates
        }
    }
    return null;
}

// OkHttp - Cookie Extraction
public Cookie bad_case_5(OkHttpClient client, HttpUrl url, String cookieName) {
    List<Cookie> cookies = client.cookieJar().loadForRequest(url);
    
    for (Cookie cookie : cookies) {
        if (cookie.name().equals(cookieName)) {
            // ruleid: java-return-element-inside-loop
            return cookie; // Returns first matching cookie without checking for duplicates
        }
    }
    return null;
}

// Retrofit - API Response Processing
public ResponseBody bad_case_6(List<Response<ResponseBody>> responses, int statusCode) {
    for (Response<ResponseBody> response : responses) {
        if (response.code() == statusCode) {
            // ruleid: java-return-element-inside-loop
            return response.body(); // Returns first response with matching status code
        }
    }
    return null;
}

// Apache Commons Exec - Command Result Processing
public String bad_case_7(List<CommandLine> commands) throws IOException {
    DefaultExecutor executor = new DefaultExecutor();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    PumpStreamHandler streamHandler = new PumpStreamHandler(outputStream);
    executor.setStreamHandler(streamHandler);
    
    for (CommandLine command : commands) {
        executor.execute(command);
        String output = outputStream.toString();
        if (output.contains("SUCCESS")) {
            // ruleid: java-return-element-inside-loop
            return output; // Returns first successful command output
        }
        outputStream.reset();
    }
    return null;
}

// JSch - SSH Connection
public ChannelSftp bad_case_8(List<String> servers, String username, String password) {
    for (String server : servers) {
        try {
            JSch jsch = new JSch();
            Session session = jsch.getSession(username, server, 22);
            session.setPassword(password);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect(3000);
            
            ChannelSftp channel = (ChannelSftp) session.openChannel("sftp");
            channel.connect();
            
            // ruleid: java-return-element-inside-loop
            return channel; // Returns first successful connection without checking alternatives
        } catch (JSchException e) {
            // Continue to next server
        }
    }
    return null;
}

// Apache Commons Net - FTP File Search
public FTPFile bad_case_9(FTPClient ftpClient, String filePattern) throws IOException {
    FTPFile[] files = ftpClient.listFiles();
    
    for (FTPFile file : files) {
        if (file.getName().matches(filePattern)) {
            // ruleid: java-return-element-inside-loop
            return file; // Returns first matching file without checking for duplicates
        }
    }
    return null;
}

// AWS SDK v2 - EC2 Instance Search
public Instance bad_case_10(Ec2Client ec2Client, String instanceName) {
    DescribeInstancesResponse response = ec2Client.describeInstances();
    
    for (Reservation reservation : response.reservations()) {
        for (Instance instance : reservation.instances()) {
            for (Tag tag : instance.tags()) {
                if (tag.key().equals("Name") && tag.value().equals(instanceName)) {
                    // ruleid: java-return-element-inside-loop
                    return instance; // Returns first matching instance without checking for duplicates
                }
            }
        }
    }
    return null;
}

// Azure Blob Storage - Blob Search
public BlobItem bad_case_11(BlobContainerClient containerClient, String blobPrefix) {
    for (BlobItem blobItem : containerClient.listBlobs()) {
        if (blobItem.getName().startsWith(blobPrefix)) {
            // ruleid: java-return-element-inside-loop
            return blobItem; // Returns first matching blob without checking for duplicates
        }
    }
    return null;
}

// MongoDB - Document Search
public Document bad_case_12(MongoCollection<Document> collection, String field, String value) {
    FindIterable<Document> documents = collection.find(new Document(field, value));
    
    for (Document document : documents) {
        // ruleid: java-return-element-inside-loop
        return document; // Returns first matching document without checking for duplicates
    }
    return null;
}

// Elasticsearch - Search Result Processing
public SearchHit bad_case_13(SearchResponse searchResponse, String fieldName, String value) {
    SearchHits hits = searchResponse.getHits();
    
    for (SearchHit hit : hits) {
        Map<String, Object> sourceAsMap = hit.getSourceAsMap();
        if (sourceAsMap.containsKey(fieldName) && sourceAsMap.get(fieldName).equals(value)) {
            // ruleid: java-return-element-inside-loop
            return hit; // Returns first matching hit without checking for duplicates
        }
    }
    return null;
}

// Redis - Key Search
public String bad_case_14(Jedis jedis, String keyPattern) {
    Set<String> keys = jedis.keys(keyPattern);
    
    for (String key : keys) {
        String value = jedis.get(key);
        if (value != null && !value.isEmpty()) {
            // ruleid: java-return-element-inside-loop
            return key; // Returns first non-empty key without checking for duplicates
        }
    }
    return null;
}

// Kafka - Message Processing
public ConsumerRecord<String, String> bad_case_15(ConsumerRecords<String, String> records, String messageContent) {
    for (ConsumerRecord<String, String> record : records) {
        if (record.value().contains(messageContent)) {
            // ruleid: java-return-element-inside-loop
            return record; // Returns first matching record without checking for duplicates
        }
    }
    return null;
}

// True Negative Examples (Safe/Secure Code)

// Spring Framework - User Authentication (Safe)
public User good_case_1(@RequestParam String username) {
    List<User> users = userRepository.findAll();
    List<User> matchingUsers = new ArrayList<>();
    
    for (User user : users) {
        if (user.getUsername().equals(username)) {
            matchingUsers.add(user);
        }
    }
    
    if (matchingUsers.isEmpty()) {
        return null;
    } else if (matchingUsers.size() == 1) {
        // ok: java-return-element-inside-loop
        return matchingUsers.get(0);
    } else {
        throw new SecurityException("Multiple users found with the same username");
    }
}

// Apache HttpClient - Finding specific HTTP response header (Safe)
public String good_case_2() throws IOException {
    HttpClient httpClient = HttpClients.createDefault();
    HttpGet request = new HttpGet("https://api.example.com/data");
    HttpResponse response = httpClient.execute(request);
    
    Header[] headers = response.getAllHeaders();
    List<String> apiKeyValues = new ArrayList<>();
    
    for (Header header : headers) {
        if (header.getName().equalsIgnoreCase("X-API-Key")) {
            apiKeyValues.add(header.getValue());
        }
    }
    
    if (apiKeyValues.isEmpty()) {
        return null;
    } else if (apiKeyValues.size() == 1) {
        // ok: java-return-element-inside-loop
        return apiKeyValues.get(0);
    } else {
        throw new SecurityException("Multiple API keys found in headers");
    }
}

// AWS SDK - S3 Object Search (Safe)
public List<S3Object> good_case_3(AmazonS3 s3Client, String bucketName, String filePrefix) {
    ObjectListing objectListing = s3Client.listObjects(bucketName);
    List<S3Object> matchingObjects = new ArrayList<>();
    
    for (S3ObjectSummary objectSummary : objectListing.getObjectSummaries()) {
        if (objectSummary.getKey().startsWith(filePrefix)) {
            matchingObjects.add(s3Client.getObject(bucketName, objectSummary.getKey()));
        }
    }
    
    // ok: java-return-element-inside-loop
    return matchingObjects; // Returns all matching objects
}

// Google Drive API - File Search (Safe)
public List<File> good_case_4(Drive driveService, String fileName) throws IOException {
    FileList result = driveService.files().list()
            .setPageSize(100)
            .execute();
    
    List<File> matchingFiles = new ArrayList<>();
    for (File file : result.getFiles()) {
        if (file.getName().equals(fileName)) {
            matchingFiles.add(file);
        }
    }
    
    // ok: java-return-element-inside-loop
    return matchingFiles; // Returns all matching files
}

// OkHttp - Cookie Extraction (Safe)
public List<Cookie> good_case_5(OkHttpClient client, HttpUrl url, String cookieName) {
    List<Cookie> cookies = client.cookieJar().loadForRequest(url);
    List<Cookie> matchingCookies = new ArrayList<>();
    
    for (Cookie cookie : cookies) {
        if (cookie.name().equals(cookieName)) {
            matchingCookies.add(cookie);
        }
    }
    
    // ok: java-return-element-inside-loop
    return matchingCookies; // Returns all matching cookies
}

// Retrofit - API Response Processing (Safe)
public List<ResponseBody> good_case_6(List<Response<ResponseBody>> responses, int statusCode) {
    List<ResponseBody> matchingResponses = new ArrayList<>();
    
    for (Response<ResponseBody> response : responses) {
        if (response.code() == statusCode) {
            matchingResponses.add(response.body());
        }
    }
    
    // ok: java-return-element-inside-loop
    return matchingResponses; // Returns all matching responses
}

// Apache Commons Exec - Command Result Processing (Safe)
public List<String> good_case_7(List<CommandLine> commands) throws IOException {
    DefaultExecutor executor = new DefaultExecutor();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    PumpStreamHandler streamHandler = new PumpStreamHandler(outputStream);
    executor.setStreamHandler(streamHandler);
    List<String> successfulOutputs = new ArrayList<>();
    
    for (CommandLine command : commands) {
        executor.execute(command);
        String output = outputStream.toString();
        if (output.contains("SUCCESS")) {
            successfulOutputs.add(output);
        }
        outputStream.reset();
    }
    
    // ok: java-return-element-inside-loop
    return successfulOutputs; // Returns all successful command outputs
}

// JSch - SSH Connection (Safe)
public List<ChannelSftp> good_case_8(List<String> servers, String username, String password) {
    List<ChannelSftp> connectedChannels = new ArrayList<>();
    
    for (String server : servers) {
        try {
            JSch jsch = new JSch();
            Session session = jsch.getSession(username, server, 22);
            session.setPassword(password);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect(3000);
            
            ChannelSftp channel = (ChannelSftp) session.openChannel("sftp");
            channel.connect();
            connectedChannels.add(channel);
        } catch (JSchException e) {
            // Continue to next server
        }
    }
    
    // ok: java-return-element-inside-loop
    return connectedChannels; // Returns all successful connections
}

// Apache Commons Net - FTP File Search (Safe)
public List<FTPFile> good_case_9(FTPClient ftpClient, String filePattern) throws IOException {
    FTPFile[] files = ftpClient.listFiles();
    List<FTPFile> matchingFiles = new ArrayList<>();
    
    for (FTPFile file : files) {
        if (file.getName().matches(filePattern)) {
            matchingFiles.add(file);
        }
    }
    
    // ok: java-return-element-inside-loop
    return matchingFiles; // Returns all matching files
}

// AWS SDK v2 - EC2 Instance Search (Safe)
public List<Instance> good_case_10(Ec2Client ec2Client, String instanceName) {
    DescribeInstancesResponse response = ec2Client.describeInstances();
    List<Instance> matchingInstances = new ArrayList<>();
    
    for (Reservation reservation : response.reservations()) {
        for (Instance instance : reservation.instances()) {
            for (Tag tag : instance.tags()) {
                if (tag.key().equals("Name") && tag.value().equals(instanceName)) {
                    matchingInstances.add(instance);
                    break; // Break inner loop only
                }
            }
        }
    }
    
    // ok: java-return-element-inside-loop
    return matchingInstances; // Returns all matching instances
}

// Azure Blob Storage - Blob Search (Safe)
public List<BlobItem> good_case_11(BlobContainerClient containerClient, String blobPrefix) {
    List<BlobItem> matchingBlobs = new ArrayList<>();
    
    for (BlobItem blobItem : containerClient.listBlobs()) {
        if (blobItem.getName().startsWith(blobPrefix)) {
            matchingBlobs.add(blobItem);
        }
    }
    
    // ok: java-return-element-inside-loop
    return matchingBlobs; // Returns all matching blobs
}

// MongoDB - Document Search (Safe)
public List<Document> good_case_12(MongoCollection<Document> collection, String field, String value) {
    FindIterable<Document> documents = collection.find(new Document(field, value));
    List<Document> matchingDocuments = new ArrayList<>();
    
    for (Document document : documents) {
        matchingDocuments.add(document);
    }
    
    // ok: java-return-element-inside-loop
    return matchingDocuments; // Returns all matching documents
}

// Elasticsearch - Search Result Processing (Safe)
public List<SearchHit> good_case_13(SearchResponse searchResponse, String fieldName, String value) {
    SearchHits hits = searchResponse.getHits();
    List<SearchHit> matchingHits = new ArrayList<>();
    
    for (SearchHit hit : hits) {
        Map<String, Object> sourceAsMap = hit.getSourceAsMap();
        if (sourceAsMap.containsKey(fieldName) && sourceAsMap.get(fieldName).equals(value)) {
            matchingHits.add(hit);
        }
    }
    
    // ok: java-return-element-inside-loop
    return matchingHits; // Returns all matching hits
}

// Redis - Key Search (Safe)
public List<String> good_case_14(Jedis jedis, String keyPattern) {
    Set<String> keys = jedis.keys(keyPattern);
    List<String> nonEmptyKeys = new ArrayList<>();
    
    for (String key : keys) {
        String value = jedis.get(key);
        if (value != null && !value.isEmpty()) {
            nonEmptyKeys.add(key);
        }
    }
    
    // ok: java-return-element-inside-loop
    return nonEmptyKeys; // Returns all non-empty keys
}

// Kafka - Message Processing (Safe)
public List<ConsumerRecord<String, String>> good_case_15(ConsumerRecords<String, String> records, String messageContent) {
    List<ConsumerRecord<String, String>> matchingRecords = new ArrayList<>();
    
    for (ConsumerRecord<String, String> record : records) {
        if (record.value().contains(messageContent)) {
            matchingRecords.add(record);
        }
    }
    
    // ok: java-return-element-inside-loop
    return matchingRecords; // Returns all matching records
}