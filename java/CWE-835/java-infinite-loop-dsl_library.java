import java.util.*;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;
import java.util.regex.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.apache.http.HttpResponse;
import org.apache.commons.io.IOUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import okhttp3.*;
import retrofit2.*;
import retrofit2.converter.gson.GsonConverterFactory;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.apache.commons.collections4.CollectionUtils;
import com.google.gson.Gson;
import com.amazonaws.services.lambda.runtime.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import org.apache.commons.lang3.StringUtils;
import javax.servlet.http.*;
import io.vertx.core.*;
import io.vertx.core.http.*;
import io.vertx.ext.web.*;
import org.apache.kafka.clients.consumer.*;
import org.apache.kafka.common.*;
import org.hibernate.*;
import javax.persistence.*;
import redis.clients.jedis.*;
import com.google.cloud.storage.*;
import io.netty.channel.*;
import io.netty.handler.codec.http.*;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.commons.validator.routines.UrlValidator;

// Security Issue: Infinite loops caused by unhandled exceptions or lack of proper termination conditions

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // Spring Web MVC - Infinite loop processing request parameters
    String userInput = request.getParameter("input");
    List<String> tokens = new ArrayList<>();
    int i = 0;
    
    // ruleid: java-infinite-loop-dsl
    while (i < userInput.length()) {
        // No termination condition that guarantees progress
        if (userInput.charAt(i) == ' ') {
            continue; // i is never incremented in this branch
        }
        tokens.add(String.valueOf(userInput.charAt(i)));
        i++;
    }
}

public void bad_case_2() {
    // OkHttp - Infinite loop in request retry mechanism
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
        .url("https://api.example.com/data")
        .build();
    
    boolean success = false;
    
    // ruleid: java-infinite-loop-dsl
    while (!success) {
        try {
            Response response = client.newCall(request).execute();
            // If the response fails, we'll retry indefinitely
            // No backoff or max retry count
            if (response.code() >= 200 && response.code() < 300) {
                success = true;
            }
        } catch (IOException e) {
            // Exception caught but no retry limit
        }
    }
}

public void bad_case_3(HttpServletRequest request) {
    // Apache Commons IO - Infinite loop in string processing
    String data = request.getParameter("data");
    StringBuilder processed = new StringBuilder();
    int index = 0;
    
    // ruleid: java-infinite-loop-dsl
    while (index < data.length()) {
        char c = data.charAt(index);
        if (c == '\\') {
            // Escape sequence handling with potential infinite loop
            if (index + 1 < data.length() && data.charAt(index + 1) == 'u') {
                // Parse unicode escape
                // Bug: index is not incremented in some cases
                if (data.charAt(index + 2) == '0') {
                    continue; // Infinite loop - index never advances
                }
                index += 6; // Skip escape sequence
            } else {
                index += 2; // Skip escape character and next char
            }
        } else {
            processed.append(c);
            index++;
        }
    }
}

public void bad_case_4() {
    // Jsoup - Infinite loop in HTML parsing
    try {
        Document doc = Jsoup.connect("https://example.com").get();
        String html = doc.html();
        List<String> tags = new ArrayList<>();
        int pos = 0;
        
        // ruleid: java-infinite-loop-dsl
        while (pos < html.length()) {
            int tagStart = html.indexOf('<', pos);
            if (tagStart == -1) break;
            
            int tagEnd = html.indexOf('>', tagStart);
            if (tagEnd == -1) {
                // If no closing bracket is found, this will cause an infinite loop
                // as pos never advances
                continue;
            }
            
            String tag = html.substring(tagStart + 1, tagEnd);
            tags.add(tag);
            pos = tagEnd + 1;
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request) {
    // Jackson ObjectMapper - Infinite loop in JSON parsing
    String jsonInput = request.getParameter("json");
    ObjectMapper mapper = new ObjectMapper();
    
    try {
        Map<String, Object> data = mapper.readValue(jsonInput, Map.class);
        String pattern = (String) data.get("pattern");
        String text = (String) data.get("text");
        
        // ruleid: java-infinite-loop-dsl
        while (text.contains(pattern)) {
            // This could cause an infinite loop if pattern is empty string
            // as empty string is always contained in any string
            int index = text.indexOf(pattern);
            text = text.substring(0, index) + text.substring(index + pattern.length());
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    // Apache HttpClient - Infinite loop in connection retry
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpGet request = new HttpGet("https://api.example.com/data");
    
    // ruleid: java-infinite-loop-dsl
    while (true) {
        try {
            HttpResponse response = httpClient.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            
            if (statusCode == 200) {
                break;
            }
            // No retry limit, will keep trying forever for non-200 responses
            Thread.sleep(1000); // Wait before retrying
        } catch (Exception e) {
            // Exception caught but loop continues indefinitely
        }
    }
}

public void bad_case_7(HttpServletRequest request) {
    // Hibernate - Infinite loop in database query processing
    String searchTerm = request.getParameter("search");
    SessionFactory sessionFactory = null; // Normally initialized elsewhere
    Session session = sessionFactory.openSession();
    
    List<Object> results = new ArrayList<>();
    int page = 0;
    int pageSize = 100;
    
    // ruleid: java-infinite-loop-dsl
    while (true) {
        Query query = session.createQuery("FROM Product WHERE name LIKE :term")
            .setParameter("term", "%" + searchTerm + "%")
            .setFirstResult(page * pageSize)
            .setMaxResults(pageSize);
        
        List<?> pageResults = query.list();
        
        if (pageResults.isEmpty()) {
            break;
        }
        
        results.addAll(pageResults);
        
        // If the search term matches all records and the database has exactly
        // pageSize records, this will cause an infinite loop
        if (pageResults.size() < pageSize) {
            break;
        }
        
        // Bug: page is not incremented in some edge cases
        if (searchTerm.length() > 0 && searchTerm.charAt(0) == '*') {
            continue; // Infinite loop - page never advances
        }
        
        page++;
    }
}

public void bad_case_8() {
    // Kafka Consumer - Infinite loop in message processing
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    props.put("group.id", "test");
    props.put("enable.auto.commit", "false");
    
    KafkaConsumer<String, String> consumer = new KafkaConsumer<>(props);
    consumer.subscribe(Arrays.asList("topic"));
    
    // ruleid: java-infinite-loop-dsl
    while (true) {
        ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(100));
        for (ConsumerRecord<String, String> record : records) {
            try {
                // Process record
                String value = record.value();
                
                // If processing fails, we don't commit and don't have a way to skip
                // This will cause the same record to be processed repeatedly
                if (value.contains("error")) {
                    // No mechanism to skip or handle this record permanently
                    continue;
                }
                
                // Normal processing
            } catch (Exception e) {
                // Exception caught but no mechanism to prevent reprocessing
                // the same record indefinitely
            }
        }
        consumer.commitSync();
    }
}

public void bad_case_9(HttpServletRequest request) {
    // AWS S3 Client - Infinite loop in file processing
    String bucketName = request.getParameter("bucket");
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    
    String continuationToken = null;
    
    // ruleid: java-infinite-loop-dsl
    do {
        ListObjectsV2Request listObjectsRequest = new ListObjectsV2Request()
            .withBucketName(bucketName)
            .withContinuationToken(continuationToken);
        
        ListObjectsV2Result result = s3Client.listObjectsV2(listObjectsRequest);
        
        for (S3ObjectSummary objectSummary : result.getObjectSummaries()) {
            try {
                // Process object
                String key = objectSummary.getKey();
                
                // Bug: in some cases we don't update the continuation token
                if (key.endsWith(".tmp")) {
                    // This will cause an infinite loop as we're not updating
                    // the continuation token when we encounter .tmp files
                    continue;
                }
            } catch (Exception e) {
                // Exception caught but loop continues
            }
        }
        
        continuationToken = result.getNextContinuationToken();
    } while (continuationToken != null);
}

public void bad_case_10() {
    // Vert.x - Infinite loop in HTTP server request handling
    Vertx vertx = Vertx.vertx();
    HttpServer server = vertx.createHttpServer();
    
    server.requestHandler(request -> {
        String path = request.path();
        
        // ruleid: java-infinite-loop-dsl
        while (path.startsWith("/")) {
            // This could cause an infinite loop if path is "/"
            // as removing one "/" from "/" still gives "/"
            path = path.substring(1);
        }
        
        request.response()
            .putHeader("content-type", "text/plain")
            .end("Path: " + path);
    });
    
    server.listen(8080);
}

public void bad_case_11(HttpServletRequest request) {
    // Redis/Jedis - Infinite loop in cache key processing
    String keyPattern = request.getParameter("keyPattern");
    Jedis jedis = new Jedis("localhost");
    
    Set<String> allKeys = new HashSet<>();
    String cursor = "0";
    
    // ruleid: java-infinite-loop-dsl
    do {
        ScanResult<String> scanResult = jedis.scan(cursor, new ScanParams().match(keyPattern));
        allKeys.addAll(scanResult.getResult());
        
        // Bug: cursor is not updated in some cases
        if (keyPattern.equals("*")) {
            // This will cause an infinite loop as cursor never changes
            continue;
        }
        
        cursor = scanResult.getCursor();
    } while (!cursor.equals("0"));
}

public void bad_case_12() {
    // Google Cloud Storage - Infinite loop in blob listing
    Storage storage = StorageOptions.getDefaultInstance().getService();
    String bucketName = "my-bucket";
    
    // ruleid: java-infinite-loop-dsl
    while (true) {
        try {
            Page<Blob> blobs = storage.list(bucketName);
            
            for (Blob blob : blobs.iterateAll()) {
                // Process blob
                String name = blob.getName();
                
                // No exit condition - will process forever
                if (name.startsWith("temp/")) {
                    // Process temp files
                }
            }
            
            // No break condition to exit the loop
        } catch (Exception e) {
            // Exception caught but loop continues indefinitely
        }
    }
}

public void bad_case_13(HttpServletRequest request) {
    // Netty - Infinite loop in HTTP content processing
    String content = request.getParameter("content");
    ByteBuf buffer = io.netty.buffer.Unpooled.copiedBuffer(content, java.nio.charset.StandardCharsets.UTF_8);
    
    int readerIndex = buffer.readerIndex();
    
    // ruleid: java-infinite-loop-dsl
    while (buffer.isReadable()) {
        byte b = buffer.readByte();
        
        // Process byte
        if (b == '\0') {
            // Reset reader index on null byte, causing infinite loop
            buffer.readerIndex(readerIndex);
        }
    }
}

public void bad_case_14() {
    // Apache Commons Validator - Infinite loop in URL validation
    UrlValidator validator = new UrlValidator();
    
    // ruleid: java-infinite-loop-dsl
    while (true) {
        try {
            String url = "https://example.com";
            boolean isValid = validator.isValid(url);
            
            if (isValid) {
                // Process valid URL
            } else {
                // Process invalid URL
            }
            
            // No exit condition - will validate the same URL forever
        } catch (Exception e) {
            // Exception caught but loop continues indefinitely
        }
    }
}

public void bad_case_15(HttpServletRequest request) {
    // Apache Commons Text - Infinite loop in string escaping
    String input = request.getParameter("input");
    StringBuilder output = new StringBuilder();
    int i = 0;
    
    // ruleid: java-infinite-loop-dsl
    while (i < input.length()) {
        char c = input.charAt(i);
        
        if (c == '&') {
            // Check for HTML entity
            int semicolon = input.indexOf(';', i);
            if (semicolon == -1) {
                // No semicolon found, but we don't advance the index
                // This will cause an infinite loop
                continue;
            }
            
            String entity = input.substring(i, semicolon + 1);
            output.append(StringEscapeUtils.unescapeHtml4(entity));
            i = semicolon + 1;
        } else {
            output.append(c);
            i++;
        }
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // Spring Web MVC - Safe loop processing request parameters
    String userInput = request.getParameter("input");
    List<String> tokens = new ArrayList<>();
    int i = 0;
    
    // ok: java-infinite-loop-dsl
    while (i < userInput.length()) {
        // Proper termination condition with guaranteed progress
        if (userInput.charAt(i) == ' ') {
            i++; // Always increment i to ensure progress
            continue;
        }
        tokens.add(String.valueOf(userInput.charAt(i)));
        i++;
    }
}

public void good_case_2() {
    // OkHttp - Safe request retry mechanism with max retries
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
        .url("https://api.example.com/data")
        .build();
    
    boolean success = false;
    int retries = 0;
    final int MAX_RETRIES = 3;
    
    // ok: java-infinite-loop-dsl
    while (!success && retries < MAX_RETRIES) {
        try {
            Response response = client.newCall(request).execute();
            if (response.code() >= 200 && response.code() < 300) {
                success = true;
            }
            retries++;
        } catch (IOException e) {
            retries++;
        }
    }
}

public void good_case_3(HttpServletRequest request) {
    // Apache Commons IO - Safe string processing
    String data = request.getParameter("data");
    StringBuilder processed = new StringBuilder();
    int index = 0;
    
    // ok: java-infinite-loop-dsl
    while (index < data.length()) {
        char c = data.charAt(index);
        if (c == '\\') {
            // Escape sequence handling with guaranteed progress
            if (index + 1 < data.length() && data.charAt(index + 1) == 'u') {
                // Parse unicode escape
                if (index + 5 < data.length()) {
                    // Safely handle unicode escape
                    index += 6; // Skip escape sequence
                } else {
                    // Not enough characters for unicode escape
                    index++; // Still make progress
                }
            } else {
                index += 2; // Skip escape character and next char
            }
        } else {
            processed.append(c);
            index++;
        }
    }
}

public void good_case_4() {
    // Jsoup - Safe HTML parsing
    try {
        Document doc = Jsoup.connect("https://example.com").get();
        String html = doc.html();
        List<String> tags = new ArrayList<>();
        int pos = 0;
        
        // ok: java-infinite-loop-dsl
        while (pos < html.length()) {
            int tagStart = html.indexOf('<', pos);
            if (tagStart == -1) break;
            
            int tagEnd = html.indexOf('>', tagStart);
            if (tagEnd == -1) {
                // If no closing bracket is found, advance past this opening bracket
                // to avoid infinite loop
                pos = tagStart + 1;
                continue;
            }
            
            String tag = html.substring(tagStart + 1, tagEnd);
            tags.add(tag);
            pos = tagEnd + 1;
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    // Jackson ObjectMapper - Safe JSON parsing
    String jsonInput = request.getParameter("json");
    ObjectMapper mapper = new ObjectMapper();
    
    try {
        Map<String, Object> data = mapper.readValue(jsonInput, Map.class);
        String pattern = (String) data.get("pattern");
        String text = (String) data.get("text");
        
        // Check for empty pattern to avoid infinite loop
        if (pattern != null && !pattern.isEmpty()) {
            // ok: java-infinite-loop-dsl
            while (text.contains(pattern)) {
                int index = text.indexOf(pattern);
                text = text.substring(0, index) + text.substring(index + pattern.length());
            }
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6() {
    // Apache HttpClient - Safe connection retry with timeout
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpGet request = new HttpGet("https://api.example.com/data");
    
    int retries = 0;
    final int MAX_RETRIES = 5;
    
    // ok: java-infinite-loop-dsl
    while (retries < MAX_RETRIES) {
        try {
            HttpResponse response = httpClient.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            
            if (statusCode == 200) {
                break;
            }
            
            retries++;
            if (retries >= MAX_RETRIES) {
                break;
            }
            
            Thread.sleep(1000); // Wait before retrying
        } catch (Exception e) {
            retries++;
            if (retries >= MAX_RETRIES) {
                break;
            }
        }
    }
}

public void good_case_7(HttpServletRequest request) {
    // Hibernate - Safe database query processing
    String searchTerm = request.getParameter("search");
    SessionFactory sessionFactory = null; // Normally initialized elsewhere
    Session session = sessionFactory.openSession();
    
    List<Object> results = new ArrayList<>();
    int page = 0;
    int pageSize = 100;
    final int MAX_PAGES = 100; // Limit to prevent infinite loops
    
    // ok: java-infinite-loop-dsl
    while (page < MAX_PAGES) {
        Query query = session.createQuery("FROM Product WHERE name LIKE :term")
            .setParameter("term", "%" + searchTerm + "%")
            .setFirstResult(page * pageSize)
            .setMaxResults(pageSize);
        
        List<?> pageResults = query.list();
        
        if (pageResults.isEmpty()) {
            break;
        }
        
        results.addAll(pageResults);
        
        if (pageResults.size() < pageSize) {
            break;
        }
        
        page++; // Always increment page to ensure progress
    }
}

public void good_case_8() {
    // Kafka Consumer - Safe message processing with timeout
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    props.put("group.id", "test");
    props.put("enable.auto.commit", "false");
    
    KafkaConsumer<String, String> consumer = new KafkaConsumer<>(props);
    consumer.subscribe(Arrays.asList("topic"));
    
    long startTime = System.currentTimeMillis();
    long timeout = 60000; // 1 minute timeout
    
    // ok: java-infinite-loop-dsl
    while (System.currentTimeMillis() - startTime < timeout) {
        ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(100));
        for (ConsumerRecord<String, String> record : records) {
            try {
                // Process record
                String value = record.value();
                
                // Skip problematic records after logging
                if (value.contains("error")) {
                    System.err.println("Skipping problematic record: " + record.offset());
                    continue;
                }
                
                // Normal processing
            } catch (Exception e) {
                // Log exception and continue
                System.err.println("Error processing record: " + e.getMessage());
            }
        }
        consumer.commitSync();
    }
}

public void good_case_9(HttpServletRequest request) {
    // AWS S3 Client - Safe file processing
    String bucketName = request.getParameter("bucket");
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    
    String continuationToken = null;
    int pageCount = 0;
    final int MAX_PAGES = 100; // Limit to prevent infinite loops
    
    // ok: java-infinite-loop-dsl
    do {
        ListObjectsV2Request listObjectsRequest = new ListObjectsV2Request()
            .withBucketName(bucketName)
            .withContinuationToken(continuationToken);
        
        ListObjectsV2Result result = s3Client.listObjectsV2(listObjectsRequest);
        
        for (S3ObjectSummary objectSummary : result.getObjectSummaries()) {
            try {
                // Process object
                String key = objectSummary.getKey();
                
                // Safe handling of all file types
                if (key.endsWith(".tmp")) {
                    // Process temp files differently but continue
                    System.out.println("Processing temp file: " + key);
                }
            } catch (Exception e) {
                // Log exception and continue
                System.err.println("Error processing object: " + e.getMessage());
            }
        }
        
        continuationToken = result.getNextContinuationToken();
        pageCount++;
        
        // Safety check to prevent infinite loops
        if (pageCount >= MAX_PAGES) {
            break;
        }
    } while (continuationToken != null);
}

public void good_case_10() {
    // Vert.x - Safe HTTP server request handling
    Vertx vertx = Vertx.vertx();
    HttpServer server = vertx.createHttpServer();
    
    server.requestHandler(request -> {
        String path = request.path();
        
        // ok: java-infinite-loop-dsl
        while (path.length() > 1 && path.startsWith("/")) {
            // This avoids infinite loop by checking length > 1
            path = path.substring(1);
        }
        
        request.response()
            .putHeader("content-type", "text/plain")
            .end("Path: " + path);
    });
    
    server.listen(8080);
}

public void good_case_11(HttpServletRequest request) {
    // Redis/Jedis - Safe cache key processing
    String keyPattern = request.getParameter("keyPattern");
    Jedis jedis = new Jedis("localhost");
    
    // Validate key pattern to prevent infinite loops
    if (keyPattern == null || keyPattern.isEmpty()) {
        keyPattern = "*";
    }
    
    Set<String> allKeys = new HashSet<>();
    String cursor = "0";
    int iterations = 0;
    final int MAX_ITERATIONS = 1000; // Safety limit
    
    // ok: java-infinite-loop-dsl
    do {
        ScanResult<String> scanResult = jedis.scan(cursor, new ScanParams().match(keyPattern));
        allKeys.addAll(scanResult.getResult());
        cursor = scanResult.getCursor();
        
        iterations++;
        if (iterations >= MAX_ITERATIONS) {
            break; // Safety exit
        }
    } while (!cursor.equals("0"));
}

public void good_case_12() {
    // Google Cloud Storage - Safe blob listing with timeout
    Storage storage = StorageOptions.getDefaultInstance().getService();
    String bucketName = "my-bucket";
    
    long startTime = System.currentTimeMillis();
    long timeout = 300000; // 5 minute timeout
    
    // ok: java-infinite-loop-dsl
    while (System.currentTimeMillis() - startTime < timeout) {
        try {
            Page<Blob> blobs = storage.list(bucketName);
            
            for (Blob blob : blobs.iterateAll()) {
                // Process blob
                String name = blob.getName();
                
                if (name.startsWith("temp/")) {
                    // Process temp files
                }
            }
            
            // Exit after processing all blobs
            break;
        } catch (Exception e) {
            // Log exception and break to prevent infinite retries
            System.err.println("Error listing blobs: " + e.getMessage());
            break;
        }
    }
}

public void good_case_13(HttpServletRequest request) {
    // Netty - Safe HTTP content processing
    String content = request.getParameter("content");
    ByteBuf buffer = io.netty.buffer.Unpooled.copiedBuffer(content, java.nio.charset.StandardCharsets.UTF_8);
    
    int maxBytes = 10000; // Safety limit
    int bytesRead = 0;
    
    // ok: java-infinite-loop-dsl
    while (buffer.isReadable() && bytesRead < maxBytes) {
        byte b = buffer.readByte();
        bytesRead++;
        
        // Process byte safely
        if (b == '\0') {
            // Handle null byte safely without resetting reader index
            System.out.println("Found null byte at position " + bytesRead);
        }
    }
}

public void good_case_14() {
    // Apache Commons Validator - Safe URL validation
    UrlValidator validator = new UrlValidator();
    
    // Sample URLs to validate
    String[] urls = {
        "https://example.com",
        "http://invalid",
        "ftp://example.org"
    };
    
    // ok: java-infinite-loop-dsl
    for (String url : urls) {
        boolean isValid = validator.isValid(url);
        
        if (isValid) {
            // Process valid URL
            System.out.println("Valid URL: " + url);
        } else {
            // Process invalid URL
            System.out.println("Invalid URL: " + url);
        }
    }
}

public void good_case_15(HttpServletRequest request) {
    // Apache Commons Text - Safe string escaping
    String input = request.getParameter("input");
    StringBuilder output = new StringBuilder();
    int i = 0;
    
    // ok: java-infinite-loop-dsl
    while (i < input.length()) {
        char c = input.charAt(i);
        
        if (c == '&') {
            // Check for HTML entity
            int semicolon = input.indexOf(';', i);
            if (semicolon == -1) {
                // No semicolon found, but we still advance the index
                output.append(c);
                i++;
                continue;
            }
            
            String entity = input.substring(i, semicolon + 1);
            output.append(StringEscapeUtils.unescapeHtml4(entity));
            i = semicolon + 1;
        } else {
            output.append(c);
            i++;
        }
    }
}