import java.util.*;
import java.util.concurrent.*;
import java.util.stream.*;
import java.util.function.*;
import java.util.logging.*;
import java.util.regex.*;
import java.io.*;
import java.nio.file.*;
import java.sql.*;
import java.time.*;
import javax.servlet.http.*;
import javax.servlet.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.springframework.http.*;
import com.google.common.collect.*;
import org.apache.commons.collections4.*;
import org.apache.commons.collections4.map.*;
import org.eclipse.collections.impl.list.mutable.*;
import org.eclipse.collections.api.list.MutableList;
import com.fasterxml.jackson.databind.*;
import org.hibernate.*;
import org.hibernate.query.*;
import javax.persistence.*;
import redis.clients.jedis.*;
import org.apache.kafka.clients.consumer.*;
import org.apache.kafka.clients.producer.*;
import org.apache.kafka.common.serialization.*;
import org.apache.commons.lang3.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.dynamodbv2.*;
import com.mongodb.*;
import com.mongodb.client.*;
import org.bson.*;

// Security Issue: Unsafe Modification of Non-Thread-Safe Collections in Parallel Streams

// True Positive Examples (Vulnerable/Insecure Code)

public class NonThreadSafeCollectionModification {

    // Using standard Java Collections with parallel streams
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1() {
        List<String> dataList = new ArrayList<>();
        dataList.add("item1");
        dataList.add("item2");
        dataList.add("item3");
        
        Map<String, Integer> resultMap = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        dataList.parallelStream().forEach(item -> {
            resultMap.put(item, item.length()); // Modifying non-thread-safe HashMap in parallel stream
        });
        
        System.out.println("Result map: " + resultMap);
    }
    
    // Using Google Guava collections with parallel streams
    public void bad_case_2() {
        List<String> userIds = Lists.newArrayList("user1", "user2", "user3");
        Map<String, UserProfile> userProfiles = Maps.newHashMap();
        
        // ruleid: java-non-threadsafe-collection-modification
        userIds.parallelStream().forEach(userId -> {
            UserProfile profile = fetchUserProfile(userId);
            userProfiles.put(userId, profile); // Modifying non-thread-safe Guava HashMap in parallel stream
        });
        
        System.out.println("Loaded " + userProfiles.size() + " user profiles");
    }
    
    // Using Apache Commons Collections with parallel streams
    public void bad_case_3() {
        List<String> logEntries = new ArrayList<>();
        // Populate log entries
        for (int i = 0; i < 1000; i++) {
            logEntries.add("Log entry " + i);
        }
        
        MultiValuedMap<String, Integer> errorMap = new ArrayListValuedHashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        logEntries.parallelStream().forEach(log -> {
            if (log.contains("ERROR")) {
                errorMap.put("error", logEntries.indexOf(log)); // Modifying non-thread-safe MultiValuedMap in parallel stream
            }
        });
        
        System.out.println("Found " + errorMap.size() + " errors");
    }
    
    // Using Eclipse Collections with parallel streams
    public void bad_case_4() {
        MutableList<Integer> numbers = FastList.newListWith(1, 2, 3, 4, 5);
        Map<Integer, Integer> squareMap = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        numbers.asParallel().forEach(num -> {
            squareMap.put(num, num * num); // Modifying non-thread-safe HashMap in Eclipse Collections parallel operation
        });
        
        System.out.println("Square map: " + squareMap);
    }
    
    // Using Jackson ObjectMapper with parallel processing
    @RestController
    public void bad_case_5(HttpServletRequest request) throws IOException {
        String jsonData = request.getParameter("data");
        ObjectMapper mapper = new ObjectMapper();
        List<Map<String, Object>> dataList = mapper.readValue(jsonData, List.class);
        
        Map<String, Object> processedData = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        dataList.parallelStream().forEach(item -> {
            String id = (String) item.get("id");
            processedData.put(id, item); // Modifying non-thread-safe HashMap in parallel stream
        });
        
        System.out.println("Processed " + processedData.size() + " items");
    }
    
    // Using Hibernate with parallel streams
    public void bad_case_6() {
        EntityManagerFactory emf = Persistence.createEntityManagerFactory("myPU");
        EntityManager em = emf.createEntityManager();
        TypedQuery<User> query = em.createQuery("SELECT u FROM User u", User.class);
        List<User> users = query.getResultList();
        
        Map<Long, UserDTO> userDtoMap = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        users.parallelStream().forEach(user -> {
            UserDTO dto = convertToDto(user);
            userDtoMap.put(user.getId(), dto); // Modifying non-thread-safe HashMap in parallel stream
        });
        
        System.out.println("Converted " + userDtoMap.size() + " users to DTOs");
        em.close();
        emf.close();
    }
    
    // Using Redis Jedis with parallel streams
    public void bad_case_7() {
        Jedis jedis = new Jedis("localhost");
        Set<String> keys = jedis.keys("user:*");
        List<String> keyList = new ArrayList<>(keys);
        
        Map<String, String> userData = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        keyList.parallelStream().forEach(key -> {
            String value = jedis.get(key);
            userData.put(key, value); // Modifying non-thread-safe HashMap in parallel stream
        });
        
        System.out.println("Retrieved " + userData.size() + " user records");
        jedis.close();
    }
    
    // Using Kafka Consumer with parallel processing
    public void bad_case_8() {
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("group.id", "test-group");
        props.put("key.deserializer", StringDeserializer.class.getName());
        props.put("value.deserializer", StringDeserializer.class.getName());
        
        KafkaConsumer<String, String> consumer = new KafkaConsumer<>(props);
        consumer.subscribe(Arrays.asList("test-topic"));
        
        ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(100));
        List<ConsumerRecord<String, String>> recordList = new ArrayList<>();
        records.forEach(recordList::add);
        
        Map<String, String> messageMap = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        recordList.parallelStream().forEach(record -> {
            messageMap.put(record.key(), record.value()); // Modifying non-thread-safe HashMap in parallel stream
        });
        
        System.out.println("Processed " + messageMap.size() + " Kafka messages");
        consumer.close();
    }
    
    // Using AWS S3 with parallel streams
    public void bad_case_9() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        List<String> objectKeys = s3Client.listObjects("my-bucket").getObjectSummaries()
                                         .stream()
                                         .map(s -> s.getKey())
                                         .collect(Collectors.toList());
        
        Map<String, Long> objectSizes = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        objectKeys.parallelStream().forEach(key -> {
            long size = s3Client.getObjectMetadata("my-bucket", key).getContentLength();
            objectSizes.put(key, size); // Modifying non-thread-safe HashMap in parallel stream
        });
        
        System.out.println("Retrieved sizes for " + objectSizes.size() + " S3 objects");
    }
    
    // Using DynamoDB with parallel streams
    public void bad_case_10() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        List<Map<String, AttributeValue>> items = dynamoDB.scan(
            new ScanRequest().withTableName("Users")).getItems();
        
        Map<String, Map<String, AttributeValue>> userMap = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        items.parallelStream().forEach(item -> {
            String userId = item.get("userId").getS();
            userMap.put(userId, item); // Modifying non-thread-safe HashMap in parallel stream
        });
        
        System.out.println("Processed " + userMap.size() + " DynamoDB items");
    }
    
    // Using MongoDB with parallel streams
    public void bad_case_11() {
        MongoClient mongoClient = MongoClients.create("mongodb://localhost:27017");
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("users");
        
        List<Document> documents = collection.find().into(new ArrayList<>());
        Map<String, Document> documentMap = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        documents.parallelStream().forEach(doc -> {
            String id = doc.getObjectId("_id").toString();
            documentMap.put(id, doc); // Modifying non-thread-safe HashMap in parallel stream
        });
        
        System.out.println("Processed " + documentMap.size() + " MongoDB documents");
        mongoClient.close();
    }
    
    // Using Spring RestTemplate with parallel streams
    @Controller
    public void bad_case_12(HttpServletRequest request) {
        String[] urls = request.getParameterValues("urls");
        if (urls == null) return;
        
        List<String> urlList = Arrays.asList(urls);
        RestTemplate restTemplate = new RestTemplate();
        Map<String, ResponseEntity<String>> responses = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        urlList.parallelStream().forEach(url -> {
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
            responses.put(url, response); // Modifying non-thread-safe HashMap in parallel stream
        });
        
        System.out.println("Received " + responses.size() + " HTTP responses");
    }
    
    // Using JDBC with parallel streams
    public void bad_case_13() throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "user", "password");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT id, name FROM users");
        
        List<Map<String, Object>> rows = new ArrayList<>();
        while (rs.next()) {
            Map<String, Object> row = new HashMap<>();
            row.put("id", rs.getInt("id"));
            row.put("name", rs.getString("name"));
            rows.add(row);
        }
        
        Map<Integer, String> userMap = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        rows.parallelStream().forEach(row -> {
            Integer id = (Integer) row.get("id");
            String name = (String) row.get("name");
            userMap.put(id, name); // Modifying non-thread-safe HashMap in parallel stream
        });
        
        System.out.println("Processed " + userMap.size() + " database rows");
        conn.close();
    }
    
    // Using File I/O with parallel streams
    public void bad_case_14() throws IOException {
        Path dir = Paths.get("/var/log");
        List<Path> logFiles = Files.list(dir)
                                  .filter(p -> p.toString().endsWith(".log"))
                                  .collect(Collectors.toList());
        
        Map<String, Long> fileSizes = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        logFiles.parallelStream().forEach(file -> {
            try {
                long size = Files.size(file);
                fileSizes.put(file.getFileName().toString(), size); // Modifying non-thread-safe HashMap in parallel stream
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        
        System.out.println("Processed " + fileSizes.size() + " log files");
    }
    
    // Using Regular Expressions with parallel streams
    public void bad_case_15(HttpServletRequest request) {
        String text = request.getParameter("text");
        if (text == null) return;
        
        List<String> lines = Arrays.asList(text.split("\n"));
        Pattern pattern = Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b");
        
        Map<String, Integer> emailCounts = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        lines.parallelStream().forEach(line -> {
            Matcher matcher = pattern.matcher(line);
            while (matcher.find()) {
                String email = matcher.group();
                emailCounts.put(email, emailCounts.getOrDefault(email, 0) + 1); // Modifying non-thread-safe HashMap in parallel stream
            }
        });
        
        System.out.println("Found " + emailCounts.size() + " unique email addresses");
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    // Using ConcurrentHashMap with standard Java Collections
    public void good_case_1() {
        List<String> dataList = new ArrayList<>();
        dataList.add("item1");
        dataList.add("item2");
        dataList.add("item3");
        
        Map<String, Integer> resultMap = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        dataList.parallelStream().forEach(item -> {
            resultMap.put(item, item.length()); // Using thread-safe ConcurrentHashMap in parallel stream
        });
        
        System.out.println("Result map: " + resultMap);
    }
    
    // Using Google Guava with synchronized collections
    public void good_case_2() {
        List<String> userIds = Lists.newArrayList("user1", "user2", "user3");
        Map<String, UserProfile> userProfiles = Maps.newConcurrentMap();
        
        // ok: java-non-threadsafe-collection-modification
        userIds.parallelStream().forEach(userId -> {
            UserProfile profile = fetchUserProfile(userId);
            userProfiles.put(userId, profile); // Using thread-safe concurrent map in parallel stream
        });
        
        System.out.println("Loaded " + userProfiles.size() + " user profiles");
    }
    
    // Using Apache Commons Collections with thread-safe approach
    public void good_case_3() {
        List<String> logEntries = new ArrayList<>();
        // Populate log entries
        for (int i = 0; i < 1000; i++) {
            logEntries.add("Log entry " + i);
        }
        
        // Using synchronized collection for thread safety
        Map<String, List<Integer>> errorMap = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        logEntries.parallelStream().forEach(log -> {
            if (log.contains("ERROR")) {
                errorMap.computeIfAbsent("error", k -> Collections.synchronizedList(new ArrayList<>()))
                       .add(logEntries.indexOf(log)); // Thread-safe modification using computeIfAbsent
            }
        });
        
        System.out.println("Found " + errorMap.get("error").size() + " errors");
    }
    
    // Using Eclipse Collections with thread-safe approach
    public void good_case_4() {
        MutableList<Integer> numbers = FastList.newListWith(1, 2, 3, 4, 5);
        Map<Integer, Integer> squareMap = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        numbers.asParallel().forEach(num -> {
            squareMap.put(num, num * num); // Using thread-safe ConcurrentHashMap in Eclipse Collections parallel operation
        });
        
        System.out.println("Square map: " + squareMap);
    }
    
    // Using Jackson ObjectMapper with thread-safe approach
    @RestController
    public void good_case_5(HttpServletRequest request) throws IOException {
        String jsonData = request.getParameter("data");
        ObjectMapper mapper = new ObjectMapper();
        List<Map<String, Object>> dataList = mapper.readValue(jsonData, List.class);
        
        Map<String, Object> processedData = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        dataList.parallelStream().forEach(item -> {
            String id = (String) item.get("id");
            processedData.put(id, item); // Using thread-safe ConcurrentHashMap in parallel stream
        });
        
        System.out.println("Processed " + processedData.size() + " items");
    }
    
    // Using Hibernate with thread-safe approach
    public void good_case_6() {
        EntityManagerFactory emf = Persistence.createEntityManagerFactory("myPU");
        EntityManager em = emf.createEntityManager();
        TypedQuery<User> query = em.createQuery("SELECT u FROM User u", User.class);
        List<User> users = query.getResultList();
        
        Map<Long, UserDTO> userDtoMap = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        users.parallelStream().forEach(user -> {
            UserDTO dto = convertToDto(user);
            userDtoMap.put(user.getId(), dto); // Using thread-safe ConcurrentHashMap in parallel stream
        });
        
        System.out.println("Converted " + userDtoMap.size() + " users to DTOs");
        em.close();
        emf.close();
    }
    
    // Using Redis Jedis with thread-safe approach
    public void good_case_7() {
        Jedis jedis = new Jedis("localhost");
        Set<String> keys = jedis.keys("user:*");
        List<String> keyList = new ArrayList<>(keys);
        
        Map<String, String> userData = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        keyList.parallelStream().forEach(key -> {
            String value = jedis.get(key);
            userData.put(key, value); // Using thread-safe ConcurrentHashMap in parallel stream
        });
        
        System.out.println("Retrieved " + userData.size() + " user records");
        jedis.close();
    }
    
    // Using Kafka Consumer with thread-safe approach
    public void good_case_8() {
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("group.id", "test-group");
        props.put("key.deserializer", StringDeserializer.class.getName());
        props.put("value.deserializer", StringDeserializer.class.getName());
        
        KafkaConsumer<String, String> consumer = new KafkaConsumer<>(props);
        consumer.subscribe(Arrays.asList("test-topic"));
        
        ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(100));
        List<ConsumerRecord<String, String>> recordList = new ArrayList<>();
        records.forEach(recordList::add);
        
        Map<String, String> messageMap = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        recordList.parallelStream().forEach(record -> {
            messageMap.put(record.key(), record.value()); // Using thread-safe ConcurrentHashMap in parallel stream
        });
        
        System.out.println("Processed " + messageMap.size() + " Kafka messages");
        consumer.close();
    }
    
    // Using AWS S3 with thread-safe approach
    public void good_case_9() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        List<String> objectKeys = s3Client.listObjects("my-bucket").getObjectSummaries()
                                         .stream()
                                         .map(s -> s.getKey())
                                         .collect(Collectors.toList());
        
        Map<String, Long> objectSizes = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        objectKeys.parallelStream().forEach(key -> {
            long size = s3Client.getObjectMetadata("my-bucket", key).getContentLength();
            objectSizes.put(key, size); // Using thread-safe ConcurrentHashMap in parallel stream
        });
        
        System.out.println("Retrieved sizes for " + objectSizes.size() + " S3 objects");
    }
    
    // Using DynamoDB with thread-safe approach
    public void good_case_10() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        List<Map<String, AttributeValue>> items = dynamoDB.scan(
            new ScanRequest().withTableName("Users")).getItems();
        
        Map<String, Map<String, AttributeValue>> userMap = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        items.parallelStream().forEach(item -> {
            String userId = item.get("userId").getS();
            userMap.put(userId, item); // Using thread-safe ConcurrentHashMap in parallel stream
        });
        
        System.out.println("Processed " + userMap.size() + " DynamoDB items");
    }
    
    // Using MongoDB with thread-safe approach
    public void good_case_11() {
        MongoClient mongoClient = MongoClients.create("mongodb://localhost:27017");
        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection<Document> collection = database.getCollection("users");
        
        List<Document> documents = collection.find().into(new ArrayList<>());
        Map<String, Document> documentMap = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        documents.parallelStream().forEach(doc -> {
            String id = doc.getObjectId("_id").toString();
            documentMap.put(id, doc); // Using thread-safe ConcurrentHashMap in parallel stream
        });
        
        System.out.println("Processed " + documentMap.size() + " MongoDB documents");
        mongoClient.close();
    }
    
    // Using Spring RestTemplate with thread-safe approach
    @Controller
    public void good_case_12(HttpServletRequest request) {
        String[] urls = request.getParameterValues("urls");
        if (urls == null) return;
        
        List<String> urlList = Arrays.asList(urls);
        RestTemplate restTemplate = new RestTemplate();
        Map<String, ResponseEntity<String>> responses = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        urlList.parallelStream().forEach(url -> {
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
            responses.put(url, response); // Using thread-safe ConcurrentHashMap in parallel stream
        });
        
        System.out.println("Received " + responses.size() + " HTTP responses");
    }
    
    // Using JDBC with thread-safe approach
    public void good_case_13() throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "user", "password");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT id, name FROM users");
        
        List<Map<String, Object>> rows = new ArrayList<>();
        while (rs.next()) {
            Map<String, Object> row = new HashMap<>();
            row.put("id", rs.getInt("id"));
            row.put("name", rs.getString("name"));
            rows.add(row);
        }
        
        Map<Integer, String> userMap = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        rows.parallelStream().forEach(row -> {
            Integer id = (Integer) row.get("id");
            String name = (String) row.get("name");
            userMap.put(id, name); // Using thread-safe ConcurrentHashMap in parallel stream
        });
        
        System.out.println("Processed " + userMap.size() + " database rows");
        conn.close();
    }
    
    // Using File I/O with thread-safe approach
    public void good_case_14() throws IOException {
        Path dir = Paths.get("/var/log");
        List<Path> logFiles = Files.list(dir)
                                  .filter(p -> p.toString().endsWith(".log"))
                                  .collect(Collectors.toList());
        
        Map<String, Long> fileSizes = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        logFiles.parallelStream().forEach(file -> {
            try {
                long size = Files.size(file);
                fileSizes.put(file.getFileName().toString(), size); // Using thread-safe ConcurrentHashMap in parallel stream
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        
        System.out.println("Processed " + fileSizes.size() + " log files");
    }
    
    // Using Regular Expressions with thread-safe approach
    public void good_case_15(HttpServletRequest request) {
        String text = request.getParameter("text");
        if (text == null) return;
        
        List<String> lines = Arrays.asList(text.split("\n"));
        Pattern pattern = Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b");
        
        Map<String, Integer> emailCounts = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        lines.parallelStream().forEach(line -> {
            Matcher matcher = pattern.matcher(line);
            while (matcher.find()) {
                String email = matcher.group();
                emailCounts.merge(email, 1, Integer::sum); // Using thread-safe ConcurrentHashMap with merge in parallel stream
            }
        });
        
        System.out.println("Found " + emailCounts.size() + " unique email addresses");
    }
    
    // Helper methods
    private UserProfile fetchUserProfile(String userId) {
        return new UserProfile(userId, "User " + userId);
    }
    
    private UserDTO convertToDto(User user) {
        return new UserDTO(user.getId(), user.getName());
    }
    
    // Helper classes
    private static class UserProfile {
        private String id;
        private String name;
        
        public UserProfile(String id, String name) {
            this.id = id;
            this.name = name;
        }
    }
    
    private static class User {
        private Long id;
        private String name;
        
        public Long getId() { return id; }
        public String getName() { return name; }
    }
    
    private static class UserDTO {
        private Long id;
        private String name;
        
        public UserDTO(Long id, String name) {
            this.id = id;
            this.name = name;
        }
    }
}
// {/fact}