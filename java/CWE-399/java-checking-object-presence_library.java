import java.util.*;
import java.io.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.springframework.http.*;
import com.google.common.collect.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import redis.clients.jedis.*;
import org.apache.commons.collections4.*;
import org.hibernate.*;
import javax.persistence.*;
import com.mongodb.*;
import com.mongodb.client.*;
import org.bson.*;
import com.google.firebase.*;
import com.google.firebase.database.*;
import com.fasterxml.jackson.databind.*;
import org.apache.commons.lang3.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.apache.http.client.*;
import okhttp3.*;
import retrofit2.*;
import retrofit2.http.*;
import com.google.gson.*;
import org.elasticsearch.client.*;
import org.elasticsearch.action.get.*;
import org.elasticsearch.action.search.*;
import org.apache.kafka.clients.consumer.*;
import org.apache.kafka.clients.producer.*;
import com.hazelcast.core.*;
import com.hazelcast.map.*;
import org.apache.cassandra.thrift.*;
import com.datastax.driver.core.*;
import io.vertx.core.*;
import io.vertx.core.http.*;
import io.vertx.ext.web.*;
import org.neo4j.driver.*;
import com.rabbitmq.client.*;
import io.lettuce.core.*;
import io.lettuce.core.api.*;

// Security Issue: Manually checking for object existence can lead to insecure object references

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // HashMap - Manual null check instead of using getOrDefault or containsKey
    HashMap<String, String> userRoles = new HashMap<>();
    userRoles.put("admin", "ADMIN");
    userRoles.put("user", "USER");
    
    String username = request.getParameter("username");
    
    // ruleid: java-checking-object-presence
    if (userRoles.get(username) != null) {
        String role = userRoles.get(username);
        System.out.println("User role: " + role);
    } else {
        System.out.println("User not found");
    }
}

public void bad_case_2(HttpServletRequest request) {
    // Spring RestTemplate - Manual null check with potential duplicate API call
    RestTemplate restTemplate = new RestTemplate();
    String userId = request.getParameter("userId");
    String apiUrl = "https://api.example.com/users/" + userId;
    
    ResponseEntity<User> response = restTemplate.getForEntity(apiUrl, User.class);
    
    // ruleid: java-checking-object-presence
    if (response.getBody() != null) {
        User user = response.getBody();
        System.out.println("User details: " + user.getName());
    } else {
        System.out.println("User not found");
    }
}

public void bad_case_3(HttpServletRequest request) {
    // AWS S3 - Manual null check instead of using doesObjectExist
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String bucketName = "user-files";
    String objectKey = request.getParameter("fileKey");
    
    try {
        // ruleid: java-checking-object-presence
        S3Object object = s3Client.getObject(bucketName, objectKey);
        if (object != null) {
            InputStream content = object.getObjectContent();
            // Process the content
        }
    } catch (AmazonS3Exception e) {
        System.out.println("File not found");
    }
}

public void bad_case_4(HttpServletRequest request) {
    // Redis Jedis - Manual null check instead of using exists
    Jedis jedis = new Jedis("localhost");
    String sessionId = request.getParameter("sessionId");
    
    // ruleid: java-checking-object-presence
    String sessionData = jedis.get(sessionId);
    if (sessionData != null) {
        System.out.println("Session data: " + sessionData);
    } else {
        System.out.println("Session not found");
    }
    jedis.close();
}

public void bad_case_5(HttpServletRequest request) {
    // Hibernate - Manual null check instead of using get with Optional
    SessionFactory sessionFactory = new Configuration().configure().buildSessionFactory();
    Session session = sessionFactory.openSession();
    
    String userId = request.getParameter("userId");
    
    // ruleid: java-checking-object-presence
    User user = session.get(User.class, userId);
    if (user != null) {
        System.out.println("User found: " + user.getName());
    } else {
        System.out.println("User not found");
    }
    session.close();
}

public void bad_case_6(HttpServletRequest request) {
    // MongoDB - Manual null check instead of using find().first() with proper handling
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("userdb");
    MongoCollection<Document> collection = database.getCollection("users");
    
    String username = request.getParameter("username");
    Document query = new Document("username", username);
    
    // ruleid: java-checking-object-presence
    Document user = collection.find(query).first();
    if (user != null) {
        System.out.println("User found: " + user.toJson());
    } else {
        System.out.println("User not found");
    }
    mongoClient.close();
}

public void bad_case_7(HttpServletRequest request) {
    // Firebase Realtime Database - Manual null check instead of using addListenerForSingleValueEvent
    FirebaseDatabase database = FirebaseDatabase.getInstance();
    DatabaseReference ref = database.getReference("users");
    
    String userId = request.getParameter("userId");
    
    // ruleid: java-checking-object-presence
    ref.child(userId).get().addOnCompleteListener(task -> {
        if (task.isSuccessful()) {
            DataSnapshot snapshot = task.getResult();
            if (snapshot != null && snapshot.getValue() != null) {
                System.out.println("User data: " + snapshot.getValue());
            } else {
                System.out.println("User not found");
            }
        }
    });
}

public void bad_case_8(HttpServletRequest request) {
    // Jackson ObjectMapper - Manual null check instead of using readTree with proper handling
    ObjectMapper mapper = new ObjectMapper();
    String jsonData = request.getParameter("jsonData");
    
    try {
        // ruleid: java-checking-object-presence
        JsonNode rootNode = mapper.readTree(jsonData);
        JsonNode nameNode = rootNode.get("name");
        if (nameNode != null) {
            String name = nameNode.asText();
            System.out.println("Name: " + name);
        } else {
            System.out.println("Name not found");
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9(HttpServletRequest request) {
    // Apache HttpClient - Manual null check instead of using HttpEntity methods
    CloseableHttpClient httpClient = HttpClients.createDefault();
    String apiUrl = "https://api.example.com/users/" + request.getParameter("userId");
    HttpGet httpGet = new HttpGet(apiUrl);
    
    try {
        CloseableHttpResponse response = httpClient.execute(httpGet);
        // ruleid: java-checking-object-presence
        HttpEntity entity = response.getEntity();
        if (entity != null) {
            String result = EntityUtils.toString(entity);
            System.out.println("Response: " + result);
        } else {
            System.out.println("No response body");
        }
        response.close();
        httpClient.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    // OkHttp - Manual null check instead of using isSuccessful() and proper response handling
    OkHttpClient client = new OkHttpClient();
    String apiUrl = "https://api.example.com/users/" + request.getParameter("userId");
    Request okRequest = new Request.Builder().url(apiUrl).build();
    
    try {
        Response response = client.newCall(okRequest).execute();
        // ruleid: java-checking-object-presence
        ResponseBody body = response.body();
        if (body != null) {
            String responseData = body.string();
            System.out.println("Response: " + responseData);
        } else {
            System.out.println("No response body");
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_11(HttpServletRequest request) {
    // Elasticsearch - Manual null check instead of using exists API
    RestHighLevelClient client = new RestHighLevelClient(
            RestClient.builder(new HttpHost("localhost", 9200, "http")));
    
    String documentId = request.getParameter("documentId");
    
    try {
        GetRequest getRequest = new GetRequest("users", documentId);
        // ruleid: java-checking-object-presence
        GetResponse getResponse = client.get(getRequest);
        if (getResponse != null && getResponse.isExists()) {
            String sourceAsString = getResponse.getSourceAsString();
            System.out.println("Document: " + sourceAsString);
        } else {
            System.out.println("Document not found");
        }
        client.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    // Apache Kafka - Manual null check instead of using ConsumerRecords methods
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    props.put("group.id", "test");
    props.put("key.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
    props.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
    
    KafkaConsumer<String, String> consumer = new KafkaConsumer<>(props);
    consumer.subscribe(Arrays.asList("user-topic"));
    
    String userId = request.getParameter("userId");
    
    // ruleid: java-checking-object-presence
    ConsumerRecords<String, String> records = consumer.poll(100);
    for (ConsumerRecord<String, String> record : records) {
        if (record.key() != null && record.key().equals(userId)) {
            System.out.println("Found record: " + record.value());
        }
    }
    consumer.close();
}

public void bad_case_13(HttpServletRequest request) {
    // Hazelcast - Manual null check instead of using containsKey
    HazelcastInstance hazelcastInstance = Hazelcast.newHazelcastInstance();
    IMap<String, String> userMap = hazelcastInstance.getMap("users");
    
    String userId = request.getParameter("userId");
    
    // ruleid: java-checking-object-presence
    String userData = userMap.get(userId);
    if (userData != null) {
        System.out.println("User data: " + userData);
    } else {
        System.out.println("User not found");
    }
    hazelcastInstance.shutdown();
}

public void bad_case_14(HttpServletRequest request) {
    // Cassandra - Manual null check instead of using isNull or proper row handling
    Cluster cluster = Cluster.builder().addContactPoint("127.0.0.1").build();
    Session session = cluster.connect("mykeyspace");
    
    String userId = request.getParameter("userId");
    
    ResultSet results = session.execute("SELECT * FROM users WHERE id = ?", userId);
    // ruleid: java-checking-object-presence
    Row row = results.one();
    if (row != null) {
        String name = row.getString("name");
        System.out.println("User name: " + name);
    } else {
        System.out.println("User not found");
    }
    
    cluster.close();
}

public void bad_case_15(HttpServletRequest request) {
    // Neo4j - Manual null check instead of using proper result handling
    Driver driver = GraphDatabase.driver("bolt://localhost:7687", AuthTokens.basic("neo4j", "password"));
    Session session = driver.session();
    
    String userId = request.getParameter("userId");
    
    // ruleid: java-checking-object-presence
    Result result = session.run("MATCH (u:User {id: $id}) RETURN u", Values.parameters("id", userId));
    if (result.hasNext()) {
        Record record = result.next();
        System.out.println("User found: " + record.get("u").asNode().get("name").asString());
    } else {
        System.out.println("User not found");
    }
    
    session.close();
    driver.close();
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // HashMap - Using getOrDefault for safe object presence checking
    HashMap<String, String> userRoles = new HashMap<>();
    userRoles.put("admin", "ADMIN");
    userRoles.put("user", "USER");
    
    String username = request.getParameter("username");
    
    // ok: java-checking-object-presence
    String role = userRoles.getOrDefault(username, "GUEST");
    System.out.println("User role: " + role);
}

public void good_case_2(HttpServletRequest request) {
    // Spring RestTemplate - Using proper response handling with isSuccessful
    RestTemplate restTemplate = new RestTemplate();
    String userId = request.getParameter("userId");
    String apiUrl = "https://api.example.com/users/" + userId;
    
    try {
        // ok: java-checking-object-presence
        ResponseEntity<User> response = restTemplate.getForEntity(apiUrl, User.class);
        if (response.getStatusCode().is2xxSuccessful()) {
            User user = response.getBody();
            System.out.println("User details: " + user.getName());
        } else {
            System.out.println("User not found or error: " + response.getStatusCode());
        }
    } catch (Exception e) {
        System.out.println("Error fetching user: " + e.getMessage());
    }
}

public void good_case_3(HttpServletRequest request) {
    // AWS S3 - Using doesObjectExist for proper object presence checking
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String bucketName = "user-files";
    String objectKey = request.getParameter("fileKey");
    
    // ok: java-checking-object-presence
    boolean objectExists = s3Client.doesObjectExist(bucketName, objectKey);
    if (objectExists) {
        S3Object object = s3Client.getObject(bucketName, objectKey);
        InputStream content = object.getObjectContent();
        // Process the content
    } else {
        System.out.println("File not found");
    }
}

public void good_case_4(HttpServletRequest request) {
    // Redis Jedis - Using exists for proper key presence checking
    Jedis jedis = new Jedis("localhost");
    String sessionId = request.getParameter("sessionId");
    
    // ok: java-checking-object-presence
    boolean keyExists = jedis.exists(sessionId);
    if (keyExists) {
        String sessionData = jedis.get(sessionId);
        System.out.println("Session data: " + sessionData);
    } else {
        System.out.println("Session not found");
    }
    jedis.close();
}

public void good_case_5(HttpServletRequest request) {
    // Hibernate - Using Optional for proper object presence handling
    SessionFactory sessionFactory = new Configuration().configure().buildSessionFactory();
    Session session = sessionFactory.openSession();
    
    String userId = request.getParameter("userId");
    
    // ok: java-checking-object-presence
    Optional<User> userOptional = Optional.ofNullable(session.get(User.class, userId));
    userOptional.ifPresentOrElse(
        user -> System.out.println("User found: " + user.getName()),
        () -> System.out.println("User not found")
    );
    
    session.close();
}

public void good_case_6(HttpServletRequest request) {
    // MongoDB - Using countDocuments for proper object existence check
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("userdb");
    MongoCollection<Document> collection = database.getCollection("users");
    
    String username = request.getParameter("username");
    Document query = new Document("username", username);
    
    // ok: java-checking-object-presence
    long count = collection.countDocuments(query);
    if (count > 0) {
        Document user = collection.find(query).first();
        System.out.println("User found: " + user.toJson());
    } else {
        System.out.println("User not found");
    }
    mongoClient.close();
}

public void good_case_7(HttpServletRequest request) {
    // Firebase Realtime Database - Using addListenerForSingleValueEvent properly
    FirebaseDatabase database = FirebaseDatabase.getInstance();
    DatabaseReference ref = database.getReference("users");
    
    String userId = request.getParameter("userId");
    
    // ok: java-checking-object-presence
    ref.child(userId).addListenerForSingleValueEvent(new ValueEventListener() {
        @Override
        public void onDataChange(DataSnapshot dataSnapshot) {
            if (dataSnapshot.exists()) {
                System.out.println("User data: " + dataSnapshot.getValue());
            } else {
                System.out.println("User not found");
            }
        }
        
        @Override
        public void onCancelled(DatabaseError databaseError) {
            System.out.println("Error: " + databaseError.getMessage());
        }
    });
}

public void good_case_8(HttpServletRequest request) {
    // Jackson ObjectMapper - Using has method for proper field presence checking
    ObjectMapper mapper = new ObjectMapper();
    String jsonData = request.getParameter("jsonData");
    
    try {
        JsonNode rootNode = mapper.readTree(jsonData);
        // ok: java-checking-object-presence
        if (rootNode.has("name")) {
            String name = rootNode.get("name").asText();
            System.out.println("Name: " + name);
        } else {
            System.out.println("Name not found");
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9(HttpServletRequest request) {
    // Apache HttpClient - Using proper response status checking
    CloseableHttpClient httpClient = HttpClients.createDefault();
    String apiUrl = "https://api.example.com/users/" + request.getParameter("userId");
    HttpGet httpGet = new HttpGet(apiUrl);
    
    try {
        CloseableHttpResponse response = httpClient.execute(httpGet);
        // ok: java-checking-object-presence
        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode >= 200 && statusCode < 300) {
            HttpEntity entity = response.getEntity();
            String result = EntityUtils.toString(entity);
            System.out.println("Response: " + result);
        } else {
            System.out.println("Error response: " + statusCode);
        }
        response.close();
        httpClient.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    // OkHttp - Using isSuccessful for proper response handling
    OkHttpClient client = new OkHttpClient();
    String apiUrl = "https://api.example.com/users/" + request.getParameter("userId");
    Request okRequest = new Request.Builder().url(apiUrl).build();
    
    try {
        Response response = client.newCall(okRequest).execute();
        // ok: java-checking-object-presence
        if (response.isSuccessful()) {
            String responseData = response.body().string();
            System.out.println("Response: " + responseData);
        } else {
            System.out.println("Error response: " + response.code());
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_11(HttpServletRequest request) {
    // Elasticsearch - Using exists API for proper document existence check
    RestHighLevelClient client = new RestHighLevelClient(
            RestClient.builder(new HttpHost("localhost", 9200, "http")));
    
    String documentId = request.getParameter("documentId");
    
    try {
        // ok: java-checking-object-presence
        GetRequest getRequest = new GetRequest("users", documentId);
        boolean exists = client.exists(getRequest);
        if (exists) {
            GetResponse getResponse = client.get(getRequest);
            String sourceAsString = getResponse.getSourceAsString();
            System.out.println("Document: " + sourceAsString);
        } else {
            System.out.println("Document not found");
        }
        client.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    // Apache Kafka - Using isEmpty for proper records checking
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    props.put("group.id", "test");
    props.put("key.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
    props.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
    
    KafkaConsumer<String, String> consumer = new KafkaConsumer<>(props);
    consumer.subscribe(Arrays.asList("user-topic"));
    
    String userId = request.getParameter("userId");
    
    // ok: java-checking-object-presence
    ConsumerRecords<String, String> records = consumer.poll(100);
    if (!records.isEmpty()) {
        for (ConsumerRecord<String, String> record : records) {
            if (userId.equals(record.key())) {
                System.out.println("Found record: " + record.value());
            }
        }
    } else {
        System.out.println("No records found");
    }
    consumer.close();
}

public void good_case_13(HttpServletRequest request) {
    // Hazelcast - Using containsKey for proper key existence check
    HazelcastInstance hazelcastInstance = Hazelcast.newHazelcastInstance();
    IMap<String, String> userMap = hazelcastInstance.getMap("users");
    
    String userId = request.getParameter("userId");
    
    // ok: java-checking-object-presence
    if (userMap.containsKey(userId)) {
        String userData = userMap.get(userId);
        System.out.println("User data: " + userData);
    } else {
        System.out.println("User not found");
    }
    hazelcastInstance.shutdown();
}

public void good_case_14(HttpServletRequest request) {
    // Cassandra - Using isBeforeFirst for proper result set checking
    Cluster cluster = Cluster.builder().addContactPoint("127.0.0.1").build();
    Session session = cluster.connect("mykeyspace");
    
    String userId = request.getParameter("userId");
    
    ResultSet results = session.execute("SELECT * FROM users WHERE id = ?", userId);
    // ok: java-checking-object-presence
    if (!results.isExhausted()) {
        Row row = results.one();
        String name = row.getString("name");
        System.out.println("User name: " + name);
    } else {
        System.out.println("User not found");
    }
    
    cluster.close();
}

public void good_case_15(HttpServletRequest request) {
    // Neo4j - Using proper transaction and result handling
    Driver driver = GraphDatabase.driver("bolt://localhost:7687", AuthTokens.basic("neo4j", "password"));
    
    String userId = request.getParameter("userId");
    
    // ok: java-checking-object-presence
    try (Session session = driver.session()) {
        session.readTransaction(tx -> {
            Result result = tx.run("MATCH (u:User {id: $id}) RETURN count(u) as count", 
                                 Values.parameters("id", userId));
            Record record = result.single();
            int count = record.get("count").asInt();
            
            if (count > 0) {
                Result userResult = tx.run("MATCH (u:User {id: $id}) RETURN u", 
                                        Values.parameters("id", userId));
                Record userRecord = userResult.single();
                System.out.println("User found: " + userRecord.get("u").asNode().get("name").asString());
            } else {
                System.out.println("User not found");
            }
            return null;
        });
    }
    
    driver.close();
}

// Class needed for examples
class User {
    private String id;
    private String name;
    
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}