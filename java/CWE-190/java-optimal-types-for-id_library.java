import java.util.HashMap;
import java.util.Map;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Column;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import org.apache.ibatis.session.SqlSession;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bson.Document;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.MongoClient;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import com.google.firebase.database.FirebaseDatabase;
import com.google.firebase.database.DatabaseReference;
import redis.clients.jedis.Jedis;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.indices.GetIndexRequest;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import com.couchbase.client.java.Cluster;
import com.couchbase.client.java.Collection;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.neo4j.driver.Session;
import org.neo4j.driver.Result;
import org.neo4j.driver.Transaction;

// Security Issue: Using int for IDs can lead to integer overflow (CWE-190) when the ID exceeds Integer.MAX_VALUE

// True Positive Examples (Vulnerable/Insecure Code)
class BadCases {
    // Spring Data JPA with int ID
// {fact rule=arithmetic-overflow@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        String userIdParam = request.getParameter("userId");
        // ruleid: java-optimal-types-for-id
        int userId = Integer.parseInt(userIdParam);
        
        // Using int for ID in Spring Data JPA
        @Entity
        class User {
            @Id
            @GeneratedValue(strategy = GenerationType.AUTO)
            // ruleid: java-optimal-types-for-id
            private int id;
            private String name;
            
            // Getters and setters
            public int getId() { return id; }
            public void setId(int id) { this.id = id; }
        }
    }

    // Hibernate with int ID
    public void bad_case_2(HttpServletRequest request, SessionFactory sessionFactory) {
        String productIdParam = request.getParameter("productId");
        // ruleid: java-optimal-types-for-id
        int productId = Integer.parseInt(productIdParam);
        
        Session session = sessionFactory.openSession();
        try {
            // Using int for product ID in Hibernate
            @Entity(name = "Product")
            class Product {
                @Id
                @GeneratedValue(strategy = GenerationType.IDENTITY)
                // ruleid: java-optimal-types-for-id
                private int id;
                private String name;
                
                public int getId() { return id; }
                public void setId(int id) { this.id = id; }
            }
            
            Product product = session.get(Product.class, productId);
        } finally {
            session.close();
        }
    }

    // JDBC with int ID
    public void bad_case_3(HttpServletRequest request, Connection connection) throws SQLException {
        String orderIdParam = request.getParameter("orderId");
        // ruleid: java-optimal-types-for-id
        int orderId = Integer.parseInt(orderIdParam);
        
        PreparedStatement stmt = connection.prepareStatement(
            "SELECT * FROM orders WHERE id = ?"
        );
        stmt.setInt(1, orderId);
        ResultSet rs = stmt.executeQuery();
    }

    // MongoDB with int ID
    public void bad_case_4(HttpServletRequest request, MongoTemplate mongoTemplate) {
        String documentIdParam = request.getParameter("documentId");
        // ruleid: java-optimal-types-for-id
        int documentId = Integer.parseInt(documentIdParam);
        
        class Document {
            // ruleid: java-optimal-types-for-id
            private int id;
            private String content;
            
            public int getId() { return id; }
            public void setId(int id) { this.id = id; }
        }
        
        Query query = new Query(Criteria.where("id").is(documentId));
        Document document = mongoTemplate.findOne(query, Document.class);
    }

    // Spring JDBC Template with int ID
    public void bad_case_5(HttpServletRequest request, JdbcTemplate jdbcTemplate) {
        String customerIdParam = request.getParameter("customerId");
        // ruleid: java-optimal-types-for-id
        int customerId = Integer.parseInt(customerIdParam);
        
        jdbcTemplate.queryForObject(
            "SELECT * FROM customers WHERE id = ?",
            new Object[]{customerId},
            (rs, rowNum) -> {
                // ruleid: java-optimal-types-for-id
                int id = rs.getInt("id");
                String name = rs.getString("name");
                return new Customer(id, name);
            }
        );
    }

    // AWS DynamoDB with int ID
    public void bad_case_6(HttpServletRequest request, AmazonDynamoDB dynamoDBClient) {
        String itemIdParam = request.getParameter("itemId");
        // ruleid: java-optimal-types-for-id
        int itemId = Integer.parseInt(itemIdParam);
        
        DynamoDB dynamoDB = new DynamoDB(dynamoDBClient);
        Table table = dynamoDB.getTable("Items");
        
        Item item = new Item()
            // ruleid: java-optimal-types-for-id
            .withPrimaryKey("id", itemId)
            .withString("name", "Test Item");
        
        table.putItem(item);
    }

    // MyBatis with int ID
    public void bad_case_7(HttpServletRequest request, SqlSession sqlSession) {
        String userIdParam = request.getParameter("userId");
        // ruleid: java-optimal-types-for-id
        int userId = Integer.parseInt(userIdParam);
        
        interface UserMapper {
            User getUserById(int id);
        }
        
        class User {
            // ruleid: java-optimal-types-for-id
            private int id;
            private String name;
            
            public int getId() { return id; }
            public void setId(int id) { this.id = id; }
        }
        
        UserMapper mapper = sqlSession.getMapper(UserMapper.class);
        User user = mapper.getUserById(userId);
    }

    // Apache HttpClient with int ID
    public void bad_case_8(HttpServletRequest request) throws IOException {
        String resourceIdParam = request.getParameter("resourceId");
        // ruleid: java-optimal-types-for-id
        int resourceId = Integer.parseInt(resourceIdParam);
        
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet httpGet = new HttpGet("https://api.example.com/resources/" + resourceId);
            httpClient.execute(httpGet);
        }
    }

    // OkHttp with int ID
    public void bad_case_9(HttpServletRequest request) throws IOException {
        String articleIdParam = request.getParameter("articleId");
        // ruleid: java-optimal-types-for-id
        int articleId = Integer.parseInt(articleIdParam);
        
        OkHttpClient client = new OkHttpClient();
        Request okRequest = new Request.Builder()
            .url("https://api.example.com/articles/" + articleId)
            .build();
        
        try (Response response = client.newCall(okRequest).execute()) {
            String responseBody = response.body().string();
        }
    }

    // Native MongoDB with int ID
    public void bad_case_10(HttpServletRequest request) {
        String recordIdParam = request.getParameter("recordId");
        // ruleid: java-optimal-types-for-id
        int recordId = Integer.parseInt(recordIdParam);
        
        MongoClient mongoClient = new MongoClient("localhost", 27017);
        MongoDatabase database = mongoClient.getDatabase("testdb");
        MongoCollection<Document> collection = database.getCollection("records");
        
        Document doc = new Document("_id", recordId)
                         .append("name", "Test Record");
        collection.insertOne(doc);
    }

    // Vert.x with int ID
    public void bad_case_11(Vertx vertx) {
        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());
        
        router.get("/api/users/:id").handler(routingContext -> {
            String userIdParam = routingContext.request().getParam("id");
            // ruleid: java-optimal-types-for-id
            int userId = Integer.parseInt(userIdParam);
            
            // Process user with int ID
            routingContext.response()
                .putHeader("content-type", "application/json")
                .end("{\"id\":" + userId + ",\"name\":\"User\"}");
        });
    }

    // Firebase Realtime Database with int ID
    public void bad_case_12(HttpServletRequest request) {
        String messageIdParam = request.getParameter("messageId");
        // ruleid: java-optimal-types-for-id
        int messageId = Integer.parseInt(messageIdParam);
        
        FirebaseDatabase database = FirebaseDatabase.getInstance();
        DatabaseReference messagesRef = database.getReference("messages");
        
        Map<String, Object> messageData = new HashMap<>();
        messageData.put("id", messageId);
        messageData.put("text", "Hello World");
        
        messagesRef.child(String.valueOf(messageId)).setValue(messageData);
    }

    // Redis with int ID
    public void bad_case_13(HttpServletRequest request) {
        String sessionIdParam = request.getParameter("sessionId");
        // ruleid: java-optimal-types-for-id
        int sessionId = Integer.parseInt(sessionIdParam);
        
        Jedis jedis = new Jedis("localhost");
        jedis.set("session:" + sessionId, "user data");
        jedis.close();
    }

    // Elasticsearch with int ID
    public void bad_case_14(HttpServletRequest request, RestHighLevelClient client) throws IOException {
        String documentIdParam = request.getParameter("documentId");
        // ruleid: java-optimal-types-for-id
        int documentId = Integer.parseInt(documentIdParam);
        
        GetRequest getRequest = new GetRequest("posts", String.valueOf(documentId));
        GetResponse getResponse = client.get(getRequest, RequestOptions.DEFAULT);
    }

    // Neo4j with int ID
    public void bad_case_15(HttpServletRequest request) {
        String nodeIdParam = request.getParameter("nodeId");
        // ruleid: java-optimal-types-for-id
        int nodeId = Integer.parseInt(nodeIdParam);
        
        Driver driver = GraphDatabase.driver("bolt://localhost:7687");
        try (org.neo4j.driver.Session session = driver.session()) {
            session.writeTransaction(tx -> {
                tx.run("MATCH (n) WHERE id(n) = $id RETURN n", 
                       Map.of("id", nodeId));
                return null;
            });
        }
    }
}
// {/fact}

// True Negative Examples (Safe/Secure Code)
class GoodCases {
    // Spring Data JPA with long ID
// {fact rule=arithmetic-overflow@v1.0 defects=0}
    public void good_case_1(HttpServletRequest request) {
        String userIdParam = request.getParameter("userId");
        // ok: java-optimal-types-for-id
        long userId = Long.parseLong(userIdParam);
        
        // Using long for ID in Spring Data JPA
        @Entity
        class User {
            @Id
            @GeneratedValue(strategy = GenerationType.AUTO)
            // ok: java-optimal-types-for-id
            private long id;
            private String name;
            
            // Getters and setters
            public long getId() { return id; }
            public void setId(long id) { this.id = id; }
        }
    }

    // Hibernate with long ID
    public void good_case_2(HttpServletRequest request, SessionFactory sessionFactory) {
        String productIdParam = request.getParameter("productId");
        // ok: java-optimal-types-for-id
        long productId = Long.parseLong(productIdParam);
        
        Session session = sessionFactory.openSession();
        try {
            // Using long for product ID in Hibernate
            @Entity(name = "Product")
            class Product {
                @Id
                @GeneratedValue(strategy = GenerationType.IDENTITY)
                // ok: java-optimal-types-for-id
                private long id;
                private String name;
                
                public long getId() { return id; }
                public void setId(long id) { this.id = id; }
            }
            
            Product product = session.get(Product.class, productId);
        } finally {
            session.close();
        }
    }

    // JDBC with long ID
    public void good_case_3(HttpServletRequest request, Connection connection) throws SQLException {
        String orderIdParam = request.getParameter("orderId");
        // ok: java-optimal-types-for-id
        long orderId = Long.parseLong(orderIdParam);
        
        PreparedStatement stmt = connection.prepareStatement(
            "SELECT * FROM orders WHERE id = ?"
        );
        stmt.setLong(1, orderId);
        ResultSet rs = stmt.executeQuery();
    }

    // MongoDB with long ID
    public void good_case_4(HttpServletRequest request, MongoTemplate mongoTemplate) {
        String documentIdParam = request.getParameter("documentId");
        // ok: java-optimal-types-for-id
        long documentId = Long.parseLong(documentIdParam);
        
        class Document {
            // ok: java-optimal-types-for-id
            private long id;
            private String content;
            
            public long getId() { return id; }
            public void setId(long id) { this.id = id; }
        }
        
        Query query = new Query(Criteria.where("id").is(documentId));
        Document document = mongoTemplate.findOne(query, Document.class);
    }

    // Spring JDBC Template with long ID
    public void good_case_5(HttpServletRequest request, JdbcTemplate jdbcTemplate) {
        String customerIdParam = request.getParameter("customerId");
        // ok: java-optimal-types-for-id
        long customerId = Long.parseLong(customerIdParam);
        
        jdbcTemplate.queryForObject(
            "SELECT * FROM customers WHERE id = ?",
            new Object[]{customerId},
            (rs, rowNum) -> {
                // ok: java-optimal-types-for-id
                long id = rs.getLong("id");
                String name = rs.getString("name");
                return new Customer(id, name);
            }
        );
    }

    // AWS DynamoDB with long ID
    public void good_case_6(HttpServletRequest request, AmazonDynamoDB dynamoDBClient) {
        String itemIdParam = request.getParameter("itemId");
        // ok: java-optimal-types-for-id
        long itemId = Long.parseLong(itemIdParam);
        
        DynamoDB dynamoDB = new DynamoDB(dynamoDBClient);
        Table table = dynamoDB.getTable("Items");
        
        Item item = new Item()
            // ok: java-optimal-types-for-id
            .withPrimaryKey("id", itemId)
            .withString("name", "Test Item");
        
        table.putItem(item);
    }

    // MyBatis with long ID
    public void good_case_7(HttpServletRequest request, SqlSession sqlSession) {
        String userIdParam = request.getParameter("userId");
        // ok: java-optimal-types-for-id
        long userId = Long.parseLong(userIdParam);
        
        interface UserMapper {
            User getUserById(long id);
        }
        
        class User {
            // ok: java-optimal-types-for-id
            private long id;
            private String name;
            
            public long getId() { return id; }
            public void setId(long id) { this.id = id; }
        }
        
        UserMapper mapper = sqlSession.getMapper(UserMapper.class);
        User user = mapper.getUserById(userId);
    }

    // Apache HttpClient with long ID
    public void good_case_8(HttpServletRequest request) throws IOException {
        String resourceIdParam = request.getParameter("resourceId");
        // ok: java-optimal-types-for-id
        long resourceId = Long.parseLong(resourceIdParam);
        
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet httpGet = new HttpGet("https://api.example.com/resources/" + resourceId);
            httpClient.execute(httpGet);
        }
    }

    // OkHttp with long ID
    public void good_case_9(HttpServletRequest request) throws IOException {
        String articleIdParam = request.getParameter("articleId");
        // ok: java-optimal-types-for-id
        long articleId = Long.parseLong(articleIdParam);
        
        OkHttpClient client = new OkHttpClient();
        Request okRequest = new Request.Builder()
            .url("https://api.example.com/articles/" + articleId)
            .build();
        
        try (Response response = client.newCall(okRequest).execute()) {
            String responseBody = response.body().string();
        }
    }

    // Native MongoDB with long ID
    public void good_case_10(HttpServletRequest request) {
        String recordIdParam = request.getParameter("recordId");
        // ok: java-optimal-types-for-id
        long recordId = Long.parseLong(recordIdParam);
        
        MongoClient mongoClient = new MongoClient("localhost", 27017);
        MongoDatabase database = mongoClient.getDatabase("testdb");
        MongoCollection<Document> collection = database.getCollection("records");
        
        Document doc = new Document("_id", recordId)
                         .append("name", "Test Record");
        collection.insertOne(doc);
    }

    // Vert.x with long ID
    public void good_case_11(Vertx vertx) {
        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());
        
        router.get("/api/users/:id").handler(routingContext -> {
            String userIdParam = routingContext.request().getParam("id");
            // ok: java-optimal-types-for-id
            long userId = Long.parseLong(userIdParam);
            
            // Process user with long ID
            routingContext.response()
                .putHeader("content-type", "application/json")
                .end("{\"id\":" + userId + ",\"name\":\"User\"}");
        });
    }

    // Firebase Realtime Database with long ID
    public void good_case_12(HttpServletRequest request) {
        String messageIdParam = request.getParameter("messageId");
        // ok: java-optimal-types-for-id
        long messageId = Long.parseLong(messageIdParam);
        
        FirebaseDatabase database = FirebaseDatabase.getInstance();
        DatabaseReference messagesRef = database.getReference("messages");
        
        Map<String, Object> messageData = new HashMap<>();
        messageData.put("id", messageId);
        messageData.put("text", "Hello World");
        
        messagesRef.child(String.valueOf(messageId)).setValue(messageData);
    }

    // Redis with long ID
    public void good_case_13(HttpServletRequest request) {
        String sessionIdParam = request.getParameter("sessionId");
        // ok: java-optimal-types-for-id
        long sessionId = Long.parseLong(sessionIdParam);
        
        Jedis jedis = new Jedis("localhost");
        jedis.set("session:" + sessionId, "user data");
        jedis.close();
    }

    // Elasticsearch with long ID
    public void good_case_14(HttpServletRequest request, RestHighLevelClient client) throws IOException {
        String documentIdParam = request.getParameter("documentId");
        // ok: java-optimal-types-for-id
        long documentId = Long.parseLong(documentIdParam);
        
        GetRequest getRequest = new GetRequest("posts", String.valueOf(documentId));
        GetResponse getResponse = client.get(getRequest, RequestOptions.DEFAULT);
    }

    // Neo4j with long ID
    public void good_case_15(HttpServletRequest request) {
        String nodeIdParam = request.getParameter("nodeId");
        // ok: java-optimal-types-for-id
        long nodeId = Long.parseLong(nodeIdParam);
        
        Driver driver = GraphDatabase.driver("bolt://localhost:7687");
        try (org.neo4j.driver.Session session = driver.session()) {
            session.writeTransaction(tx -> {
                tx.run("MATCH (n) WHERE id(n) = $id RETURN n", 
                       Map.of("id", nodeId));
                return null;
            });
        }
    }
}
// {/fact}

// Helper class for examples
class Customer {
    private long id;
    private String name;
    
    public Customer(long id, String name) {
        this.id = id;
        this.name = name;
    }
}