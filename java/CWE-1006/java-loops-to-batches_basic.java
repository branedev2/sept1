import java.util.*;
import java.sql.*;
import java.io.*;
import java.net.http.*;
import java.net.URI;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import com.amazonaws.auth.*;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import com.mongodb.*;
import com.mongodb.client.*;
import org.bson.Document;
import com.google.api.client.http.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.Pipeline;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.entity.StringEntity;

public class LoopsToBatchesExamples {

    // True Positives (Vulnerable Code)

// {fact rule=batches-preferred-over-loops@v1.0 defects=1}
    public void bad_case_1(List<String> userIds) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        for (String userId : userIds) {
            // ruleid: java-loops-to-batches
            PreparedStatement stmt = conn.prepareStatement("UPDATE users SET last_login = NOW() WHERE id = ?");
            stmt.setString(1, userId);
            stmt.executeUpdate();
            stmt.close();
        }
        conn.close();
    }

    public void bad_case_2(List<String> documentIds) {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        for (String docId : documentIds) {
            // ruleid: java-loops-to-batches
            s3Client.getObject("my-bucket", "documents/" + docId);
        }
    }

    public void bad_case_3(List<String> customerIds) {
        MongoClient mongoClient = MongoClients.create("mongodb://localhost:27017");
        MongoDatabase database = mongoClient.getDatabase("customers");
        MongoCollection<Document> collection = database.getCollection("profiles");
        
        for (String id : customerIds) {
            // ruleid: java-loops-to-batches
            collection.updateOne(
                new Document("_id", id),
                new Document("$set", new Document("lastChecked", new Date()))
            );
        }
        mongoClient.close();
    }

    public void bad_case_4(List<String> apiKeys) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        
        for (String key : apiKeys) {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.example.com/validate"))
                .header("X-API-Key", key)
                .build();
            
            // ruleid: java-loops-to-batches
            client.send(request, HttpResponse.BodyHandlers.ofString());
        }
    }

    public void bad_case_5(List<Map<String, Object>> products) throws IOException {
        RestHighLevelClient client = new RestHighLevelClient();
        
        for (Map<String, Object> product : products) {
            IndexRequest request = new IndexRequest("products")
                .id(product.get("id").toString())
                .source(product);
            
            // ruleid: java-loops-to-batches
            client.index(request, RequestOptions.DEFAULT);
        }
        client.close();
    }

    public void bad_case_6(List<String> emails) {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        
        for (String email : emails) {
            try {
                HttpPost request = new HttpPost("https://api.mailservice.com/send");
                StringEntity params = new StringEntity("{\"to\":\"" + email + "\",\"subject\":\"Welcome\"}");
                request.setEntity(params);
                request.setHeader("Content-Type", "application/json");
                
                // ruleid: java-loops-to-batches
                httpClient.execute(request);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public void bad_case_7(List<Item> items, DynamoDbClient dynamoDbClient) {
        for (Item item : items) {
            Map<String, AttributeValue> itemValues = new HashMap<>();
            itemValues.put("id", AttributeValue.builder().s(item.getId()).build());
            itemValues.put("name", AttributeValue.builder().s(item.getName()).build());
            
            PutItemRequest request = PutItemRequest.builder()
                .tableName("Items")
                .item(itemValues)
                .build();
            
            // ruleid: java-loops-to-batches
            dynamoDbClient.putItem(request);
        }
    }

    public void bad_case_8(List<String> keys, Jedis jedis) {
        for (String key : keys) {
            // ruleid: java-loops-to-batches
            jedis.get(key);
        }
    }

    public void bad_case_9(List<User> users) throws SQLException {
        DataSource dataSource = getDataSource();
        Connection connection = dataSource.getConnection();
        
        for (User user : users) {
            PreparedStatement ps = connection.prepareStatement(
                "INSERT INTO users (name, email, created_at) VALUES (?, ?, ?)");
            ps.setString(1, user.getName());
            ps.setString(2, user.getEmail());
            ps.setTimestamp(3, new Timestamp(System.currentTimeMillis()));
            
            // ruleid: java-loops-to-batches
            ps.executeUpdate();
            ps.close();
        }
        connection.close();
    }

    public void bad_case_10(List<String> fileIds) {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        for (String fileId : fileIds) {
            // ruleid: java-loops-to-batches
            s3Client.deleteObject("user-files", fileId);
        }
    }

    public void bad_case_11(List<String> phoneNumbers) throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        
        for (String phoneNumber : phoneNumbers) {
            HttpPost request = new HttpPost("https://api.sms-service.com/send");
            StringEntity params = new StringEntity("{\"to\":\"" + phoneNumber + "\",\"message\":\"Alert!\"}");
            request.setEntity(params);
            request.setHeader("Content-Type", "application/json");
            
            // ruleid: java-loops-to-batches
            httpClient.execute(request);
        }
        httpClient.close();
    }

    public void bad_case_12(List<String> orderIds, JdbcTemplate jdbcTemplate) {
        for (String orderId : orderIds) {
            // ruleid: java-loops-to-batches
            jdbcTemplate.update("UPDATE orders SET status = 'PROCESSED' WHERE id = ?", orderId);
        }
    }

    public void bad_case_13(List<Document> documents, MongoCollection<Document> collection) {
        for (Document doc : documents) {
            // ruleid: java-loops-to-batches
            collection.insertOne(doc);
        }
    }

    public void bad_case_14(List<String> urls) throws IOException {
        HttpTransport httpTransport = new NetHttpTransport();
        JsonFactory jsonFactory = new JacksonFactory();
        HttpRequestFactory requestFactory = httpTransport.createRequestFactory();
        
        for (String url : urls) {
            GenericUrl genericUrl = new GenericUrl(url);
            HttpRequest request = requestFactory.buildGetRequest(genericUrl);
            
            // ruleid: java-loops-to-batches
            request.execute();
        }
    }

    public void bad_case_15(List<String> cacheKeys, Jedis jedis) {
        for (String key : cacheKeys) {
            // ruleid: java-loops-to-batches
            jedis.del(key);
        }
    }

    // True Negatives (Secure Code)

    public void good_case_1(List<String> userIds) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        // ok: java-loops-to-batches
        PreparedStatement stmt = conn.prepareStatement("UPDATE users SET last_login = NOW() WHERE id = ?");
        for (String userId : userIds) {
            stmt.setString(1, userId);
            stmt.addBatch();
        }
        stmt.executeBatch();
        stmt.close();
        conn.close();
    }

    public void good_case_2(List<String> documentIds) {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        // ok: java-loops-to-batches
        TransferManager transferManager = TransferManagerBuilder.standard().withS3Client(s3Client).build();
        MultipleFileDownload download = transferManager.downloadDirectory(
            "my-bucket", 
            "documents", 
            new File("/local/path"),
            documentIds.stream().map(id -> "documents/" + id).collect(Collectors.toList())
        );
        try {
            download.waitForCompletion();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_3(List<String> customerIds) {
        MongoClient mongoClient = MongoClients.create("mongodb://localhost:27017");
        MongoDatabase database = mongoClient.getDatabase("customers");
        MongoCollection<Document> collection = database.getCollection("profiles");
        
        List<WriteModel<Document>> updates = new ArrayList<>();
        for (String id : customerIds) {
            updates.add(
                new UpdateOneModel<>(
                    new Document("_id", id),
                    new Document("$set", new Document("lastChecked", new Date()))
                )
            );
        }
        
        // ok: java-loops-to-batches
        collection.bulkWrite(updates);
        mongoClient.close();
    }

    public void good_case_4(List<String> apiKeys) {
        // ok: java-loops-to-batches
        // Using a batch API endpoint that accepts multiple keys
        CloseableHttpClient httpClient = HttpClients.createDefault();
        try {
            HttpPost request = new HttpPost("https://api.example.com/validate-batch");
            StringEntity params = new StringEntity("{\"keys\":" + apiKeys.toString() + "}");
            request.setEntity(params);
            request.setHeader("Content-Type", "application/json");
            httpClient.execute(request);
            httpClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5(List<Map<String, Object>> products) throws IOException {
        RestHighLevelClient client = new RestHighLevelClient();
        
        BulkRequest bulkRequest = new BulkRequest();
        for (Map<String, Object> product : products) {
            IndexRequest request = new IndexRequest("products")
                .id(product.get("id").toString())
                .source(product);
            bulkRequest.add(request);
        }
        
        // ok: java-loops-to-batches
        BulkResponse bulkResponse = client.bulk(bulkRequest, RequestOptions.DEFAULT);
        client.close();
    }

    public void good_case_6(List<String> emails) {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        
        try {
            // Prepare batch request with all emails
            List<Map<String, String>> emailRequests = new ArrayList<>();
            for (String email : emails) {
                Map<String, String> emailRequest = new HashMap<>();
                emailRequest.put("to", email);
                emailRequest.put("subject", "Welcome");
                emailRequests.add(emailRequest);
            }
            
            // ok: java-loops-to-batches
            HttpPost request = new HttpPost("https://api.mailservice.com/send-batch");
            StringEntity params = new StringEntity(convertToJson(emailRequests));
            request.setEntity(params);
            request.setHeader("Content-Type", "application/json");
            httpClient.execute(request);
            httpClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7(List<Item> items, DynamoDbClient dynamoDbClient) {
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        for (Item item : items) {
            Map<String, AttributeValue> itemValues = new HashMap<>();
            itemValues.put("id", AttributeValue.builder().s(item.getId()).build());
            itemValues.put("name", AttributeValue.builder().s(item.getName()).build());
            
            PutRequest putRequest = PutRequest.builder().item(itemValues).build();
            WriteRequest writeRequest = WriteRequest.builder().putRequest(putRequest).build();
            writeRequests.add(writeRequest);
        }
        
        // ok: java-loops-to-batches
        BatchWriteItemRequest batchWriteItemRequest = BatchWriteItemRequest.builder()
            .requestItems(Collections.singletonMap("Items", writeRequests))
            .build();
        dynamoDbClient.batchWriteItem(batchWriteItemRequest);
    }

    public void good_case_8(List<String> keys, Jedis jedis) {
        // ok: java-loops-to-batches
        String[] keysArray = keys.toArray(new String[0]);
        List<String> values = jedis.mget(keysArray);
    }

    public void good_case_9(List<User> users) throws SQLException {
        DataSource dataSource = getDataSource();
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        
        // ok: java-loops-to-batches
        jdbcTemplate.batchUpdate(
            "INSERT INTO users (name, email, created_at) VALUES (?, ?, ?)",
            new BatchPreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps, int i) throws SQLException {
                    User user = users.get(i);
                    ps.setString(1, user.getName());
                    ps.setString(2, user.getEmail());
                    ps.setTimestamp(3, new Timestamp(System.currentTimeMillis()));
                }
                
                @Override
                public int getBatchSize() {
                    return users.size();
                }
            }
        );
    }

    public void good_case_10(List<String> fileIds) {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // ok: java-loops-to-batches
        DeleteObjectsRequest deleteObjectsRequest = new DeleteObjectsRequest("user-files")
            .withKeys(fileIds.stream()
                .map(id -> new DeleteObjectsRequest.KeyVersion(id))
                .collect(Collectors.toList()));
        s3Client.deleteObjects(deleteObjectsRequest);
    }

    public void good_case_11(List<String> phoneNumbers) {
        // ok: java-loops-to-batches
        // Using a batch SMS API
        CloseableHttpClient httpClient = HttpClients.createDefault();
        try {
            HttpPost request = new HttpPost("https://api.sms-service.com/send-batch");
            
            List<Map<String, String>> messages = new ArrayList<>();
            for (String phoneNumber : phoneNumbers) {
                Map<String, String> message = new HashMap<>();
                message.put("to", phoneNumber);
                message.put("message", "Alert!");
                messages.add(message);
            }
            
            StringEntity params = new StringEntity(convertToJson(messages));
            request.setEntity(params);
            request.setHeader("Content-Type", "application/json");
            httpClient.execute(request);
            httpClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12(List<String> orderIds, JdbcTemplate jdbcTemplate) {
        // ok: java-loops-to-batches
        jdbcTemplate.batchUpdate(
            "UPDATE orders SET status = 'PROCESSED' WHERE id = ?",
            new BatchPreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps, int i) throws SQLException {
                    ps.setString(1, orderIds.get(i));
                }
                
                @Override
                public int getBatchSize() {
                    return orderIds.size();
                }
            }
        );
    }

    public void good_case_13(List<Document> documents, MongoCollection<Document> collection) {
        // ok: java-loops-to-batches
        collection.insertMany(documents);
    }

    public void good_case_14(List<String> urls) {
        // ok: java-loops-to-batches
        // Using CompletableFuture for parallel execution instead of sequential API calls
        HttpClient client = HttpClient.newHttpClient();
        
        List<CompletableFuture<HttpResponse<String>>> futures = urls.stream()
            .map(url -> HttpRequest.newBuilder()
                .uri(URI.create(url))
                .build())
            .map(request -> client.sendAsync(request, HttpResponse.BodyHandlers.ofString()))
            .collect(Collectors.toList());
        
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
    }

    public void good_case_15(List<String> cacheKeys, Jedis jedis) {
        // ok: java-loops-to-batches
        String[] keysArray = cacheKeys.toArray(new String[0]);
        jedis.del(keysArray);
    }

    // Helper methods and classes
    private DataSource getDataSource() {
        // Implementation would return a configured DataSource
        return null;
    }
    
    private String convertToJson(Object obj) {
        // Implementation would convert object to JSON string
        return "{}";
    }
    
    private static class User {
        private String name;
        private String email;
        
        public String getName() { return name; }
        public String getEmail() { return email; }
    }
    
    private static class Item {
        private String id;
        private String name;
        
        public String getId() { return id; }
        public String getName() { return name; }
    }
}
// {/fact}