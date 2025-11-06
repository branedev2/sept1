import java.util.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;
import java.util.stream.*;
import org.hibernate.*;
import org.hibernate.query.Query;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import com.google.api.services.bigquery.*;
import com.google.api.services.bigquery.model.*;
import com.mongodb.*;
import com.mongodb.client.*;
import org.bson.Document;
import com.sendgrid.*;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.*;
import software.amazon.awssdk.services.dynamodb.*;
import software.amazon.awssdk.services.dynamodb.model.*;
import org.elasticsearch.action.index.*;
import org.elasticsearch.client.*;
import org.elasticsearch.common.xcontent.*;
import com.stripe.*;
import com.stripe.model.*;
import com.stripe.param.*;
import com.azure.storage.blob.*;
import com.azure.storage.blob.models.*;
import com.google.firebase.*;
import com.google.firebase.database.*;
import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import redis.clients.jedis.*;
import org.apache.kafka.clients.producer.*;
import com.rabbitmq.client.*;
import javax.jms.*;
import com.google.cloud.storage.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.apache.http.entity.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

// Security Issue: Inefficient API usage in loops instead of using batch operations

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // JDBC Database Operations in a loop
    String[] userIds = request.getParameterValues("userIds");
    Connection conn = null;
    
    try {
        conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // ruleid: java-loops-to-batches
        for (String userId : userIds) {
            PreparedStatement stmt = conn.prepareStatement("UPDATE users SET status = ? WHERE id = ?");
            stmt.setString(1, "active");
            stmt.setString(2, userId);
            stmt.executeUpdate();
            stmt.close();
        }
    } catch (SQLException e) {
        e.printStackTrace();
    } finally {
        try { if (conn != null) conn.close(); } catch (SQLException e) { e.printStackTrace(); }
    }
}

public void bad_case_2(HttpServletRequest request) {
    // AWS S3 Operations in a loop
    String[] fileKeys = request.getParameterValues("fileKeys");
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String bucketName = "my-bucket";
    
    // ruleid: java-loops-to-batches
    for (String fileKey : fileKeys) {
        s3Client.deleteObject(bucketName, fileKey);
    }
}

public void bad_case_3(HttpServletRequest request) {
    // MongoDB document operations in a loop
    String[] documentIds = request.getParameterValues("documentIds");
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("documents");
    
    // ruleid: java-loops-to-batches
    for (String id : documentIds) {
        Document doc = new Document("_id", id)
                .append("status", "processed")
                .append("lastUpdated", new Date());
        collection.insertOne(doc);
    }
    mongoClient.close();
}

public void bad_case_4(HttpServletRequest request) {
    // SendGrid email operations in a loop
    String[] recipients = request.getParameterValues("recipients");
    String apiKey = "SG.REDAC_REDACTED_TWILIO_ID_SENDGRID_KEY";
    SendGrid sg = new SendGrid(apiKey);
    
    // ruleid: java-loops-to-batches
    for (String recipient : recipients) {
        Email from = new Email("test@example.com");
        Email to = new Email(recipient);
        Content content = new Content("text/plain", "Hello, World!");
        Mail mail = new Mail(from, "Subject", to, content);
        
        Request req = new Request();
        try {
            req.setMethod(Method.POST);
            req.setEndpoint("mail/send");
            req.setBody(mail.build());
            sg.api(req);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
}

public void bad_case_5(HttpServletRequest request) {
    // AWS DynamoDB operations in a loop
    String[] itemIds = request.getParameterValues("itemIds");
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    String tableName = "Products";
    
    // ruleid: java-loops-to-batches
    for (String id : itemIds) {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("id", AttributeValue.builder().s(id).build());
        item.put("status", AttributeValue.builder().s("archived").build());
        
        PutItemRequest putItemRequest = PutItemRequest.builder()
            .tableName(tableName)
            .item(item)
            .build();
            
        dynamoDbClient.putItem(putItemRequest);
    }
}

public void bad_case_6(HttpServletRequest request) {
    // Elasticsearch document indexing in a loop
    String[] documentIds = request.getParameterValues("documentIds");
    RestHighLevelClient client = new RestHighLevelClient(
            RestClient.builder(new HttpHost("localhost", 9200, "http")));
    
    // ruleid: java-loops-to-batches
    for (String id : documentIds) {
        try {
            Map<String, Object> jsonMap = new HashMap<>();
            jsonMap.put("id", id);
            jsonMap.put("status", "indexed");
            jsonMap.put("timestamp", new Date());
            
            IndexRequest indexRequest = new IndexRequest("posts")
                .id(id)
                .source(jsonMap);
                
            client.index(indexRequest, RequestOptions.DEFAULT);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

public void bad_case_7(HttpServletRequest request) {
    // Stripe API operations in a loop
    String[] customerIds = request.getParameterValues("customerIds");
    Stripe.apiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
    
    // ruleid: java-loops-to-batches
    for (String customerId : customerIds) {
        try {
            Customer customer = Customer.retrieve(customerId);
            CustomerUpdateParams params = CustomerUpdateParams.builder()
                .setMetadata(Map.of("processed", "true"))
                .build();
            customer.update(params);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

public void bad_case_8(HttpServletRequest request) {
    // Azure Blob Storage operations in a loop
    String[] blobNames = request.getParameterValues("blobNames");
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
        .connectionString("DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;EndpointSuffix=core.windows.net")
        .buildClient();
    BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("mycontainer");
    
    // ruleid: java-loops-to-batches
    for (String blobName : blobNames) {
        BlobClient blobClient = containerClient.getBlobClient(blobName);
        blobClient.delete();
    }
}

public void bad_case_9(HttpServletRequest request) {
    // Firebase Realtime Database operations in a loop
    String[] userIds = request.getParameterValues("userIds");
    FirebaseDatabase database = FirebaseDatabase.getInstance();
    DatabaseReference usersRef = database.getReference("users");
    
    // ruleid: java-loops-to-batches
    for (String userId : userIds) {
        Map<String, Object> updates = new HashMap<>();
        updates.put("status", "active");
        updates.put("lastLogin", ServerValue.TIMESTAMP);
        
        usersRef.child(userId).updateChildren(updates, (error, ref) -> {
            if (error != null) {
                System.err.println("Data could not be saved: " + error.getMessage());
            }
        });
    }
}

public void bad_case_10(HttpServletRequest request) {
    // Twilio SMS sending in a loop
    String[] phoneNumbers = request.getParameterValues("phoneNumbers");
    Twilio.init("AC_REDACTED_TWILIO_ID_SID", "AUTH_TOKEN");
    
    // ruleid: java-loops-to-batches
    for (String phoneNumber : phoneNumbers) {
        Message message = Message.creator(
            new com.twilio.type.PhoneNumber(phoneNumber),
            new com.twilio.type.PhoneNumber("+15551234567"),
            "Hello from Twilio!"
        ).create();
    }
}

public void bad_case_11(HttpServletRequest request) {
    // Redis operations in a loop
    String[] keys = request.getParameterValues("keys");
    Jedis jedis = new Jedis("localhost");
    
    // ruleid: java-loops-to-batches
    for (String key : keys) {
        jedis.set(key, "processed");
        jedis.expire(key, 3600);
    }
    jedis.close();
}

public void bad_case_12(HttpServletRequest request) {
    // Kafka message production in a loop
    String[] messages = request.getParameterValues("messages");
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    
    Producer<String, String> producer = new KafkaProducer<>(props);
    
    // ruleid: java-loops-to-batches
    for (String message : messages) {
        ProducerRecord<String, String> record = new ProducerRecord<>("my-topic", message);
        producer.send(record);
    }
    
    producer.close();
}

public void bad_case_13(HttpServletRequest request) {
    // RabbitMQ message publishing in a loop
    String[] messages = request.getParameterValues("messages");
    ConnectionFactory factory = new ConnectionFactory();
    factory.setHost("localhost");
    
    try (Connection connection = factory.newConnection();
         Channel channel = connection.createChannel()) {
        
        String queueName = "task_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
        channel.queueDeclare(queueName, true, false, false, null);
        
        // ruleid: java-loops-to-batches
        for (String message : messages) {
            channel.basicPublish("", queueName,
                    MessageProperties.PERSISTENT_TEXT_PLAIN,
                    message.getBytes("UTF-8"));
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) {
    // Google Cloud Storage operations in a loop
    String[] objectNames = request.getParameterValues("objectNames");
    Storage storage = StorageOptions.getDefaultInstance().getService();
    String bucketName = "my-bucket";
    
    // ruleid: java-loops-to-batches
    for (String objectName : objectNames) {
        BlobId blobId = BlobId.of(bucketName, objectName);
        storage.delete(blobId);
    }
}

public void bad_case_15(HttpServletRequest request) {
    // HTTP Client operations in a loop
    String[] endpoints = request.getParameterValues("endpoints");
    CloseableHttpClient httpClient = HttpClients.createDefault();
    
    // ruleid: java-loops-to-batches
    for (String endpoint : endpoints) {
        try {
            HttpGet httpGet = new HttpGet("https://api.example.com/" + endpoint);
            CloseableHttpResponse response = httpClient.execute(httpGet);
            // Process response
            response.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    try {
        httpClient.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // JDBC Database Operations using batch
    String[] userIds = request.getParameterValues("userIds");
    Connection conn = null;
    
    try {
        conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        
        // ok: java-loops-to-batches
        PreparedStatement stmt = conn.prepareStatement("UPDATE users SET status = ? WHERE id = ?");
        for (String userId : userIds) {
            stmt.setString(1, "active");
            stmt.setString(2, userId);
            stmt.addBatch();
        }
        stmt.executeBatch();
        stmt.close();
    } catch (SQLException e) {
        e.printStackTrace();
    } finally {
        try { if (conn != null) conn.close(); } catch (SQLException e) { e.printStackTrace(); }
    }
}

public void good_case_2(HttpServletRequest request) {
    // AWS S3 Operations using batch delete
    String[] fileKeys = request.getParameterValues("fileKeys");
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String bucketName = "my-bucket";
    
    // ok: java-loops-to-batches
    DeleteObjectsRequest deleteObjectsRequest = new DeleteObjectsRequest(bucketName)
        .withKeys(Arrays.stream(fileKeys)
                 .map(key -> new DeleteObjectsRequest.KeyVersion(key))
                 .toArray(DeleteObjectsRequest.KeyVersion[]::new));
    s3Client.deleteObjects(deleteObjectsRequest);
}

public void good_case_3(HttpServletRequest request) {
    // MongoDB document operations using bulk write
    String[] documentIds = request.getParameterValues("documentIds");
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    MongoDatabase database = mongoClient.getDatabase("mydb");
    MongoCollection<Document> collection = database.getCollection("documents");
    
    // ok: java-loops-to-batches
    List<InsertOneModel<Document>> documents = new ArrayList<>();
    for (String id : documentIds) {
        Document doc = new Document("_id", id)
                .append("status", "processed")
                .append("lastUpdated", new Date());
        documents.add(new InsertOneModel<>(doc));
    }
    collection.bulkWrite(documents);
    mongoClient.close();
}

public void good_case_4(HttpServletRequest request) {
    // SendGrid email operations using personalization for multiple recipients
    String[] recipients = request.getParameterValues("recipients");
    String apiKey = "SG.REDAC_REDACTED_TWILIO_ID_SENDGRID_KEY";
    SendGrid sg = new SendGrid(apiKey);
    
    // ok: java-loops-to-batches
    Mail mail = new Mail();
    Email from = new Email("test@example.com");
    mail.setFrom(from);
    mail.setSubject("Hello World");
    
    Personalization personalization = new Personalization();
    for (String recipient : recipients) {
        personalization.addTo(new Email(recipient));
    }
    mail.addPersonalization(personalization);
    
    Content content = new Content("text/plain", "Hello, World!");
    mail.addContent(content);
    
    Request req = new Request();
    try {
        req.setMethod(Method.POST);
        req.setEndpoint("mail/send");
        req.setBody(mail.build());
        sg.api(req);
    } catch (IOException ex) {
        ex.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    // AWS DynamoDB operations using batch write
    String[] itemIds = request.getParameterValues("itemIds");
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    String tableName = "Products";
    
    // ok: java-loops-to-batches
    List<WriteRequest> writeRequests = new ArrayList<>();
    for (String id : itemIds) {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("id", AttributeValue.builder().s(id).build());
        item.put("status", AttributeValue.builder().s("archived").build());
        
        WriteRequest writeRequest = WriteRequest.builder()
            .putRequest(PutRequest.builder().item(item).build())
            .build();
        writeRequests.add(writeRequest);
    }
    
    // Batch write in chunks of 25 (DynamoDB limit)
    for (int i = 0; i < writeRequests.size(); i += 25) {
        int end = Math.min(i + 25, writeRequests.size());
        Map<String, List<WriteRequest>> requestItems = Map.of(tableName, writeRequests.subList(i, end));
        
        BatchWriteItemRequest batchWriteItemRequest = BatchWriteItemRequest.builder()
            .requestItems(requestItems)
            .build();
            
        dynamoDbClient.batchWriteItem(batchWriteItemRequest);
    }
}

public void good_case_6(HttpServletRequest request) {
    // Elasticsearch document indexing using bulk API
    String[] documentIds = request.getParameterValues("documentIds");
    RestHighLevelClient client = new RestHighLevelClient(
            RestClient.builder(new HttpHost("localhost", 9200, "http")));
    
    // ok: java-loops-to-batches
    BulkRequest bulkRequest = new BulkRequest();
    for (String id : documentIds) {
        Map<String, Object> jsonMap = new HashMap<>();
        jsonMap.put("id", id);
        jsonMap.put("status", "indexed");
        jsonMap.put("timestamp", new Date());
        
        IndexRequest indexRequest = new IndexRequest("posts")
            .id(id)
            .source(jsonMap);
            
        bulkRequest.add(indexRequest);
    }
    
    try {
        client.bulk(bulkRequest, RequestOptions.DEFAULT);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_7(HttpServletRequest request) {
    // Stripe API operations using collection update
    String[] customerIds = request.getParameterValues("customerIds");
    Stripe.apiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
    
    // ok: java-loops-to-batches
    try {
        Map<String, Object> params = new HashMap<>();
        params.put("limit", customerIds.length);
        
        // First retrieve all customers in one API call
        CustomerCollection customers = Customer.list(params);
        
        // Then filter and update in memory
        for (Customer customer : customers.getData()) {
            if (Arrays.asList(customerIds).contains(customer.getId())) {
                CustomerUpdateParams updateParams = CustomerUpdateParams.builder()
                    .setMetadata(Map.of("processed", "true"))
                    .build();
                customer.update(updateParams);
            }
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    // Azure Blob Storage operations using parallel execution
    String[] blobNames = request.getParameterValues("blobNames");
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
        .connectionString("DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;EndpointSuffix=core.windows.net")
        .buildClient();
    BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("mycontainer");
    
    // ok: java-loops-to-batches
    List<CompletableFuture<Void>> futures = new ArrayList<>();
    
    for (String blobName : blobNames) {
        BlobClient blobClient = containerClient.getBlobClient(blobName);
        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            blobClient.delete();
        });
        futures.add(future);
    }
    
    // Wait for all operations to complete
    CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
}

public void good_case_9(HttpServletRequest request) {
    // Firebase Realtime Database operations using batch update
    String[] userIds = request.getParameterValues("userIds");
    FirebaseDatabase database = FirebaseDatabase.getInstance();
    DatabaseReference usersRef = database.getReference("users");
    
    // ok: java-loops-to-batches
    Map<String, Object> childUpdates = new HashMap<>();
    for (String userId : userIds) {
        Map<String, Object> userValues = new HashMap<>();
        userValues.put("status", "active");
        userValues.put("lastLogin", ServerValue.TIMESTAMP);
        
        childUpdates.put("/" + userId, userValues);
    }
    
    usersRef.updateChildren(childUpdates, (error, ref) -> {
        if (error != null) {
            System.err.println("Data could not be saved: " + error.getMessage());
        }
    });
}

public void good_case_10(HttpServletRequest request) {
    // Twilio SMS sending using parallel execution
    String[] phoneNumbers = request.getParameterValues("phoneNumbers");
    Twilio.init("AC_REDACTED_TWILIO_ID_SID", "AUTH_TOKEN");
    
    // ok: java-loops-to-batches
    ExecutorService executor = Executors.newFixedThreadPool(10);
    List<CompletableFuture<Message>> futures = new ArrayList<>();
    
    for (String phoneNumber : phoneNumbers) {
        CompletableFuture<Message> future = CompletableFuture.supplyAsync(() -> {
            return Message.creator(
                new com.twilio.type.PhoneNumber(phoneNumber),
                new com.twilio.type.PhoneNumber("+15551234567"),
                "Hello from Twilio!"
            ).create();
        }, executor);
        futures.add(future);
    }
    
    // Wait for all messages to be sent
    CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
    executor.shutdown();
}

public void good_case_11(HttpServletRequest request) {
    // Redis operations using pipelining
    String[] keys = request.getParameterValues("keys");
    Jedis jedis = new Jedis("localhost");
    
    // ok: java-loops-to-batches
    Pipeline pipeline = jedis.pipelined();
    for (String key : keys) {
        pipeline.set(key, "processed");
        pipeline.expire(key, 3600);
    }
    pipeline.sync();
    jedis.close();
}

public void good_case_12(HttpServletRequest request) {
    // Kafka message production using batch
    String[] messages = request.getParameterValues("messages");
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    props.put("batch.size", 16384);
    props.put("linger.ms", 10);
    
    Producer<String, String> producer = new KafkaProducer<>(props);
    
    // ok: java-loops-to-batches
    List<Future<RecordMetadata>> futures = new ArrayList<>();
    for (String message : messages) {
        ProducerRecord<String, String> record = new ProducerRecord<>("my-topic", message);
        futures.add(producer.send(record));
    }
    
    // Wait for all messages to be sent
    for (Future<RecordMetadata> future : futures) {
        try {
            future.get();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    producer.close();
}

public void good_case_13(HttpServletRequest request) {
    // RabbitMQ message publishing using transaction
    String[] messages = request.getParameterValues("messages");
    ConnectionFactory factory = new ConnectionFactory();
    factory.setHost("localhost");
    
    try (Connection connection = factory.newConnection();
         Channel channel = connection.createChannel()) {
        
        String queueName = "task_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
        channel.queueDeclare(queueName, true, false, false, null);
        
        // ok: java-loops-to-batches
        channel.txSelect();
        for (String message : messages) {
            channel.basicPublish("", queueName,
                    MessageProperties.PERSISTENT_TEXT_PLAIN,
                    message.getBytes("UTF-8"));
        }
        channel.txCommit();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) {
    // Google Cloud Storage operations using batch
    String[] objectNames = request.getParameterValues("objectNames");
    Storage storage = StorageOptions.getDefaultInstance().getService();
    String bucketName = "my-bucket";
    
    // ok: java-loops-to-batches
    List<BlobId> blobIds = new ArrayList<>();
    for (String objectName : objectNames) {
        blobIds.add(BlobId.of(bucketName, objectName));
    }
    
    // Delete objects in batches of 100
    List<List<BlobId>> batches = new ArrayList<>();
    for (int i = 0; i < blobIds.size(); i += 100) {
        batches.add(blobIds.subList(i, Math.min(i + 100, blobIds.size())));
    }
    
    for (List<BlobId> batch : batches) {
        List<Boolean> deleteResults = storage.delete(batch);
        // Process results if needed
    }
}

public void good_case_15(HttpServletRequest request) {
    // HTTP Client operations using parallel execution
    String[] endpoints = request.getParameterValues("endpoints");
    CloseableHttpClient httpClient = HttpClients.createDefault();
    
    // ok: java-loops-to-batches
    ExecutorService executor = Executors.newFixedThreadPool(10);
    List<CompletableFuture<String>> futures = new ArrayList<>();
    
    for (String endpoint : endpoints) {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                HttpGet httpGet = new HttpGet("https://api.example.com/" + endpoint);
                CloseableHttpResponse response = httpClient.execute(httpGet);
                // Process response
                String result = EntityUtils.toString(response.getEntity());
                response.close();
                return result;
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
        }, executor);
        futures.add(future);
    }
    
    // Wait for all requests to complete
    CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
    executor.shutdown();
    
    try {
        httpClient.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}