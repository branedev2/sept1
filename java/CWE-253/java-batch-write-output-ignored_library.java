import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import com.amazonaws.services.dynamodb.AmazonDynamoDB;
import com.amazonaws.services.dynamodb.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodb.model.*;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.WriteBatch;
import com.google.cloud.firestore.WriteResult;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.bulk.BulkWriteResult;
import com.mongodb.client.model.*;
import org.bson.Document;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Session;
import org.neo4j.driver.Transaction;
import org.neo4j.driver.TransactionWork;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.Pipeline;
import redis.clients.jedis.Response;
import com.datastax.driver.core.BatchStatement;
import com.datastax.driver.core.ResultSet;
import com.datastax.driver.core.Session;
import com.couchbase.client.java.Bucket;
import com.couchbase.client.java.document.JsonDocument;
import com.couchbase.client.java.document.json.JsonObject;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.IMap;
import org.apache.hadoop.hbase.client.*;
import org.apache.hadoop.hbase.util.Bytes;
import com.aerospike.client.AerospikeClient;
import com.aerospike.client.Bin;
import com.aerospike.client.Key;
import com.aerospike.client.policy.WritePolicy;
import com.orientechnologies.orient.core.db.ODatabaseSession;
import com.orientechnologies.orient.core.db.OrientDB;
import com.orientechnologies.orient.core.db.OrientDBConfig;
import com.orientechnologies.orient.core.record.OElement;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.*;
import org.apache.ignite.Ignite;
import org.apache.ignite.IgniteCache;
import org.apache.ignite.transactions.Transaction;
import org.infinispan.Cache;
import org.infinispan.manager.DefaultCacheManager;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;

// Security Issue: Batch requests can contain failed items, potentially leading to data loss if not properly handled.

// True Positive Examples (Vulnerable/Insecure Code)
public void bad_case_1(HttpServletRequest request) {
    // AWS DynamoDB SDK v2 - Not checking for failed items in batch write
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    
    String tableName = "Users";
    List<String> userIds = Arrays.asList(request.getParameter("userIds").split(","));
    
    List<WriteRequest> writeRequests = new ArrayList<>();
    for (String userId : userIds) {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("userId", AttributeValue.builder().s(userId).build());
        item.put("status", AttributeValue.builder().s("active").build());
        
        PutRequest putRequest = PutRequest.builder().item(item).build();
        writeRequests.add(WriteRequest.builder().putRequest(putRequest).build());
    }
    
    Map<String, List<WriteRequest>> requestItems = new HashMap<>();
    requestItems.put(tableName, writeRequests);
    
    BatchWriteItemRequest batchWriteItemRequest = BatchWriteItemRequest.builder()
            .requestItems(requestItems)
            .build();
    
    // ruleid: java-batch-write-output-ignored
    dynamoDbClient.batchWriteItem(batchWriteItemRequest);
    // No check for unprocessed items
}

public void bad_case_2(HttpServletRequest request) {
    // AWS DynamoDB SDK v1 - Not checking for failed items in batch write
    AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
    
    String tableName = "Products";
    List<String> productIds = Arrays.asList(request.getParameter("productIds").split(","));
    
    List<com.amazonaws.services.dynamodb.model.WriteRequest> writeRequests = new ArrayList<>();
    for (String productId : productIds) {
        Map<String, com.amazonaws.services.dynamodb.model.AttributeValue> item = new HashMap<>();
        item.put("productId", new com.amazonaws.services.dynamodb.model.AttributeValue(productId));
        item.put("inStock", new com.amazonaws.services.dynamodb.model.AttributeValue().withBOOL(true));
        
        com.amazonaws.services.dynamodb.model.PutRequest putRequest = new com.amazonaws.services.dynamodb.model.PutRequest(item);
        writeRequests.add(new com.amazonaws.services.dynamodb.model.WriteRequest(putRequest));
    }
    
    Map<String, List<com.amazonaws.services.dynamodb.model.WriteRequest>> requestItems = new HashMap<>();
    requestItems.put(tableName, writeRequests);
    
    // ruleid: java-batch-write-output-ignored
    dynamoDB.batchWriteItem(requestItems);
    // No check for unprocessed items
}

public void bad_case_3(HttpServletRequest request) {
    // MongoDB - Not checking for failed operations in bulk write
    MongoClient mongoClient = MongoClients.create("mongodb://localhost:27017");
    MongoCollection<Document> collection = mongoClient.getDatabase("testdb").getCollection("users");
    
    String[] emails = request.getParameter("emails").split(",");
    List<WriteModel<Document>> writes = new ArrayList<>();
    
    for (String email : emails) {
        Document doc = new Document("email", email)
                .append("createdAt", new Date());
        writes.add(new InsertOneModel<>(doc));
    }
    
    // ruleid: java-batch-write-output-ignored
    collection.bulkWrite(writes);
    // No check for write errors
    
    mongoClient.close();
}

public void bad_case_4(HttpServletRequest request) {
    // Elasticsearch - Not checking for failed items in bulk request
    RestHighLevelClient client = new RestHighLevelClient();
    
    String[] documentIds = request.getParameter("documentIds").split(",");
    String[] contents = request.getParameter("contents").split(",");
    
    BulkRequest bulkRequest = new BulkRequest();
    for (int i = 0; i < documentIds.length; i++) {
        IndexRequest indexRequest = new IndexRequest("posts")
                .id(documentIds[i])
                .source("content", contents[i], "timestamp", new Date());
        bulkRequest.add(indexRequest);
    }
    
    try {
        // ruleid: java-batch-write-output-ignored
        BulkResponse bulkResponse = client.bulk(bulkRequest, RequestOptions.DEFAULT);
        // No check for failures in the response
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request) {
    // Google Firestore - Not checking for failed writes in batch
    Firestore db = null; // Assume initialized elsewhere
    
    String[] userIds = request.getParameter("userIds").split(",");
    String[] names = request.getParameter("names").split(",");
    
    WriteBatch batch = db.batch();
    
    for (int i = 0; i < userIds.length; i++) {
        batch.set(db.collection("users").document(userIds[i]), 
                  Map.of("name", names[i], "updatedAt", new Date()));
    }
    
    try {
        // ruleid: java-batch-write-output-ignored
        batch.commit();
        // No verification of write results
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6(HttpServletRequest request) {
    // Redis Pipeline - Not checking for failed operations
    Jedis jedis = new Jedis("localhost");
    
    String[] keys = request.getParameter("keys").split(",");
    String[] values = request.getParameter("values").split(",");
    
    Pipeline pipeline = jedis.pipelined();
    
    for (int i = 0; i < keys.length; i++) {
        pipeline.set(keys[i], values[i]);
    }
    
    // ruleid: java-batch-write-output-ignored
    pipeline.sync();
    // No verification of operation results
    
    jedis.close();
}

public void bad_case_7(HttpServletRequest request) {
    // Cassandra Batch Statement - Not checking for failed operations
    com.datastax.driver.core.Session session = null; // Assume initialized elsewhere
    
    String[] userIds = request.getParameter("userIds").split(",");
    String[] emails = request.getParameter("emails").split(",");
    
    BatchStatement batch = new BatchStatement();
    
    for (int i = 0; i < userIds.length; i++) {
        batch.add(session.prepare("INSERT INTO users (id, email) VALUES (?, ?)")
                .bind(userIds[i], emails[i]));
    }
    
    // ruleid: java-batch-write-output-ignored
    session.execute(batch);
    // No verification of batch execution results
}

public void bad_case_8(HttpServletRequest request) {
    // Couchbase Batch Operations - Not checking for failed operations
    Bucket bucket = null; // Assume initialized elsewhere
    
    String[] documentIds = request.getParameter("documentIds").split(",");
    String[] contents = request.getParameter("contents").split(",");
    
    List<JsonDocument> documents = new ArrayList<>();
    for (int i = 0; i < documentIds.length; i++) {
        JsonObject content = JsonObject.create().put("content", contents[i]);
        documents.add(JsonDocument.create(documentIds[i], content));
    }
    
    // ruleid: java-batch-write-output-ignored
    for (JsonDocument doc : documents) {
        bucket.upsert(doc);
    }
    // No verification of individual operation results
}

public void bad_case_9(HttpServletRequest request) {
    // HBase Batch Operations - Not checking for failed operations
    BufferedMutator mutator = null; // Assume initialized elsewhere
    
    String[] rowKeys = request.getParameter("rowKeys").split(",");
    String[] values = request.getParameter("values").split(",");
    
    List<Mutation> mutations = new ArrayList<>();
    for (int i = 0; i < rowKeys.length; i++) {
        Put put = new Put(Bytes.toBytes(rowKeys[i]));
        put.addColumn(Bytes.toBytes("cf"), Bytes.toBytes("col"), Bytes.toBytes(values[i]));
        mutations.add(put);
    }
    
    try {
        // ruleid: java-batch-write-output-ignored
        mutator.mutate(mutations);
        // No verification of mutation results
        mutator.flush();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    // Aerospike Batch Operations - Not checking for failed operations
    AerospikeClient client = null; // Assume initialized elsewhere
    WritePolicy policy = new WritePolicy();
    
    String[] keys = request.getParameter("keys").split(",");
    String[] values = request.getParameter("values").split(",");
    
    // ruleid: java-batch-write-output-ignored
    for (int i = 0; i < keys.length; i++) {
        Key key = new Key("namespace", "set", keys[i]);
        Bin bin = new Bin("value", values[i]);
        client.put(policy, key, bin);
    }
    // No verification of individual operation results
}

public void bad_case_11(HttpServletRequest request) {
    // OrientDB Batch Operations - Not checking for failed operations
    OrientDB orient = new OrientDB("embedded:/tmp/databases/", OrientDBConfig.defaultConfig());
    ODatabaseSession db = orient.open("test", "admin", "admin");
    
    String[] names = request.getParameter("names").split(",");
    String[] emails = request.getParameter("emails").split(",");
    
    db.begin();
    
    try {
        for (int i = 0; i < names.length; i++) {
            OElement element = db.newElement("Person");
            element.setProperty("name", names[i]);
            element.setProperty("email", emails[i]);
            // ruleid: java-batch-write-output-ignored
            element.save();
            // No verification of individual save results
        }
        
        db.commit();
    } catch (Exception e) {
        db.rollback();
        e.printStackTrace();
    } finally {
        db.close();
        orient.close();
    }
}

public void bad_case_12(HttpServletRequest request) {
    // AWS S3 Batch Operations - Not checking for failed operations
    S3Client s3Client = S3Client.create();
    
    String bucketName = request.getParameter("bucketName");
    String[] objectKeys = request.getParameter("objectKeys").split(",");
    
    List<ObjectIdentifier> objectIds = new ArrayList<>();
    for (String key : objectKeys) {
        objectIds.add(ObjectIdentifier.builder().key(key).build());
    }
    
    DeleteObjectsRequest deleteRequest = DeleteObjectsRequest.builder()
            .bucket(bucketName)
            .delete(Delete.builder().objects(objectIds).build())
            .build();
    
    // ruleid: java-batch-write-output-ignored
    s3Client.deleteObjects(deleteRequest);
    // No check for failed deletions
}

public void bad_case_13(HttpServletRequest request) {
    // Apache Ignite Batch Operations - Not checking for failed operations
    Ignite ignite = null; // Assume initialized elsewhere
    IgniteCache<String, String> cache = ignite.getOrCreateCache("myCache");
    
    String[] keys = request.getParameter("keys").split(",");
    String[] values = request.getParameter("values").split(",");
    
    Map<String, String> entries = new HashMap<>();
    for (int i = 0; i < keys.length; i++) {
        entries.put(keys[i], values[i]);
    }
    
    // ruleid: java-batch-write-output-ignored
    cache.putAll(entries);
    // No verification of batch operation results
}

public void bad_case_14(HttpServletRequest request) {
    // Hazelcast Batch Operations - Not checking for failed operations
    HazelcastInstance hazelcastInstance = null; // Assume initialized elsewhere
    IMap<String, String> map = hazelcastInstance.getMap("myMap");
    
    String[] keys = request.getParameter("keys").split(",");
    String[] values = request.getParameter("values").split(",");
    
    Map<String, String> entries = new HashMap<>();
    for (int i = 0; i < keys.length; i++) {
        entries.put(keys[i], values[i]);
    }
    
    // ruleid: java-batch-write-output-ignored
    map.putAll(entries);
    // No verification of batch operation results
}

public void bad_case_15(HttpServletRequest request) {
    // Infinispan Batch Operations - Not checking for failed operations
    DefaultCacheManager cacheManager = null; // Assume initialized elsewhere
    Cache<String, String> cache = cacheManager.getCache();
    
    String[] keys = request.getParameter("keys").split(",");
    String[] values = request.getParameter("values").split(",");
    
    Map<String, String> entries = new HashMap<>();
    for (int i = 0; i < keys.length; i++) {
        entries.put(keys[i], values[i]);
    }
    
    // ruleid: java-batch-write-output-ignored
    cache.putAll(entries);
    // No verification of batch operation results
}

// True Negative Examples (Safe/Secure Code)
public void good_case_1(HttpServletRequest request) {
    // AWS DynamoDB SDK v2 - Properly checking for unprocessed items
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    
    String tableName = "Users";
    List<String> userIds = Arrays.asList(request.getParameter("userIds").split(","));
    
    List<WriteRequest> writeRequests = new ArrayList<>();
    for (String userId : userIds) {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("userId", AttributeValue.builder().s(userId).build());
        item.put("status", AttributeValue.builder().s("active").build());
        
        PutRequest putRequest = PutRequest.builder().item(item).build();
        writeRequests.add(WriteRequest.builder().putRequest(putRequest).build());
    }
    
    Map<String, List<WriteRequest>> requestItems = new HashMap<>();
    requestItems.put(tableName, writeRequests);
    
    BatchWriteItemRequest batchWriteItemRequest = BatchWriteItemRequest.builder()
            .requestItems(requestItems)
            .build();
    
    // ok: java-batch-write-output-ignored
    BatchWriteItemResponse response = dynamoDbClient.batchWriteItem(batchWriteItemRequest);
    
    // Handle unprocessed items
    Map<String, List<WriteRequest>> unprocessedItems = response.unprocessedItems();
    if (!unprocessedItems.isEmpty()) {
        // Retry logic for unprocessed items
        BatchWriteItemRequest retryRequest = BatchWriteItemRequest.builder()
                .requestItems(unprocessedItems)
                .build();
        dynamoDbClient.batchWriteItem(retryRequest);
    }
}

public void good_case_2(HttpServletRequest request) {
    // AWS DynamoDB SDK v1 - Properly checking for unprocessed items
    AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
    
    String tableName = "Products";
    List<String> productIds = Arrays.asList(request.getParameter("productIds").split(","));
    
    List<com.amazonaws.services.dynamodb.model.WriteRequest> writeRequests = new ArrayList<>();
    for (String productId : productIds) {
        Map<String, com.amazonaws.services.dynamodb.model.AttributeValue> item = new HashMap<>();
        item.put("productId", new com.amazonaws.services.dynamodb.model.AttributeValue(productId));
        item.put("inStock", new com.amazonaws.services.dynamodb.model.AttributeValue().withBOOL(true));
        
        com.amazonaws.services.dynamodb.model.PutRequest putRequest = new com.amazonaws.services.dynamodb.model.PutRequest(item);
        writeRequests.add(new com.amazonaws.services.dynamodb.model.WriteRequest(putRequest));
    }
    
    Map<String, List<com.amazonaws.services.dynamodb.model.WriteRequest>> requestItems = new HashMap<>();
    requestItems.put(tableName, writeRequests);
    
    // ok: java-batch-write-output-ignored
    com.amazonaws.services.dynamodb.model.BatchWriteItemResult result = dynamoDB.batchWriteItem(requestItems);
    
    // Handle unprocessed items
    Map<String, List<com.amazonaws.services.dynamodb.model.WriteRequest>> unprocessedItems = result.getUnprocessedItems();
    if (!unprocessedItems.isEmpty()) {
        // Retry logic for unprocessed items
        dynamoDB.batchWriteItem(unprocessedItems);
    }
}

public void good_case_3(HttpServletRequest request) {
    // MongoDB - Properly checking for write errors in bulk write
    MongoClient mongoClient = MongoClients.create("mongodb://localhost:27017");
    MongoCollection<Document> collection = mongoClient.getDatabase("testdb").getCollection("users");
    
    String[] emails = request.getParameter("emails").split(",");
    List<WriteModel<Document>> writes = new ArrayList<>();
    
    for (String email : emails) {
        Document doc = new Document("email", email)
                .append("createdAt", new Date());
        writes.add(new InsertOneModel<>(doc));
    }
    
    // ok: java-batch-write-output-ignored
    BulkWriteResult result = collection.bulkWrite(writes);
    
    // Check for write errors
    if (result.getInsertedCount() != writes.size()) {
        // Handle partial success scenario
        System.err.println("Some documents were not inserted. Expected: " + writes.size() + 
                           ", Actual: " + result.getInsertedCount());
    }
    
    mongoClient.close();
}

public void good_case_4(HttpServletRequest request) {
    // Elasticsearch - Properly checking for failed items in bulk request
    RestHighLevelClient client = new RestHighLevelClient();
    
    String[] documentIds = request.getParameter("documentIds").split(",");
    String[] contents = request.getParameter("contents").split(",");
    
    BulkRequest bulkRequest = new BulkRequest();
    for (int i = 0; i < documentIds.length; i++) {
        IndexRequest indexRequest = new IndexRequest("posts")
                .id(documentIds[i])
                .source("content", contents[i], "timestamp", new Date());
        bulkRequest.add(indexRequest);
    }
    
    try {
        // ok: java-batch-write-output-ignored
        BulkResponse bulkResponse = client.bulk(bulkRequest, RequestOptions.DEFAULT);
        
        // Check for failures
        if (bulkResponse.hasFailures()) {
            // Process failures
            Arrays.stream(bulkResponse.getItems())
                  .filter(item -> item.isFailed())
                  .forEach(item -> {
                      System.err.println("Failed item: " + item.getId() + ", Error: " + item.getFailureMessage());
                  });
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    // Google Firestore - Properly checking for failed writes in batch
    Firestore db = null; // Assume initialized elsewhere
    
    String[] userIds = request.getParameter("userIds").split(",");
    String[] names = request.getParameter("names").split(",");
    
    WriteBatch batch = db.batch();
    
    for (int i = 0; i < userIds.length; i++) {
        batch.set(db.collection("users").document(userIds[i]), 
                  Map.of("name", names[i], "updatedAt", new Date()));
    }
    
    try {
        // ok: java-batch-write-output-ignored
        List<WriteResult> results = batch.commit().get();
        
        // Verify results
        if (results.size() != userIds.length) {
            System.err.println("Not all writes were successful. Expected: " + userIds.length + 
                               ", Actual: " + results.size());
        }
        
        // Process results
        for (WriteResult result : results) {
            System.out.println("Write timestamp: " + result.getUpdateTime());
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6(HttpServletRequest request) {
    // Redis Pipeline - Properly checking for failed operations
    Jedis jedis = new Jedis("localhost");
    
    String[] keys = request.getParameter("keys").split(",");
    String[] values = request.getParameter("values").split(",");
    
    Pipeline pipeline = jedis.pipelined();
    
    List<Response<String>> responses = new ArrayList<>();
    for (int i = 0; i < keys.length; i++) {
        responses.add(pipeline.set(keys[i], values[i]));
    }
    
    // ok: java-batch-write-output-ignored
    pipeline.sync();
    
    // Verify responses
    for (int i = 0; i < responses.size(); i++) {
        Response<String> response = responses.get(i);
        if (!"OK".equals(response.get())) {
            System.err.println("Failed to set key: " + keys[i]);
        }
    }
    
    jedis.close();
}

public void good_case_7(HttpServletRequest request) {
    // Cassandra Batch Statement - Properly checking for failed operations
    com.datastax.driver.core.Session session = null; // Assume initialized elsewhere
    
    String[] userIds = request.getParameter("userIds").split(",");
    String[] emails = request.getParameter("emails").split(",");
    
    BatchStatement batch = new BatchStatement();
    
    for (int i = 0; i < userIds.length; i++) {
        batch.add(session.prepare("INSERT INTO users (id, email) VALUES (?, ?)")
                .bind(userIds[i], emails[i]));
    }
    
    try {
        // ok: java-batch-write-output-ignored
        ResultSet results = session.execute(batch);
        
        // Verify execution
        if (!results.wasApplied()) {
            System.err.println("Batch was not applied successfully");
        }
        
        // Additional verification if needed
        if (results.getExecutionInfo().getWarnings() != null && !results.getExecutionInfo().getWarnings().isEmpty()) {
            for (String warning : results.getExecutionInfo().getWarnings()) {
                System.err.println("Warning: " + warning);
            }
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    // Couchbase Batch Operations - Properly checking for failed operations
    Bucket bucket = null; // Assume initialized elsewhere
    
    String[] documentIds = request.getParameter("documentIds").split(",");
    String[] contents = request.getParameter("contents").split(",");
    
    List<JsonDocument> documents = new ArrayList<>();
    for (int i = 0; i < documentIds.length; i++) {
        JsonObject content = JsonObject.create().put("content", contents[i]);
        documents.add(JsonDocument.create(documentIds[i], content));
    }
    
    // ok: java-batch-write-output-ignored
    List<JsonDocument> results = new ArrayList<>();
    List<String> failedIds = new ArrayList<>();
    
    for (JsonDocument doc : documents) {
        try {
            JsonDocument result = bucket.upsert(doc);
            results.add(result);
        } catch (Exception e) {
            failedIds.add(doc.id());
            System.err.println("Failed to upsert document: " + doc.id() + ", Error: " + e.getMessage());
        }
    }
    
    // Handle failed operations
    if (!failedIds.isEmpty()) {
        System.err.println("Failed to upsert " + failedIds.size() + " documents");
    }
}

public void good_case_9(HttpServletRequest request) {
    // HBase Batch Operations - Properly checking for failed operations
    BufferedMutator mutator = null; // Assume initialized elsewhere
    
    String[] rowKeys = request.getParameter("rowKeys").split(",");
    String[] values = request.getParameter("values").split(",");
    
    List<Mutation> mutations = new ArrayList<>();
    for (int i = 0; i < rowKeys.length; i++) {
        Put put = new Put(Bytes.toBytes(rowKeys[i]));
        put.addColumn(Bytes.toBytes("cf"), Bytes.toBytes("col"), Bytes.toBytes(values[i]));
        mutations.add(put);
    }
    
    try {
        // ok: java-batch-write-output-ignored
        mutator.mutate(mutations);
        
        // Implement custom callback to handle failures
        BufferedMutator.ExceptionListener listener = new BufferedMutator.ExceptionListener() {
            @Override
            public void onException(RetriesExhaustedWithDetailsException e, BufferedMutator mutator) {
                for (int i = 0; i < e.getNumExceptions(); i++) {
                    System.err.println("Failed mutation: " + e.getRow(i) + ", Error: " + e.getCause(i));
                }
            }
        };
        
        // Flush and check for errors
        mutator.flush();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    // Aerospike Batch Operations - Properly checking for failed operations
    AerospikeClient client = null; // Assume initialized elsewhere
    WritePolicy policy = new WritePolicy();
    
    String[] keys = request.getParameter("keys").split(",");
    String[] values = request.getParameter("values").split(",");
    
    // ok: java-batch-write-output-ignored
    List<String> failedKeys = new ArrayList<>();
    
    for (int i = 0; i < keys.length; i++) {
        try {
            Key key = new Key("namespace", "set", keys[i]);
            Bin bin = new Bin("value", values[i]);
            client.put(policy, key, bin);
        } catch (Exception e) {
            failedKeys.add(keys[i]);
            System.err.println("Failed to write key: " + keys[i] + ", Error: " + e.getMessage());
        }
    }
    
    // Handle failed operations
    if (!failedKeys.isEmpty()) {
        System.err.println("Failed to write " + failedKeys.size() + " keys");
    }
}

public void good_case_11(HttpServletRequest request) {
    // OrientDB Batch Operations - Properly checking for failed operations
    OrientDB orient = new OrientDB("embedded:/tmp/databases/", OrientDBConfig.defaultConfig());
    ODatabaseSession db = orient.open("test", "admin", "admin");
    
    String[] names = request.getParameter("names").split(",");
    String[] emails = request.getParameter("emails").split(",");
    
    db.begin();
    
    List<String> failedIndices = new ArrayList<>();
    
    try {
        for (int i = 0; i < names.length; i++) {
            try {
                OElement element = db.newElement("Person");
                element.setProperty("name", names[i]);
                element.setProperty("email", emails[i]);
                
                // ok: java-batch-write-output-ignored
                element.save();
            } catch (Exception e) {
                failedIndices.add(String.valueOf(i));
                System.err.println("Failed to save element at index " + i + ": " + e.getMessage());
            }
        }
        
        // Handle failed operations
        if (!failedIndices.isEmpty()) {
            System.err.println("Failed to save " + failedIndices.size() + " elements");
            // Decide whether to commit or rollback based on failure count
            if (failedIndices.size() > names.length / 2) {
                db.rollback();
                return;
            }
        }
        
        db.commit();
    } catch (Exception e) {
        db.rollback();
        e.printStackTrace();
    } finally {
        db.close();
        orient.close();
    }
}

public void good_case_12(HttpServletRequest request) {
    // AWS S3 Batch Operations - Properly checking for failed operations
    S3Client s3Client = S3Client.create();
    
    String bucketName = request.getParameter("bucketName");
    String[] objectKeys = request.getParameter("objectKeys").split(",");
    
    List<ObjectIdentifier> objectIds = new ArrayList<>();
    for (String key : objectKeys) {
        objectIds.add(ObjectIdentifier.builder().key(key).build());
    }
    
    DeleteObjectsRequest deleteRequest = DeleteObjectsRequest.builder()
            .bucket(bucketName)
            .delete(Delete.builder().objects(objectIds).build())
            .build();
    
    // ok: java-batch-write-output-ignored
    DeleteObjectsResponse response = s3Client.deleteObjects(deleteRequest);
    
    // Check for failed deletions
    if (response.hasDeleted() && response.hasErrors()) {
        System.out.println("Successfully deleted: " + response.deleted().size() + " objects");
        System.err.println("Failed to delete: " + response.errors().size() + " objects");
        
        // Process errors
        for (Error error : response.errors()) {
            System.err.println("Failed to delete: " + error.key() + ", Error: " + error.message());
        }
    }
}

public void good_case_13(HttpServletRequest request) {
    // Apache Ignite Batch Operations - Properly checking for failed operations
    Ignite ignite = null; // Assume initialized elsewhere
    IgniteCache<String, String> cache = ignite.getOrCreateCache("myCache");
    
    String[] keys = request.getParameter("keys").split(",");
    String[] values = request.getParameter("values").split(",");
    
    Map<String, String> entries = new HashMap<>();
    for (int i = 0; i < keys.length; i++) {
        entries.put(keys[i], values[i]);
    }
    
    try (org.apache.ignite.transactions.Transaction tx = ignite.transactions().txStart()) {
        // ok: java-batch-write-output-ignored
        cache.putAll(entries);
        
        // Verify all entries were written
        for (String key : entries.keySet()) {
            if (!cache.containsKey(key)) {
                throw new RuntimeException("Failed to write key: " + key);
            }
        }
        
        tx.commit();
    } catch (Exception e) {
        System.err.println("Failed to write batch: " + e.getMessage());
        // Transaction will be automatically rolled back
    }
}

public void good_case_14(HttpServletRequest request) {
    // Hazelcast Batch Operations - Properly checking for failed operations
    HazelcastInstance hazelcastInstance = null; // Assume initialized elsewhere
    IMap<String, String> map = hazelcastInstance.getMap("myMap");
    
    String[] keys = request.getParameter("keys").split(",");
    String[] values = request.getParameter("values").split(",");
    
    Map<String, String> entries = new HashMap<>();
    for (int i = 0; i < keys.length; i++) {
        entries.put(keys[i], values[i]);
    }
    
    // ok: java-batch-write-output-ignored
    map.putAll(entries);
    
    // Verify all entries were written
    List<String> failedKeys = entries.keySet().stream()
            .filter(key -> !map.containsKey(key) || !entries.get(key).equals(map.get(key)))
            .collect(Collectors.toList());
    
    if (!failedKeys.isEmpty()) {
        System.err.println("Failed to write " + failedKeys.size() + " keys");
        // Handle failed writes
    }
}

public void good_case_15(HttpServletRequest request) {
    // Infinispan Batch Operations - Properly checking for failed operations
    DefaultCacheManager cacheManager = null; // Assume initialized elsewhere
    Cache<String, String> cache = cacheManager.getCache();
    
    String[] keys = request.getParameter("keys").split(",");
    String[] values = request.getParameter("values").split(",");
    
    Map<String, String> entries = new HashMap<>();
    for (int i = 0; i < keys.length; i++) {
        entries.put(keys[i], values[i]);
    }
    
    // ok: java-batch-write-output-ignored
    CompletableFuture<Void> future = cache.putAllAsync(entries);
    
    try {
        // Wait for completion and check for errors
        future.get();
        
        // Verify all entries were written
        for (String key : entries.keySet()) {
            if (!cache.containsKey(key) || !entries.get(key).equals(cache.get(key))) {
                System.err.println("Failed to write key: " + key);
            }
        }
    } catch (Exception e) {
        System.err.println("Batch operation failed: " + e.getMessage());
    }
}