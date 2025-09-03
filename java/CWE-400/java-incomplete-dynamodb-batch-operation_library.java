import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.TableWriteItems;
import com.amazonaws.services.dynamodbv2.document.BatchWriteItemOutcome;
import com.amazonaws.services.dynamodbv2.model.*;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import software.amazon.awssdk.regions.Region;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.BatchWriteItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.WriteBatch;
import com.amazonaws.services.dynamodbv2.document.BatchGetItemOutcome;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.ItemCollection;
import com.amazonaws.services.dynamodbv2.document.Page;
import com.amazonaws.services.dynamodbv2.document.QueryOutcome;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.spec.QuerySpec;
import com.amazonaws.services.dynamodbv2.document.utils.ValueMap;
import com.amazonaws.services.dynamodbv2.document.spec.BatchGetItemSpec;
import com.amazonaws.services.dynamodbv2.document.TableKeysAndAttributes;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import software.amazon.awssdk.enhanced.dynamodb.model.BatchGetItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.ReadBatch;
import software.amazon.awssdk.enhanced.dynamodb.model.BatchGetResultPage;
import software.amazon.awssdk.enhanced.dynamodb.model.BatchGetResultPagePublisher;

import java.util.*;
import java.util.concurrent.TimeUnit;

// Security Issue: Incomplete DynamoDB Batch Operation Handling

// True Positive Examples (Vulnerable/Insecure Code)
public class DynamoDBBatchOperationExamples {

// {fact rule=resource-leak@v1.0 defects=1}
    public void bad_case_1() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        
        TableWriteItems items = new TableWriteItems("ProductCatalog")
            .withItemsToPut(
                new Item().withPrimaryKey("Id", 101).withString("Title", "Book 101 Title"),
                new Item().withPrimaryKey("Id", 102).withString("Title", "Book 102 Title"));
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        dynamoDB.batchWriteItem(items);
        
        // No handling of unprocessed items
    }

    public void bad_case_2() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        
        List<WriteRequest> writeRequests = new ArrayList<>();
        writeRequests.add(new WriteRequest().withPutRequest(
            new PutRequest().withItem(Map.of(
                "Id", new AttributeValue().withN("103"),
                "Title", new AttributeValue().withS("Book 103 Title")
            ))
        ));
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        requestItems.put("ProductCatalog", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest()
            .withRequestItems(requestItems);
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        client.batchWriteItem(batchWriteItemRequest);
        
        // No handling of unprocessed items
    }

    public void bad_case_3() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
            .region(Region.US_EAST_1)
            .build();
            
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("Id", AttributeValue.builder().n("104").build());
        item.put("Title", AttributeValue.builder().s("Book 104 Title").build());
        
        writeRequests.add(
            WriteRequest.builder()
                .putRequest(PutRequest.builder().item(item).build())
                .build()
        );
        
        requestItems.put("ProductCatalog", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = BatchWriteItemRequest.builder()
            .requestItems(requestItems)
            .build();
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        dynamoDbClient.batchWriteItem(batchWriteItemRequest);
        
        // No handling of unprocessed items
    }

    public void bad_case_4() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        List<Object> itemsToSave = Arrays.asList(
            new Product(105, "Book 105 Title"),
            new Product(106, "Book 106 Title")
        );
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        mapper.batchSave(itemsToSave);
        
        // No handling of failures
    }

    public void bad_case_5() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
            .region(Region.US_EAST_1)
            .build();
        DynamoDbEnhancedClient enhancedClient = DynamoDbEnhancedClient.builder()
            .dynamoDbClient(dynamoDbClient)
            .build();
            
        DynamoDbTable<Product> productTable = enhancedClient.table("ProductCatalog", 
            TableSchema.fromBean(Product.class));
            
        WriteBatch writeBatch = WriteBatch.builder(Product.class)
            .mappedTableResource(productTable)
            .addPutItem(new Product(107, "Book 107 Title"))
            .addPutItem(new Product(108, "Book 108 Title"))
            .build();
            
        BatchWriteItemEnhancedRequest batchWriteItemEnhancedRequest = 
            BatchWriteItemEnhancedRequest.builder()
                .writeBatches(writeBatch)
                .build();
                
        // ruleid: java-incomplete-dynamodb-batch-operation
        enhancedClient.batchWriteItem(batchWriteItemEnhancedRequest);
        
        // No handling of unprocessed items
    }

    public void bad_case_6() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        
        TableKeysAndAttributes tableKeysAndAttributes = new TableKeysAndAttributes("ProductCatalog");
        tableKeysAndAttributes.addHashOnlyPrimaryKeys("Id", 101, 102, 103);
        
        BatchGetItemSpec batchGetItemSpec = new BatchGetItemSpec()
            .withTableKeyAndAttributes(tableKeysAndAttributes);
            
        // ruleid: java-incomplete-dynamodb-batch-operation
        BatchGetItemOutcome outcome = dynamoDB.batchGetItem(batchGetItemSpec);
        
        // No handling of unprocessed keys
    }

    public void bad_case_7() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        KeysAndAttributes keysAndAttributes = new KeysAndAttributes();
        
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        Map<String, AttributeValue> key1 = new HashMap<>();
        key1.put("Id", new AttributeValue().withN("104"));
        keys.add(key1);
        
        Map<String, AttributeValue> key2 = new HashMap<>();
        key2.put("Id", new AttributeValue().withN("105"));
        keys.add(key2);
        
        keysAndAttributes.setKeys(keys);
        requestItems.put("ProductCatalog", keysAndAttributes);
        
        BatchGetItemRequest batchGetItemRequest = new BatchGetItemRequest()
            .withRequestItems(requestItems);
            
        // ruleid: java-incomplete-dynamodb-batch-operation
        client.batchGetItem(batchGetItemRequest);
        
        // No handling of unprocessed keys
    }

    public void bad_case_8() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
            .region(Region.US_EAST_1)
            .build();
            
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        
        Map<String, AttributeValue> key1 = new HashMap<>();
        key1.put("Id", AttributeValue.builder().n("106").build());
        keys.add(key1);
        
        KeysAndAttributes keysAndAttributes = KeysAndAttributes.builder()
            .keys(keys)
            .build();
            
        requestItems.put("ProductCatalog", keysAndAttributes);
        
        software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest batchGetItemRequest = 
            software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest.builder()
                .requestItems(requestItems)
                .build();
                
        // ruleid: java-incomplete-dynamodb-batch-operation
        dynamoDbClient.batchGetItem(batchGetItemRequest);
        
        // No handling of unprocessed keys
    }

    public void bad_case_9() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
            .region(Region.US_EAST_1)
            .build();
        DynamoDbEnhancedClient enhancedClient = DynamoDbEnhancedClient.builder()
            .dynamoDbClient(dynamoDbClient)
            .build();
            
        DynamoDbTable<Product> productTable = enhancedClient.table("ProductCatalog", 
            TableSchema.fromBean(Product.class));
            
        ReadBatch readBatch = ReadBatch.builder(Product.class)
            .mappedTableResource(productTable)
            .addGetItem(key -> key.partitionValue(107))
            .addGetItem(key -> key.partitionValue(108))
            .build();
            
        BatchGetItemEnhancedRequest batchGetItemEnhancedRequest = 
            BatchGetItemEnhancedRequest.builder()
                .readBatches(readBatch)
                .build();
                
        // ruleid: java-incomplete-dynamodb-batch-operation
        enhancedClient.batchGetItem(batchGetItemEnhancedRequest);
        
        // No handling of unprocessed keys
    }

    public void bad_case_10() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        List<Object> itemsToDelete = Arrays.asList(
            new Product(109, "Book 109 Title"),
            new Product(110, "Book 110 Title")
        );
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        mapper.batchDelete(itemsToDelete);
        
        // No handling of failures
    }

    public void bad_case_11() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        List<Object> keysToLoad = Arrays.asList(
            new Product(111, null),
            new Product(112, null)
        );
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        mapper.batchLoad(keysToLoad);
        
        // No handling of failures
    }

    public void bad_case_12() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        
        List<TableWriteItems> tableWriteItems = new ArrayList<>();
        tableWriteItems.add(new TableWriteItems("ProductCatalog")
            .withItemsToPut(
                new Item().withPrimaryKey("Id", 113).withString("Title", "Book 113 Title"),
                new Item().withPrimaryKey("Id", 114).withString("Title", "Book 114 Title")));
                
        tableWriteItems.add(new TableWriteItems("Orders")
            .withItemsToPut(
                new Item().withPrimaryKey("OrderId", "O1").withNumber("Total", 100),
                new Item().withPrimaryKey("OrderId", "O2").withNumber("Total", 200)));
                
        // ruleid: java-incomplete-dynamodb-batch-operation
        dynamoDB.batchWriteItemUnprocessed(tableWriteItems);
        
        // No handling of unprocessed items
    }

    public void bad_case_13() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        
        TableWriteItems items = new TableWriteItems("ProductCatalog")
            .withItemsToPut(
                new Item().withPrimaryKey("Id", 115).withString("Title", "Book 115 Title"),
                new Item().withPrimaryKey("Id", 116).withString("Title", "Book 116 Title"));
                
        BatchWriteItemOutcome outcome = dynamoDB.batchWriteItem(items);
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        if (!outcome.getUnprocessedItems().isEmpty()) {
            // Just log the error but don't retry
            System.out.println("Some items were not processed: " + outcome.getUnprocessedItems());
        }
    }

    public void bad_case_14() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
            .region(Region.US_EAST_1)
            .build();
            
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("Id", AttributeValue.builder().n("117").build());
        item.put("Title", AttributeValue.builder().s("Book 117 Title").build());
        
        writeRequests.add(
            WriteRequest.builder()
                .putRequest(PutRequest.builder().item(item).build())
                .build()
        );
        
        requestItems.put("ProductCatalog", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = BatchWriteItemRequest.builder()
            .requestItems(requestItems)
            .build();
            
        BatchWriteItemResponse response = dynamoDbClient.batchWriteItem(batchWriteItemRequest);
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        if (!response.unprocessedItems().isEmpty()) {
            // Just log the error but don't retry
            System.out.println("Some items were not processed: " + response.unprocessedItems());
        }
    }

    public void bad_case_15() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        KeysAndAttributes keysAndAttributes = new KeysAndAttributes();
        
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        Map<String, AttributeValue> key1 = new HashMap<>();
        key1.put("Id", new AttributeValue().withN("118"));
        keys.add(key1);
        
        keysAndAttributes.setKeys(keys);
        requestItems.put("ProductCatalog", keysAndAttributes);
        
        BatchGetItemRequest batchGetItemRequest = new BatchGetItemRequest()
            .withRequestItems(requestItems);
            
        BatchGetItemResult result = client.batchGetItem(batchGetItemRequest);
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        if (!result.getUnprocessedKeys().isEmpty()) {
            // Just log the error but don't retry
            System.out.println("Some keys were not processed: " + result.getUnprocessedKeys());
        }
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        
        TableWriteItems items = new TableWriteItems("ProductCatalog")
            .withItemsToPut(
                new Item().withPrimaryKey("Id", 201).withString("Title", "Book 201 Title"),
                new Item().withPrimaryKey("Id", 202).withString("Title", "Book 202 Title"));
        
        // ok: java-incomplete-dynamodb-batch-operation
        BatchWriteItemOutcome outcome = dynamoDB.batchWriteItem(items);
        
        // Process unprocessed items with retries
        Map<String, List<WriteRequest>> unprocessedItems = outcome.getUnprocessedItems();
        int retries = 0;
        while (!unprocessedItems.isEmpty() && retries < 5) {
            retries++;
            try {
                Thread.sleep(Math.min(100 * (int)Math.pow(2, retries), 1000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            outcome = dynamoDB.batchWriteItemUnprocessed(unprocessedItems);
            unprocessedItems = outcome.getUnprocessedItems();
        }
    }

    public void good_case_2() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        
        List<WriteRequest> writeRequests = new ArrayList<>();
        writeRequests.add(new WriteRequest().withPutRequest(
            new PutRequest().withItem(Map.of(
                "Id", new AttributeValue().withN("203"),
                "Title", new AttributeValue().withS("Book 203 Title")
            ))
        ));
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        requestItems.put("ProductCatalog", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest()
            .withRequestItems(requestItems);
        
        // ok: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = client.batchWriteItem(batchWriteItemRequest);
        
        // Process unprocessed items with retries
        Map<String, List<WriteRequest>> unprocessedItems = result.getUnprocessedItems();
        int retries = 0;
        while (!unprocessedItems.isEmpty() && retries < 5) {
            retries++;
            try {
                Thread.sleep(Math.min(100 * (int)Math.pow(2, retries), 1000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            result = client.batchWriteItem(new BatchWriteItemRequest().withRequestItems(unprocessedItems));
            unprocessedItems = result.getUnprocessedItems();
        }
    }

    public void good_case_3() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
            .region(Region.US_EAST_1)
            .build();
            
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("Id", AttributeValue.builder().n("204").build());
        item.put("Title", AttributeValue.builder().s("Book 204 Title").build());
        
        writeRequests.add(
            WriteRequest.builder()
                .putRequest(PutRequest.builder().item(item).build())
                .build()
        );
        
        requestItems.put("ProductCatalog", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = BatchWriteItemRequest.builder()
            .requestItems(requestItems)
            .build();
        
        // ok: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResponse response = dynamoDbClient.batchWriteItem(batchWriteItemRequest);
        
        // Process unprocessed items with retries
        Map<String, List<WriteRequest>> unprocessedItems = response.unprocessedItems();
        int retries = 0;
        while (!unprocessedItems.isEmpty() && retries < 5) {
            retries++;
            try {
                TimeUnit.MILLISECONDS.sleep(Math.min(100 * (int)Math.pow(2, retries), 1000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            response = dynamoDbClient.batchWriteItem(
                BatchWriteItemRequest.builder().requestItems(unprocessedItems).build());
            unprocessedItems = response.unprocessedItems();
        }
    }

    public void good_case_4() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        List<Object> itemsToSave = Arrays.asList(
            new Product(205, "Book 205 Title"),
            new Product(206, "Book 206 Title")
        );
        
        // ok: java-incomplete-dynamodb-batch-operation
        List<DynamoDBMapper.FailedBatch> failedBatches = mapper.batchSave(itemsToSave);
        
        // Handle failed batches
        if (!failedBatches.isEmpty()) {
            for (DynamoDBMapper.FailedBatch failedBatch : failedBatches) {
                System.err.println("Error: " + failedBatch.getException());
                List<Object> failedItems = new ArrayList<>();
                for (int i = failedBatch.getUnprocessedItems().size() - 1; i >= 0; i--) {
                    failedItems.add(itemsToSave.get(i + failedBatch.getUnprocessedItems().size()));
                }
                // Retry the failed items
                if (!failedItems.isEmpty()) {
                    List<DynamoDBMapper.FailedBatch> retryFailures = mapper.batchSave(failedItems);
                    // Continue handling retries as needed
                }
            }
        }
    }

    public void good_case_5() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
            .region(Region.US_EAST_1)
            .build();
        DynamoDbEnhancedClient enhancedClient = DynamoDbEnhancedClient.builder()
            .dynamoDbClient(dynamoDbClient)
            .build();
            
        DynamoDbTable<Product> productTable = enhancedClient.table("ProductCatalog", 
            TableSchema.fromBean(Product.class));
            
        WriteBatch writeBatch = WriteBatch.builder(Product.class)
            .mappedTableResource(productTable)
            .addPutItem(new Product(207, "Book 207 Title"))
            .addPutItem(new Product(208, "Book 208 Title"))
            .build();
            
        BatchWriteItemEnhancedRequest batchWriteItemEnhancedRequest = 
            BatchWriteItemEnhancedRequest.builder()
                .writeBatches(writeBatch)
                .build();
                
        // ok: java-incomplete-dynamodb-batch-operation
        software.amazon.awssdk.services.dynamodb.model.BatchWriteItemResponse response = 
            enhancedClient.batchWriteItem(batchWriteItemEnhancedRequest);
        
        // Process unprocessed items with retries
        Map<String, List<WriteRequest>> unprocessedItems = response.unprocessedItems();
        int retries = 0;
        while (!unprocessedItems.isEmpty() && retries < 5) {
            retries++;
            try {
                TimeUnit.MILLISECONDS.sleep(Math.min(100 * (int)Math.pow(2, retries), 1000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            
            // Create a new batch request with unprocessed items
            BatchWriteItemRequest retryRequest = BatchWriteItemRequest.builder()
                .requestItems(unprocessedItems)
                .build();
                
            response = dynamoDbClient.batchWriteItem(retryRequest);
            unprocessedItems = response.unprocessedItems();
        }
    }

    public void good_case_6() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        
        TableKeysAndAttributes tableKeysAndAttributes = new TableKeysAndAttributes("ProductCatalog");
        tableKeysAndAttributes.addHashOnlyPrimaryKeys("Id", 209, 210, 211);
        
        BatchGetItemSpec batchGetItemSpec = new BatchGetItemSpec()
            .withTableKeyAndAttributes(tableKeysAndAttributes);
            
        // ok: java-incomplete-dynamodb-batch-operation
        BatchGetItemOutcome outcome = dynamoDB.batchGetItem(batchGetItemSpec);
        
        // Process unprocessed keys with retries
        Map<String, KeysAndAttributes> unprocessedKeys = outcome.getUnprocessedKeys();
        int retries = 0;
        while (!unprocessedKeys.isEmpty() && retries < 5) {
            retries++;
            try {
                Thread.sleep(Math.min(100 * (int)Math.pow(2, retries), 1000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            BatchGetItemSpec retrySpec = new BatchGetItemSpec()
                .withRequestItems(unprocessedKeys);
            outcome = dynamoDB.batchGetItem(retrySpec);
            unprocessedKeys = outcome.getUnprocessedKeys();
        }
    }

    public void good_case_7() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        KeysAndAttributes keysAndAttributes = new KeysAndAttributes();
        
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        Map<String, AttributeValue> key1 = new HashMap<>();
        key1.put("Id", new AttributeValue().withN("212"));
        keys.add(key1);
        
        Map<String, AttributeValue> key2 = new HashMap<>();
        key2.put("Id", new AttributeValue().withN("213"));
        keys.add(key2);
        
        keysAndAttributes.setKeys(keys);
        requestItems.put("ProductCatalog", keysAndAttributes);
        
        BatchGetItemRequest batchGetItemRequest = new BatchGetItemRequest()
            .withRequestItems(requestItems);
            
        // ok: java-incomplete-dynamodb-batch-operation
        BatchGetItemResult result = client.batchGetItem(batchGetItemRequest);
        
        // Process unprocessed keys with retries
        Map<String, KeysAndAttributes> unprocessedKeys = result.getUnprocessedKeys();
        int retries = 0;
        while (!unprocessedKeys.isEmpty() && retries < 5) {
            retries++;
            try {
                Thread.sleep(Math.min(100 * (int)Math.pow(2, retries), 1000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            result = client.batchGetItem(new BatchGetItemRequest().withRequestItems(unprocessedKeys));
            unprocessedKeys = result.getUnprocessedKeys();
        }
    }

    public void good_case_8() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
            .region(Region.US_EAST_1)
            .build();
            
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        
        Map<String, AttributeValue> key1 = new HashMap<>();
        key1.put("Id", AttributeValue.builder().n("214").build());
        keys.add(key1);
        
        KeysAndAttributes keysAndAttributes = KeysAndAttributes.builder()
            .keys(keys)
            .build();
            
        requestItems.put("ProductCatalog", keysAndAttributes);
        
        software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest batchGetItemRequest = 
            software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest.builder()
                .requestItems(requestItems)
                .build();
                
        // ok: java-incomplete-dynamodb-batch-operation
        software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse response = 
            dynamoDbClient.batchGetItem(batchGetItemRequest);
        
        // Process unprocessed keys with retries
        Map<String, KeysAndAttributes> unprocessedKeys = response.unprocessedKeys();
        int retries = 0;
        while (!unprocessedKeys.isEmpty() && retries < 5) {
            retries++;
            try {
                TimeUnit.MILLISECONDS.sleep(Math.min(100 * (int)Math.pow(2, retries), 1000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            response = dynamoDbClient.batchGetItem(
                software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest.builder()
                    .requestItems(unprocessedKeys)
                    .build());
            unprocessedKeys = response.unprocessedKeys();
        }
    }

    public void good_case_9() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
            .region(Region.US_EAST_1)
            .build();
        DynamoDbEnhancedClient enhancedClient = DynamoDbEnhancedClient.builder()
            .dynamoDbClient(dynamoDbClient)
            .build();
            
        DynamoDbTable<Product> productTable = enhancedClient.table("ProductCatalog", 
            TableSchema.fromBean(Product.class));
            
        ReadBatch readBatch = ReadBatch.builder(Product.class)
            .mappedTableResource(productTable)
            .addGetItem(key -> key.partitionValue(215))
            .addGetItem(key -> key.partitionValue(216))
            .build();
            
        BatchGetItemEnhancedRequest batchGetItemEnhancedRequest = 
            BatchGetItemEnhancedRequest.builder()
                .readBatches(readBatch)
                .build();
                
        // ok: java-incomplete-dynamodb-batch-operation
        BatchGetResultPagePublisher resultPages = enhancedClient.batchGetItem(batchGetItemEnhancedRequest);
        
        // Process all result pages and handle unprocessed keys
        resultPages.subscribe(page -> {
            // Process the current page of results
            Map<String, KeysAndAttributes> unprocessedKeys = page.unprocessedKeysForTable(productTable);
            
            if (!unprocessedKeys.isEmpty()) {
                // Retry the unprocessed keys
                int retries = 0;
                Map<String, KeysAndAttributes> currentUnprocessedKeys = unprocessedKeys;
                
                while (!currentUnprocessedKeys.isEmpty() && retries < 5) {
                    retries++;
                    try {
                        TimeUnit.MILLISECONDS.sleep(Math.min(100 * (int)Math.pow(2, retries), 1000));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    
                    software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse response = 
                        dynamoDbClient.batchGetItem(
                            software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest.builder()
                                .requestItems(currentUnprocessedKeys)
                                .build());
                    currentUnprocessedKeys = response.unprocessedKeys();
                }
            }
        });
    }

    public void good_case_10() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        List<Object> itemsToDelete = Arrays.asList(
            new Product(217, "Book 217 Title"),
            new Product(218, "Book 218 Title")
        );
        
        // ok: java-incomplete-dynamodb-batch-operation
        List<DynamoDBMapper.FailedBatch> failedBatches = mapper.batchDelete(itemsToDelete);
        
        // Handle failed batches
        if (!failedBatches.isEmpty()) {
            for (DynamoDBMapper.FailedBatch failedBatch : failedBatches) {
                System.err.println("Error: " + failedBatch.getException());
                List<Object> failedItems = new ArrayList<>();
                for (int i = failedBatch.getUnprocessedItems().size() - 1; i >= 0; i--) {
                    failedItems.add(itemsToDelete.get(i + failedBatch.getUnprocessedItems().size()));
                }
                // Retry the failed items
                if (!failedItems.isEmpty()) {
                    List<DynamoDBMapper.FailedBatch> retryFailures = mapper.batchDelete(failedItems);
                    // Continue handling retries as needed
                }
            }
        }
    }

    public void good_case_11() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDBMapper mapper = new DynamoDBMapper(client);
        
        List<Object> keysToLoad = Arrays.asList(
            new Product(219, null),
            new Product(220, null)
        );
        
        // ok: java-incomplete-dynamodb-batch-operation
        Map<String, List<Object>> batchResults = mapper.batchLoad(keysToLoad);
        
        // Check if all items were loaded successfully
        if (batchResults.isEmpty() || batchResults.values().stream().mapToInt(List::size).sum() < keysToLoad.size()) {
            // Some items were not loaded, retry with exponential backoff
            int retries = 0;
            while (retries < 5) {
                retries++;
                try {
                    Thread.sleep(Math.min(100 * (int)Math.pow(2, retries), 1000));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                
                // Create a list of keys that were not loaded
                List<Object> unloadedKeys = new ArrayList<>();
                for (Object key : keysToLoad) {
                    boolean found = false;
                    for (List<Object> loadedItems : batchResults.values()) {
                        for (Object loadedItem : loadedItems) {
                            if (((Product)loadedItem).getId() == ((Product)key).getId()) {
                                found = true;
                                break;
                            }
                        }
                        if (found) break;
                    }
                    if (!found) {
                        unloadedKeys.add(key);
                    }
                }
                
                if (unloadedKeys.isEmpty()) {
                    break;
                }
                
                // Retry loading the unloaded keys
                Map<String, List<Object>> retryResults = mapper.batchLoad(unloadedKeys);
                batchResults.putAll(retryResults);
            }
        }
    }

    public void good_case_12() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        
        List<TableWriteItems> tableWriteItems = new ArrayList<>();
        tableWriteItems.add(new TableWriteItems("ProductCatalog")
            .withItemsToPut(
                new Item().withPrimaryKey("Id", 221).withString("Title", "Book 221 Title"),
                new Item().withPrimaryKey("Id", 222).withString("Title", "Book 222 Title")));
                
        tableWriteItems.add(new TableWriteItems("Orders")
            .withItemsToPut(
                new Item().withPrimaryKey("OrderId", "O3").withNumber("Total", 300),
                new Item().withPrimaryKey("OrderId", "O4").withNumber("Total", 400)));
                
        // ok: java-incomplete-dynamodb-batch-operation
        List<BatchWriteItemOutcome> outcomes = new ArrayList<>();
        Map<String, List<WriteRequest>> unprocessedItems = dynamoDB.batchWriteItemUnprocessed(tableWriteItems);
        
        // Process unprocessed items with retries
        int retries = 0;
        while (!unprocessedItems.isEmpty() && retries < 5) {
            retries++;
            try {
                Thread.sleep(Math.min(100 * (int)Math.pow(2, retries), 1000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            BatchWriteItemOutcome outcome = dynamoDB.batchWriteItemUnprocessed(unprocessedItems);
            outcomes.add(outcome);
            unprocessedItems = outcome.getUnprocessedItems();
        }
    }

    public void good_case_13() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        DynamoDB dynamoDB = new DynamoDB(client);
        
        TableWriteItems items = new TableWriteItems("ProductCatalog")
            .withItemsToPut(
                new Item().withPrimaryKey("Id", 223).withString("Title", "Book 223 Title"),
                new Item().withPrimaryKey("Id", 224).withString("Title", "Book 224 Title"));
                
        // ok: java-incomplete-dynamodb-batch-operation
        BatchWriteItemOutcome outcome = dynamoDB.batchWriteItem(items);
        
        // Process unprocessed items with exponential backoff
        Map<String, List<WriteRequest>> unprocessedItems = outcome.getUnprocessedItems();
        int maxRetries = 5;
        int retries = 0;
        
        while (!unprocessedItems.isEmpty() && retries < maxRetries) {
            retries++;
            try {
                // Exponential backoff with jitter
                long delay = (long) (Math.min(100 * Math.pow(2, retries), 1000) * (0.5 + Math.random() * 0.5));
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            
            System.out.println("Retrying " + unprocessedItems.size() + " unprocessed items, attempt " + retries);
            outcome = dynamoDB.batchWriteItemUnprocessed(unprocessedItems);
            unprocessedItems = outcome.getUnprocessedItems();
        }
        
        if (!unprocessedItems.isEmpty()) {
            System.err.println("Failed to process all items after " + maxRetries + " retries");
            // Consider additional error handling or alerting
        }
    }

    public void good_case_14() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
            .region(Region.US_EAST_1)
            .build();
            
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("Id", AttributeValue.builder().n("225").build());
        item.put("Title", AttributeValue.builder().s("Book 225 Title").build());
        
        writeRequests.add(
            WriteRequest.builder()
                .putRequest(PutRequest.builder().item(item).build())
                .build()
        );
        
        requestItems.put("ProductCatalog", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = BatchWriteItemRequest.builder()
            .requestItems(requestItems)
            .build();
            
        // ok: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResponse response = dynamoDbClient.batchWriteItem(batchWriteItemRequest);
        
        // Process unprocessed items with custom retry policy
        Map<String, List<WriteRequest>> unprocessedItems = response.unprocessedItems();
        int maxRetries = 10;
        int retries = 0;
        
        while (!unprocessedItems.isEmpty() && retries < maxRetries) {
            retries++;
            
            // Calculate backoff time with jitter
            long baseDelay = 50;
            long maxDelay = 1000;
            long delay = Math.min(baseDelay * (1L << retries), maxDelay);
            delay = (long)(delay * (0.5 + Math.random() * 0.5)); // Add jitter
            
            try {
                TimeUnit.MILLISECONDS.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            
            System.out.println("Retrying " + unprocessedItems.size() + " unprocessed items, attempt " + retries);
            response = dynamoDbClient.batchWriteItem(
                BatchWriteItemRequest.builder().requestItems(unprocessedItems).build());
            unprocessedItems = response.unprocessedItems();
        }
        
        if (!unprocessedItems.isEmpty()) {
            System.err.println("Failed to process all items after " + maxRetries + " retries");
            // Consider additional error handling or alerting
        }
    }

    public void good_case_15() {
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        KeysAndAttributes keysAndAttributes = new KeysAndAttributes();
        
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        Map<String, AttributeValue> key1 = new HashMap<>();
        key1.put("Id", new AttributeValue().withN("226"));
        keys.add(key1);
        
        keysAndAttributes.setKeys(keys);
        requestItems.put("ProductCatalog", keysAndAttributes);
        
        BatchGetItemRequest batchGetItemRequest = new BatchGetItemRequest()
            .withRequestItems(requestItems);
            
        // ok: java-incomplete-dynamodb-batch-operation
        BatchGetItemResult result = client.batchGetItem(batchGetItemRequest);
        
        // Process unprocessed keys with adaptive retry strategy
        Map<String, KeysAndAttributes> unprocessedKeys = result.getUnprocessedKeys();
        int maxRetries = 8;
        int retries = 0;
        
        while (!unprocessedKeys.isEmpty() && retries < maxRetries) {
            retries++;
            
            // Adaptive backoff based on number of unprocessed keys
            long baseDelay = 50;
            long maxDelay = 2000;
            double scaleFactor = 1.0 + (unprocessedKeys.values().stream()
                .mapToInt(ka -> ka.getKeys().size()).sum() / 10.0);
            long delay = Math.min((long)(baseDelay * Math.pow(2, retries) * scaleFactor), maxDelay);
            
            try {
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            
            System.out.println("Retrying " + unprocessedKeys.size() + " unprocessed keys, attempt " + retries);
            result = client.batchGetItem(new BatchGetItemRequest().withRequestItems(unprocessedKeys));
            
            // Process the results from this retry
            Map<String, List<Map<String, AttributeValue>>> items = result.getResponses();
            for (Map.Entry<String, List<Map<String, AttributeValue>>> entry : items.entrySet()) {
                System.out.println("Retrieved " + entry.getValue().size() + " items from table " + entry.getKey());
            }
            
            unprocessedKeys = result.getUnprocessedKeys();
        }
        
        if (!unprocessedKeys.isEmpty()) {
            System.err.println("Failed to retrieve all items after " + maxRetries + " retries");
            // Consider additional error handling or alerting
        }
    }

    // Product class for examples
    static class Product {
        private int id;
        private String title;
        
        public Product() {}
        
        public Product(int id, String title) {
            this.id = id;
            this.title = title;
        }
        
        public int getId() {
            return id;
        }
        
        public void setId(int id) {
            this.id = id;
        }
        
        public String getTitle() {
            return title;
        }
        
        public void setTitle(String title) {
            this.title = title;
        }
    }
}
// {/fact}