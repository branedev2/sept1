import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.BatchGetItemRequest;
import com.amazonaws.services.dynamodbv2.model.BatchGetItemResult;
import com.amazonaws.services.dynamodbv2.model.BatchWriteItemRequest;
import com.amazonaws.services.dynamodbv2.model.BatchWriteItemResult;
import com.amazonaws.services.dynamodbv2.model.DeleteRequest;
import com.amazonaws.services.dynamodbv2.model.KeysAndAttributes;
import com.amazonaws.services.dynamodbv2.model.PutRequest;
import com.amazonaws.services.dynamodbv2.model.WriteRequest;

public class DynamoDBBatchOperationExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=resource-leak@v1.0 defects=1}
    public void bad_case_1() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        // Create some write requests
        Map<String, AttributeValue> item1 = new HashMap<>();
        item1.put("id", new AttributeValue("1"));
        item1.put("data", new AttributeValue("value1"));
        
        Map<String, AttributeValue> item2 = new HashMap<>();
        item2.put("id", new AttributeValue("2"));
        item2.put("data", new AttributeValue("value2"));
        
        writeRequests.add(new WriteRequest(new PutRequest(item1)));
        writeRequests.add(new WriteRequest(new PutRequest(item2)));
        
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        // No check for unprocessed items
    }

    public void bad_case_2() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        Map<String, AttributeValue> key1 = new HashMap<>();
        key1.put("id", new AttributeValue("1"));
        keys.add(key1);
        
        requestItems.put("MyTable", new KeysAndAttributes().withKeys(keys));
        
        BatchGetItemRequest batchGetItemRequest = new BatchGetItemRequest(requestItems);
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        BatchGetItemResult result = dynamoDB.batchGetItem(batchGetItemRequest);
        // No handling of unprocessed keys
    }

    public void bad_case_3() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        for (int i = 0; i < 30; i++) {
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("id", new AttributeValue(String.valueOf(i)));
            item.put("data", new AttributeValue("value" + i));
            writeRequests.add(new WriteRequest(new PutRequest(item)));
        }
        
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        try {
            // ruleid: java-incomplete-dynamodb-batch-operation
            BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
            System.out.println("Batch write completed");
            // No check for unprocessed items, even in try-catch block
        } catch (Exception e) {
            System.err.println("Error in batch write: " + e.getMessage());
        }
    }

    public void bad_case_4() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Create batch delete requests
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        for (String id : Arrays.asList("1", "2", "3", "4", "5")) {
            Map<String, AttributeValue> key = new HashMap<>();
            key.put("id", new AttributeValue(id));
            writeRequests.add(new WriteRequest(new DeleteRequest(key)));
        }
        
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        
        // Checking if result exists but not checking unprocessed items
        if (result != null) {
            System.out.println("Batch delete operation completed");
        }
    }

    public void bad_case_5() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            Map<String, AttributeValue> key = new HashMap<>();
            key.put("id", new AttributeValue(String.valueOf(i)));
            keys.add(key);
        }
        
        requestItems.put("MyTable", new KeysAndAttributes().withKeys(keys));
        
        BatchGetItemRequest batchGetItemRequest = new BatchGetItemRequest(requestItems);
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        BatchGetItemResult result = dynamoDB.batchGetItem(batchGetItemRequest);
        
        // Only processing the returned items, not handling unprocessed keys
        Map<String, List<Map<String, AttributeValue>>> responses = result.getResponses();
        for (String tableName : responses.keySet()) {
            List<Map<String, AttributeValue>> items = responses.get(tableName);
            for (Map<String, AttributeValue> item : items) {
                System.out.println("Item: " + item);
            }
        }
    }

    public void bad_case_6() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Multiple tables in one batch request
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        
        // Table 1
        List<WriteRequest> writeRequestsTable1 = new ArrayList<>();
        Map<String, AttributeValue> item1 = new HashMap<>();
        item1.put("id", new AttributeValue("1"));
        writeRequestsTable1.add(new WriteRequest(new PutRequest(item1)));
        requestItems.put("Table1", writeRequestsTable1);
        
        // Table 2
        List<WriteRequest> writeRequestsTable2 = new ArrayList<>();
        Map<String, AttributeValue> item2 = new HashMap<>();
        item2.put("id", new AttributeValue("2"));
        writeRequestsTable2.add(new WriteRequest(new PutRequest(item2)));
        requestItems.put("Table2", writeRequestsTable2);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        // No check for unprocessed items across multiple tables
    }

    public void bad_case_7() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Create a method that performs batch operations but doesn't handle unprocessed items
        Map<String, List<WriteRequest>> requestItems = createBatchWriteRequests();
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        
        // Only logging the result without checking unprocessed items
        System.out.println("Batch operation completed with result: " + result);
    }

    public void bad_case_8() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        Map<String, AttributeValue> key1 = new HashMap<>();
        key1.put("id", new AttributeValue("1"));
        keys.add(key1);
        
        requestItems.put("MyTable", new KeysAndAttributes().withKeys(keys));
        
        BatchGetItemRequest batchGetItemRequest = new BatchGetItemRequest(requestItems);
        
        // Checking unprocessed keys but not retrying
        // ruleid: java-incomplete-dynamodb-batch-operation
        BatchGetItemResult result = dynamoDB.batchGetItem(batchGetItemRequest);
        
        Map<String, KeysAndAttributes> unprocessedKeys = result.getUnprocessedKeys();
        if (!unprocessedKeys.isEmpty()) {
            System.out.println("There are unprocessed keys: " + unprocessedKeys);
            // Just logging, but not retrying
        }
    }

    public void bad_case_9() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Create batch write requests
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        for (int i = 0; i < 25; i++) {
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("id", new AttributeValue(String.valueOf(i)));
            writeRequests.add(new WriteRequest(new PutRequest(item)));
        }
        
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        
        // Only checking if unprocessed items exist, but not handling them
        if (!result.getUnprocessedItems().isEmpty()) {
            System.err.println("Warning: Some items were not processed");
        }
    }

    public void bad_case_10() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Create batch get request
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            Map<String, AttributeValue> key = new HashMap<>();
            key.put("id", new AttributeValue(String.valueOf(i)));
            keys.add(key);
        }
        
        requestItems.put("MyTable", new KeysAndAttributes().withKeys(keys));
        
        BatchGetItemRequest batchGetItemRequest = new BatchGetItemRequest(requestItems);
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        try {
            BatchGetItemResult result = dynamoDB.batchGetItem(batchGetItemRequest);
            // Processing results but not handling unprocessed keys
            Map<String, List<Map<String, AttributeValue>>> responses = result.getResponses();
            System.out.println("Retrieved " + responses.size() + " items");
        } catch (Exception e) {
            System.err.println("Error in batch get: " + e.getMessage());
        }
    }

    public void bad_case_11() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Create a complex batch write with mixed operations
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        // Add some put requests
        Map<String, AttributeValue> item1 = new HashMap<>();
        item1.put("id", new AttributeValue("1"));
        writeRequests.add(new WriteRequest(new PutRequest(item1)));
        
        // Add some delete requests
        Map<String, AttributeValue> key1 = new HashMap<>();
        key1.put("id", new AttributeValue("2"));
        writeRequests.add(new WriteRequest(new DeleteRequest(key1)));
        
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        // No handling of unprocessed items for mixed operation types
    }

    public void bad_case_12() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Create batch requests with pagination
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        for (int i = 0; i < 100; i++) {  // Large number of items
            Map<String, AttributeValue> key = new HashMap<>();
            key.put("id", new AttributeValue(String.valueOf(i)));
            keys.add(key);
        }
        
        requestItems.put("MyTable", new KeysAndAttributes().withKeys(keys));
        
        BatchGetItemRequest batchGetItemRequest = new BatchGetItemRequest(requestItems);
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        BatchGetItemResult result = dynamoDB.batchGetItem(batchGetItemRequest);
        
        // Only processing the first page of results
        Map<String, List<Map<String, AttributeValue>>> responses = result.getResponses();
        System.out.println("Retrieved items: " + responses);
        // Not handling unprocessed keys or pagination
    }

    public void bad_case_13() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Batch operation with conditional checks (which can lead to unprocessed items)
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        for (int i = 0; i < 10; i++) {
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("id", new AttributeValue(String.valueOf(i)));
            item.put("data", new AttributeValue("value" + i));
            writeRequests.add(new WriteRequest(new PutRequest(item)));
        }
        
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        // ruleid: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        
        // Incorrect handling - only checking size but not retrying
        if (result.getUnprocessedItems().size() > 0) {
            System.out.println("Some items were not processed due to conditional check failures");
        }
    }

    public void bad_case_14() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Batch operation inside a transaction
        try {
            // First operation
            Map<String, List<WriteRequest>> requestItems1 = new HashMap<>();
            List<WriteRequest> writeRequests1 = new ArrayList<>();
            Map<String, AttributeValue> item1 = new HashMap<>();
            item1.put("id", new AttributeValue("1"));
            writeRequests1.add(new WriteRequest(new PutRequest(item1)));
            requestItems1.put("MyTable", writeRequests1);
            
            // ruleid: java-incomplete-dynamodb-batch-operation
            BatchWriteItemResult result1 = dynamoDB.batchWriteItem(requestItems1);
            
            // Second operation
            Map<String, List<WriteRequest>> requestItems2 = new HashMap<>();
            List<WriteRequest> writeRequests2 = new ArrayList<>();
            Map<String, AttributeValue> item2 = new HashMap<>();
            item2.put("id", new AttributeValue("2"));
            writeRequests2.add(new WriteRequest(new PutRequest(item2)));
            requestItems2.put("MyTable", writeRequests2);
            
            // ruleid: java-incomplete-dynamodb-batch-operation
            BatchWriteItemResult result2 = dynamoDB.batchWriteItem(requestItems2);
            
            // No handling of unprocessed items for either operation
            
        } catch (Exception e) {
            System.err.println("Transaction failed: " + e.getMessage());
        }
    }

    public void bad_case_15() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Batch operation with custom retry logic that doesn't actually retry
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("id", new AttributeValue("1"));
        writeRequests.add(new WriteRequest(new PutRequest(item)));
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        int maxRetries = 3;
        int retryCount = 0;
        
        while (retryCount < maxRetries) {
            // ruleid: java-incomplete-dynamodb-batch-operation
            BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
            
            // Incorrect retry logic - incrementing counter but not actually retrying unprocessed items
            retryCount++;
            
            if (result.getUnprocessedItems().isEmpty()) {
                break;
            }
            
            // No actual retry of unprocessed items, just incrementing counter
            System.out.println("Retry " + retryCount + " of " + maxRetries);
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        Map<String, AttributeValue> item1 = new HashMap<>();
        item1.put("id", new AttributeValue("1"));
        item1.put("data", new AttributeValue("value1"));
        
        Map<String, AttributeValue> item2 = new HashMap<>();
        item2.put("id", new AttributeValue("2"));
        item2.put("data", new AttributeValue("value2"));
        
        writeRequests.add(new WriteRequest(new PutRequest(item1)));
        writeRequests.add(new WriteRequest(new PutRequest(item2)));
        
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        // ok: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        Map<String, List<WriteRequest>> unprocessedItems = result.getUnprocessedItems();
        
        // Retry unprocessed items
        while (!unprocessedItems.isEmpty()) {
            BatchWriteItemRequest retryRequest = new BatchWriteItemRequest(unprocessedItems);
            result = dynamoDB.batchWriteItem(retryRequest);
            unprocessedItems = result.getUnprocessedItems();
        }
    }

    public void good_case_2() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        Map<String, AttributeValue> key1 = new HashMap<>();
        key1.put("id", new AttributeValue("1"));
        keys.add(key1);
        
        requestItems.put("MyTable", new KeysAndAttributes().withKeys(keys));
        
        BatchGetItemRequest batchGetItemRequest = new BatchGetItemRequest(requestItems);
        
        // ok: java-incomplete-dynamodb-batch-operation
        BatchGetItemResult result = dynamoDB.batchGetItem(batchGetItemRequest);
        Map<String, KeysAndAttributes> unprocessedKeys = result.getUnprocessedKeys();
        
        // Retry unprocessed keys
        while (!unprocessedKeys.isEmpty()) {
            BatchGetItemRequest retryRequest = new BatchGetItemRequest(unprocessedKeys);
            result = dynamoDB.batchGetItem(retryRequest);
            unprocessedKeys = result.getUnprocessedKeys();
        }
    }

    public void good_case_3() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        for (int i = 0; i < 30; i++) {
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("id", new AttributeValue(String.valueOf(i)));
            item.put("data", new AttributeValue("value" + i));
            writeRequests.add(new WriteRequest(new PutRequest(item)));
        }
        
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        try {
            // ok: java-incomplete-dynamodb-batch-operation
            BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
            Map<String, List<WriteRequest>> unprocessedItems = result.getUnprocessedItems();
            
            // Retry with exponential backoff
            int retries = 0;
            int maxRetries = 5;
            while (!unprocessedItems.isEmpty() && retries < maxRetries) {
                retries++;
                // Exponential backoff
                try {
                    Thread.sleep((long) Math.pow(2, retries) * 100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                
                BatchWriteItemRequest retryRequest = new BatchWriteItemRequest(unprocessedItems);
                result = dynamoDB.batchWriteItem(retryRequest);
                unprocessedItems = result.getUnprocessedItems();
            }
        } catch (Exception e) {
            System.err.println("Error in batch write: " + e.getMessage());
        }
    }

    public void good_case_4() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Create batch delete requests
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        for (String id : Arrays.asList("1", "2", "3", "4", "5")) {
            Map<String, AttributeValue> key = new HashMap<>();
            key.put("id", new AttributeValue(id));
            writeRequests.add(new WriteRequest(new DeleteRequest(key)));
        }
        
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        // ok: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        
        // Process and retry unprocessed items
        Map<String, List<WriteRequest>> unprocessedItems = result.getUnprocessedItems();
        if (!unprocessedItems.isEmpty()) {
            System.out.println("Retrying unprocessed items");
            BatchWriteItemRequest retryRequest = new BatchWriteItemRequest(unprocessedItems);
            result = dynamoDB.batchWriteItem(retryRequest);
            // Continue retrying if needed
        }
    }

    public void good_case_5() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            Map<String, AttributeValue> key = new HashMap<>();
            key.put("id", new AttributeValue(String.valueOf(i)));
            keys.add(key);
        }
        
        requestItems.put("MyTable", new KeysAndAttributes().withKeys(keys));
        
        BatchGetItemRequest batchGetItemRequest = new BatchGetItemRequest(requestItems);
        
        // ok: java-incomplete-dynamodb-batch-operation
        BatchGetItemResult result = dynamoDB.batchGetItem(batchGetItemRequest);
        
        // Process returned items
        Map<String, List<Map<String, AttributeValue>>> responses = result.getResponses();
        for (String tableName : responses.keySet()) {
            List<Map<String, AttributeValue>> items = responses.get(tableName);
            for (Map<String, AttributeValue> item : items) {
                System.out.println("Item: " + item);
            }
        }
        
        // Handle unprocessed keys
        Map<String, KeysAndAttributes> unprocessedKeys = result.getUnprocessedKeys();
        while (!unprocessedKeys.isEmpty()) {
            BatchGetItemRequest retryRequest = new BatchGetItemRequest(unprocessedKeys);
            result = dynamoDB.batchGetItem(retryRequest);
            
            // Process newly returned items
            responses = result.getResponses();
            for (String tableName : responses.keySet()) {
                List<Map<String, AttributeValue>> items = responses.get(tableName);
                for (Map<String, AttributeValue> item : items) {
                    System.out.println("Item from retry: " + item);
                }
            }
            
            unprocessedKeys = result.getUnprocessedKeys();
        }
    }

    public void good_case_6() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Multiple tables in one batch request
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        
        // Table 1
        List<WriteRequest> writeRequestsTable1 = new ArrayList<>();
        Map<String, AttributeValue> item1 = new HashMap<>();
        item1.put("id", new AttributeValue("1"));
        writeRequestsTable1.add(new WriteRequest(new PutRequest(item1)));
        requestItems.put("Table1", writeRequestsTable1);
        
        // Table 2
        List<WriteRequest> writeRequestsTable2 = new ArrayList<>();
        Map<String, AttributeValue> item2 = new HashMap<>();
        item2.put("id", new AttributeValue("2"));
        writeRequestsTable2.add(new WriteRequest(new PutRequest(item2)));
        requestItems.put("Table2", writeRequestsTable2);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        // ok: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        Map<String, List<WriteRequest>> unprocessedItems = result.getUnprocessedItems();
        
        // Retry unprocessed items across multiple tables
        int maxRetries = 3;
        int retryCount = 0;
        
        while (!unprocessedItems.isEmpty() && retryCount < maxRetries) {
            retryCount++;
            try {
                Thread.sleep(1000 * retryCount); // Backoff strategy
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            BatchWriteItemRequest retryRequest = new BatchWriteItemRequest(unprocessedItems);
            result = dynamoDB.batchWriteItem(retryRequest);
            unprocessedItems = result.getUnprocessedItems();
        }
        
        // Check if there are still unprocessed items after max retries
        if (!unprocessedItems.isEmpty()) {
            System.err.println("Failed to process all items after " + maxRetries + " retries");
        }
    }

    public void good_case_7() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Create a method that performs batch operations and properly handles unprocessed items
        Map<String, List<WriteRequest>> requestItems = createBatchWriteRequests();
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        // ok: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        Map<String, List<WriteRequest>> unprocessedItems = result.getUnprocessedItems();
        
        // Implement a retry mechanism with timeout
        long startTime = System.currentTimeMillis();
        long timeout = 30000; // 30 seconds timeout
        
        while (!unprocessedItems.isEmpty() && System.currentTimeMillis() - startTime < timeout) {
            try {
                Thread.sleep(500); // Wait before retry
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            BatchWriteItemRequest retryRequest = new BatchWriteItemRequest(unprocessedItems);
            result = dynamoDB.batchWriteItem(retryRequest);
            unprocessedItems = result.getUnprocessedItems();
        }
        
        if (!unprocessedItems.isEmpty()) {
            System.err.println("Could not process all items within timeout period");
        }
    }

    public void good_case_8() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        Map<String, AttributeValue> key1 = new HashMap<>();
        key1.put("id", new AttributeValue("1"));
        keys.add(key1);
        
        requestItems.put("MyTable", new KeysAndAttributes().withKeys(keys));
        
        BatchGetItemRequest batchGetItemRequest = new BatchGetItemRequest(requestItems);
        
        // ok: java-incomplete-dynamodb-batch-operation
        BatchGetItemResult result = dynamoDB.batchGetItem(batchGetItemRequest);
        
        // Properly handling unprocessed keys with retry
        Map<String, KeysAndAttributes> unprocessedKeys = result.getUnprocessedKeys();
        if (!unprocessedKeys.isEmpty()) {
            System.out.println("Retrying unprocessed keys: " + unprocessedKeys);
            
            // Retry with backoff
            int retryCount = 0;
            int maxRetries = 5;
            while (!unprocessedKeys.isEmpty() && retryCount < maxRetries) {
                retryCount++;
                try {
                    TimeUnit.MILLISECONDS.sleep(50 * retryCount);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                
                BatchGetItemRequest retryRequest = new BatchGetItemRequest(unprocessedKeys);
                result = dynamoDB.batchGetItem(retryRequest);
                unprocessedKeys = result.getUnprocessedKeys();
            }
        }
    }

    public void good_case_9() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Create batch write requests
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        for (int i = 0; i < 25; i++) {
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("id", new AttributeValue(String.valueOf(i)));
            writeRequests.add(new WriteRequest(new PutRequest(item)));
        }
        
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        // ok: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        
        // Properly handling unprocessed items with a custom retry function
        retryUnprocessedItems(dynamoDB, result.getUnprocessedItems());
    }

    // Helper method for good_case_9
    private void retryUnprocessedItems(AmazonDynamoDB dynamoDB, Map<String, List<WriteRequest>> unprocessedItems) {
        int maxRetries = 10;
        int retries = 0;
        
        while (!unprocessedItems.isEmpty() && retries < maxRetries) {
            retries++;
            try {
                Thread.sleep(100 * retries); // Increasing backoff
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            BatchWriteItemRequest retryRequest = new BatchWriteItemRequest(unprocessedItems);
            BatchWriteItemResult result = dynamoDB.batchWriteItem(retryRequest);
            unprocessedItems = result.getUnprocessedItems();
        }
        
        if (!unprocessedItems.isEmpty()) {
            System.err.println("Failed to process all items after " + maxRetries + " retries");
            // Additional error handling or logging
        }
    }

    public void good_case_10() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Create batch get request
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            Map<String, AttributeValue> key = new HashMap<>();
            key.put("id", new AttributeValue(String.valueOf(i)));
            keys.add(key);
        }
        
        requestItems.put("MyTable", new KeysAndAttributes().withKeys(keys));
        
        BatchGetItemRequest batchGetItemRequest = new BatchGetItemRequest(requestItems);
        
        // ok: java-incomplete-dynamodb-batch-operation
        try {
            BatchGetItemResult result = dynamoDB.batchGetItem(batchGetItemRequest);
            
            // Process results
            Map<String, List<Map<String, AttributeValue>>> responses = result.getResponses();
            System.out.println("Retrieved " + responses.size() + " items");
            
            // Handle unprocessed keys with retry logic
            Map<String, KeysAndAttributes> unprocessedKeys = result.getUnprocessedKeys();
            int retryCount = 0;
            
            while (!unprocessedKeys.isEmpty() && retryCount < 3) {
                retryCount++;
                System.out.println("Retrying " + unprocessedKeys.size() + " unprocessed keys, attempt " + retryCount);
                
                BatchGetItemRequest retryRequest = new BatchGetItemRequest(unprocessedKeys);
                result = dynamoDB.batchGetItem(retryRequest);
                
                // Process additional results from retry
                Map<String, List<Map<String, AttributeValue>>> retryResponses = result.getResponses();
                for (String tableName : retryResponses.keySet()) {
                    if (responses.containsKey(tableName)) {
                        responses.get(tableName).addAll(retryResponses.get(tableName));
                    } else {
                        responses.put(tableName, retryResponses.get(tableName));
                    }
                }
                
                unprocessedKeys = result.getUnprocessedKeys();
            }
            
            if (!unprocessedKeys.isEmpty()) {
                System.err.println("Could not process all keys after maximum retries");
            }
        } catch (Exception e) {
            System.err.println("Error in batch get: " + e.getMessage());
        }
    }

    public void good_case_11() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Create a complex batch write with mixed operations
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        // Add some put requests
        Map<String, AttributeValue> item1 = new HashMap<>();
        item1.put("id", new AttributeValue("1"));
        writeRequests.add(new WriteRequest(new PutRequest(item1)));
        
        // Add some delete requests
        Map<String, AttributeValue> key1 = new HashMap<>();
        key1.put("id", new AttributeValue("2"));
        writeRequests.add(new WriteRequest(new DeleteRequest(key1)));
        
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        // ok: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        
        // Handle unprocessed items for mixed operation types
        Map<String, List<WriteRequest>> unprocessedItems = result.getUnprocessedItems();
        
        // Retry with jitter-based backoff
        int maxRetries = 5;
        int baseDelay = 100; // ms
        int retryCount = 0;
        
        while (!unprocessedItems.isEmpty() && retryCount < maxRetries) {
            retryCount++;
            
            // Calculate jitter-based delay
            double jitter = Math.random();
            long delay = (long)(baseDelay * Math.pow(2, retryCount) * jitter);
            
            try {
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            BatchWriteItemRequest retryRequest = new BatchWriteItemRequest(unprocessedItems);
            result = dynamoDB.batchWriteItem(retryRequest);
            unprocessedItems = result.getUnprocessedItems();
        }
    }

    public void good_case_12() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Create batch requests with pagination handling
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        for (int i = 0; i < 100; i++) {  // Large number of items
            Map<String, AttributeValue> key = new HashMap<>();
            key.put("id", new AttributeValue(String.valueOf(i)));
            keys.add(key);
        }
        
        requestItems.put("MyTable", new KeysAndAttributes().withKeys(keys));
        
        BatchGetItemRequest batchGetItemRequest = new BatchGetItemRequest(requestItems);
        
        // ok: java-incomplete-dynamodb-batch-operation
        BatchGetItemResult result = dynamoDB.batchGetItem(batchGetItemRequest);
        
        // Process initial results
        Map<String, List<Map<String, AttributeValue>>> allResponses = new HashMap<>(result.getResponses());
        
        // Handle pagination and unprocessed keys
        Map<String, KeysAndAttributes> unprocessedKeys = result.getUnprocessedKeys();
        while (!unprocessedKeys.isEmpty()) {
            BatchGetItemRequest retryRequest = new BatchGetItemRequest(unprocessedKeys);
            result = dynamoDB.batchGetItem(retryRequest);
            
            // Merge responses
            Map<String, List<Map<String, AttributeValue>>> responses = result.getResponses();
            for (String tableName : responses.keySet()) {
                if (allResponses.containsKey(tableName)) {
                    allResponses.get(tableName).addAll(responses.get(tableName));
                } else {
                    allResponses.put(tableName, responses.get(tableName));
                }
            }
            
            unprocessedKeys = result.getUnprocessedKeys();
        }
        
        // Process all retrieved items
        for (String tableName : allResponses.keySet()) {
            System.out.println("Retrieved " + allResponses.get(tableName).size() + " items from " + tableName);
        }
    }

    public void good_case_13() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Batch operation with conditional checks (which can lead to unprocessed items)
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        for (int i = 0; i < 10; i++) {
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("id", new AttributeValue(String.valueOf(i)));
            item.put("data", new AttributeValue("value" + i));
            writeRequests.add(new WriteRequest(new PutRequest(item)));
        }
        
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        // ok: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        
        // Proper handling with conditional check failures
        Map<String, List<WriteRequest>> unprocessedItems = result.getUnprocessedItems();
        if (!unprocessedItems.isEmpty()) {
            System.out.println("Some items were not processed due to conditional check failures");
            
            // Implement retry with backoff
            int maxRetries = 5;
            for (int attempt = 0; attempt < maxRetries && !unprocessedItems.isEmpty(); attempt++) {
                try {
                    // Exponential backoff with jitter
                    long delay = (long) (Math.pow(2, attempt) * 100 + Math.random() * 100);
                    Thread.sleep(delay);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                
                BatchWriteItemRequest retryRequest = new BatchWriteItemRequest(unprocessedItems);
                result = dynamoDB.batchWriteItem(retryRequest);
                unprocessedItems = result.getUnprocessedItems();
            }
            
            if (!unprocessedItems.isEmpty()) {
                System.err.println("Failed to process all items after maximum retries");
                // Additional error handling
            }
        }
    }

    public void good_case_14() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Batch operation inside a transaction with proper handling
        try {
            // First operation
            Map<String, List<WriteRequest>> requestItems1 = new HashMap<>();
            List<WriteRequest> writeRequests1 = new ArrayList<>();
            Map<String, AttributeValue> item1 = new HashMap<>();
            item1.put("id", new AttributeValue("1"));
            writeRequests1.add(new WriteRequest(new PutRequest(item1)));
            requestItems1.put("MyTable", writeRequests1);
            
            // ok: java-incomplete-dynamodb-batch-operation
            BatchWriteItemResult result1 = dynamoDB.batchWriteItem(requestItems1);
            Map<String, List<WriteRequest>> unprocessedItems1 = result1.getUnprocessedItems();
            
            // Retry first operation's unprocessed items
            while (!unprocessedItems1.isEmpty()) {
                BatchWriteItemRequest retryRequest = new BatchWriteItemRequest(unprocessedItems1);
                result1 = dynamoDB.batchWriteItem(retryRequest);
                unprocessedItems1 = result1.getUnprocessedItems();
            }
            
            // Second operation
            Map<String, List<WriteRequest>> requestItems2 = new HashMap<>();
            List<WriteRequest> writeRequests2 = new ArrayList<>();
            Map<String, AttributeValue> item2 = new HashMap<>();
            item2.put("id", new AttributeValue("2"));
            writeRequests2.add(new WriteRequest(new PutRequest(item2)));
            requestItems2.put("MyTable", writeRequests2);
            
            // ok: java-incomplete-dynamodb-batch-operation
            BatchWriteItemResult result2 = dynamoDB.batchWriteItem(requestItems2);
            Map<String, List<WriteRequest>> unprocessedItems2 = result2.getUnprocessedItems();
            
            // Retry second operation's unprocessed items
            while (!unprocessedItems2.isEmpty()) {
                BatchWriteItemRequest retryRequest = new BatchWriteItemRequest(unprocessedItems2);
                result2 = dynamoDB.batchWriteItem(retryRequest);
                unprocessedItems2 = result2.getUnprocessedItems();
            }
            
        } catch (Exception e) {
            System.err.println("Transaction failed: " + e.getMessage());
        }
    }

    public void good_case_15() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        // Batch operation with custom retry logic that properly retries
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("id", new AttributeValue("1"));
        writeRequests.add(new WriteRequest(new PutRequest(item)));
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest(requestItems);
        
        int maxRetries = 3;
        int retryCount = 0;
        
        // ok: java-incomplete-dynamodb-batch-operation
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        Map<String, List<WriteRequest>> unprocessedItems = result.getUnprocessedItems();
        
        // Proper retry logic with backoff
        while (!unprocessedItems.isEmpty() && retryCount < maxRetries) {
            retryCount++;
            
            try {
                // Exponential backoff
                Thread.sleep((long) Math.pow(2, retryCount) * 100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            // Actually retry the unprocessed items
            BatchWriteItemRequest retryRequest = new BatchWriteItemRequest(unprocessedItems);
            result = dynamoDB.batchWriteItem(retryRequest);
            unprocessedItems = result.getUnprocessedItems();
        }
        
        if (!unprocessedItems.isEmpty()) {
            System.err.println("Failed to process all items after " + maxRetries + " retries");
        } else {
            System.out.println("Successfully processed all batch items");
        }
    }

    // Helper method for creating batch write requests
    private Map<String, List<WriteRequest>> createBatchWriteRequests() {
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        for (int i = 0; i < 5; i++) {
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("id", new AttributeValue(String.valueOf(i)));
            item.put("data", new AttributeValue("test-data-" + i));
            writeRequests.add(new WriteRequest(new PutRequest(item)));
        }
        
        requestItems.put("MyTable", writeRequests);
        return requestItems;
    }
}
// {/fact}