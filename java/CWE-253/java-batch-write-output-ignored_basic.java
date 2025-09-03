import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.BatchWriteItemRequest;
import com.amazonaws.services.dynamodbv2.model.BatchWriteItemResult;
import com.amazonaws.services.dynamodbv2.model.PutRequest;
import com.amazonaws.services.dynamodbv2.model.WriteRequest;

import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemResponse;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

public class BatchWriteOutputExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=aws-dynamodb-mapper-batch-output-ignored@v1.0 defects=1}
    public void bad_case_1() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        // Create some write requests
        Map<String, AttributeValue> item1 = new HashMap<>();
        item1.put("id", new AttributeValue("1"));
        item1.put("data", new AttributeValue("test data 1"));
        
        Map<String, AttributeValue> item2 = new HashMap<>();
        item2.put("id", new AttributeValue("2"));
        item2.put("data", new AttributeValue("test data 2"));
        
        writeRequests.add(new WriteRequest().withPutRequest(new PutRequest().withItem(item1)));
        writeRequests.add(new WriteRequest().withPutRequest(new PutRequest().withItem(item2)));
        
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest().withRequestItems(requestItems);
        
        // ruleid: java-batch-write-output-ignored
        dynamoDB.batchWriteItem(batchWriteItemRequest);
        // No check for unprocessed items, potential data loss
    }

    public void bad_case_2() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        // Populate requestItems with data to write
        
        try {
            BatchWriteItemRequest request = new BatchWriteItemRequest().withRequestItems(requestItems);
            // ruleid: java-batch-write-output-ignored
            BatchWriteItemResult result = dynamoDB.batchWriteItem(request);
            System.out.println("Batch write completed");
            // Result is captured but unprocessed items are not checked
        } catch (Exception e) {
            System.err.println("Error in batch write: " + e.getMessage());
        }
    }

    public void bad_case_3() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.create();
        
        Map<String, List<software.amazon.awssdk.services.dynamodb.model.WriteRequest>> requestItems = new HashMap<>();
        // Populate requestItems
        
        software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest request = 
            software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest.builder()
                .requestItems(requestItems)
                .build();
        
        // ruleid: java-batch-write-output-ignored
        dynamoDbClient.batchWriteItem(request);
        // No check for unprocessed items
    }

    public void bad_case_4() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        for (int i = 0; i < 5; i++) {
            Map<String, List<WriteRequest>> requestItems = generateBatchRequests(i);
            BatchWriteItemRequest request = new BatchWriteItemRequest().withRequestItems(requestItems);
            
            // ruleid: java-batch-write-output-ignored
            BatchWriteItemResult result = dynamoDB.batchWriteItem(request);
            // Result is stored but never checked for unprocessed items
        }
    }

    public void bad_case_5() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        // Populate requestItems
        
        BatchWriteItemRequest request = new BatchWriteItemRequest().withRequestItems(requestItems);
        
        try {
            // ruleid: java-batch-write-output-ignored
            BatchWriteItemResult result = dynamoDB.batchWriteItem(request);
            
            // Only checking if result is null, but not checking unprocessed items
            if (result != null) {
                System.out.println("Batch write successful");
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    public void bad_case_6() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.create();
        
        Map<String, List<software.amazon.awssdk.services.dynamodb.model.WriteRequest>> requestItems = new HashMap<>();
        // Populate requestItems
        
        software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest request = 
            software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest.builder()
                .requestItems(requestItems)
                .build();
        
        // ruleid: java-batch-write-output-ignored
        BatchWriteItemResponse response = dynamoDbClient.batchWriteItem(request);
        
        // Checking response but not unprocessed items
        if (response.hasUnprocessedItems()) {
            // Do nothing with the unprocessed items
        }
    }

    public void bad_case_7() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        // Populate requestItems
        
        BatchWriteItemRequest request = new BatchWriteItemRequest().withRequestItems(requestItems);
        
        // ruleid: java-batch-write-output-ignored
        BatchWriteItemResult result = dynamoDB.batchWriteItem(request);
        
        // Checking if there are unprocessed items but not handling them
        if (!result.getUnprocessedItems().isEmpty()) {
            System.out.println("There were unprocessed items");
            // No retry logic or handling of unprocessed items
        }
    }

    public void bad_case_8() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        List<Map<String, AttributeValue>> items = new ArrayList<>();
        // Populate items
        
        // Process items in batches of 25
        for (int i = 0; i < items.size(); i += 25) {
            int end = Math.min(i + 25, items.size());
            List<Map<String, AttributeValue>> batch = items.subList(i, end);
            
            Map<String, List<WriteRequest>> requestItems = new HashMap<>();
            List<WriteRequest> writeRequests = batch.stream()
                .map(item -> new WriteRequest().withPutRequest(new PutRequest().withItem(item)))
                .collect(Collectors.toList());
            requestItems.put("MyTable", writeRequests);
            
            // ruleid: java-batch-write-output-ignored
            dynamoDB.batchWriteItem(new BatchWriteItemRequest().withRequestItems(requestItems));
            // No check for unprocessed items
        }
    }

    public void bad_case_9() {
        try {
            DataSource dataSource = getDataSource();
            Connection conn = dataSource.getConnection();
            conn.setAutoCommit(false);
            
            Statement stmt = conn.createStatement();
            
            // Add multiple statements to batch
            stmt.addBatch("INSERT INTO users (name, email) VALUES ('User1', 'user1@example.com')");
            stmt.addBatch("INSERT INTO users (name, email) VALUES ('User2', 'user2@example.com')");
            stmt.addBatch("INSERT INTO users (name, email) VALUES ('User3', 'user3@example.com')");
            
            // ruleid: java-batch-write-output-ignored
            stmt.executeBatch();
            conn.commit();
            
            // No check for failed operations in the batch
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            DataSource dataSource = getDataSource();
            Connection conn = dataSource.getConnection();
            
            PreparedStatement pstmt = conn.prepareStatement("INSERT INTO products (name, price) VALUES (?, ?)");
            
            // Add multiple items to batch
            for (int i = 0; i < 100; i++) {
                pstmt.setString(1, "Product" + i);
                pstmt.setDouble(2, 10.0 + i);
                pstmt.addBatch();
            }
            
            // ruleid: java-batch-write-output-ignored
            pstmt.executeBatch();
            // No check for failed operations in the batch
            
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        // Populate requestItems
        
        BatchWriteItemRequest request = new BatchWriteItemRequest().withRequestItems(requestItems);
        
        Thread batchWriteThread = new Thread(() -> {
            try {
                // ruleid: java-batch-write-output-ignored
                dynamoDB.batchWriteItem(request);
                System.out.println("Batch write completed in background thread");
                // No check for unprocessed items
            } catch (Exception e) {
                System.err.println("Error in batch write: " + e.getMessage());
            }
        });
        
        batchWriteThread.start();
    }

    public void bad_case_12() {
        try {
            DataSource dataSource = getDataSource();
            Connection conn = dataSource.getConnection();
            
            PreparedStatement pstmt = conn.prepareStatement("UPDATE inventory SET quantity = ? WHERE product_id = ?");
            
            // Add multiple updates to batch
            Map<String, Integer> updates = new HashMap<>();
            updates.put("prod1", 10);
            updates.put("prod2", 20);
            updates.put("prod3", 30);
            
            for (Map.Entry<String, Integer> entry : updates.entrySet()) {
                pstmt.setInt(1, entry.getValue());
                pstmt.setString(2, entry.getKey());
                pstmt.addBatch();
            }
            
            // ruleid: java-batch-write-output-ignored
            int[] results = pstmt.executeBatch();
            // Results array contains status for each operation, but it's not checked
            
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        // Populate requestItems
        
        BatchWriteItemRequest request = new BatchWriteItemRequest().withRequestItems(requestItems);
        
        try {
            // ruleid: java-batch-write-output-ignored
            BatchWriteItemResult result = dynamoDB.batchWriteItem(request);
            
            // Logging the result but not checking for unprocessed items
            System.out.println("Batch write completed with result: " + result);
        } catch (Exception e) {
            System.err.println("Failed to perform batch write: " + e.getMessage());
        }
    }

    public void bad_case_14() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.create();
        
        // Create multiple batch requests
        List<software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest> batchRequests = new ArrayList<>();
        // Populate batchRequests
        
        for (software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest request : batchRequests) {
            try {
                // ruleid: java-batch-write-output-ignored
                dynamoDbClient.batchWriteItem(request);
                // No check for unprocessed items
            } catch (Exception e) {
                System.err.println("Error processing batch: " + e.getMessage());
            }
        }
    }

    public void bad_case_15() {
        try {
            DataSource dataSource = getDataSource();
            Connection conn = dataSource.getConnection();
            
            Statement stmt = conn.createStatement();
            
            List<String> queries = Arrays.asList(
                "INSERT INTO logs (message) VALUES ('Log entry 1')",
                "INSERT INTO logs (message) VALUES ('Log entry 2')",
                "INSERT INTO logs (message) VALUES ('Log entry 3')"
            );
            
            for (String query : queries) {
                stmt.addBatch(query);
            }
            
            // ruleid: java-batch-write-output-ignored
            int[] updateCounts = stmt.executeBatch();
            
            // Just closing resources without checking batch results
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        // Create some write requests
        Map<String, AttributeValue> item1 = new HashMap<>();
        item1.put("id", new AttributeValue("1"));
        item1.put("data", new AttributeValue("test data 1"));
        
        Map<String, AttributeValue> item2 = new HashMap<>();
        item2.put("id", new AttributeValue("2"));
        item2.put("data", new AttributeValue("test data 2"));
        
        writeRequests.add(new WriteRequest().withPutRequest(new PutRequest().withItem(item1)));
        writeRequests.add(new WriteRequest().withPutRequest(new PutRequest().withItem(item2)));
        
        requestItems.put("MyTable", writeRequests);
        
        BatchWriteItemRequest batchWriteItemRequest = new BatchWriteItemRequest().withRequestItems(requestItems);
        
        // ok: java-batch-write-output-ignored
        BatchWriteItemResult result = dynamoDB.batchWriteItem(batchWriteItemRequest);
        
        // Check for unprocessed items and retry if necessary
        Map<String, List<WriteRequest>> unprocessedItems = result.getUnprocessedItems();
        while (!unprocessedItems.isEmpty()) {
            System.out.println("Retrying unprocessed items: " + unprocessedItems.size());
            BatchWriteItemResult retryResult = dynamoDB.batchWriteItem(
                new BatchWriteItemRequest().withRequestItems(unprocessedItems));
            unprocessedItems = retryResult.getUnprocessedItems();
        }
    }

    public void good_case_2() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        // Populate requestItems with data to write
        
        try {
            BatchWriteItemRequest request = new BatchWriteItemRequest().withRequestItems(requestItems);
            // ok: java-batch-write-output-ignored
            BatchWriteItemResult result = dynamoDB.batchWriteItem(request);
            
            // Check for unprocessed items
            if (!result.getUnprocessedItems().isEmpty()) {
                System.out.println("There were unprocessed items. Handling them now.");
                handleUnprocessedItems(result.getUnprocessedItems(), dynamoDB);
            }
        } catch (Exception e) {
            System.err.println("Error in batch write: " + e.getMessage());
        }
    }

    public void good_case_3() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.create();
        
        Map<String, List<software.amazon.awssdk.services.dynamodb.model.WriteRequest>> requestItems = new HashMap<>();
        // Populate requestItems
        
        software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest request = 
            software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest.builder()
                .requestItems(requestItems)
                .build();
        
        // ok: java-batch-write-output-ignored
        BatchWriteItemResponse response = dynamoDbClient.batchWriteItem(request);
        
        // Check for unprocessed items and retry
        Map<String, List<software.amazon.awssdk.services.dynamodb.model.WriteRequest>> unprocessedItems = response.unprocessedItems();
        int retryCount = 0;
        
        while (!unprocessedItems.isEmpty() && retryCount < 5) {
            System.out.println("Retrying unprocessed items, attempt " + (retryCount + 1));
            software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest retryRequest = 
                software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest.builder()
                    .requestItems(unprocessedItems)
                    .build();
            
            response = dynamoDbClient.batchWriteItem(retryRequest);
            unprocessedItems = response.unprocessedItems();
            retryCount++;
        }
        
        if (!unprocessedItems.isEmpty()) {
            System.err.println("Failed to process all items after " + retryCount + " retries");
            // Log or handle remaining unprocessed items
        }
    }

    public void good_case_4() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        for (int i = 0; i < 5; i++) {
            Map<String, List<WriteRequest>> requestItems = generateBatchRequests(i);
            BatchWriteItemRequest request = new BatchWriteItemRequest().withRequestItems(requestItems);
            
            // ok: java-batch-write-output-ignored
            BatchWriteItemResult result = dynamoDB.batchWriteItem(request);
            
            // Process any unprocessed items with exponential backoff
            int retries = 0;
            Map<String, List<WriteRequest>> unprocessedItems = result.getUnprocessedItems();
            
            while (!unprocessedItems.isEmpty() && retries < 3) {
                try {
                    // Exponential backoff
                    Thread.sleep((long) (Math.pow(2, retries) * 100));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                
                BatchWriteItemRequest retryRequest = new BatchWriteItemRequest().withRequestItems(unprocessedItems);
                result = dynamoDB.batchWriteItem(retryRequest);
                unprocessedItems = result.getUnprocessedItems();
                retries++;
            }
            
            if (!unprocessedItems.isEmpty()) {
                System.err.println("Failed to process all items in batch " + i);
                // Log the remaining unprocessed items for manual handling
            }
        }
    }

    public void good_case_5() {
        try {
            DataSource dataSource = getDataSource();
            Connection conn = dataSource.getConnection();
            conn.setAutoCommit(false);
            
            Statement stmt = conn.createStatement();
            
            // Add multiple statements to batch
            stmt.addBatch("INSERT INTO users (name, email) VALUES ('User1', 'user1@example.com')");
            stmt.addBatch("INSERT INTO users (name, email) VALUES ('User2', 'user2@example.com')");
            stmt.addBatch("INSERT INTO users (name, email) VALUES ('User3', 'user3@example.com')");
            
            // ok: java-batch-write-output-ignored
            int[] results = stmt.executeBatch();
            
            // Check each result
            boolean allSuccessful = true;
            for (int i = 0; i < results.length; i++) {
                if (results[i] == Statement.EXECUTE_FAILED) {
                    System.err.println("Execution failed for statement at index " + i);
                    allSuccessful = false;
                }
            }
            
            if (allSuccessful) {
                conn.commit();
            } else {
                conn.rollback();
                System.err.println("Batch execution had failures, rolling back transaction");
            }
            
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            DataSource dataSource = getDataSource();
            Connection conn = dataSource.getConnection();
            
            PreparedStatement pstmt = conn.prepareStatement("INSERT INTO products (name, price) VALUES (?, ?)");
            
            // Add multiple items to batch
            for (int i = 0; i < 100; i++) {
                pstmt.setString(1, "Product" + i);
                pstmt.setDouble(2, 10.0 + i);
                pstmt.addBatch();
            }
            
            // ok: java-batch-write-output-ignored
            int[] updateCounts = pstmt.executeBatch();
            
            // Check for failures and log them
            List<Integer> failedIndices = new ArrayList<>();
            for (int i = 0; i < updateCounts.length; i++) {
                if (updateCounts[i] == PreparedStatement.EXECUTE_FAILED) {
                    failedIndices.add(i);
                }
            }
            
            if (!failedIndices.isEmpty()) {
                System.err.println("Failed to insert products at indices: " + failedIndices);
                // Handle failures (e.g., retry or log for manual intervention)
            }
            
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        // Populate requestItems
        
        BatchWriteItemRequest request = new BatchWriteItemRequest().withRequestItems(requestItems);
        
        // ok: java-batch-write-output-ignored
        BatchWriteItemResult result = dynamoDB.batchWriteItem(request);
        
        // Implement a complete retry mechanism with backoff
        int maxRetries = 5;
        int retryCount = 0;
        Map<String, List<WriteRequest>> unprocessedItems = result.getUnprocessedItems();
        
        while (!unprocessedItems.isEmpty() && retryCount < maxRetries) {
            // Implement exponential backoff
            try {
                long delay = (long) (Math.pow(2, retryCount) * 100);
                System.out.println("Waiting " + delay + "ms before retry");
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            
            System.out.println("Retry #" + (retryCount + 1) + " for unprocessed items");
            BatchWriteItemRequest retryRequest = new BatchWriteItemRequest().withRequestItems(unprocessedItems);
            result = dynamoDB.batchWriteItem(retryRequest);
            unprocessedItems = result.getUnprocessedItems();
            retryCount++;
        }
        
        if (!unprocessedItems.isEmpty()) {
            System.err.println("Failed to process all items after " + maxRetries + " retries");
            // Log detailed information about remaining items for manual handling
            for (Map.Entry<String, List<WriteRequest>> entry : unprocessedItems.entrySet()) {
                System.err.println("Table: " + entry.getKey() + ", Unprocessed items: " + entry.getValue().size());
            }
        }
    }

    public void good_case_8() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.create();
        
        Map<String, List<software.amazon.awssdk.services.dynamodb.model.WriteRequest>> requestItems = new HashMap<>();
        // Populate requestItems
        
        software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest request = 
            software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest.builder()
                .requestItems(requestItems)
                .build();
        
        // ok: java-batch-write-output-ignored
        BatchWriteItemResponse response = dynamoDbClient.batchWriteItem(request);
        
        // Process unprocessed items with a custom handler
        if (response.hasUnprocessedItems() && !response.unprocessedItems().isEmpty()) {
            processUnprocessedItems(dynamoDbClient, response.unprocessedItems());
        }
    }

    public void good_case_9() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        List<Map<String, AttributeValue>> items = new ArrayList<>();
        // Populate items
        
        // Process items in batches of 25
        for (int i = 0; i < items.size(); i += 25) {
            int end = Math.min(i + 25, items.size());
            List<Map<String, AttributeValue>> batch = items.subList(i, end);
            
            Map<String, List<WriteRequest>> requestItems = new HashMap<>();
            List<WriteRequest> writeRequests = batch.stream()
                .map(item -> new WriteRequest().withPutRequest(new PutRequest().withItem(item)))
                .collect(Collectors.toList());
            requestItems.put("MyTable", writeRequests);
            
            // ok: java-batch-write-output-ignored
            BatchWriteItemResult result = dynamoDB.batchWriteItem(new BatchWriteItemRequest().withRequestItems(requestItems));
            
            // Handle unprocessed items
            Map<String, List<WriteRequest>> unprocessedItems = result.getUnprocessedItems();
            if (!unprocessedItems.isEmpty()) {
                System.out.println("Handling unprocessed items for batch starting at index " + i);
                // Implement retry logic or queue unprocessed items for later processing
                retryUnprocessedItems(dynamoDB, unprocessedItems);
            }
        }
    }

    public void good_case_10() {
        try {
            DataSource dataSource = getDataSource();
            Connection conn = dataSource.getConnection();
            conn.setAutoCommit(false);
            
            Statement stmt = conn.createStatement();
            
            // Track which statements are added to the batch
            List<String> batchStatements = new ArrayList<>();
            
            String stmt1 = "INSERT INTO users (name, email) VALUES ('User1', 'user1@example.com')";
            String stmt2 = "INSERT INTO users (name, email) VALUES ('User2', 'user2@example.com')";
            String stmt3 = "INSERT INTO users (name, email) VALUES ('User3', 'user3@example.com')";
            
            stmt.addBatch(stmt1);
            batchStatements.add(stmt1);
            stmt.addBatch(stmt2);
            batchStatements.add(stmt2);
            stmt.addBatch(stmt3);
            batchStatements.add(stmt3);
            
            // ok: java-batch-write-output-ignored
            int[] results = stmt.executeBatch();
            
            // Process results and handle any failures
            List<String> failedStatements = new ArrayList<>();
            for (int i = 0; i < results.length; i++) {
                if (results[i] == Statement.EXECUTE_FAILED) {
                    failedStatements.add(batchStatements.get(i));
                }
            }
            
            if (failedStatements.isEmpty()) {
                conn.commit();
                System.out.println("All batch operations successful");
            } else {
                conn.rollback();
                System.err.println("Some batch operations failed: " + failedStatements);
                // Handle failures appropriately
            }
            
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        // Populate requestItems
        
        BatchWriteItemRequest request = new BatchWriteItemRequest().withRequestItems(requestItems);
        
        Thread batchWriteThread = new Thread(() -> {
            try {
                // ok: java-batch-write-output-ignored
                BatchWriteItemResult result = dynamoDB.batchWriteItem(request);
                
                // Check for unprocessed items
                Map<String, List<WriteRequest>> unprocessedItems = result.getUnprocessedItems();
                if (!unprocessedItems.isEmpty()) {
                    System.out.println("Handling unprocessed items in background thread");
                    
                    // Retry logic for unprocessed items
                    int maxRetries = 3;
                    int retryCount = 0;
                    
                    while (!unprocessedItems.isEmpty() && retryCount < maxRetries) {
                        try {
                            Thread.sleep(1000); // Wait before retry
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                        
                        BatchWriteItemRequest retryRequest = new BatchWriteItemRequest().withRequestItems(unprocessedItems);
                        BatchWriteItemResult retryResult = dynamoDB.batchWriteItem(retryRequest);
                        unprocessedItems = retryResult.getUnprocessedItems();
                        retryCount++;
                    }
                    
                    if (!unprocessedItems.isEmpty()) {
                        System.err.println("Failed to process all items after " + maxRetries + " retries");
                        // Log remaining items for manual handling
                    }
                }
            } catch (Exception e) {
                System.err.println("Error in batch write: " + e.getMessage());
            }
        });
        
        batchWriteThread.start();
    }

    public void good_case_12() {
        try {
            DataSource dataSource = getDataSource();
            Connection conn = dataSource.getConnection();
            
            PreparedStatement pstmt = conn.prepareStatement("UPDATE inventory SET quantity = ? WHERE product_id = ?");
            
            // Add multiple updates to batch
            Map<String, Integer> updates = new HashMap<>();
            updates.put("prod1", 10);
            updates.put("prod2", 20);
            updates.put("prod3", 30);
            
            // Keep track of which updates were added to the batch
            List<Map.Entry<String, Integer>> batchEntries = new ArrayList<>();
            
            for (Map.Entry<String, Integer> entry : updates.entrySet()) {
                pstmt.setInt(1, entry.getValue());
                pstmt.setString(2, entry.getKey());
                pstmt.addBatch();
                batchEntries.add(entry);
            }
            
            // ok: java-batch-write-output-ignored
            int[] results = pstmt.executeBatch();
            
            // Check each result and handle failures
            for (int i = 0; i < results.length; i++) {
                if (results[i] == Statement.EXECUTE_FAILED) {
                    Map.Entry<String, Integer> failedEntry = batchEntries.get(i);
                    System.err.println("Failed to update product: " + failedEntry.getKey() + 
                                      " with quantity: " + failedEntry.getValue());
                    // Handle the failure (e.g., retry or log for manual intervention)
                }
            }
            
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        // Populate requestItems
        
        BatchWriteItemRequest request = new BatchWriteItemRequest().withRequestItems(requestItems);
        
        // ok: java-batch-write-output-ignored
        BatchWriteItemResult result = dynamoDB.batchWriteItem(request);
        
        // Create a custom handler for unprocessed items with circuit breaker pattern
        BatchWriteHandler handler = new BatchWriteHandler(dynamoDB);
        if (!result.getUnprocessedItems().isEmpty()) {
            boolean success = handler.handleUnprocessedItems(result.getUnprocessedItems());
            if (!success) {
                // Circuit breaker tripped, take alternative action
                System.err.println("Failed to process all items after multiple retries");
                // Implement fallback strategy (e.g., store to a dead letter queue)
            }
        }
    }

    public void good_case_14() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.create();
        
        // Create multiple batch requests
        List<software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest> batchRequests = new ArrayList<>();
        // Populate batchRequests
        
        for (software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest request : batchRequests) {
            try {
                // ok: java-batch-write-output-ignored
                BatchWriteItemResponse response = dynamoDbClient.batchWriteItem(request);
                
                // Process any unprocessed items
                if (response.hasUnprocessedItems()) {
                    Map<String, List<software.amazon.awssdk.services.dynamodb.model.WriteRequest>> unprocessedItems = 
                        response.unprocessedItems();
                    
                    if (!unprocessedItems.isEmpty()) {
                        System.out.println("Processing unprocessed items");
                        
                        // Implement retry with backoff
                        int retryCount = 0;
                        int maxRetries = 3;
                        
                        while (!unprocessedItems.isEmpty() && retryCount < maxRetries) {
                            try {
                                Thread.sleep((long) (Math.pow(2, retryCount) * 100));
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                break;
                            }
                            
                            software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest retryRequest = 
                                software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest.builder()
                                    .requestItems(unprocessedItems)
                                    .build();
                            
                            response = dynamoDbClient.batchWriteItem(retryRequest);
                            unprocessedItems = response.unprocessedItems();
                            retryCount++;
                        }
                        
                        if (!unprocessedItems.isEmpty()) {
                            System.err.println("Failed to process all items after " + maxRetries + " retries");
                            // Log or store unprocessed items for later handling
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("Error processing batch: " + e.getMessage());
            }
        }
    }

    public void good_case_15() {
        try {
            DataSource dataSource = getDataSource();
            Connection conn = dataSource.getConnection();
            
            Statement stmt = conn.createStatement();
            
            List<String> queries = Arrays.asList(
                "INSERT INTO logs (message) VALUES ('Log entry 1')",
                "INSERT INTO logs (message) VALUES ('Log entry 2')",
                "INSERT INTO logs (message) VALUES ('Log entry 3')"
            );
            
            for (String query : queries) {
                stmt.addBatch(query);
            }
            
            // ok: java-batch-write-output-ignored
            int[] updateCounts = stmt.executeBatch();
            
            // Check each result and handle accordingly
            boolean hasFailures = false;
            for (int i = 0; i < updateCounts.length; i++) {
                if (updateCounts[i] == Statement.EXECUTE_FAILED) {
                    System.err.println("Failed to execute: " + queries.get(i));
                    hasFailures = true;
                    // Handle the specific failure
                    handleFailedQuery(queries.get(i));
                }
            }
            
            if (hasFailures) {
                System.err.println("Some batch operations failed");
            } else {
                System.out.println("All batch operations completed successfully");
            }
            
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Helper methods
    private Map<String, List<WriteRequest>> generateBatchRequests(int batchNumber) {
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        for (int i = 0; i < 10; i++) {
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("id", new AttributeValue(batchNumber + "-" + i));
            item.put("data", new AttributeValue("data for " + batchNumber + "-" + i));
            
            writeRequests.add(new WriteRequest().withPutRequest(new PutRequest().withItem(item)));
        }
        
        requestItems.put("MyTable", writeRequests);
        return requestItems;
    }
    
    private void handleUnprocessedItems(Map<String, List<WriteRequest>> unprocessedItems, AmazonDynamoDB dynamoDB) {
        int retries = 0;
        int maxRetries = 3;
        
        while (!unprocessedItems.isEmpty() && retries < maxRetries) {
            try {
                Thread.sleep(1000); // Wait before retry
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            
            BatchWriteItemRequest retryRequest = new BatchWriteItemRequest().withRequestItems(unprocessedItems);
            BatchWriteItemResult result = dynamoDB.batchWriteItem(retryRequest);
            unprocessedItems = result.getUnprocessedItems();
            retries++;
        }
        
        if (!unprocessedItems.isEmpty()) {
            System.err.println("Failed to process all items after " + maxRetries + " retries");
        }
    }
    
    private void processUnprocessedItems(DynamoDbClient dynamoDbClient, 
                                        Map<String, List<software.amazon.awssdk.services.dynamodb.model.WriteRequest>> unprocessedItems) {
        int retries = 0;
        int maxRetries = 5;
        
        while (!unprocessedItems.isEmpty() && retries < maxRetries) {
            try {
                Thread.sleep((long) (Math.pow(2, retries) * 100)); // Exponential backoff
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            
            software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest retryRequest = 
                software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest.builder()
                    .requestItems(unprocessedItems)
                    .build();
            
            BatchWriteItemResponse response = dynamoDbClient.batchWriteItem(retryRequest);
            unprocessedItems = response.unprocessedItems();
            retries++;
        }
        
        if (!unprocessedItems.isEmpty()) {
            // Log remaining unprocessed items for manual handling
            System.err.println("Failed to process all items after " + maxRetries + " retries");
        }
    }
    
    private void retryUnprocessedItems(AmazonDynamoDB dynamoDB, Map<String, List<WriteRequest>> unprocessedItems) {
        int retries = 0;
        int maxRetries = 3;
        
        while (!unprocessedItems.isEmpty() && retries < maxRetries) {
            try {
                Thread.sleep(1000); // Wait before retry
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            
            BatchWriteItemRequest retryRequest = new BatchWriteItemRequest().withRequestItems(unprocessedItems);
            BatchWriteItemResult result = dynamoDB.batchWriteItem(retryRequest);
            unprocessedItems = result.getUnprocessedItems();
            retries++;
        }
        
        if (!unprocessedItems.isEmpty()) {
            System.err.println("Failed to process all items after " + maxRetries + " retries");
            // Store unprocessed items for later processing
            storeUnprocessedItemsForLaterProcessing(unprocessedItems);
        }
    }
    
    private void storeUnprocessedItemsForLaterProcessing(Map<String, List<WriteRequest>> unprocessedItems) {
        // Implementation to store unprocessed items for later processing
        System.out.println("Storing " + unprocessedItems.size() + " unprocessed items for later processing");
    }
    
    private void handleFailedQuery(String query) {
        // Implementation to handle a failed query
        System.out.println("Handling failed query: " + query);
    }
    
    private DataSource getDataSource() {
        // Implementation to get a data source
        return null; // Placeholder
    }
    
    // Custom handler class for batch write operations
    private class BatchWriteHandler {
        private final AmazonDynamoDB dynamoDB;
        private int failureCount = 0;
        private static final int CIRCUIT_BREAKER_THRESHOLD = 5;
        
        public BatchWriteHandler(AmazonDynamoDB dynamoDB) {
            this.dynamoDB = dynamoDB;
        }
        
        public boolean handleUnprocessedItems(Map<String, List<WriteRequest>> unprocessedItems) {
            if (failureCount >= CIRCUIT_BREAKER_THRESHOLD) {
                System.err.println("Circuit breaker open, not attempting further retries");
                return false;
            }
            
            int retries = 0;
            int maxRetries = 3;
            
            while (!unprocessedItems.isEmpty() && retries < maxRetries) {
                try {
                    Thread.sleep(1000); // Wait before retry
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                
                BatchWriteItemRequest retryRequest = new BatchWriteItemRequest().withRequestItems(unprocessedItems);
                BatchWriteItemResult result = dynamoDB.batchWriteItem(retryRequest);
                unprocessedItems = result.getUnprocessedItems();
                retries++;
            }
            
            if (!unprocessedItems.isEmpty()) {
                failureCount++;
                return false;
            }
            
            return true;
        }
    }
}
// {/fact}