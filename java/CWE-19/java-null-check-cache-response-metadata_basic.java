import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.GetItemRequest;
import com.amazonaws.services.dynamodbv2.model.GetItemResult;
import java.util.Map;
import java.util.HashMap;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class NullCheckCacheResponseMetadataExamples {

    private AmazonS3 s3Client = new AmazonS3Client();
    private ConcurrentMap<String, ObjectMetadata> metadataCache = new ConcurrentHashMap<>();
    private ConcurrentMap<String, GetItemResult> dynamoCache = new ConcurrentHashMap<>();
    
    // True Positive Examples (Vulnerable Code)
    
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    public void bad_case_1() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        // Get cached metadata
        ObjectMetadata metadata = metadataCache.get(key);
        
        // ruleid: java-null-check-cache-response-metadata
        long contentLength = metadata.getContentLength(); // No null check before accessing
    }
    
    public void bad_case_2() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        if (metadata != null) {
            System.out.println("Metadata found");
        }
        
        // ruleid: java-null-check-cache-response-metadata
        String contentType = metadata.getContentType(); // Accessing after incomplete null check
    }
    
    public void bad_case_3() {
        try {
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            ObjectMetadata metadata = metadataCache.get(key);
            
            // ruleid: java-null-check-cache-response-metadata
            System.out.println("ETag: " + metadata.getETag()); // No null check in try block
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
    
    public void bad_case_4() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        
        if (bucketName != null) {
            // ruleid: java-null-check-cache-response-metadata
            System.out.println("Last Modified: " + metadata.getLastModified()); // Checking wrong variable
        }
    }
    
    public void bad_case_5() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = null;
        if (metadataCache.containsKey(key)) {
            metadata = metadataCache.get(key);
        }
        
        // ruleid: java-null-check-cache-response-metadata
        long contentLength = metadata.getContentLength(); // containsKey doesn't guarantee non-null value
    }
    
    public void bad_case_6() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        String tableName = "my-table";
        String itemId = "item-123";
        
        GetItemResult result = dynamoCache.get(itemId);
        
        // ruleid: java-null-check-cache-response-metadata
        Map<String, AttributeValue> item = result.getItem(); // No null check before accessing
    }
    
    public void bad_case_7() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        boolean hasMetadata = (metadata != null);
        
        if (hasMetadata) {
            System.out.println("Has metadata");
        }
        
        // ruleid: java-null-check-cache-response-metadata
        System.out.println("Content Type: " + metadata.getContentType()); // Check not used properly
    }
    
    public void bad_case_8() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        
        try {
            // ruleid: java-null-check-cache-response-metadata
            processMetadata(metadata.getUserMetadata()); // No null check before method call
        } catch (NullPointerException e) {
            System.err.println("NPE caught: " + e.getMessage());
        }
    }
    
    public void bad_case_9() {
        String tableName = "my-table";
        String itemId = "item-123";
        
        GetItemResult result = dynamoCache.get(itemId);
        
        if (result != null && result.getItem() == null) {
            System.out.println("Item not found");
        } else {
            // ruleid: java-null-check-cache-response-metadata
            AttributeValue nameAttr = result.getItem().get("name"); // Incomplete null check
        }
    }
    
    public void bad_case_10() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.getOrDefault(key, null);
        
        // ruleid: java-null-check-cache-response-metadata
        System.out.println("Content Length: " + metadata.getContentLength()); // getOrDefault can return null
    }
    
    public void bad_case_11() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        
        if (key.startsWith("important")) {
            // ruleid: java-null-check-cache-response-metadata
            processMetadata(metadata.getUserMetadata()); // Conditional not checking for null
        }
    }
    
    public void bad_case_12() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        ObjectMetadata backupMetadata = metadataCache.get("backup-" + key);
        
        // ruleid: java-null-check-cache-response-metadata
        long contentLength = (metadata != null) ? metadata.getContentLength() : backupMetadata.getContentLength(); // Only checking one variable
    }
    
    public void bad_case_13() {
        String tableName = "my-table";
        String itemId = "item-123";
        
        GetItemResult result = dynamoCache.get(itemId);
        
        for (int i = 0; i < 5; i++) {
            // ruleid: java-null-check-cache-response-metadata
            if (result.getItem() != null && result.getItem().containsKey("count")) { // No null check on result
                System.out.println("Has count attribute");
            }
        }
    }
    
    public void bad_case_14() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        
        switch(key.length()) {
            case 10:
                // ruleid: java-null-check-cache-response-metadata
                System.out.println(metadata.getContentType()); // No null check in switch
                break;
            default:
                System.out.println("Unknown key length");
        }
    }
    
    public void bad_case_15() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        
        Runnable task = () -> {
            // ruleid: java-null-check-cache-response-metadata
            System.out.println("Content Length: " + metadata.getContentLength()); // No null check in lambda
        };
        
        new Thread(task).start();
    }
    
    // True Negative Examples (Safe Code)
    
    public void good_case_1() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        
        // ok: java-null-check-cache-response-metadata
        if (metadata != null) {
            long contentLength = metadata.getContentLength();
            System.out.println("Content Length: " + contentLength);
        }
    }
    
    public void good_case_2() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        
        // ok: java-null-check-cache-response-metadata
        String contentType = metadata != null ? metadata.getContentType() : "unknown";
        System.out.println("Content Type: " + contentType);
    }
    
    public void good_case_3() {
        try {
            String bucketName = "my-bucket";
            String key = "my-object-key";
            
            ObjectMetadata metadata = metadataCache.get(key);
            
            // ok: java-null-check-cache-response-metadata
            if (metadata != null) {
                System.out.println("ETag: " + metadata.getETag());
            } else {
                System.out.println("Metadata not found in cache");
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
    
    public void good_case_4() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        
        // ok: java-null-check-cache-response-metadata
        if (metadata == null) {
            System.out.println("Metadata not found");
            return;
        }
        
        System.out.println("Last Modified: " + metadata.getLastModified());
    }
    
    public void good_case_5() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        String tableName = "my-table";
        String itemId = "item-123";
        
        GetItemResult result = dynamoCache.get(itemId);
        
        // ok: java-null-check-cache-response-metadata
        if (result != null && result.getItem() != null) {
            Map<String, AttributeValue> item = result.getItem();
            System.out.println("Item: " + item);
        }
    }
    
    public void good_case_6() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        
        try {
            // ok: java-null-check-cache-response-metadata
            if (metadata != null) {
                processMetadata(metadata.getUserMetadata());
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
    
    public void good_case_7() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        // ok: java-null-check-cache-response-metadata
        ObjectMetadata metadata = metadataCache.computeIfAbsent(key, k -> {
            try {
                S3Object object = s3Client.getObject(new GetObjectRequest(bucketName, k));
                return object.getObjectMetadata();
            } catch (AmazonServiceException e) {
                return new ObjectMetadata(); // Return empty metadata instead of null
            }
        });
        
        long contentLength = metadata.getContentLength(); // Safe because computeIfAbsent won't return null
    }
    
    public void good_case_8() {
        String tableName = "my-table";
        String itemId = "item-123";
        
        GetItemResult result = dynamoCache.get(itemId);
        
        // ok: java-null-check-cache-response-metadata
        Map<String, AttributeValue> item = (result != null) ? result.getItem() : new HashMap<>();
        
        if (item.containsKey("name")) {
            System.out.println("Name: " + item.get("name").getS());
        }
    }
    
    public void good_case_9() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        
        // ok: java-null-check-cache-response-metadata
        long contentLength = 0;
        if (metadata != null) {
            contentLength = metadata.getContentLength();
        }
        
        System.out.println("Content Length: " + contentLength);
    }
    
    public void good_case_10() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        
        // ok: java-null-check-cache-response-metadata
        if (metadata == null) {
            metadata = fetchMetadataFromS3(bucketName, key);
            metadataCache.put(key, metadata);
        }
        
        long contentLength = metadata.getContentLength(); // Safe after ensuring metadata is not null
    }
    
    public void good_case_11() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        ObjectMetadata backupMetadata = metadataCache.get("backup-" + key);
        
        // ok: java-null-check-cache-response-metadata
        long contentLength = 0;
        if (metadata != null) {
            contentLength = metadata.getContentLength();
        } else if (backupMetadata != null) {
            contentLength = backupMetadata.getContentLength();
        }
        
        System.out.println("Content Length: " + contentLength);
    }
    
    public void good_case_12() {
        String tableName = "my-table";
        String itemId = "item-123";
        
        GetItemResult result = dynamoCache.get(itemId);
        
        // ok: java-null-check-cache-response-metadata
        if (result == null) {
            System.out.println("Result not found in cache");
            return;
        }
        
        Map<String, AttributeValue> item = result.getItem();
        if (item != null) {
            System.out.println("Item found");
        }
    }
    
    public void good_case_13() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        
        Runnable task = () -> {
            // ok: java-null-check-cache-response-metadata
            if (metadata != null) {
                System.out.println("Content Length: " + metadata.getContentLength());
            }
        };
        
        new Thread(task).start();
    }
    
    public void good_case_14() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        ObjectMetadata metadata = metadataCache.get(key);
        
        switch(key.length()) {
            case 10:
                // ok: java-null-check-cache-response-metadata
                if (metadata != null) {
                    System.out.println(metadata.getContentType());
                }
                break;
            default:
                System.out.println("Unknown key length");
        }
    }
    
    public void good_case_15() {
        String bucketName = "my-bucket";
        String key = "my-object-key";
        
        // ok: java-null-check-cache-response-metadata
        ObjectMetadata metadata = metadataCache.getOrDefault(key, new ObjectMetadata());
        
        // Safe because getOrDefault provides a default non-null value
        System.out.println("Content Length: " + metadata.getContentLength());
    }
    
    // Helper methods
    private void processMetadata(Map<String, String> userMetadata) {
        // Process metadata
    }
    
    private ObjectMetadata fetchMetadataFromS3(String bucketName, String key) {
        try {
            S3Object object = s3Client.getObject(new GetObjectRequest(bucketName, key));
            return object.getObjectMetadata();
        } catch (AmazonServiceException e) {
            return new ObjectMetadata();
        }
    }
}
// {/fact}