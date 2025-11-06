import com.amazonaws.services.kinesis.AmazonKinesis;
import com.amazonaws.services.kinesis.AmazonKinesisClientBuilder;
import com.amazonaws.services.kinesis.model.*;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class KinesisFailedPutObjectsHandling {
    private static final Logger logger = Logger.getLogger(KinesisFailedPutObjectsHandling.class.getName());

    // True Positive Examples (Bad Cases)

// {fact rule=aws-dynamodb-mapper-batch-output-ignored@v1.0 defects=1}
    public void bad_case_1() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        List<PutRecordsRequestEntry> recordEntries = new ArrayList<>();
        
        for (int i = 0; i < 500; i++) {
            PutRecordsRequestEntry entry = new PutRecordsRequestEntry();
            entry.setData(ByteBuffer.wrap(("data-" + i).getBytes()));
            entry.setPartitionKey(UUID.randomUUID().toString());
            recordEntries.add(entry);
        }
        
        PutRecordsRequest putRecordsRequest = new PutRecordsRequest();
        putRecordsRequest.setStreamName("MyKinesisStream");
        putRecordsRequest.setRecords(recordEntries);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult putRecordsResult = kinesisClient.putRecords(putRecordsRequest);
        // No checking of failed records
    }

    public void bad_case_2() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        List<PutRecordsRequestEntry> recordEntries = new ArrayList<>();
        
        for (int i = 0; i < 100; i++) {
            PutRecordsRequestEntry entry = new PutRecordsRequestEntry();
            entry.setData(ByteBuffer.wrap(("log-entry-" + i).getBytes()));
            entry.setPartitionKey("partition-" + (i % 10));
            recordEntries.add(entry);
        }
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("LogStream")
            .withRecords(recordEntries);
        
        try {
            // ruleid: java-checking-failed-put-objects-to-kinesis
            kinesisClient.putRecords(request);
            logger.info("Records sent to Kinesis");
        } catch (Exception e) {
            logger.severe("Error sending records: " + e.getMessage());
        }
    }

    public void bad_case_3() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        List<PutRecordsRequestEntry> recordEntries = new ArrayList<>();
        
        recordEntries.add(createRecord("user1", "login"));
        recordEntries.add(createRecord("user2", "logout"));
        recordEntries.add(createRecord("user3", "purchase"));
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("ActivityStream")
            .withRecords(recordEntries);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        logger.info("Put records completed with " + result.getRecords().size() + " records");
    }

    public void bad_case_4() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        List<PutRecordsRequestEntry> recordEntries = new ArrayList<>();
        
        for (String message : getMessages()) {
            PutRecordsRequestEntry entry = new PutRecordsRequestEntry();
            entry.setData(ByteBuffer.wrap(message.getBytes()));
            entry.setPartitionKey(UUID.randomUUID().toString());
            recordEntries.add(entry);
        }
        
        PutRecordsRequest request = new PutRecordsRequest();
        request.setStreamName("MessageStream");
        request.setRecords(recordEntries);
        
        try {
            // ruleid: java-checking-failed-put-objects-to-kinesis
            PutRecordsResult result = kinesisClient.putRecords(request);
            if (result.getFailedRecordCount() > 0) {
                // Detected failures but not handling individual records
                logger.warning("Some records failed: " + result.getFailedRecordCount());
            }
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    public void bad_case_5() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        List<PutRecordsRequestEntry> recordEntries = new ArrayList<>();
        
        for (int i = 0; i < 10; i++) {
            PutRecordsRequestEntry entry = new PutRecordsRequestEntry();
            entry.setData(ByteBuffer.wrap(("metric-" + i).getBytes()));
            entry.setPartitionKey("metric-key");
            recordEntries.add(entry);
        }
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("MetricsStream")
            .withRecords(recordEntries);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        kinesisClient.putRecords(request);
    }

    public void bad_case_6() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap(("event-" + i).getBytes()))
                .withPartitionKey("partition-" + (i % 5)));
        }
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("EventStream")
            .withRecords(entries);
        
        try {
            // ruleid: java-checking-failed-put-objects-to-kinesis
            PutRecordsResult result = kinesisClient.putRecords(request);
            logger.info("Put " + entries.size() + " records to Kinesis");
        } catch (Exception e) {
            logger.severe("Failed to put records: " + e.getMessage());
        }
    }

    public void bad_case_7() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        String streamName = "TransactionStream";
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap(("transaction-" + i).getBytes()))
                .withPartitionKey(UUID.randomUUID().toString()));
        }
        
        PutRecordsRequest request = new PutRecordsRequest();
        request.setStreamName(streamName);
        request.setRecords(entries);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        int successCount = entries.size() - result.getFailedRecordCount();
        logger.info(successCount + " records successfully sent");
    }

    public void bad_case_8() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        entries.add(createRecord("sensor1", "temperature:72"));
        entries.add(createRecord("sensor2", "temperature:68"));
        entries.add(createRecord("sensor3", "temperature:70"));
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("SensorData")
            .withRecords(entries);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        try {
            kinesisClient.putRecords(request);
        } catch (Exception e) {
            // Only catching exceptions, not checking for failed records
            logger.severe("Error sending sensor data: " + e.getMessage());
        }
    }

    public void bad_case_9() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<String> userEvents = getUserEvents();
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        
        for (String event : userEvents) {
            entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap(event.getBytes()))
                .withPartitionKey("user-events"));
        }
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("UserActivityStream")
            .withRecords(entries);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        // No checking of failed records
    }

    public void bad_case_10() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap(("batch-item-" + i).getBytes()))
                .withPartitionKey("batch-key"));
        }
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("BatchProcessingStream")
            .withRecords(entries);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        if (result.getRecords().size() > 0) {
            logger.info("Records processed");
        }
    }

    public void bad_case_11() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            PutRecordsRequestEntry entry = new PutRecordsRequestEntry();
            entry.setData(ByteBuffer.wrap(("notification-" + i).getBytes()));
            entry.setPartitionKey("notification");
            entries.add(entry);
        }
        
        PutRecordsRequest request = new PutRecordsRequest();
        request.setStreamName("NotificationStream");
        request.setRecords(entries);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        kinesisClient.putRecords(request);
        logger.info("Sent notifications to Kinesis");
    }

    public void bad_case_12() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        for (String logMessage : getLogMessages()) {
            PutRecordsRequestEntry entry = new PutRecordsRequestEntry();
            entry.setData(ByteBuffer.wrap(logMessage.getBytes()));
            entry.setPartitionKey("logs");
            entries.add(entry);
        }
        
        PutRecordsRequest request = new PutRecordsRequest();
        request.setStreamName("LoggingStream");
        request.setRecords(entries);
        
        try {
            // ruleid: java-checking-failed-put-objects-to-kinesis
            PutRecordsResult result = kinesisClient.putRecords(request);
            logger.info("Log batch sent to Kinesis");
        } catch (Exception e) {
            logger.severe("Failed to send logs: " + e.getMessage());
        }
    }

    public void bad_case_13() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        entries.add(createRecord("order1", "create"));
        entries.add(createRecord("order2", "update"));
        entries.add(createRecord("order3", "delete"));
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("OrderStream")
            .withRecords(entries);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        if (result.getRecords() != null) {
            // Not checking for failures
            logger.info("Order events sent");
        }
    }

    public void bad_case_14() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap(("analytics-" + i).getBytes()))
                .withPartitionKey("analytics"));
        }
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("AnalyticsStream")
            .withRecords(entries);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        try {
            kinesisClient.putRecords(request);
            logger.info("Analytics data sent");
        } catch (AmazonKinesisException e) {
            // Only catching exceptions, not checking for partial failures
            logger.severe("Failed to send analytics data: " + e.getMessage());
        }
    }

    public void bad_case_15() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        for (int i = 0; i < 200; i++) {
            entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap(("metric-" + i).getBytes()))
                .withPartitionKey("metric-" + (i % 10)));
        }
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("MetricsStream")
            .withRecords(entries);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        // Just logging the total count, not checking failures
        logger.info("Sent " + entries.size() + " metrics to Kinesis");
    }

    // True Negative Examples (Good Cases)

    public void good_case_1() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        List<PutRecordsRequestEntry> recordEntries = new ArrayList<>();
        
        for (int i = 0; i < 500; i++) {
            PutRecordsRequestEntry entry = new PutRecordsRequestEntry();
            entry.setData(ByteBuffer.wrap(("data-" + i).getBytes()));
            entry.setPartitionKey(UUID.randomUUID().toString());
            recordEntries.add(entry);
        }
        
        PutRecordsRequest putRecordsRequest = new PutRecordsRequest();
        putRecordsRequest.setStreamName("MyKinesisStream");
        putRecordsRequest.setRecords(recordEntries);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult putRecordsResult = kinesisClient.putRecords(putRecordsRequest);
        if (putRecordsResult.getFailedRecordCount() > 0) {
            List<PutRecordsRequestEntry> failedRecordEntries = new ArrayList<>();
            List<PutRecordsResultEntry> records = putRecordsResult.getRecords();
            
            for (int i = 0; i < records.size(); i++) {
                PutRecordsResultEntry resultEntry = records.get(i);
                if (resultEntry.getErrorCode() != null) {
                    failedRecordEntries.add(recordEntries.get(i));
                    logger.warning("Record failed with error: " + resultEntry.getErrorCode() + " - " + resultEntry.getErrorMessage());
                }
            }
            
            // Retry failed records
            if (!failedRecordEntries.isEmpty()) {
                retryFailedRecords(kinesisClient, "MyKinesisStream", failedRecordEntries);
            }
        }
    }

    public void good_case_2() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        List<PutRecordsRequestEntry> recordEntries = new ArrayList<>();
        
        for (int i = 0; i < 100; i++) {
            PutRecordsRequestEntry entry = new PutRecordsRequestEntry();
            entry.setData(ByteBuffer.wrap(("log-entry-" + i).getBytes()));
            entry.setPartitionKey("partition-" + (i % 10));
            recordEntries.add(entry);
        }
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("LogStream")
            .withRecords(recordEntries);
        
        try {
            // ok: java-checking-failed-put-objects-to-kinesis
            PutRecordsResult result = kinesisClient.putRecords(request);
            logger.info("Records sent to Kinesis");
            
            if (result.getFailedRecordCount() > 0) {
                logger.warning("Failed to put " + result.getFailedRecordCount() + " records");
                List<PutRecordsResultEntry> records = result.getRecords();
                
                for (int i = 0; i < records.size(); i++) {
                    PutRecordsResultEntry entry = records.get(i);
                    if (entry.getErrorCode() != null) {
                        logger.warning("Record at index " + i + " failed with error: " + 
                                      entry.getErrorCode() + " - " + entry.getErrorMessage());
                    }
                }
            }
        } catch (Exception e) {
            logger.severe("Error sending records: " + e.getMessage());
        }
    }

    public void good_case_3() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        List<PutRecordsRequestEntry> recordEntries = new ArrayList<>();
        
        recordEntries.add(createRecord("user1", "login"));
        recordEntries.add(createRecord("user2", "logout"));
        recordEntries.add(createRecord("user3", "purchase"));
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("ActivityStream")
            .withRecords(recordEntries);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        logger.info("Put records completed with " + result.getRecords().size() + " records");
        
        if (result.getFailedRecordCount() > 0) {
            List<PutRecordsResultEntry> resultEntries = result.getRecords();
            List<PutRecordsRequestEntry> failedRecords = new ArrayList<>();
            
            for (int i = 0; i < resultEntries.size(); i++) {
                if (resultEntries.get(i).getErrorCode() != null) {
                    logger.warning("Record " + i + " failed with error: " + 
                                  resultEntries.get(i).getErrorCode());
                    failedRecords.add(recordEntries.get(i));
                }
            }
            
            if (!failedRecords.isEmpty()) {
                logger.info("Retrying " + failedRecords.size() + " failed records");
                retryFailedRecords(kinesisClient, "ActivityStream", failedRecords);
            }
        }
    }

    public void good_case_4() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        List<PutRecordsRequestEntry> recordEntries = new ArrayList<>();
        
        for (String message : getMessages()) {
            PutRecordsRequestEntry entry = new PutRecordsRequestEntry();
            entry.setData(ByteBuffer.wrap(message.getBytes()));
            entry.setPartitionKey(UUID.randomUUID().toString());
            recordEntries.add(entry);
        }
        
        PutRecordsRequest request = new PutRecordsRequest();
        request.setStreamName("MessageStream");
        request.setRecords(recordEntries);
        
        try {
            // ok: java-checking-failed-put-objects-to-kinesis
            PutRecordsResult result = kinesisClient.putRecords(request);
            if (result.getFailedRecordCount() > 0) {
                logger.warning("Some records failed: " + result.getFailedRecordCount());
                
                List<PutRecordsResultEntry> resultEntries = result.getRecords();
                for (int i = 0; i < resultEntries.size(); i++) {
                    PutRecordsResultEntry entry = resultEntries.get(i);
                    if (entry.getErrorCode() != null) {
                        logger.warning("Record " + i + " failed with error: " + 
                                      entry.getErrorCode() + " - " + entry.getErrorMessage());
                        // Handle individual failed record
                        handleFailedRecord(recordEntries.get(i), entry);
                    }
                }
            }
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    public void good_case_5() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        List<PutRecordsRequestEntry> recordEntries = new ArrayList<>();
        
        for (int i = 0; i < 10; i++) {
            PutRecordsRequestEntry entry = new PutRecordsRequestEntry();
            entry.setData(ByteBuffer.wrap(("metric-" + i).getBytes()));
            entry.setPartitionKey("metric-key");
            recordEntries.add(entry);
        }
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("MetricsStream")
            .withRecords(recordEntries);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        
        // Check for failed records
        int failedCount = result.getFailedRecordCount();
        if (failedCount > 0) {
            logger.warning(failedCount + " records failed to be put into the stream");
            
            // Create a list to hold failed records for retry
            List<PutRecordsRequestEntry> failedRecords = new ArrayList<>();
            List<PutRecordsResultEntry> putResults = result.getRecords();
            
            for (int i = 0; i < putResults.size(); i++) {
                PutRecordsResultEntry putResult = putResults.get(i);
                if (putResult.getErrorCode() != null) {
                    logger.warning("Record " + i + " failed with error: " + 
                                  putResult.getErrorCode() + " - " + putResult.getErrorMessage());
                    failedRecords.add(recordEntries.get(i));
                }
            }
            
            // Retry the failed records
            if (!failedRecords.isEmpty()) {
                retryFailedRecords(kinesisClient, "MetricsStream", failedRecords);
            }
        }
    }

    public void good_case_6() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap(("event-" + i).getBytes()))
                .withPartitionKey("partition-" + (i % 5)));
        }
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("EventStream")
            .withRecords(entries);
        
        try {
            // ok: java-checking-failed-put-objects-to-kinesis
            PutRecordsResult result = kinesisClient.putRecords(request);
            logger.info("Put " + entries.size() + " records to Kinesis");
            
            if (result.getFailedRecordCount() > 0) {
                logger.warning(result.getFailedRecordCount() + " records failed");
                
                // Process failed records
                List<PutRecordsResultEntry> records = result.getRecords();
                for (int i = 0; i < records.size(); i++) {
                    PutRecordsResultEntry record = records.get(i);
                    if (record.getErrorCode() != null) {
                        logger.warning("Record " + i + " failed with error: " + 
                                      record.getErrorCode() + " - " + record.getErrorMessage());
                        // Save failed record for retry
                        saveFailedRecordForRetry(entries.get(i));
                    }
                }
            }
        } catch (Exception e) {
            logger.severe("Failed to put records: " + e.getMessage());
        }
    }

    public void good_case_7() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        String streamName = "TransactionStream";
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap(("transaction-" + i).getBytes()))
                .withPartitionKey(UUID.randomUUID().toString()));
        }
        
        PutRecordsRequest request = new PutRecordsRequest();
        request.setStreamName(streamName);
        request.setRecords(entries);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        int successCount = entries.size() - result.getFailedRecordCount();
        logger.info(successCount + " records successfully sent");
        
        if (result.getFailedRecordCount() > 0) {
            List<PutRecordsResultEntry> records = result.getRecords();
            List<PutRecordsRequestEntry> failedEntries = new ArrayList<>();
            
            for (int i = 0; i < records.size(); i++) {
                if (records.get(i).getErrorCode() != null) {
                    logger.warning("Failed record: " + i + " with error: " + 
                                  records.get(i).getErrorCode() + " - " + 
                                  records.get(i).getErrorMessage());
                    failedEntries.add(entries.get(i));
                }
            }
            
            if (!failedEntries.isEmpty()) {
                // Retry with exponential backoff
                retryWithBackoff(kinesisClient, streamName, failedEntries, 1);
            }
        }
    }

    public void good_case_8() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        entries.add(createRecord("sensor1", "temperature:72"));
        entries.add(createRecord("sensor2", "temperature:68"));
        entries.add(createRecord("sensor3", "temperature:70"));
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("SensorData")
            .withRecords(entries);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        try {
            PutRecordsResult result = kinesisClient.putRecords(request);
            
            if (result.getFailedRecordCount() > 0) {
                logger.warning("Failed to send " + result.getFailedRecordCount() + " sensor readings");
                
                List<PutRecordsResultEntry> records = result.getRecords();
                for (int i = 0; i < records.size(); i++) {
                    PutRecordsResultEntry record = records.get(i);
                    if (record.getErrorCode() != null) {
                        logger.warning("Sensor reading " + i + " failed: " + 
                                      record.getErrorCode() + " - " + record.getErrorMessage());
                        // Store failed reading for later retry
                        storeFailedReading(entries.get(i));
                    }
                }
            }
        } catch (Exception e) {
            logger.severe("Error sending sensor data: " + e.getMessage());
        }
    }

    public void good_case_9() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<String> userEvents = getUserEvents();
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        
        for (String event : userEvents) {
            entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap(event.getBytes()))
                .withPartitionKey("user-events"));
        }
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("UserActivityStream")
            .withRecords(entries);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        
        if (result.getFailedRecordCount() > 0) {
            logger.warning(result.getFailedRecordCount() + " user events failed to send");
            
            // Extract failed records for retry
            List<PutRecordsResultEntry> resultEntries = result.getRecords();
            List<PutRecordsRequestEntry> failedEntries = new ArrayList<>();
            
            for (int i = 0; i < resultEntries.size(); i++) {
                if (resultEntries.get(i).getErrorCode() != null) {
                    logger.warning("User event " + i + " failed with error: " + 
                                  resultEntries.get(i).getErrorCode());
                    failedEntries.add(entries.get(i));
                }
            }
            
            // Retry failed records
            if (!failedEntries.isEmpty()) {
                retryUserEvents(kinesisClient, failedEntries);
            }
        }
    }

    public void good_case_10() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap(("batch-item-" + i).getBytes()))
                .withPartitionKey("batch-key"));
        }
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("BatchProcessingStream")
            .withRecords(entries);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        
        // Check for failures and handle them
        int failedCount = result.getFailedRecordCount();
        if (failedCount > 0) {
            logger.warning(failedCount + " batch items failed to process");
            
            List<PutRecordsResultEntry> resultEntries = result.getRecords();
            List<Integer> failedIndices = new ArrayList<>();
            
            for (int i = 0; i < resultEntries.size(); i++) {
                if (resultEntries.get(i).getErrorCode() != null) {
                    failedIndices.add(i);
                    logger.warning("Batch item " + i + " failed: " + resultEntries.get(i).getErrorMessage());
                }
            }
            
            // Process failed indices
            processBatchFailures(entries, failedIndices);
        }
    }

    public void good_case_11() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            PutRecordsRequestEntry entry = new PutRecordsRequestEntry();
            entry.setData(ByteBuffer.wrap(("notification-" + i).getBytes()));
            entry.setPartitionKey("notification");
            entries.add(entry);
        }
        
        PutRecordsRequest request = new PutRecordsRequest();
        request.setStreamName("NotificationStream");
        request.setRecords(entries);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        logger.info("Sent notifications to Kinesis");
        
        // Check for failed records
        if (result.getFailedRecordCount() > 0) {
            logger.warning(result.getFailedRecordCount() + " notifications failed to send");
            
            List<PutRecordsResultEntry> records = result.getRecords();
            for (int i = 0; i < records.size(); i++) {
                PutRecordsResultEntry record = records.get(i);
                if (record.getErrorCode() != null) {
                    logger.warning("Notification " + i + " failed: " + record.getErrorCode());
                    // Handle the failed notification
                    handleFailedNotification(entries.get(i), record);
                }
            }
        }
    }

    public void good_case_12() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        for (String logMessage : getLogMessages()) {
            PutRecordsRequestEntry entry = new PutRecordsRequestEntry();
            entry.setData(ByteBuffer.wrap(logMessage.getBytes()));
            entry.setPartitionKey("logs");
            entries.add(entry);
        }
        
        PutRecordsRequest request = new PutRecordsRequest();
        request.setStreamName("LoggingStream");
        request.setRecords(entries);
        
        try {
            // ok: java-checking-failed-put-objects-to-kinesis
            PutRecordsResult result = kinesisClient.putRecords(request);
            logger.info("Log batch sent to Kinesis");
            
            // Check for failures
            if (result.getFailedRecordCount() > 0) {
                logger.warning(result.getFailedRecordCount() + " log entries failed to send");
                
                // Process each record to find failures
                List<PutRecordsResultEntry> resultEntries = result.getRecords();
                for (int i = 0; i < resultEntries.size(); i++) {
                    PutRecordsResultEntry entry = resultEntries.get(i);
                    if (entry.getErrorCode() != null) {
                        logger.warning("Log entry " + i + " failed: " + entry.getErrorCode());
                        // Save failed log entry to local storage
                        saveFailedLogEntry(entries.get(i));
                    }
                }
            }
        } catch (Exception e) {
            logger.severe("Failed to send logs: " + e.getMessage());
        }
    }

    public void good_case_13() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        entries.add(createRecord("order1", "create"));
        entries.add(createRecord("order2", "update"));
        entries.add(createRecord("order3", "delete"));
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("OrderStream")
            .withRecords(entries);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        
        // Process results and check for failures
        if (result.getFailedRecordCount() > 0) {
            logger.warning(result.getFailedRecordCount() + " order events failed");
            
            List<PutRecordsResultEntry> resultEntries = result.getRecords();
            for (int i = 0; i < resultEntries.size(); i++) {
                PutRecordsResultEntry entry = resultEntries.get(i);
                if (entry.getErrorCode() != null) {
                    logger.warning("Order event " + i + " failed: " + entry.getErrorCode());
                    // Handle the specific order event failure
                    handleOrderEventFailure(entries.get(i), entry);
                } else {
                    logger.info("Order event " + i + " succeeded with shard ID: " + entry.getShardId());
                }
            }
        } else {
            logger.info("All order events sent successfully");
        }
    }

    public void good_case_14() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap(("analytics-" + i).getBytes()))
                .withPartitionKey("analytics"));
        }
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("AnalyticsStream")
            .withRecords(entries);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        try {
            PutRecordsResult result = kinesisClient.putRecords(request);
            logger.info("Analytics data sent");
            
            // Check for partial failures
            if (result.getFailedRecordCount() > 0) {
                logger.warning("Some analytics records failed: " + result.getFailedRecordCount());
                
                // Process each record
                List<PutRecordsResultEntry> resultEntries = result.getRecords();
                for (int i = 0; i < resultEntries.size(); i++) {
                    PutRecordsResultEntry entry = resultEntries.get(i);
                    if (entry.getErrorCode() != null) {
                        logger.warning("Analytics record " + i + " failed: " + 
                                      entry.getErrorCode() + " - " + entry.getErrorMessage());
                        // Queue for retry
                        queueForRetry(entries.get(i));
                    }
                }
            }
        } catch (AmazonKinesisException e) {
            logger.severe("Failed to send analytics data: " + e.getMessage());
        }
    }

    public void good_case_15() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        for (int i = 0; i < 200; i++) {
            entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap(("metric-" + i).getBytes()))
                .withPartitionKey("metric-" + (i % 10)));
        }
        
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName("MetricsStream")
            .withRecords(entries);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        logger.info("Sent " + entries.size() + " metrics to Kinesis");
        
        // Check for failed records and handle them
        int failedCount = result.getFailedRecordCount();
        if (failedCount > 0) {
            logger.warning(failedCount + " metrics failed to send");
            
            // Collect failed records for retry
            List<PutRecordsRequestEntry> failedEntries = new ArrayList<>();
            List<PutRecordsResultEntry> resultEntries = result.getRecords();
            
            for (int i = 0; i < resultEntries.size(); i++) {
                PutRecordsResultEntry entry = resultEntries.get(i);
                if (entry.getErrorCode() != null) {
                    logger.warning("Metric " + i + " failed: " + entry.getErrorCode());
                    failedEntries.add(entries.get(i));
                }
            }
            
            // Retry the failed metrics
            if (!failedEntries.isEmpty()) {
                retryFailedMetrics(kinesisClient, failedEntries);
            }
        }
    }

    // Helper methods
    
    private PutRecordsRequestEntry createRecord(String key, String data) {
        return new PutRecordsRequestEntry()
            .withData(ByteBuffer.wrap(data.getBytes()))
            .withPartitionKey(key);
    }
    
    private List<String> getMessages() {
        List<String> messages = new ArrayList<>();
        messages.add("Message 1");
        messages.add("Message 2");
        messages.add("Message 3");
        return messages;
    }
    
    private List<String> getUserEvents() {
        List<String> events = new ArrayList<>();
        events.add("User logged in");
        events.add("User viewed page");
        events.add("User clicked button");
        return events;
    }
    
    private List<String> getLogMessages() {
        List<String> logs = new ArrayList<>();
        logs.add("INFO: System started");
        logs.add("DEBUG: Processing request");
        logs.add("ERROR: Connection failed");
        return logs;
    }
    
    private void retryFailedRecords(AmazonKinesis client, String streamName, List<PutRecordsRequestEntry> failedRecords) {
        PutRecordsRequest request = new PutRecordsRequest()
            .withStreamName(streamName)
            .withRecords(failedRecords);
        
        PutRecordsResult result = client.putRecords(request);
        if (result.getFailedRecordCount() > 0) {
            logger.warning("Still failed to put " + result.getFailedRecordCount() + " records after retry");
            // Could implement further retry logic here
        }
    }
    
    private void handleFailedRecord(PutRecordsRequestEntry record, PutRecordsResultEntry result) {
        logger.warning("Handling failed record with error: " + result.getErrorCode());
        // Implementation for handling failed records
    }
    
    private void saveFailedRecordForRetry(PutRecordsRequestEntry entry) {
        // Implementation to save failed record for later retry
        logger.info("Saved failed record for retry");
    }
    
    private void retryWithBackoff(AmazonKinesis client, String streamName, 
                                 List<PutRecordsRequestEntry> entries, int attempt) {
        if (attempt > 3) {
            logger.severe("Failed to put records after 3 attempts");
            return;
        }
        
        try {
            // Exponential backoff
            Thread.sleep((long) Math.pow(2, attempt) * 100);
            
            PutRecordsRequest request = new PutRecordsRequest()
                .withStreamName(streamName)
                .withRecords(entries);
            
            PutRecordsResult result = client.putRecords(request);
            
            if (result.getFailedRecordCount() > 0) {
                List<PutRecordsRequestEntry> stillFailedEntries = new ArrayList<>();
                List<PutRecordsResultEntry> records = result.getRecords();
                
                for (int i = 0; i < records.size(); i++) {
                    if (records.get(i).getErrorCode() != null) {
                        stillFailedEntries.add(entries.get(i));
                    }
                }
                
                if (!stillFailedEntries.isEmpty()) {
                    retryWithBackoff(client, streamName, stillFailedEntries, attempt + 1);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.severe("Retry interrupted: " + e.getMessage());
        }
    }
    
    private void storeFailedReading(PutRecordsRequestEntry entry) {
        // Implementation to store failed sensor reading
        logger.info("Stored failed sensor reading for later processing");
    }
    
    private void retryUserEvents(AmazonKinesis client, List<PutRecordsRequestEntry> failedEntries) {
        // Implementation to retry user events
        logger.info("Retrying " + failedEntries.size() + " failed user events");
    }
    
    private void processBatchFailures(List<PutRecordsRequestEntry> entries, List<Integer> failedIndices) {
        // Implementation to process batch failures
        logger.info("Processing " + failedIndices.size() + " batch failures");
    }
    
    private void handleFailedNotification(PutRecordsRequestEntry entry, PutRecordsResultEntry result) {
        // Implementation to handle failed notification
        logger.info("Handling failed notification: " + result.getErrorCode());
    }
    
    private void saveFailedLogEntry(PutRecordsRequestEntry entry) {
        // Implementation to save failed log entry
        logger.info("Saved failed log entry to local storage");
    }
    
    private void handleOrderEventFailure(PutRecordsRequestEntry entry, PutRecordsResultEntry result) {
        // Implementation to handle order event failure
        logger.info("Handling order event failure: " + result.getErrorCode());
    }
    
    private void queueForRetry(PutRecordsRequestEntry entry) {
        // Implementation to queue for retry
        logger.info("Queued failed record for retry");
    }
    
    private void retryFailedMetrics(AmazonKinesis client, List<PutRecordsRequestEntry> failedEntries) {
        // Implementation to retry failed metrics
        logger.info("Retrying " + failedEntries.size() + " failed metrics");
    }
}
// {/fact}