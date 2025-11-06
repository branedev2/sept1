import com.amazonaws.services.kinesis.AmazonKinesis;
import com.amazonaws.services.kinesis.AmazonKinesisClientBuilder;
import com.amazonaws.services.kinesis.model.*;
import software.amazon.awssdk.services.kinesis.KinesisClient;
import software.amazon.awssdk.services.kinesis.model.PutRecordsRequest;
import software.amazon.awssdk.services.kinesis.model.PutRecordsResponse;
import software.amazon.awssdk.services.kinesis.model.PutRecordsRequestEntry;
import software.amazon.awssdk.core.SdkBytes;
import com.amazonaws.services.firehose.AmazonKinesisFirehose;
import com.amazonaws.services.firehose.AmazonKinesisFirehoseClientBuilder;
import com.amazonaws.services.firehose.model.*;
import software.amazon.awssdk.services.firehose.FirehoseClient;
import software.amazon.awssdk.services.firehose.model.*;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.*;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.*;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.*;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import com.amazonaws.services.sns.model.*;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.*;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.*;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.*;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.*;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import com.amazonaws.services.batch.AWSBatch;
import com.amazonaws.services.batch.AWSBatchClientBuilder;
import com.amazonaws.services.batch.model.*;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

// Security Issue: Batch requests to AWS services can result in partial failures, leading to potential data loss if not properly handled.

// True Positive Examples (Vulnerable/Insecure Code)
public class KinesisPartialFailureTests {

// {fact rule=aws-dynamodb-mapper-batch-output-ignored@v1.0 defects=1}
    public void bad_case_1() {
        // AWS SDK v1 Kinesis PutRecords without checking failures
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap("data1".getBytes()))
                .withPartitionKey("key1"));
        entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap("data2".getBytes()))
                .withPartitionKey("key2"));
        
        PutRecordsRequest request = new PutRecordsRequest()
                .withStreamName("myStream")
                .withRecords(entries);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        
        // No checking of failed records
        System.out.println("Records sent: " + entries.size());
    }

    public void bad_case_2() {
        // AWS SDK v2 Kinesis PutRecords without checking failures
        KinesisClient kinesisClient = KinesisClient.create();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        entries.add(software.amazon.awssdk.services.kinesis.model.PutRecordsRequestEntry.builder()
                .data(SdkBytes.fromUtf8String("data1"))
                .partitionKey("key1")
                .build());
        entries.add(software.amazon.awssdk.services.kinesis.model.PutRecordsRequestEntry.builder()
                .data(SdkBytes.fromUtf8String("data2"))
                .partitionKey("key2")
                .build());
        
        PutRecordsRequest request = PutRecordsRequest.builder()
                .streamName("myStream")
                .records(entries)
                .build();
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        PutRecordsResponse response = kinesisClient.putRecords(request);
        
        // No checking of failed records
        System.out.println("Request completed");
    }

    public void bad_case_3() {
        // AWS SDK v1 Firehose PutRecordBatch without checking failures
        AmazonKinesisFirehose firehoseClient = AmazonKinesisFirehoseClientBuilder.defaultClient();
        
        List<Record> records = new ArrayList<>();
        records.add(new Record().withData(ByteBuffer.wrap("data1".getBytes())));
        records.add(new Record().withData(ByteBuffer.wrap("data2".getBytes())));
        
        PutRecordBatchRequest request = new PutRecordBatchRequest()
                .withDeliveryStreamName("myDeliveryStream")
                .withRecords(records);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        PutRecordBatchResult result = firehoseClient.putRecordBatch(request);
        
        // No checking of failed records
        System.out.println("Batch sent to Firehose");
    }

    public void bad_case_4() {
        // AWS SDK v2 Firehose PutRecordBatch without checking failures
        FirehoseClient firehoseClient = FirehoseClient.create();
        
        List<software.amazon.awssdk.services.firehose.model.Record> records = new ArrayList<>();
        records.add(software.amazon.awssdk.services.firehose.model.Record.builder()
                .data(SdkBytes.fromUtf8String("data1"))
                .build());
        records.add(software.amazon.awssdk.services.firehose.model.Record.builder()
                .data(SdkBytes.fromUtf8String("data2"))
                .build());
        
        software.amazon.awssdk.services.firehose.model.PutRecordBatchRequest request = 
                software.amazon.awssdk.services.firehose.model.PutRecordBatchRequest.builder()
                .deliveryStreamName("myDeliveryStream")
                .records(records)
                .build();
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        software.amazon.awssdk.services.firehose.model.PutRecordBatchResponse response = 
                firehoseClient.putRecordBatch(request);
        
        // No checking of failed records
        System.out.println("Batch sent");
    }

    public void bad_case_5() {
        // AWS SDK v1 DynamoDB BatchWriteItem without checking failures
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.defaultClient();
        
        java.util.Map<String, List<WriteRequest>> requestItems = new java.util.HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        writeRequests.add(new WriteRequest().withPutRequest(
                new PutRequest().withItem(java.util.Collections.singletonMap("id", new AttributeValue("1")))));
        writeRequests.add(new WriteRequest().withPutRequest(
                new PutRequest().withItem(java.util.Collections.singletonMap("id", new AttributeValue("2")))));
        
        requestItems.put("myTable", writeRequests);
        
        BatchWriteItemRequest request = new BatchWriteItemRequest().withRequestItems(requestItems);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        BatchWriteItemResult result = dynamoDBClient.batchWriteItem(request);
        
        // No checking of unprocessed items
        System.out.println("Batch write completed");
    }

    public void bad_case_6() {
        // AWS SDK v2 DynamoDB BatchWriteItem without checking failures
        DynamoDbClient dynamoDbClient = DynamoDbClient.create();
        
        java.util.Map<String, List<software.amazon.awssdk.services.dynamodb.model.WriteRequest>> requestItems = 
                new java.util.HashMap<>();
        
        List<software.amazon.awssdk.services.dynamodb.model.WriteRequest> writeRequests = new ArrayList<>();
        
        java.util.Map<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue> item1 = 
                java.util.Collections.singletonMap("id", 
                        software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder().s("1").build());
        
        java.util.Map<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue> item2 = 
                java.util.Collections.singletonMap("id", 
                        software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder().s("2").build());
        
        writeRequests.add(software.amazon.awssdk.services.dynamodb.model.WriteRequest.builder()
                .putRequest(software.amazon.awssdk.services.dynamodb.model.PutRequest.builder().item(item1).build())
                .build());
        
        writeRequests.add(software.amazon.awssdk.services.dynamodb.model.WriteRequest.builder()
                .putRequest(software.amazon.awssdk.services.dynamodb.model.PutRequest.builder().item(item2).build())
                .build());
        
        requestItems.put("myTable", writeRequests);
        
        software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest request = 
                software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest.builder()
                .requestItems(requestItems)
                .build();
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        software.amazon.awssdk.services.dynamodb.model.BatchWriteItemResponse response = 
                dynamoDbClient.batchWriteItem(request);
        
        // No checking of unprocessed items
        System.out.println("Batch write completed");
    }

    public void bad_case_7() {
        // AWS SDK v1 SQS SendMessageBatch without checking failures
        AmazonSQS sqsClient = AmazonSQSClientBuilder.defaultClient();
        
        List<SendMessageBatchRequestEntry> entries = new ArrayList<>();
        entries.add(new SendMessageBatchRequestEntry("1", "message1"));
        entries.add(new SendMessageBatchRequestEntry("2", "message2"));
        
        SendMessageBatchRequest request = new SendMessageBatchRequest()
                .withQueueUrl("https://sqs.region.amazonaws.com/123456789012/myQueue")
                .withEntries(entries);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        SendMessageBatchResult result = sqsClient.sendMessageBatch(request);
        
        // No checking of failed messages
        System.out.println("Messages sent to SQS");
    }

    public void bad_case_8() {
        // AWS SDK v2 SQS SendMessageBatch without checking failures
        SqsClient sqsClient = SqsClient.create();
        
        List<software.amazon.awssdk.services.sqs.model.SendMessageBatchRequestEntry> entries = new ArrayList<>();
        entries.add(software.amazon.awssdk.services.sqs.model.SendMessageBatchRequestEntry.builder()
                .id("1")
                .messageBody("message1")
                .build());
        entries.add(software.amazon.awssdk.services.sqs.model.SendMessageBatchRequestEntry.builder()
                .id("2")
                .messageBody("message2")
                .build());
        
        software.amazon.awssdk.services.sqs.model.SendMessageBatchRequest request = 
                software.amazon.awssdk.services.sqs.model.SendMessageBatchRequest.builder()
                .queueUrl("https://sqs.region.amazonaws.com/123456789012/myQueue")
                .entries(entries)
                .build();
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        software.amazon.awssdk.services.sqs.model.SendMessageBatchResponse response = 
                sqsClient.sendMessageBatch(request);
        
        // No checking of failed messages
        System.out.println("Messages sent");
    }

    public void bad_case_9() {
        // AWS SDK v1 SNS PublishBatch without checking failures
        AmazonSNS snsClient = AmazonSNSClientBuilder.defaultClient();
        
        List<PublishBatchRequestEntry> entries = new ArrayList<>();
        entries.add(new PublishBatchRequestEntry()
                .withId("1")
                .withMessage("message1"));
        entries.add(new PublishBatchRequestEntry()
                .withId("2")
                .withMessage("message2"));
        
        PublishBatchRequest request = new PublishBatchRequest()
                .withTopicArn("arn:aws:sns:region:123456789012:myTopic")
                .withPublishBatchRequestEntries(entries);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        PublishBatchResult result = snsClient.publishBatch(request);
        
        // No checking of failed messages
        System.out.println("Messages published to SNS");
    }

    public void bad_case_10() {
        // AWS SDK v2 SNS PublishBatch without checking failures
        SnsClient snsClient = SnsClient.create();
        
        List<software.amazon.awssdk.services.sns.model.PublishBatchRequestEntry> entries = new ArrayList<>();
        entries.add(software.amazon.awssdk.services.sns.model.PublishBatchRequestEntry.builder()
                .id("1")
                .message("message1")
                .build());
        entries.add(software.amazon.awssdk.services.sns.model.PublishBatchRequestEntry.builder()
                .id("2")
                .message("message2")
                .build());
        
        software.amazon.awssdk.services.sns.model.PublishBatchRequest request = 
                software.amazon.awssdk.services.sns.model.PublishBatchRequest.builder()
                .topicArn("arn:aws:sns:region:123456789012:myTopic")
                .publishBatchRequestEntries(entries)
                .build();
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        software.amazon.awssdk.services.sns.model.PublishBatchResponse response = 
                snsClient.publishBatch(request);
        
        // No checking of failed messages
        System.out.println("Messages published");
    }

    public void bad_case_11() {
        // AWS SDK v1 Lambda InvokeAsync without checking failures
        AWSLambda lambdaClient = AWSLambdaClientBuilder.defaultClient();
        
        InvokeAsyncRequest request = new InvokeAsyncRequest()
                .withFunctionName("myFunction")
                .withInvokeArgs(ByteBuffer.wrap("{\"key\":\"value\"}".getBytes()));
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        InvokeAsyncResult result = lambdaClient.invokeAsync(request);
        
        // No checking of status code
        System.out.println("Lambda function invoked");
    }

    public void bad_case_12() {
        // AWS SDK v1 S3 multipart upload without checking failures
        AmazonS3 s3Client = AmazonS3ClientBuilder.defaultClient();
        
        InitiateMultipartUploadRequest initRequest = new InitiateMultipartUploadRequest("mybucket", "mykey");
        InitiateMultipartUploadResult initResponse = s3Client.initiateMultipartUpload(initRequest);
        
        List<PartETag> partETags = new ArrayList<>();
        
        // Upload parts
        UploadPartRequest uploadRequest1 = new UploadPartRequest()
                .withBucketName("mybucket")
                .withKey("mykey")
                .withUploadId(initResponse.getUploadId())
                .withPartNumber(1)
                .withPartSize(5242880)
                .withFile(new java.io.File("/path/to/file"));
        
        UploadPartRequest uploadRequest2 = new UploadPartRequest()
                .withBucketName("mybucket")
                .withKey("mykey")
                .withUploadId(initResponse.getUploadId())
                .withPartNumber(2)
                .withPartSize(5242880)
                .withFile(new java.io.File("/path/to/file"));
        
        partETags.add(s3Client.uploadPart(uploadRequest1).getPartETag());
        partETags.add(s3Client.uploadPart(uploadRequest2).getPartETag());
        
        CompleteMultipartUploadRequest compRequest = new CompleteMultipartUploadRequest(
                "mybucket", "mykey", initResponse.getUploadId(), partETags);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        CompleteMultipartUploadResult result = s3Client.completeMultipartUpload(compRequest);
        
        // No checking of failures
        System.out.println("Upload completed");
    }

    public void bad_case_13() {
        // AWS SDK v2 S3 multipart upload without checking failures
        S3Client s3Client = S3Client.create();
        
        software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest createRequest = 
                software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest.builder()
                .bucket("mybucket")
                .key("mykey")
                .build();
        
        software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse createResponse = 
                s3Client.createMultipartUpload(createRequest);
        
        List<software.amazon.awssdk.services.s3.model.CompletedPart> completedParts = new ArrayList<>();
        
        // Upload parts
        software.amazon.awssdk.services.s3.model.UploadPartRequest uploadRequest1 = 
                software.amazon.awssdk.services.s3.model.UploadPartRequest.builder()
                .bucket("mybucket")
                .key("mykey")
                .uploadId(createResponse.uploadId())
                .partNumber(1)
                .build();
        
        software.amazon.awssdk.services.s3.model.UploadPartRequest uploadRequest2 = 
                software.amazon.awssdk.services.s3.model.UploadPartRequest.builder()
                .bucket("mybucket")
                .key("mykey")
                .uploadId(createResponse.uploadId())
                .partNumber(2)
                .build();
        
        // Assume we have the part responses
        completedParts.add(software.amazon.awssdk.services.s3.model.CompletedPart.builder()
                .partNumber(1)
                .eTag("etag1")
                .build());
        completedParts.add(software.amazon.awssdk.services.s3.model.CompletedPart.builder()
                .partNumber(2)
                .eTag("etag2")
                .build());
        
        software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest completeRequest = 
                software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest.builder()
                .bucket("mybucket")
                .key("mykey")
                .uploadId(createResponse.uploadId())
                .multipartUpload(software.amazon.awssdk.services.s3.model.CompletedMultipartUpload.builder()
                        .parts(completedParts)
                        .build())
                .build();
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse completeResponse = 
                s3Client.completeMultipartUpload(completeRequest);
        
        // No checking of failures
        System.out.println("Upload completed");
    }

    public void bad_case_14() {
        // AWS SDK v1 Batch SubmitJob without checking failures
        AWSBatch batchClient = AWSBatchClientBuilder.defaultClient();
        
        SubmitJobRequest request = new SubmitJobRequest()
                .withJobName("myJob")
                .withJobQueue("myQueue")
                .withJobDefinition("myJobDef");
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        SubmitJobResult result = batchClient.submitJob(request);
        
        // No checking of job status
        System.out.println("Job submitted: " + result.getJobId());
    }

    public void bad_case_15() {
        // AWS SDK v1 DynamoDB BatchGetItem without checking failures
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.defaultClient();
        
        java.util.Map<String, KeysAndAttributes> requestItems = new java.util.HashMap<>();
        
        List<java.util.Map<String, AttributeValue>> keys = new ArrayList<>();
        keys.add(java.util.Collections.singletonMap("id", new AttributeValue("1")));
        keys.add(java.util.Collections.singletonMap("id", new AttributeValue("2")));
        
        requestItems.put("myTable", new KeysAndAttributes().withKeys(keys));
        
        BatchGetItemRequest request = new BatchGetItemRequest().withRequestItems(requestItems);
        
        // ruleid: java-checking-failed-put-objects-to-kinesis
        BatchGetItemResult result = dynamoDBClient.batchGetItem(request);
        
        // No checking of unprocessed keys
        System.out.println("Batch get completed");
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1() {
        // AWS SDK v1 Kinesis PutRecords with proper failure checking
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap("data1".getBytes()))
                .withPartitionKey("key1"));
        entries.add(new PutRecordsRequestEntry()
                .withData(ByteBuffer.wrap("data2".getBytes()))
                .withPartitionKey("key2"));
        
        PutRecordsRequest request = new PutRecordsRequest()
                .withStreamName("myStream")
                .withRecords(entries);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        PutRecordsResult result = kinesisClient.putRecords(request);
        
        // Properly checking for failed records
        if (result.getFailedRecordCount() > 0) {
            System.out.println("Some records failed to be put to Kinesis");
            List<PutRecordsResultEntry> records = result.getRecords();
            for (int i = 0; i < records.size(); i++) {
                if (records.get(i).getErrorCode() != null) {
                    System.out.println("Record " + i + " failed with error: " + records.get(i).getErrorMessage());
                    // Handle retry logic here
                }
            }
        }
    }

    public void good_case_2() {
        // AWS SDK v2 Kinesis PutRecords with proper failure checking
        KinesisClient kinesisClient = KinesisClient.create();
        
        List<PutRecordsRequestEntry> entries = new ArrayList<>();
        entries.add(software.amazon.awssdk.services.kinesis.model.PutRecordsRequestEntry.builder()
                .data(SdkBytes.fromUtf8String("data1"))
                .partitionKey("key1")
                .build());
        entries.add(software.amazon.awssdk.services.kinesis.model.PutRecordsRequestEntry.builder()
                .data(SdkBytes.fromUtf8String("data2"))
                .partitionKey("key2")
                .build());
        
        PutRecordsRequest request = PutRecordsRequest.builder()
                .streamName("myStream")
                .records(entries)
                .build();
        
        // ok: java-checking-failed-put-objects-to-kinesis
        PutRecordsResponse response = kinesisClient.putRecords(request);
        
        // Properly checking for failed records
        if (response.failedRecordCount() > 0) {
            System.out.println("Some records failed to be put to Kinesis");
            List<software.amazon.awssdk.services.kinesis.model.PutRecordsResultEntry> records = response.records();
            for (int i = 0; i < records.size(); i++) {
                if (records.get(i).errorCode() != null) {
                    System.out.println("Record " + i + " failed with error: " + records.get(i).errorMessage());
                    // Handle retry logic here
                }
            }
        }
    }

    public void good_case_3() {
        // AWS SDK v1 Firehose PutRecordBatch with proper failure checking
        AmazonKinesisFirehose firehoseClient = AmazonKinesisFirehoseClientBuilder.defaultClient();
        
        List<Record> records = new ArrayList<>();
        records.add(new Record().withData(ByteBuffer.wrap("data1".getBytes())));
        records.add(new Record().withData(ByteBuffer.wrap("data2".getBytes())));
        
        PutRecordBatchRequest request = new PutRecordBatchRequest()
                .withDeliveryStreamName("myDeliveryStream")
                .withRecords(records);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        PutRecordBatchResult result = firehoseClient.putRecordBatch(request);
        
        // Properly checking for failed records
        if (result.getFailedPutCount() > 0) {
            System.out.println("Some records failed to be put to Firehose");
            List<PutRecordBatchResponseEntry> responseEntries = result.getRequestResponses();
            for (int i = 0; i < responseEntries.size(); i++) {
                if (responseEntries.get(i).getErrorCode() != null) {
                    System.out.println("Record " + i + " failed with error: " + responseEntries.get(i).getErrorMessage());
                    // Handle retry logic here
                }
            }
        }
    }

    public void good_case_4() {
        // AWS SDK v2 Firehose PutRecordBatch with proper failure checking
        FirehoseClient firehoseClient = FirehoseClient.create();
        
        List<software.amazon.awssdk.services.firehose.model.Record> records = new ArrayList<>();
        records.add(software.amazon.awssdk.services.firehose.model.Record.builder()
                .data(SdkBytes.fromUtf8String("data1"))
                .build());
        records.add(software.amazon.awssdk.services.firehose.model.Record.builder()
                .data(SdkBytes.fromUtf8String("data2"))
                .build());
        
        software.amazon.awssdk.services.firehose.model.PutRecordBatchRequest request = 
                software.amazon.awssdk.services.firehose.model.PutRecordBatchRequest.builder()
                .deliveryStreamName("myDeliveryStream")
                .records(records)
                .build();
        
        // ok: java-checking-failed-put-objects-to-kinesis
        software.amazon.awssdk.services.firehose.model.PutRecordBatchResponse response = 
                firehoseClient.putRecordBatch(request);
        
        // Properly checking for failed records
        if (response.failedPutCount() > 0) {
            System.out.println("Some records failed to be put to Firehose");
            List<software.amazon.awssdk.services.firehose.model.PutRecordBatchResponseEntry> responseEntries = 
                    response.requestResponses();
            for (int i = 0; i < responseEntries.size(); i++) {
                if (responseEntries.get(i).errorCode() != null) {
                    System.out.println("Record " + i + " failed with error: " + responseEntries.get(i).errorMessage());
                    // Handle retry logic here
                }
            }
        }
    }

    public void good_case_5() {
        // AWS SDK v1 DynamoDB BatchWriteItem with proper failure checking
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.defaultClient();
        
        java.util.Map<String, List<WriteRequest>> requestItems = new java.util.HashMap<>();
        List<WriteRequest> writeRequests = new ArrayList<>();
        
        writeRequests.add(new WriteRequest().withPutRequest(
                new PutRequest().withItem(java.util.Collections.singletonMap("id", new AttributeValue("1")))));
        writeRequests.add(new WriteRequest().withPutRequest(
                new PutRequest().withItem(java.util.Collections.singletonMap("id", new AttributeValue("2")))));
        
        requestItems.put("myTable", writeRequests);
        
        BatchWriteItemRequest request = new BatchWriteItemRequest().withRequestItems(requestItems);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        BatchWriteItemResult result = dynamoDBClient.batchWriteItem(request);
        
        // Properly checking for unprocessed items
        java.util.Map<String, List<WriteRequest>> unprocessedItems = result.getUnprocessedItems();
        if (!unprocessedItems.isEmpty()) {
            System.out.println("Some items were not processed");
            for (String tableName : unprocessedItems.keySet()) {
                System.out.println("Table " + tableName + " has " + unprocessedItems.get(tableName).size() + 
                        " unprocessed items");
                // Handle retry logic here
            }
        }
    }

    public void good_case_6() {
        // AWS SDK v2 DynamoDB BatchWriteItem with proper failure checking
        DynamoDbClient dynamoDbClient = DynamoDbClient.create();
        
        java.util.Map<String, List<software.amazon.awssdk.services.dynamodb.model.WriteRequest>> requestItems = 
                new java.util.HashMap<>();
        
        List<software.amazon.awssdk.services.dynamodb.model.WriteRequest> writeRequests = new ArrayList<>();
        
        java.util.Map<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue> item1 = 
                java.util.Collections.singletonMap("id", 
                        software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder().s("1").build());
        
        java.util.Map<String, software.amazon.awssdk.services.dynamodb.model.AttributeValue> item2 = 
                java.util.Collections.singletonMap("id", 
                        software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder().s("2").build());
        
        writeRequests.add(software.amazon.awssdk.services.dynamodb.model.WriteRequest.builder()
                .putRequest(software.amazon.awssdk.services.dynamodb.model.PutRequest.builder().item(item1).build())
                .build());
        
        writeRequests.add(software.amazon.awssdk.services.dynamodb.model.WriteRequest.builder()
                .putRequest(software.amazon.awssdk.services.dynamodb.model.PutRequest.builder().item(item2).build())
                .build());
        
        requestItems.put("myTable", writeRequests);
        
        software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest request = 
                software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest.builder()
                .requestItems(requestItems)
                .build();
        
        // ok: java-checking-failed-put-objects-to-kinesis
        software.amazon.awssdk.services.dynamodb.model.BatchWriteItemResponse response = 
                dynamoDbClient.batchWriteItem(request);
        
        // Properly checking for unprocessed items
        java.util.Map<String, List<software.amazon.awssdk.services.dynamodb.model.WriteRequest>> unprocessedItems = 
                response.unprocessedItems();
        if (!unprocessedItems.isEmpty()) {
            System.out.println("Some items were not processed");
            for (String tableName : unprocessedItems.keySet()) {
                System.out.println("Table " + tableName + " has " + unprocessedItems.get(tableName).size() + 
                        " unprocessed items");
                // Handle retry logic here
            }
        }
    }

    public void good_case_7() {
        // AWS SDK v1 SQS SendMessageBatch with proper failure checking
        AmazonSQS sqsClient = AmazonSQSClientBuilder.defaultClient();
        
        List<SendMessageBatchRequestEntry> entries = new ArrayList<>();
        entries.add(new SendMessageBatchRequestEntry("1", "message1"));
        entries.add(new SendMessageBatchRequestEntry("2", "message2"));
        
        SendMessageBatchRequest request = new SendMessageBatchRequest()
                .withQueueUrl("https://sqs.region.amazonaws.com/123456789012/myQueue")
                .withEntries(entries);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        SendMessageBatchResult result = sqsClient.sendMessageBatch(request);
        
        // Properly checking for failed messages
        List<BatchResultErrorEntry> failed = result.getFailed();
        if (!failed.isEmpty()) {
            System.out.println("Some messages failed to be sent");
            for (BatchResultErrorEntry error : failed) {
                System.out.println("Message " + error.getId() + " failed with error: " + error.getMessage());
                // Handle retry logic here
            }
        }
    }

    public void good_case_8() {
        // AWS SDK v2 SQS SendMessageBatch with proper failure checking
        SqsClient sqsClient = SqsClient.create();
        
        List<software.amazon.awssdk.services.sqs.model.SendMessageBatchRequestEntry> entries = new ArrayList<>();
        entries.add(software.amazon.awssdk.services.sqs.model.SendMessageBatchRequestEntry.builder()
                .id("1")
                .messageBody("message1")
                .build());
        entries.add(software.amazon.awssdk.services.sqs.model.SendMessageBatchRequestEntry.builder()
                .id("2")
                .messageBody("message2")
                .build());
        
        software.amazon.awssdk.services.sqs.model.SendMessageBatchRequest request = 
                software.amazon.awssdk.services.sqs.model.SendMessageBatchRequest.builder()
                .queueUrl("https://sqs.region.amazonaws.com/123456789012/myQueue")
                .entries(entries)
                .build();
        
        // ok: java-checking-failed-put-objects-to-kinesis
        software.amazon.awssdk.services.sqs.model.SendMessageBatchResponse response = 
                sqsClient.sendMessageBatch(request);
        
        // Properly checking for failed messages
        List<software.amazon.awssdk.services.sqs.model.BatchResultErrorEntry> failed = response.failed();
        if (!failed.isEmpty()) {
            System.out.println("Some messages failed to be sent");
            for (software.amazon.awssdk.services.sqs.model.BatchResultErrorEntry error : failed) {
                System.out.println("Message " + error.id() + " failed with error: " + error.message());
                // Handle retry logic here
            }
        }
    }

    public void good_case_9() {
        // AWS SDK v1 SNS PublishBatch with proper failure checking
        AmazonSNS snsClient = AmazonSNSClientBuilder.defaultClient();
        
        List<PublishBatchRequestEntry> entries = new ArrayList<>();
        entries.add(new PublishBatchRequestEntry()
                .withId("1")
                .withMessage("message1"));
        entries.add(new PublishBatchRequestEntry()
                .withId("2")
                .withMessage("message2"));
        
        PublishBatchRequest request = new PublishBatchRequest()
                .withTopicArn("arn:aws:sns:region:123456789012:myTopic")
                .withPublishBatchRequestEntries(entries);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        PublishBatchResult result = snsClient.publishBatch(request);
        
        // Properly checking for failed messages
        List<BatchResultErrorEntry> failed = result.getFailed();
        if (!failed.isEmpty()) {
            System.out.println("Some messages failed to be published");
            for (BatchResultErrorEntry error : failed) {
                System.out.println("Message " + error.getId() + " failed with error: " + error.getMessage());
                // Handle retry logic here
            }
        }
    }

    public void good_case_10() {
        // AWS SDK v2 SNS PublishBatch with proper failure checking
        SnsClient snsClient = SnsClient.create();
        
        List<software.amazon.awssdk.services.sns.model.PublishBatchRequestEntry> entries = new ArrayList<>();
        entries.add(software.amazon.awssdk.services.sns.model.PublishBatchRequestEntry.builder()
                .id("1")
                .message("message1")
                .build());
        entries.add(software.amazon.awssdk.services.sns.model.PublishBatchRequestEntry.builder()
                .id("2")
                .message("message2")
                .build());
        
        software.amazon.awssdk.services.sns.model.PublishBatchRequest request = 
                software.amazon.awssdk.services.sns.model.PublishBatchRequest.builder()
                .topicArn("arn:aws:sns:region:123456789012:myTopic")
                .publishBatchRequestEntries(entries)
                .build();
        
        // ok: java-checking-failed-put-objects-to-kinesis
        software.amazon.awssdk.services.sns.model.PublishBatchResponse response = 
                snsClient.publishBatch(request);
        
        // Properly checking for failed messages
        List<software.amazon.awssdk.services.sns.model.BatchResultErrorEntry> failed = response.failed();
        if (!failed.isEmpty()) {
            System.out.println("Some messages failed to be published");
            for (software.amazon.awssdk.services.sns.model.BatchResultErrorEntry error : failed) {
                System.out.println("Message " + error.id() + " failed with error: " + error.message());
                // Handle retry logic here
            }
        }
    }

    public void good_case_11() {
        // AWS SDK v1 Lambda InvokeAsync with proper status checking
        AWSLambda lambdaClient = AWSLambdaClientBuilder.defaultClient();
        
        InvokeAsyncRequest request = new InvokeAsyncRequest()
                .withFunctionName("myFunction")
                .withInvokeArgs(ByteBuffer.wrap("{\"key\":\"value\"}".getBytes()));
        
        // ok: java-checking-failed-put-objects-to-kinesis
        InvokeAsyncResult result = lambdaClient.invokeAsync(request);
        
        // Properly checking status code
        if (result.getStatus() != 202) {
            System.out.println("Lambda function invocation failed with status: " + result.getStatus());
            // Handle retry logic here
        } else {
            System.out.println("Lambda function invoked successfully");
        }
    }

    public void good_case_12() {
        // AWS SDK v1 S3 multipart upload with proper error checking
        AmazonS3 s3Client = AmazonS3ClientBuilder.defaultClient();
        
        InitiateMultipartUploadRequest initRequest = new InitiateMultipartUploadRequest("mybucket", "mykey");
        InitiateMultipartUploadResult initResponse = s3Client.initiateMultipartUpload(initRequest);
        
        List<PartETag> partETags = new ArrayList<>();
        
        try {
            // Upload parts
            UploadPartRequest uploadRequest1 = new UploadPartRequest()
                    .withBucketName("mybucket")
                    .withKey("mykey")
                    .withUploadId(initResponse.getUploadId())
                    .withPartNumber(1)
                    .withPartSize(5242880)
                    .withFile(new java.io.File("/path/to/file"));
            
            UploadPartRequest uploadRequest2 = new UploadPartRequest()
                    .withBucketName("mybucket")
                    .withKey("mykey")
                    .withUploadId(initResponse.getUploadId())
                    .withPartNumber(2)
                    .withPartSize(5242880)
                    .withFile(new java.io.File("/path/to/file"));
            
            partETags.add(s3Client.uploadPart(uploadRequest1).getPartETag());
            partETags.add(s3Client.uploadPart(uploadRequest2).getPartETag());
            
            CompleteMultipartUploadRequest compRequest = new CompleteMultipartUploadRequest(
                    "mybucket", "mykey", initResponse.getUploadId(), partETags);
            
            // ok: java-checking-failed-put-objects-to-kinesis
            CompleteMultipartUploadResult result = s3Client.completeMultipartUpload(compRequest);
            
            // Properly checking for successful completion
            if (result.getETag() != null) {
                System.out.println("Upload completed successfully with ETag: " + result.getETag());
            } else {
                System.out.println("Upload may have failed, no ETag returned");
                // Handle retry logic here
            }
        } catch (Exception e) {
            // Abort the upload on failure
            s3Client.abortMultipartUpload(new AbortMultipartUploadRequest(
                    "mybucket", "mykey", initResponse.getUploadId()));
            System.out.println("Upload failed: " + e.getMessage());
        }
    }

    public void good_case_13() {
        // AWS SDK v2 S3 multipart upload with proper error checking
        S3Client s3Client = S3Client.create();
        
        software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest createRequest = 
                software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest.builder()
                .bucket("mybucket")
                .key("mykey")
                .build();
        
        software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse createResponse = 
                s3Client.createMultipartUpload(createRequest);
        
        List<software.amazon.awssdk.services.s3.model.CompletedPart> completedParts = new ArrayList<>();
        
        try {
            // Upload parts
            software.amazon.awssdk.services.s3.model.UploadPartRequest uploadRequest1 = 
                    software.amazon.awssdk.services.s3.model.UploadPartRequest.builder()
                    .bucket("mybucket")
                    .key("mykey")
                    .uploadId(createResponse.uploadId())
                    .partNumber(1)
                    .build();
            
            software.amazon.awssdk.services.s3.model.UploadPartRequest uploadRequest2 = 
                    software.amazon.awssdk.services.s3.model.UploadPartRequest.builder()
                    .bucket("mybucket")
                    .key("mykey")
                    .uploadId(createResponse.uploadId())
                    .partNumber(2)
                    .build();
            
            // Assume we have the part responses
            completedParts.add(software.amazon.awssdk.services.s3.model.CompletedPart.builder()
                    .partNumber(1)
                    .eTag("etag1")
                    .build());
            completedParts.add(software.amazon.awssdk.services.s3.model.CompletedPart.builder()
                    .partNumber(2)
                    .eTag("etag2")
                    .build());
            
            software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest completeRequest = 
                    software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest.builder()
                    .bucket("mybucket")
                    .key("mykey")
                    .uploadId(createResponse.uploadId())
                    .multipartUpload(software.amazon.awssdk.services.s3.model.CompletedMultipartUpload.builder()
                            .parts(completedParts)
                            .build())
                    .build();
            
            // ok: java-checking-failed-put-objects-to-kinesis
            software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse completeResponse = 
                    s3Client.completeMultipartUpload(completeRequest);
            
            // Properly checking for successful completion
            if (completeResponse.eTag() != null) {
                System.out.println("Upload completed successfully with ETag: " + completeResponse.eTag());
            } else {
                System.out.println("Upload may have failed, no ETag returned");
                // Handle retry logic here
            }
        } catch (Exception e) {
            // Abort the upload on failure
            s3Client.abortMultipartUpload(software.amazon.awssdk.services.s3.model.AbortMultipartUploadRequest.builder()
                    .bucket("mybucket")
                    .key("mykey")
                    .uploadId(createResponse.uploadId())
                    .build());
            System.out.println("Upload failed: " + e.getMessage());
        }
    }

    public void good_case_14() {
        // AWS SDK v1 Batch SubmitJob with proper status checking
        AWSBatch batchClient = AWSBatchClientBuilder.defaultClient();
        
        SubmitJobRequest request = new SubmitJobRequest()
                .withJobName("myJob")
                .withJobQueue("myQueue")
                .withJobDefinition("myJobDef");
        
        // ok: java-checking-failed-put-objects-to-kinesis
        SubmitJobResult result = batchClient.submitJob(request);
        
        // Properly checking job status
        if (result.getJobId() != null && !result.getJobId().isEmpty()) {
            // Verify job status
            DescribeJobsRequest describeRequest = new DescribeJobsRequest().withJobs(result.getJobId());
            DescribeJobsResult describeResult = batchClient.describeJobs(describeRequest);
            
            if (!describeResult.getJobs().isEmpty()) {
                String status = describeResult.getJobs().get(0).getStatus();
                System.out.println("Job submitted with ID: " + result.getJobId() + " and status: " + status);
                
                if ("FAILED".equals(status)) {
                    System.out.println("Job submission failed with reason: " + 
                            describeResult.getJobs().get(0).getStatusReason());
                    // Handle retry logic here
                }
            }
        } else {
            System.out.println("Job submission failed, no job ID returned");
        }
    }

    public void good_case_15() {
        // AWS SDK v1 DynamoDB BatchGetItem with proper failure checking
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.defaultClient();
        
        java.util.Map<String, KeysAndAttributes> requestItems = new java.util.HashMap<>();
        
        List<java.util.Map<String, AttributeValue>> keys = new ArrayList<>();
        keys.add(java.util.Collections.singletonMap("id", new AttributeValue("1")));
        keys.add(java.util.Collections.singletonMap("id", new AttributeValue("2")));
        
        requestItems.put("myTable", new KeysAndAttributes().withKeys(keys));
        
        BatchGetItemRequest request = new BatchGetItemRequest().withRequestItems(requestItems);
        
        // ok: java-checking-failed-put-objects-to-kinesis
        BatchGetItemResult result = dynamoDBClient.batchGetItem(request);
        
        // Properly checking for unprocessed keys
        java.util.Map<String, KeysAndAttributes> unprocessedKeys = result.getUnprocessedKeys();
        if (!unprocessedKeys.isEmpty()) {
            System.out.println("Some keys were not processed");
            for (String tableName : unprocessedKeys.keySet()) {
                System.out.println("Table " + tableName + " has " + 
                        unprocessedKeys.get(tableName).getKeys().size() + " unprocessed keys");
                // Handle retry logic here
                BatchGetItemRequest retryRequest = new BatchGetItemRequest().withRequestItems(unprocessedKeys);
                BatchGetItemResult retryResult = dynamoDBClient.batchGetItem(retryRequest);
                // Continue processing or retry as needed
            }
        }
    }
}
// {/fact}