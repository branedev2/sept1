import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.dynamodb.AmazonDynamoDB;
import com.amazonaws.services.dynamodb.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodb.model.ScanRequest;
import com.amazonaws.services.dynamodb.model.ScanResult;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.amazonaws.services.lambda.model.InvokeResult;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import com.amazonaws.services.sns.model.PublishRequest;
import com.amazonaws.services.sns.model.PublishResult;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.amazonaws.services.sqs.model.SendMessageResult;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.DescribeInstancesRequest;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.rds.AmazonRDS;
import com.amazonaws.services.rds.AmazonRDSClientBuilder;
import com.amazonaws.services.rds.model.DescribeDBInstancesRequest;
import com.amazonaws.services.rds.model.DescribeDBInstancesResult;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.AmazonClientException;
import com.amazonaws.SdkClientException;
import java.util.Map;
import java.util.HashMap;

public class UncaughtExceptionsExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=check-uncaught-exceptions@v1.0 defects=1}
    public void bad_case_1() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // ruleid: java-check-uncaught-exceptions
        S3Object object = s3Client.getObject("my-bucket", "my-key");
        // No exception handling for potential AmazonServiceException or AmazonClientException
    }

    public void bad_case_2() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        ScanRequest scanRequest = new ScanRequest().withTableName("my-table");
        
        // ruleid: java-check-uncaught-exceptions
        ScanResult result = dynamoDBClient.scan(scanRequest);
        // No exception handling for potential DynamoDB exceptions
    }

    public void bad_case_3() {
        AWSLambda lambdaClient = AWSLambdaClientBuilder.standard().build();
        InvokeRequest invokeRequest = new InvokeRequest()
            .withFunctionName("my-function")
            .withPayload("{}");
            
        // ruleid: java-check-uncaught-exceptions
        InvokeResult result = lambdaClient.invoke(invokeRequest);
        // No exception handling for Lambda invocation exceptions
    }

    public void bad_case_4() {
        AmazonSNS snsClient = AmazonSNSClientBuilder.standard().build();
        PublishRequest publishRequest = new PublishRequest()
            .withTopicArn("arn:aws:sns:us-east-1:123456789012:my-topic")
            .withMessage("Hello, SNS!");
            
        // ruleid: java-check-uncaught-exceptions
        PublishResult result = snsClient.publish(publishRequest);
        // No exception handling for SNS publish exceptions
    }

    public void bad_case_5() {
        AmazonSQS sqsClient = AmazonSQSClientBuilder.standard().build();
        SendMessageRequest sendMessageRequest = new SendMessageRequest()
            .withQueueUrl("https://sqs.us-east-1.amazonaws.com/123456789012/my-queue")
            .withMessageBody("Hello, SQS!");
            
        // ruleid: java-check-uncaught-exceptions
        SendMessageResult result = sqsClient.sendMessage(sendMessageRequest);
        // No exception handling for SQS exceptions
    }

    public void bad_case_6() {
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        DescribeInstancesRequest request = new DescribeInstancesRequest();
        
        // ruleid: java-check-uncaught-exceptions
        DescribeInstancesResult result = ec2Client.describeInstances(request);
        // No exception handling for EC2 API exceptions
    }

    public void bad_case_7() {
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard().build();
        DescribeDBInstancesRequest request = new DescribeDBInstancesRequest();
        
        // ruleid: java-check-uncaught-exceptions
        DescribeDBInstancesResult result = rdsClient.describeDBInstances(request);
        // No exception handling for RDS API exceptions
    }

    public void bad_case_8() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // ruleid: java-check-uncaught-exceptions
        boolean exists = s3Client.doesBucketExistV2("my-non-existent-bucket");
        // No exception handling for S3 API exceptions
    }

    public void bad_case_9() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, String> expressionAttributeNames = new HashMap<>();
        expressionAttributeNames.put("#yr", "year");
        
        // ruleid: java-check-uncaught-exceptions
        dynamoDBClient.deleteTable("my-table");
        // No exception handling for DynamoDB exceptions
    }

    public void bad_case_10() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        try {
            s3Client.getObject("bucket1", "key1");
        } catch (AmazonServiceException e) {
            // First exception is handled
        }
        
        // ruleid: java-check-uncaught-exceptions
        s3Client.getObject("bucket2", "key2");
        // Second call has no exception handling
    }

    public void bad_case_11() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        if (true) {
            // ruleid: java-check-uncaught-exceptions
            s3Client.putObject("my-bucket", "my-key", "content");
            // No exception handling within conditional block
        }
    }

    public void bad_case_12() {
        AmazonSNS snsClient = AmazonSNSClientBuilder.standard().build();
        
        for (int i = 0; i < 5; i++) {
            // ruleid: java-check-uncaught-exceptions
            snsClient.createTopic("topic-" + i);
            // No exception handling within loop
        }
    }

    public void bad_case_13() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ruleid: java-check-uncaught-exceptions
        s3Client.listBuckets();
        dynamoDBClient.listTables();
        // Multiple AWS API calls without exception handling
    }

    public void bad_case_14() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        try {
            // Some other operation
            System.out.println("Doing something else");
        } catch (Exception e) {
            // Exception handling for the wrong operation
        }
        
        // ruleid: java-check-uncaught-exceptions
        s3Client.deleteObject("my-bucket", "my-key");
        // No exception handling for the AWS API call
    }

    public void bad_case_15() {
        Runnable task = () -> {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            // ruleid: java-check-uncaught-exceptions
            s3Client.getBucketLocation("my-bucket");
            // No exception handling in lambda expression
        };
        new Thread(task).start();
    }

    // True Negative Examples (Safe Code)

    public void good_case_1() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        try {
            // ok: java-check-uncaught-exceptions
            S3Object object = s3Client.getObject("my-bucket", "my-key");
            // Process the object
        } catch (AmazonServiceException ase) {
            System.err.println("Service error: " + ase.getMessage());
        } catch (AmazonClientException ace) {
            System.err.println("Client error: " + ace.getMessage());
        }
    }

    public void good_case_2() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        ScanRequest scanRequest = new ScanRequest().withTableName("my-table");
        
        try {
            // ok: java-check-uncaught-exceptions
            ScanResult result = dynamoDBClient.scan(scanRequest);
            // Process the result
        } catch (Exception e) {
            System.err.println("Error scanning DynamoDB table: " + e.getMessage());
        }
    }

    public void good_case_3() {
        AWSLambda lambdaClient = AWSLambdaClientBuilder.standard().build();
        InvokeRequest invokeRequest = new InvokeRequest()
            .withFunctionName("my-function")
            .withPayload("{}");
            
        try {
            // ok: java-check-uncaught-exceptions
            InvokeResult result = lambdaClient.invoke(invokeRequest);
            // Process the result
        } catch (AmazonServiceException ase) {
            System.err.println("Lambda invocation failed: " + ase.getMessage());
        } catch (AmazonClientException ace) {
            System.err.println("Client error: " + ace.getMessage());
        }
    }

    public void good_case_4() {
        AmazonSNS snsClient = AmazonSNSClientBuilder.standard().build();
        PublishRequest publishRequest = new PublishRequest()
            .withTopicArn("arn:aws:sns:us-east-1:123456789012:my-topic")
            .withMessage("Hello, SNS!");
            
        try {
            // ok: java-check-uncaught-exceptions
            PublishResult result = snsClient.publish(publishRequest);
            System.out.println("Message published with ID: " + result.getMessageId());
        } catch (Exception e) {
            System.err.println("Failed to publish message: " + e.getMessage());
        }
    }

    public void good_case_5() {
        AmazonSQS sqsClient = AmazonSQSClientBuilder.standard().build();
        SendMessageRequest sendMessageRequest = new SendMessageRequest()
            .withQueueUrl("https://sqs.us-east-1.amazonaws.com/123456789012/my-queue")
            .withMessageBody("Hello, SQS!");
            
        try {
            // ok: java-check-uncaught-exceptions
            SendMessageResult result = sqsClient.sendMessage(sendMessageRequest);
            System.out.println("Message sent with ID: " + result.getMessageId());
        } catch (AmazonServiceException ase) {
            System.err.println("Service error: " + ase.getMessage());
        } catch (AmazonClientException ace) {
            System.err.println("Client error: " + ace.getMessage());
        }
    }

    public void good_case_6() {
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        DescribeInstancesRequest request = new DescribeInstancesRequest();
        
        try {
            // ok: java-check-uncaught-exceptions
            DescribeInstancesResult result = ec2Client.describeInstances(request);
            // Process the result
        } catch (Exception e) {
            System.err.println("Failed to describe EC2 instances: " + e.getMessage());
        }
    }

    public void good_case_7() {
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard().build();
        DescribeDBInstancesRequest request = new DescribeDBInstancesRequest();
        
        try {
            // ok: java-check-uncaught-exceptions
            DescribeDBInstancesResult result = rdsClient.describeDBInstances(request);
            // Process the result
        } catch (AmazonServiceException ase) {
            System.err.println("RDS service error: " + ase.getMessage());
        } catch (AmazonClientException ace) {
            System.err.println("RDS client error: " + ace.getMessage());
        }
    }

    public void good_case_8() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        try {
            // ok: java-check-uncaught-exceptions
            boolean exists = s3Client.doesBucketExistV2("my-non-existent-bucket");
            if (exists) {
                System.out.println("Bucket exists");
            } else {
                System.out.println("Bucket does not exist");
            }
        } catch (SdkClientException e) {
            System.err.println("Error checking bucket existence: " + e.getMessage());
        }
    }

    public void good_case_9() {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        try {
            // ok: java-check-uncaught-exceptions
            dynamoDBClient.deleteTable("my-table");
            System.out.println("Table deletion initiated");
        } catch (Exception e) {
            System.err.println("Failed to delete table: " + e.getMessage());
        }
    }

    public void good_case_10() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        try {
            // ok: java-check-uncaught-exceptions
            s3Client.getObject("bucket1", "key1");
            s3Client.getObject("bucket2", "key2");
            // Multiple AWS API calls within the same try-catch block
        } catch (AmazonServiceException e) {
            System.err.println("Service error: " + e.getMessage());
        } catch (AmazonClientException e) {
            System.err.println("Client error: " + e.getMessage());
        }
    }

    public void good_case_11() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        if (true) {
            try {
                // ok: java-check-uncaught-exceptions
                s3Client.putObject("my-bucket", "my-key", "content");
                System.out.println("Object uploaded successfully");
            } catch (Exception e) {
                System.err.println("Failed to upload object: " + e.getMessage());
            }
        }
    }

    public void good_case_12() {
        AmazonSNS snsClient = AmazonSNSClientBuilder.standard().build();
        
        for (int i = 0; i < 5; i++) {
            try {
                // ok: java-check-uncaught-exceptions
                snsClient.createTopic("topic-" + i);
                System.out.println("Topic created: topic-" + i);
            } catch (Exception e) {
                System.err.println("Failed to create topic: " + e.getMessage());
            }
        }
    }

    public void good_case_13() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        try {
            // ok: java-check-uncaught-exceptions
            s3Client.listBuckets();
            dynamoDBClient.listTables();
            // Multiple AWS API calls within the same try-catch block
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    public void good_case_14() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        try {
            System.out.println("Doing something else");
            // ok: java-check-uncaught-exceptions
            s3Client.deleteObject("my-bucket", "my-key");
            // AWS API call is within the try-catch block
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    public void good_case_15() {
        Runnable task = () -> {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            try {
                // ok: java-check-uncaught-exceptions
                s3Client.getBucketLocation("my-bucket");
                System.out.println("Got bucket location");
            } catch (Exception e) {
                System.err.println("Error getting bucket location: " + e.getMessage());
            }
        };
        new Thread(task).start();
    }
}
// {/fact}