import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import com.amazonaws.services.lambda.runtime.events.DynamodbEvent;
import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.KinesisEvent;
import com.amazonaws.services.lambda.runtime.events.CloudWatchLogsEvent;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import com.amazonaws.services.lambda.runtime.events.CognitoEvent;
import com.amazonaws.services.lambda.runtime.events.ConfigEvent;
import com.amazonaws.services.lambda.runtime.events.IoTButtonEvent;
import com.amazonaws.services.lambda.runtime.events.LexEvent;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.kinesis.KinesisClient;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cognito.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.iot.IotClient;
import software.amazon.awssdk.services.lexruntimev2.LexRuntimeV2Client;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.apigateway.ApiGatewayClient;
import software.amazon.awssdk.services.cloudformation.CloudFormationClient;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.rds.RdsClient;
import software.amazon.awssdk.services.elasticbeanstalk.ElasticBeanstalkClient;
import software.amazon.awssdk.services.ecs.EcsClient;
import software.amazon.awssdk.services.elasticloadbalancing.ElasticLoadBalancingClient;
import software.amazon.awssdk.services.route53.Route53Client;
import software.amazon.awssdk.services.ssm.SsmClient;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

// Security Issue: Using mutable instance variables in AWS Lambda functions can lead to unexpected behavior, data leakage, and performance issues due to state persistence across invocations.

// True Positive Examples (Vulnerable/Insecure Code)

public class MutableInstanceVariableInLambdaExamples {

    // True Positive Examples (Vulnerable/Insecure Code)
    
    public static class bad_case_1 implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
        // ruleid: java-mutable-instance-variable-in-lambda
        private List<String> requestHistory = new ArrayList<>();
        private S3Client s3Client = S3Client.builder().build();
        
        @Override
        public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
            // Using mutable instance variable in Lambda function
            requestHistory.add(input.getPath());
            
            // Process with S3 client
            s3Client.listBuckets().buckets().forEach(bucket -> {
                requestHistory.add(bucket.name());
            });
            
            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(200)
                    .withBody("Processed " + requestHistory.size() + " requests");
        }
    }
    
    public static class bad_case_2 implements RequestHandler<S3Event, String> {
        // ruleid: java-mutable-instance-variable-in-lambda
        private Map<String, Integer> fileCountByBucket = new HashMap<>();
        private DynamoDbClient dynamoDbClient = DynamoDbClient.builder().build();
        
        @Override
        public String handleRequest(S3Event input, Context context) {
            input.getRecords().forEach(record -> {
                String bucketName = record.getS3().getBucket().getName();
                // Using mutable instance variable
                fileCountByBucket.put(bucketName, fileCountByBucket.getOrDefault(bucketName, 0) + 1);
            });
            
            return "Processed files in " + fileCountByBucket.size() + " buckets";
        }
    }
    
    public static class bad_case_3 implements RequestHandler<DynamodbEvent, String> {
        // ruleid: java-mutable-instance-variable-in-lambda
        private int totalRecordsProcessed = 0;
        private SnsClient snsClient = SnsClient.builder().build();
        
        @Override
        public String handleRequest(DynamodbEvent input, Context context) {
            input.getRecords().forEach(record -> {
                // Using mutable instance variable
                totalRecordsProcessed++;
                
                if (totalRecordsProcessed % 100 == 0) {
                    snsClient.publish(builder -> builder
                        .topicArn("arn:aws:sns:region:account:topic")
                        .message("Processed " + totalRecordsProcessed + " records")
                    );
                }
            });
            
            return "Total records processed: " + totalRecordsProcessed;
        }
    }
    
    public static class bad_case_4 implements RequestHandler<SNSEvent, String> {
        // ruleid: java-mutable-instance-variable-in-lambda
        private List<String> messageIds = new ArrayList<>();
        private SqsClient sqsClient = SqsClient.builder().build();
        
        @Override
        public String handleRequest(SNSEvent input, Context context) {
            input.getRecords().forEach(record -> {
                // Using mutable instance variable
                messageIds.add(record.getSns().getMessageId());
                
                sqsClient.sendMessage(builder -> builder
                    .queueUrl("https://sqs.region.amazonaws.com/account/queue")
                    .messageBody("Processed message: " + record.getSns().getMessage())
                );
            });
            
            return "Processed " + messageIds.size() + " messages";
        }
    }
    
    public static class bad_case_5 implements RequestHandler<SQSEvent, String> {
        // ruleid: java-mutable-instance-variable-in-lambda
        private Map<String, String> messageAttributes = new HashMap<>();
        private KinesisClient kinesisClient = KinesisClient.builder().build();
        
        @Override
        public String handleRequest(SQSEvent input, Context context) {
            input.getRecords().forEach(record -> {
                // Using mutable instance variable
                messageAttributes.put(record.getMessageId(), record.getBody());
                
                kinesisClient.putRecord(builder -> builder
                    .streamName("my-stream")
                    .data(software.amazon.awssdk.core.SdkBytes.fromUtf8String(record.getBody()))
                    .partitionKey("partition-key")
                );
            });
            
            return "Processed " + messageAttributes.size() + " messages";
        }
    }
    
    public static class bad_case_6 implements RequestHandler<KinesisEvent, String> {
        // ruleid: java-mutable-instance-variable-in-lambda
        private long totalBytesProcessed = 0;
        private CloudWatchClient cloudWatchClient = CloudWatchClient.builder().build();
        
        @Override
        public String handleRequest(KinesisEvent input, Context context) {
            input.getRecords().forEach(record -> {
                byte[] data = record.getKinesis().getData().array();
                // Using mutable instance variable
                totalBytesProcessed += data.length;
                
                // Process data
            });
            
            return "Processed " + totalBytesProcessed + " bytes";
        }
    }
    
    public static class bad_case_7 implements RequestHandler<CloudWatchLogsEvent, String> {
        // ruleid: java-mutable-instance-variable-in-lambda
        private int errorCount = 0;
        private CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.builder().build();
        
        @Override
        public String handleRequest(CloudWatchLogsEvent input, Context context) {
            // Process logs
            String logData = input.getAwsLogs().getData();
            if (logData.contains("ERROR")) {
                // Using mutable instance variable
                errorCount++;
            }
            
            return "Found " + errorCount + " errors";
        }
    }
    
    public static class bad_case_8 implements RequestHandler<ScheduledEvent, String> {
        // ruleid: java-mutable-instance-variable-in-lambda
        private long lastExecutionTime = 0;
        private LambdaClient lambdaClient = LambdaClient.builder().build();
        
        @Override
        public String handleRequest(ScheduledEvent input, Context context) {
            long currentTime = System.currentTimeMillis();
            long timeSinceLastExecution = 0;
            
            if (lastExecutionTime > 0) {
                // Using mutable instance variable
                timeSinceLastExecution = currentTime - lastExecutionTime;
            }
            
            // Update mutable instance variable
            lastExecutionTime = currentTime;
            
            return "Time since last execution: " + timeSinceLastExecution + " ms";
        }
    }
    
    public static class bad_case_9 implements RequestHandler<CognitoEvent, String> {
        // ruleid: java-mutable-instance-variable-in-lambda
        private Map<String, Integer> userLoginAttempts = new HashMap<>();
        private IotClient iotClient = IotClient.builder().build();
        
        @Override
        public String handleRequest(CognitoEvent input, Context context) {
            String username = input.getUserName();
            
            // Using mutable instance variable
            int attempts = userLoginAttempts.getOrDefault(username, 0) + 1;
            userLoginAttempts.put(username, attempts);
            
            if (attempts > 3) {
                // Send alert
            }
            
            return "User " + username + " has attempted login " + attempts + " times";
        }
    }
    
    public static class bad_case_10 implements RequestHandler<ConfigEvent, String> {
        // ruleid: java-mutable-instance-variable-in-lambda
        private List<String> nonCompliantResources = new ArrayList<>();
        private LexRuntimeV2Client lexClient = LexRuntimeV2Client.builder().build();
        
        @Override
        public String handleRequest(ConfigEvent input, Context context) {
            String resourceId = input.getResourceId();
            if (!input.isCompliant()) {
                // Using mutable instance variable
                nonCompliantResources.add(resourceId);
            }
            
            return "Found " + nonCompliantResources.size() + " non-compliant resources";
        }
    }
    
    public static class bad_case_11 implements RequestHandler<IoTButtonEvent, String> {
        // ruleid: java-mutable-instance-variable-in-lambda
        private int buttonPressCount = 0;
        private SecretsManagerClient secretsManagerClient = SecretsManagerClient.builder().build();
        
        @Override
        public String handleRequest(IoTButtonEvent input, Context context) {
            // Using mutable instance variable
            buttonPressCount++;
            
            String clickType = input.getClickType();
            if ("DOUBLE".equals(clickType)) {
                // Reset counter
                buttonPressCount = 0;
            }
            
            return "Button pressed " + buttonPressCount + " times";
        }
    }
    
    public static class bad_case_12 implements RequestHandler<LexEvent, String> {
        // ruleid: java-mutable-instance-variable-in-lambda
        private Map<String, String> sessionAttributes = new HashMap<>();
        private ApiGatewayClient apiGatewayClient = ApiGatewayClient.builder().build();
        
        @Override
        public String handleRequest(LexEvent input, Context context) {
            String userId = input.getUserId();
            
            // Using mutable instance variable
            sessionAttributes.putAll(input.getSessionAttributes());
            
            // Process intent
            String intentName = input.getCurrentIntent().getName();
            
            return "Processed intent " + intentName + " for user " + userId;
        }
    }
    
    public static class bad_case_13 implements RequestHandler<Map<String, Object>, String> {
        // ruleid: java-mutable-instance-variable-in-lambda
        private int invocationCount = 0;
        private CloudFormationClient cloudFormationClient = CloudFormationClient.builder().build();
        
        @Override
        public String handleRequest(Map<String, Object> input, Context context) {
            // Using mutable instance variable
            invocationCount++;
            
            return "Lambda function has been invoked " + invocationCount + " times";
        }
    }
    
    public static class bad_case_14 implements RequestHandler<Map<String, Object>, String> {
        // ruleid: java-mutable-instance-variable-in-lambda
        private Map<String, Object> cache = new HashMap<>();
        private Ec2Client ec2Client = Ec2Client.builder().build();
        
        @Override
        public String handleRequest(Map<String, Object> input, Context context) {
            String cacheKey = input.get("key").toString();
            
            if (!cache.containsKey(cacheKey)) {
                // Using mutable instance variable
                cache.put(cacheKey, "Computed value for " + cacheKey);
            }
            
            return cache.get(cacheKey).toString();
        }
    }
    
    public static class bad_case_15 implements RequestHandler<Map<String, Object>, String> {
        // ruleid: java-mutable-instance-variable-in-lambda
        private List<String> processedIds = new ArrayList<>();
        private RdsClient rdsClient = RdsClient.builder().build();
        
        @Override
        public String handleRequest(Map<String, Object> input, Context context) {
            String id = input.get("id").toString();
            
            // Using mutable instance variable
            if (!processedIds.contains(id)) {
                processedIds.add(id);
                // Process the ID
            } else {
                return "ID " + id + " has already been processed";
            }
            
            return "Successfully processed ID " + id;
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    public static class good_case_1 implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
        private final S3Client s3Client = S3Client.builder().build();
        
        @Override
        public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            List<String> requestHistory = new ArrayList<>();
            requestHistory.add(input.getPath());
            
            // Process with S3 client
            s3Client.listBuckets().buckets().forEach(bucket -> {
                requestHistory.add(bucket.name());
            });
            
            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(200)
                    .withBody("Processed " + requestHistory.size() + " requests");
        }
    }
    
    public static class good_case_2 implements RequestHandler<S3Event, String> {
        private final DynamoDbClient dynamoDbClient = DynamoDbClient.builder().build();
        
        @Override
        public String handleRequest(S3Event input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            Map<String, Integer> fileCountByBucket = new HashMap<>();
            
            input.getRecords().forEach(record -> {
                String bucketName = record.getS3().getBucket().getName();
                fileCountByBucket.put(bucketName, fileCountByBucket.getOrDefault(bucketName, 0) + 1);
            });
            
            return "Processed files in " + fileCountByBucket.size() + " buckets";
        }
    }
    
    public static class good_case_3 implements RequestHandler<DynamodbEvent, String> {
        private final SnsClient snsClient = SnsClient.builder().build();
        
        @Override
        public String handleRequest(DynamodbEvent input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            final int[] totalRecordsProcessed = {0};
            
            input.getRecords().forEach(record -> {
                totalRecordsProcessed[0]++;
                
                if (totalRecordsProcessed[0] % 100 == 0) {
                    snsClient.publish(builder -> builder
                        .topicArn("arn:aws:sns:region:account:topic")
                        .message("Processed " + totalRecordsProcessed[0] + " records")
                    );
                }
            });
            
            return "Total records processed: " + totalRecordsProcessed[0];
        }
    }
    
    public static class good_case_4 implements RequestHandler<SNSEvent, String> {
        private final SqsClient sqsClient = SqsClient.builder().build();
        
        @Override
        public String handleRequest(SNSEvent input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            List<String> messageIds = new ArrayList<>();
            
            input.getRecords().forEach(record -> {
                messageIds.add(record.getSns().getMessageId());
                
                sqsClient.sendMessage(builder -> builder
                    .queueUrl("https://sqs.region.amazonaws.com/account/queue")
                    .messageBody("Processed message: " + record.getSns().getMessage())
                );
            });
            
            return "Processed " + messageIds.size() + " messages";
        }
    }
    
    public static class good_case_5 implements RequestHandler<SQSEvent, String> {
        private final KinesisClient kinesisClient = KinesisClient.builder().build();
        
        @Override
        public String handleRequest(SQSEvent input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            Map<String, String> messageAttributes = new HashMap<>();
            
            input.getRecords().forEach(record -> {
                messageAttributes.put(record.getMessageId(), record.getBody());
                
                kinesisClient.putRecord(builder -> builder
                    .streamName("my-stream")
                    .data(software.amazon.awssdk.core.SdkBytes.fromUtf8String(record.getBody()))
                    .partitionKey("partition-key")
                );
            });
            
            return "Processed " + messageAttributes.size() + " messages";
        }
    }
    
    public static class good_case_6 implements RequestHandler<KinesisEvent, String> {
        private final CloudWatchClient cloudWatchClient = CloudWatchClient.builder().build();
        
        @Override
        public String handleRequest(KinesisEvent input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            long totalBytesProcessed = 0;
            
            for (KinesisEvent.KinesisEventRecord record : input.getRecords()) {
                byte[] data = record.getKinesis().getData().array();
                totalBytesProcessed += data.length;
                
                // Process data
            }
            
            return "Processed " + totalBytesProcessed + " bytes";
        }
    }
    
    public static class good_case_7 implements RequestHandler<CloudWatchLogsEvent, String> {
        private final CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.builder().build();
        
        @Override
        public String handleRequest(CloudWatchLogsEvent input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            int errorCount = 0;
            
            // Process logs
            String logData = input.getAwsLogs().getData();
            if (logData.contains("ERROR")) {
                errorCount++;
            }
            
            return "Found " + errorCount + " errors";
        }
    }
    
    public static class good_case_8 implements RequestHandler<ScheduledEvent, String> {
        private final LambdaClient lambdaClient = LambdaClient.builder().build();
        
        @Override
        public String handleRequest(ScheduledEvent input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            long currentTime = System.currentTimeMillis();
            
            // Store execution time in DynamoDB or other persistent store instead of instance variable
            // This is just a placeholder for the example
            String lastExecutionTimeStr = getLastExecutionTimeFromDatabase();
            long lastExecutionTime = lastExecutionTimeStr != null ? Long.parseLong(lastExecutionTimeStr) : 0;
            
            long timeSinceLastExecution = lastExecutionTime > 0 ? currentTime - lastExecutionTime : 0;
            
            // Update in database
            saveLastExecutionTimeToDatabase(String.valueOf(currentTime));
            
            return "Time since last execution: " + timeSinceLastExecution + " ms";
        }
        
        private String getLastExecutionTimeFromDatabase() {
            // Implementation would retrieve from database
            return "0";
        }
        
        private void saveLastExecutionTimeToDatabase(String time) {
            // Implementation would save to database
        }
    }
    
    public static class good_case_9 implements RequestHandler<CognitoEvent, String> {
        private final IotClient iotClient = IotClient.builder().build();
        
        @Override
        public String handleRequest(CognitoEvent input, Context context) {
            String username = input.getUserName();
            
            // ok: java-mutable-instance-variable-in-lambda
            // Retrieve login attempts from a database or other persistent store
            int attempts = getUserLoginAttemptsFromDatabase(username) + 1;
            
            // Update in database
            saveUserLoginAttemptsToDatabase(username, attempts);
            
            if (attempts > 3) {
                // Send alert
            }
            
            return "User " + username + " has attempted login " + attempts + " times";
        }
        
        private int getUserLoginAttemptsFromDatabase(String username) {
            // Implementation would retrieve from database
            return 0;
        }
        
        private void saveUserLoginAttemptsToDatabase(String username, int attempts) {
            // Implementation would save to database
        }
    }
    
    public static class good_case_10 implements RequestHandler<ConfigEvent, String> {
        private final LexRuntimeV2Client lexClient = LexRuntimeV2Client.builder().build();
        
        @Override
        public String handleRequest(ConfigEvent input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            List<String> nonCompliantResources = new ArrayList<>();
            
            String resourceId = input.getResourceId();
            if (!input.isCompliant()) {
                nonCompliantResources.add(resourceId);
                // Store in database or send notification
            }
            
            return "Found " + nonCompliantResources.size() + " non-compliant resources in this invocation";
        }
    }
    
    public static class good_case_11 implements RequestHandler<IoTButtonEvent, String> {
        private final SecretsManagerClient secretsManagerClient = SecretsManagerClient.builder().build();
        
        @Override
        public String handleRequest(IoTButtonEvent input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            // Retrieve button press count from a database or other persistent store
            int buttonPressCount = getButtonPressCountFromDatabase() + 1;
            
            String clickType = input.getClickType();
            if ("DOUBLE".equals(clickType)) {
                // Reset counter
                buttonPressCount = 0;
            }
            
            // Update in database
            saveButtonPressCountToDatabase(buttonPressCount);
            
            return "Button pressed " + buttonPressCount + " times";
        }
        
        private int getButtonPressCountFromDatabase() {
            // Implementation would retrieve from database
            return 0;
        }
        
        private void saveButtonPressCountToDatabase(int count) {
            // Implementation would save to database
        }
    }
    
    public static class good_case_12 implements RequestHandler<LexEvent, String> {
        private final ApiGatewayClient apiGatewayClient = ApiGatewayClient.builder().build();
        
        @Override
        public String handleRequest(LexEvent input, Context context) {
            String userId = input.getUserId();
            
            // ok: java-mutable-instance-variable-in-lambda
            Map<String, String> sessionAttributes = new HashMap<>(input.getSessionAttributes());
            
            // Process intent
            String intentName = input.getCurrentIntent().getName();
            
            // Return updated session attributes in response
            return "Processed intent " + intentName + " for user " + userId;
        }
    }
    
    public static class good_case_13 implements RequestHandler<Map<String, Object>, String> {
        private final CloudFormationClient cloudFormationClient = CloudFormationClient.builder().build();
        
        @Override
        public String handleRequest(Map<String, Object> input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            // Use CloudWatch metrics to track invocation count instead of instance variable
            // This is just a placeholder for the example
            int invocationCount = getInvocationCountFromCloudWatch() + 1;
            updateInvocationCountInCloudWatch(invocationCount);
            
            return "Lambda function has been invoked " + invocationCount + " times according to CloudWatch";
        }
        
        private int getInvocationCountFromCloudWatch() {
            // Implementation would retrieve from CloudWatch
            return 0;
        }
        
        private void updateInvocationCountInCloudWatch(int count) {
            // Implementation would update CloudWatch metric
        }
    }
    
    public static class good_case_14 implements RequestHandler<Map<String, Object>, String> {
        private final Ec2Client ec2Client = Ec2Client.builder().build();
        private final ElasticBeanstalkClient elasticBeanstalkClient = ElasticBeanstalkClient.builder().build();
        
        @Override
        public String handleRequest(Map<String, Object> input, Context context) {
            String cacheKey = input.get("key").toString();
            
            // ok: java-mutable-instance-variable-in-lambda
            // Use DynamoDB or ElastiCache for caching instead of instance variable
            String cachedValue = getCachedValueFromDatabase(cacheKey);
            
            if (cachedValue == null) {
                cachedValue = "Computed value for " + cacheKey;
                storeCachedValueInDatabase(cacheKey, cachedValue);
            }
            
            return cachedValue;
        }
        
        private String getCachedValueFromDatabase(String key) {
            // Implementation would retrieve from database
            return null;
        }
        
        private void storeCachedValueInDatabase(String key, String value) {
            // Implementation would store in database
        }
    }
    
    public static class good_case_15 implements RequestHandler<Map<String, Object>, String> {
        private final EcsClient ecsClient = EcsClient.builder().build();
        
        @Override
        public String handleRequest(Map<String, Object> input, Context context) {
            String id = input.get("id").toString();
            
            // ok: java-mutable-instance-variable-in-lambda
            // Check if ID has been processed using DynamoDB or other persistent store
            boolean alreadyProcessed = checkIfIdProcessedInDatabase(id);
            
            if (!alreadyProcessed) {
                markIdAsProcessedInDatabase(id);
                // Process the ID
            } else {
                return "ID " + id + " has already been processed";
            }
            
            return "Successfully processed ID " + id;
        }
        
        private boolean checkIfIdProcessedInDatabase(String id) {
            // Implementation would check database
            return false;
        }
        
        private void markIdAsProcessedInDatabase(String id) {
            // Implementation would update database
        }
    }
}