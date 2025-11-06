import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.rds.AmazonRDS;
import com.amazonaws.services.rds.AmazonRDSClientBuilder;
import com.amazonaws.services.cloudwatch.AmazonCloudWatch;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClientBuilder;
import com.amazonaws.services.elasticbeanstalk.AWSElasticBeanstalk;
import com.amazonaws.services.elasticbeanstalk.AWSElasticBeanstalkClientBuilder;
import com.amazonaws.services.elasticloadbalancing.AmazonElasticLoadBalancing;
import com.amazonaws.services.elasticloadbalancing.AmazonElasticLoadBalancingClientBuilder;
import com.amazonaws.services.cloudformation.AmazonCloudFormation;
import com.amazonaws.services.cloudformation.AmazonCloudFormationClientBuilder;
import com.amazonaws.services.apigateway.AmazonApiGateway;
import com.amazonaws.services.apigateway.AmazonApiGatewayClientBuilder;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.kinesis.AmazonKinesis;
import com.amazonaws.services.kinesis.AmazonKinesisClientBuilder;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.regions.Regions;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.CountDownLatch;

// Security Issue: Shared AWS SDK client builders in multi-threaded contexts can lead to race conditions

// True Positive Examples (Vulnerable/Insecure Code)
class BadExamples {
// {fact rule=thread-safety-violation@v1.0 defects=1}
    public void bad_case_1() {
        // Shared S3 client builder in a multi-threaded context
        // ruleid: java-aws-client-builder-shared-instance
        final AmazonS3ClientBuilder sharedBuilder = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_WEST_2);
        
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        CountDownLatch latch = new CountDownLatch(10);
        
        for (int i = 0; i < 10; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Each thread modifies and uses the same builder
                    if (index % 2 == 0) {
                        sharedBuilder.withRegion(Regions.US_EAST_1);
                    } else {
                        sharedBuilder.withRegion(Regions.US_WEST_1);
                    }
                    AmazonS3 s3Client = sharedBuilder.build();
                    s3Client.listBuckets();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void bad_case_2() {
        // Shared DynamoDB client builder in a multi-threaded context
        // ruleid: java-aws-client-builder-shared-instance
        final AmazonDynamoDBClientBuilder sharedBuilder = AmazonDynamoDBClientBuilder.standard();
        
        ExecutorService executorService = Executors.newFixedThreadPool(5);
        CountDownLatch latch = new CountDownLatch(5);
        
        for (int i = 0; i < 5; i++) {
            final String tableName = "Table" + i;
            executorService.submit(() -> {
                try {
                    // Different threads configure the same builder
                    sharedBuilder.withRegion(i % 2 == 0 ? Regions.EU_WEST_1 : Regions.EU_CENTRAL_1);
                    AmazonDynamoDB dynamoClient = sharedBuilder.build();
                    dynamoClient.describeTable(tableName);
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void bad_case_3() {
        // Shared Lambda client builder in a multi-threaded context
        // ruleid: java-aws-client-builder-shared-instance
        final AWSLambdaClientBuilder sharedBuilder = AWSLambdaClientBuilder.standard()
                .withRegion(Regions.US_EAST_2);
        
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        CountDownLatch latch = new CountDownLatch(3);
        
        for (int i = 0; i < 3; i++) {
            final String functionName = "Function" + i;
            executorService.submit(() -> {
                try {
                    // Multiple threads use the same builder with different configurations
                    if (functionName.endsWith("1")) {
                        sharedBuilder.withRegion(Regions.AP_NORTHEAST_1);
                    } else {
                        sharedBuilder.withRegion(Regions.AP_SOUTHEAST_2);
                    }
                    AWSLambda lambdaClient = sharedBuilder.build();
                    lambdaClient.listFunctions();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void bad_case_4() {
        // Shared SQS client builder in a multi-threaded context
        // ruleid: java-aws-client-builder-shared-instance
        final AmazonSQSClientBuilder sharedBuilder = AmazonSQSClientBuilder.standard();
        
        ExecutorService executorService = Executors.newFixedThreadPool(4);
        CountDownLatch latch = new CountDownLatch(4);
        
        for (int i = 0; i < 4; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Each thread configures the shared builder differently
                    Regions region = index % 2 == 0 ? Regions.US_WEST_2 : Regions.US_EAST_1;
                    sharedBuilder.withRegion(region);
                    AmazonSQS sqsClient = sharedBuilder.build();
                    sqsClient.listQueues();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void bad_case_5() {
        // Shared SNS client builder in a multi-threaded context
        // ruleid: java-aws-client-builder-shared-instance
        final AmazonSNSClientBuilder sharedBuilder = AmazonSNSClientBuilder.standard();
        
        ExecutorService executorService = Executors.newFixedThreadPool(5);
        CountDownLatch latch = new CountDownLatch(5);
        
        for (int i = 0; i < 5; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Concurrent modification of the shared builder
                    if (index % 3 == 0) {
                        sharedBuilder.withRegion(Regions.EU_WEST_1);
                    } else if (index % 3 == 1) {
                        sharedBuilder.withRegion(Regions.EU_CENTRAL_1);
                    } else {
                        sharedBuilder.withRegion(Regions.EU_WEST_2);
                    }
                    AmazonSNS snsClient = sharedBuilder.build();
                    snsClient.listTopics();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void bad_case_6() {
        // Shared EC2 client builder in a multi-threaded context
        // ruleid: java-aws-client-builder-shared-instance
        final AmazonEC2ClientBuilder sharedBuilder = AmazonEC2ClientBuilder.standard()
                .withRegion(Regions.US_WEST_2);
        
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        CountDownLatch latch = new CountDownLatch(3);
        
        for (int i = 0; i < 3; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Different threads modify the same builder
                    if (index == 0) {
                        sharedBuilder.withRegion(Regions.US_EAST_1);
                    } else if (index == 1) {
                        sharedBuilder.withRegion(Regions.EU_WEST_1);
                    }
                    AmazonEC2 ec2Client = sharedBuilder.build();
                    ec2Client.describeInstances();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void bad_case_7() {
        // Shared RDS client builder in a multi-threaded context
        // ruleid: java-aws-client-builder-shared-instance
        final AmazonRDSClientBuilder sharedBuilder = AmazonRDSClientBuilder.standard();
        
        ExecutorService executorService = Executors.newFixedThreadPool(4);
        CountDownLatch latch = new CountDownLatch(4);
        
        for (int i = 0; i < 4; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Concurrent configuration of the shared builder
                    Regions region;
                    switch (index % 4) {
                        case 0: region = Regions.US_EAST_1; break;
                        case 1: region = Regions.US_WEST_1; break;
                        case 2: region = Regions.EU_WEST_1; break;
                        default: region = Regions.AP_NORTHEAST_1; break;
                    }
                    sharedBuilder.withRegion(region);
                    AmazonRDS rdsClient = sharedBuilder.build();
                    rdsClient.describeDBInstances();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void bad_case_8() {
        // Shared CloudWatch client builder in a multi-threaded context
        // ruleid: java-aws-client-builder-shared-instance
        final AmazonCloudWatchClientBuilder sharedBuilder = AmazonCloudWatchClientBuilder.standard();
        
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        CountDownLatch latch = new CountDownLatch(2);
        
        for (int i = 0; i < 2; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Two threads modify the same builder
                    if (index == 0) {
                        sharedBuilder.withRegion(Regions.US_EAST_1);
                    } else {
                        sharedBuilder.withRegion(Regions.US_WEST_2);
                    }
                    AmazonCloudWatch cloudWatchClient = sharedBuilder.build();
                    cloudWatchClient.listMetrics();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void bad_case_9() {
        // Shared ElasticBeanstalk client builder in a multi-threaded context
        // ruleid: java-aws-client-builder-shared-instance
        final AWSElasticBeanstalkClientBuilder sharedBuilder = AWSElasticBeanstalkClientBuilder.standard();
        
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        CountDownLatch latch = new CountDownLatch(3);
        
        for (int i = 0; i < 3; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Multiple threads configure the same builder
                    if (index % 2 == 0) {
                        sharedBuilder.withRegion(Regions.US_WEST_1);
                    } else {
                        sharedBuilder.withRegion(Regions.US_EAST_2);
                    }
                    AWSElasticBeanstalk ebClient = sharedBuilder.build();
                    ebClient.describeApplications();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void bad_case_10() {
        // Shared ELB client builder in a multi-threaded context
        // ruleid: java-aws-client-builder-shared-instance
        final AmazonElasticLoadBalancingClientBuilder sharedBuilder = AmazonElasticLoadBalancingClientBuilder.standard();
        
        ExecutorService executorService = Executors.newFixedThreadPool(5);
        CountDownLatch latch = new CountDownLatch(5);
        
        for (int i = 0; i < 5; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Concurrent modification of shared builder
                    Regions region;
                    switch (index % 3) {
                        case 0: region = Regions.US_EAST_1; break;
                        case 1: region = Regions.EU_WEST_1; break;
                        default: region = Regions.AP_SOUTHEAST_1; break;
                    }
                    sharedBuilder.withRegion(region);
                    AmazonElasticLoadBalancing elbClient = sharedBuilder.build();
                    elbClient.describeLoadBalancers();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void bad_case_11() {
        // Shared CloudFormation client builder in a multi-threaded context
        // ruleid: java-aws-client-builder-shared-instance
        final AmazonCloudFormationClientBuilder sharedBuilder = AmazonCloudFormationClientBuilder.standard();
        
        ExecutorService executorService = Executors.newFixedThreadPool(4);
        CountDownLatch latch = new CountDownLatch(4);
        
        for (int i = 0; i < 4; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Multiple threads modify the same builder
                    if (index % 2 == 0) {
                        sharedBuilder.withRegion(Regions.US_EAST_1);
                    } else {
                        sharedBuilder.withRegion(Regions.EU_WEST_1);
                    }
                    AmazonCloudFormation cfClient = sharedBuilder.build();
                    cfClient.listStacks();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void bad_case_12() {
        // Shared API Gateway client builder in a multi-threaded context
        // ruleid: java-aws-client-builder-shared-instance
        final AmazonApiGatewayClientBuilder sharedBuilder = AmazonApiGatewayClientBuilder.standard();
        
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        CountDownLatch latch = new CountDownLatch(3);
        
        for (int i = 0; i < 3; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Concurrent configuration of shared builder
                    Regions region;
                    if (index == 0) {
                        region = Regions.US_EAST_1;
                    } else if (index == 1) {
                        region = Regions.US_WEST_2;
                    } else {
                        region = Regions.EU_CENTRAL_1;
                    }
                    sharedBuilder.withRegion(region);
                    AmazonApiGateway apiGatewayClient = sharedBuilder.build();
                    apiGatewayClient.getRestApis();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void bad_case_13() {
        // Shared Cognito client builder in a multi-threaded context
        // ruleid: java-aws-client-builder-shared-instance
        final AWSCognitoIdentityProviderClientBuilder sharedBuilder = AWSCognitoIdentityProviderClientBuilder.standard();
        
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        CountDownLatch latch = new CountDownLatch(2);
        
        for (int i = 0; i < 2; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Two threads modify the same builder
                    if (index == 0) {
                        sharedBuilder.withRegion(Regions.US_EAST_1);
                    } else {
                        sharedBuilder.withRegion(Regions.US_WEST_2);
                    }
                    AWSCognitoIdentityProvider cognitoClient = sharedBuilder.build();
                    cognitoClient.listUserPools(null);
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void bad_case_14() {
        // Shared Kinesis client builder in a multi-threaded context
        // ruleid: java-aws-client-builder-shared-instance
        final AmazonKinesisClientBuilder sharedBuilder = AmazonKinesisClientBuilder.standard();
        
        ExecutorService executorService = Executors.newFixedThreadPool(4);
        CountDownLatch latch = new CountDownLatch(4);
        
        for (int i = 0; i < 4; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Concurrent modification of shared builder
                    Regions region;
                    switch (index % 3) {
                        case 0: region = Regions.US_EAST_1; break;
                        case 1: region = Regions.US_WEST_2; break;
                        default: region = Regions.EU_WEST_1; break;
                    }
                    sharedBuilder.withRegion(region);
                    AmazonKinesis kinesisClient = sharedBuilder.build();
                    kinesisClient.listStreams();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void bad_case_15() {
        // Shared SecretsManager client builder in a multi-threaded context
        // ruleid: java-aws-client-builder-shared-instance
        final AWSSecretsManagerClientBuilder sharedBuilder = AWSSecretsManagerClientBuilder.standard();
        
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        CountDownLatch latch = new CountDownLatch(3);
        
        for (int i = 0; i < 3; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Multiple threads configure the same builder
                    if (index % 2 == 0) {
                        sharedBuilder.withRegion(Regions.US_EAST_1);
                    } else {
                        sharedBuilder.withRegion(Regions.EU_WEST_1);
                    }
                    AWSSecretsManager secretsClient = sharedBuilder.build();
                    secretsClient.listSecrets(null);
                } finally {
                    latch.countDown();
                }
            });
        }
    }
}
// {/fact}

// True Negative Examples (Safe/Secure Code)
class GoodExamples {
// {fact rule=thread-safety-violation@v1.0 defects=0}
    public void good_case_1() {
        // Creating a new S3 client builder for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        CountDownLatch latch = new CountDownLatch(10);
        
        for (int i = 0; i < 10; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Each thread creates its own builder
                    // ok: java-aws-client-builder-shared-instance
                    AmazonS3ClientBuilder builder = AmazonS3ClientBuilder.standard();
                    
                    if (index % 2 == 0) {
                        builder.withRegion(Regions.US_EAST_1);
                    } else {
                        builder.withRegion(Regions.US_WEST_1);
                    }
                    AmazonS3 s3Client = builder.build();
                    s3Client.listBuckets();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void good_case_2() {
        // Creating a new DynamoDB client builder for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(5);
        CountDownLatch latch = new CountDownLatch(5);
        
        for (int i = 0; i < 5; i++) {
            final String tableName = "Table" + i;
            executorService.submit(() -> {
                try {
                    // Each thread creates its own builder
                    // ok: java-aws-client-builder-shared-instance
                    AmazonDynamoDBClientBuilder builder = AmazonDynamoDBClientBuilder.standard();
                    
                    builder.withRegion(i % 2 == 0 ? Regions.EU_WEST_1 : Regions.EU_CENTRAL_1);
                    AmazonDynamoDB dynamoClient = builder.build();
                    dynamoClient.describeTable(tableName);
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void good_case_3() {
        // Creating a new Lambda client builder for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        CountDownLatch latch = new CountDownLatch(3);
        
        for (int i = 0; i < 3; i++) {
            final String functionName = "Function" + i;
            executorService.submit(() -> {
                try {
                    // Each thread creates its own builder
                    // ok: java-aws-client-builder-shared-instance
                    AWSLambdaClientBuilder builder = AWSLambdaClientBuilder.standard();
                    
                    if (functionName.endsWith("1")) {
                        builder.withRegion(Regions.AP_NORTHEAST_1);
                    } else {
                        builder.withRegion(Regions.AP_SOUTHEAST_2);
                    }
                    AWSLambda lambdaClient = builder.build();
                    lambdaClient.listFunctions();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void good_case_4() {
        // Creating a new SQS client builder for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(4);
        CountDownLatch latch = new CountDownLatch(4);
        
        for (int i = 0; i < 4; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Each thread creates its own builder
                    // ok: java-aws-client-builder-shared-instance
                    AmazonSQSClientBuilder builder = AmazonSQSClientBuilder.standard();
                    
                    Regions region = index % 2 == 0 ? Regions.US_WEST_2 : Regions.US_EAST_1;
                    builder.withRegion(region);
                    AmazonSQS sqsClient = builder.build();
                    sqsClient.listQueues();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void good_case_5() {
        // Creating a new SNS client builder for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(5);
        CountDownLatch latch = new CountDownLatch(5);
        
        for (int i = 0; i < 5; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Each thread creates its own builder
                    // ok: java-aws-client-builder-shared-instance
                    AmazonSNSClientBuilder builder = AmazonSNSClientBuilder.standard();
                    
                    if (index % 3 == 0) {
                        builder.withRegion(Regions.EU_WEST_1);
                    } else if (index % 3 == 1) {
                        builder.withRegion(Regions.EU_CENTRAL_1);
                    } else {
                        builder.withRegion(Regions.EU_WEST_2);
                    }
                    AmazonSNS snsClient = builder.build();
                    snsClient.listTopics();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void good_case_6() {
        // Creating a new EC2 client builder for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        CountDownLatch latch = new CountDownLatch(3);
        
        for (int i = 0; i < 3; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Each thread creates its own builder
                    // ok: java-aws-client-builder-shared-instance
                    AmazonEC2ClientBuilder builder = AmazonEC2ClientBuilder.standard();
                    
                    if (index == 0) {
                        builder.withRegion(Regions.US_EAST_1);
                    } else if (index == 1) {
                        builder.withRegion(Regions.EU_WEST_1);
                    } else {
                        builder.withRegion(Regions.US_WEST_2);
                    }
                    AmazonEC2 ec2Client = builder.build();
                    ec2Client.describeInstances();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void good_case_7() {
        // Creating a new RDS client builder for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(4);
        CountDownLatch latch = new CountDownLatch(4);
        
        for (int i = 0; i < 4; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Each thread creates its own builder
                    // ok: java-aws-client-builder-shared-instance
                    AmazonRDSClientBuilder builder = AmazonRDSClientBuilder.standard();
                    
                    Regions region;
                    switch (index % 4) {
                        case 0: region = Regions.US_EAST_1; break;
                        case 1: region = Regions.US_WEST_1; break;
                        case 2: region = Regions.EU_WEST_1; break;
                        default: region = Regions.AP_NORTHEAST_1; break;
                    }
                    builder.withRegion(region);
                    AmazonRDS rdsClient = builder.build();
                    rdsClient.describeDBInstances();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void good_case_8() {
        // Creating a new CloudWatch client builder for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        CountDownLatch latch = new CountDownLatch(2);
        
        for (int i = 0; i < 2; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Each thread creates its own builder
                    // ok: java-aws-client-builder-shared-instance
                    AmazonCloudWatchClientBuilder builder = AmazonCloudWatchClientBuilder.standard();
                    
                    if (index == 0) {
                        builder.withRegion(Regions.US_EAST_1);
                    } else {
                        builder.withRegion(Regions.US_WEST_2);
                    }
                    AmazonCloudWatch cloudWatchClient = builder.build();
                    cloudWatchClient.listMetrics();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void good_case_9() {
        // Creating a new ElasticBeanstalk client builder for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        CountDownLatch latch = new CountDownLatch(3);
        
        for (int i = 0; i < 3; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Each thread creates its own builder
                    // ok: java-aws-client-builder-shared-instance
                    AWSElasticBeanstalkClientBuilder builder = AWSElasticBeanstalkClientBuilder.standard();
                    
                    if (index % 2 == 0) {
                        builder.withRegion(Regions.US_WEST_1);
                    } else {
                        builder.withRegion(Regions.US_EAST_2);
                    }
                    AWSElasticBeanstalk ebClient = builder.build();
                    ebClient.describeApplications();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void good_case_10() {
        // Creating a new ELB client builder for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(5);
        CountDownLatch latch = new CountDownLatch(5);
        
        for (int i = 0; i < 5; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Each thread creates its own builder
                    // ok: java-aws-client-builder-shared-instance
                    AmazonElasticLoadBalancingClientBuilder builder = AmazonElasticLoadBalancingClientBuilder.standard();
                    
                    Regions region;
                    switch (index % 3) {
                        case 0: region = Regions.US_EAST_1; break;
                        case 1: region = Regions.EU_WEST_1; break;
                        default: region = Regions.AP_SOUTHEAST_1; break;
                    }
                    builder.withRegion(region);
                    AmazonElasticLoadBalancing elbClient = builder.build();
                    elbClient.describeLoadBalancers();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void good_case_11() {
        // Creating a new CloudFormation client builder for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(4);
        CountDownLatch latch = new CountDownLatch(4);
        
        for (int i = 0; i < 4; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Each thread creates its own builder
                    // ok: java-aws-client-builder-shared-instance
                    AmazonCloudFormationClientBuilder builder = AmazonCloudFormationClientBuilder.standard();
                    
                    if (index % 2 == 0) {
                        builder.withRegion(Regions.US_EAST_1);
                    } else {
                        builder.withRegion(Regions.EU_WEST_1);
                    }
                    AmazonCloudFormation cfClient = builder.build();
                    cfClient.listStacks();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void good_case_12() {
        // Creating a new API Gateway client builder for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        CountDownLatch latch = new CountDownLatch(3);
        
        for (int i = 0; i < 3; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Each thread creates its own builder
                    // ok: java-aws-client-builder-shared-instance
                    AmazonApiGatewayClientBuilder builder = AmazonApiGatewayClientBuilder.standard();
                    
                    Regions region;
                    if (index == 0) {
                        region = Regions.US_EAST_1;
                    } else if (index == 1) {
                        region = Regions.US_WEST_2;
                    } else {
                        region = Regions.EU_CENTRAL_1;
                    }
                    builder.withRegion(region);
                    AmazonApiGateway apiGatewayClient = builder.build();
                    apiGatewayClient.getRestApis();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void good_case_13() {
        // Creating a new Cognito client builder for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        CountDownLatch latch = new CountDownLatch(2);
        
        for (int i = 0; i < 2; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Each thread creates its own builder
                    // ok: java-aws-client-builder-shared-instance
                    AWSCognitoIdentityProviderClientBuilder builder = AWSCognitoIdentityProviderClientBuilder.standard();
                    
                    if (index == 0) {
                        builder.withRegion(Regions.US_EAST_1);
                    } else {
                        builder.withRegion(Regions.US_WEST_2);
                    }
                    AWSCognitoIdentityProvider cognitoClient = builder.build();
                    cognitoClient.listUserPools(null);
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void good_case_14() {
        // Creating a new Kinesis client builder for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(4);
        CountDownLatch latch = new CountDownLatch(4);
        
        for (int i = 0; i < 4; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Each thread creates its own builder
                    // ok: java-aws-client-builder-shared-instance
                    AmazonKinesisClientBuilder builder = AmazonKinesisClientBuilder.standard();
                    
                    Regions region;
                    switch (index % 3) {
                        case 0: region = Regions.US_EAST_1; break;
                        case 1: region = Regions.US_WEST_2; break;
                        default: region = Regions.EU_WEST_1; break;
                    }
                    builder.withRegion(region);
                    AmazonKinesis kinesisClient = builder.build();
                    kinesisClient.listStreams();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void good_case_15() {
        // Creating a new SecretsManager client builder for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        CountDownLatch latch = new CountDownLatch(3);
        
        for (int i = 0; i < 3; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Each thread creates its own builder
                    // ok: java-aws-client-builder-shared-instance
                    AWSSecretsManagerClientBuilder builder = AWSSecretsManagerClientBuilder.standard();
                    
                    if (index % 2 == 0) {
                        builder.withRegion(Regions.US_EAST_1);
                    } else {
                        builder.withRegion(Regions.EU_WEST_1);
                    }
                    AWSSecretsManager secretsClient = builder.build();
                    secretsClient.listSecrets(null);
                } finally {
                    latch.countDown();
                }
            });
        }
    }
}
// {/fact}