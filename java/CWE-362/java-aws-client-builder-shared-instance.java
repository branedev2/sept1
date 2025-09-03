import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.cloudwatch.AmazonCloudWatch;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClientBuilder;
import com.amazonaws.services.rds.AmazonRDS;
import com.amazonaws.services.rds.AmazonRDSClientBuilder;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.regions.Regions;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.CountDownLatch;

public class AwsClientBuilderExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=thread-safety-violation@v1.0 defects=1}
    public void bad_case_1() {
        // Shared builder instance used in multiple threads
        final AmazonS3ClientBuilder sharedBuilder = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1);
        
        ExecutorService executorService = Executors.newFixedThreadPool(5);
        CountDownLatch latch = new CountDownLatch(5);
        
        for (int i = 0; i < 5; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // ruleid: java-aws-client-builder-shared-instance
                    AmazonS3 s3Client = sharedBuilder
                            .withCredentials(new DefaultAWSCredentialsProviderChain())
                            .build();
                    s3Client.listBuckets();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void bad_case_2() {
        // Shared DynamoDB builder in a multi-threaded context
        final AmazonDynamoDBClientBuilder sharedBuilder = AmazonDynamoDBClientBuilder.standard();
        
        Thread thread1 = new Thread(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonDynamoDB dynamoClient = sharedBuilder
                    .withRegion(Regions.US_WEST_1)
                    .build();
            dynamoClient.listTables();
        });
        
        Thread thread2 = new Thread(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonDynamoDB dynamoClient = sharedBuilder
                    .withRegion(Regions.US_EAST_2)
                    .build();
            dynamoClient.listTables();
        });
        
        thread1.start();
        thread2.start();
    }

    public void bad_case_3() {
        // Shared Lambda client builder with static field
        class LambdaService {
            private static final AWSLambdaClientBuilder sharedBuilder = AWSLambdaClientBuilder.standard();
            
            public void executeInThread(String functionName) {
                new Thread(() -> {
                    // ruleid: java-aws-client-builder-shared-instance
                    AWSLambda lambdaClient = sharedBuilder
                            .withRegion(Regions.EU_WEST_1)
                            .build();
                    lambdaClient.listFunctions();
                }).start();
            }
        }
        
        LambdaService service = new LambdaService();
        service.executeInThread("function1");
        service.executeInThread("function2");
    }

    public void bad_case_4() {
        // Shared EC2 client builder in a thread pool
        final AmazonEC2ClientBuilder sharedBuilder = AmazonEC2ClientBuilder.standard()
                .withRegion(Regions.AP_NORTHEAST_1);
        
        ExecutorService executor = Executors.newCachedThreadPool();
        
        for (int i = 0; i < 3; i++) {
            executor.execute(() -> {
                // ruleid: java-aws-client-builder-shared-instance
                AmazonEC2 ec2Client = sharedBuilder.build();
                ec2Client.describeInstances();
            });
        }
    }

    public void bad_case_5() {
        // Shared SNS client builder with endpoint configuration
        final AmazonSNSClientBuilder sharedBuilder = AmazonSNSClientBuilder.standard();
        final AwsClientBuilder.EndpointConfiguration endpoint = 
                new AwsClientBuilder.EndpointConfiguration("sns.us-west-2.amazonaws.com", "us-west-2");
        sharedBuilder.withEndpointConfiguration(endpoint);
        
        Runnable task1 = () -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonSNS snsClient = sharedBuilder.build();
            snsClient.listTopics();
        };
        
        Runnable task2 = () -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonSNS snsClient = sharedBuilder.build();
            snsClient.listSubscriptions();
        };
        
        new Thread(task1).start();
        new Thread(task2).start();
    }

    public void bad_case_6() {
        // Shared SQS client builder in a custom thread factory
        final AmazonSQSClientBuilder sharedBuilder = AmazonSQSClientBuilder.standard()
                .withRegion(Regions.SA_EAST_1);
        
        class SQSWorker implements Runnable {
            private final String queueUrl;
            
            SQSWorker(String queueUrl) {
                this.queueUrl = queueUrl;
            }
            
            @Override
            public void run() {
                // ruleid: java-aws-client-builder-shared-instance
                AmazonSQS sqsClient = sharedBuilder.build();
                sqsClient.getQueueAttributes(queueUrl, null);
            }
        }
        
        new Thread(new SQSWorker("queue1")).start();
        new Thread(new SQSWorker("queue2")).start();
    }

    public void bad_case_7() {
        // Shared CloudWatch client builder with credentials
        final BasicAWSCredentials awsCreds = new BasicAWSCredentials("accessKey", "secretKey");
        final AmazonCloudWatchClientBuilder sharedBuilder = AmazonCloudWatchClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds));
        
        ExecutorService executor = Executors.newFixedThreadPool(2);
        
        executor.submit(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonCloudWatch cloudWatchClient = sharedBuilder
                    .withRegion(Regions.EU_CENTRAL_1)
                    .build();
            cloudWatchClient.listDashboards();
        });
        
        executor.submit(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonCloudWatch cloudWatchClient = sharedBuilder
                    .withRegion(Regions.EU_WEST_2)
                    .build();
            cloudWatchClient.listMetrics();
        });
    }

    public void bad_case_8() {
        // Shared RDS client builder with singleton pattern
        class RDSClientProvider {
            private static final AmazonRDSClientBuilder sharedBuilder = AmazonRDSClientBuilder.standard();
            
            public static AmazonRDS getClient(Regions region) {
                // ruleid: java-aws-client-builder-shared-instance
                return sharedBuilder.withRegion(region).build();
            }
        }
        
        Thread t1 = new Thread(() -> {
            AmazonRDS rdsClient = RDSClientProvider.getClient(Regions.US_WEST_1);
            rdsClient.describeDBInstances();
        });
        
        Thread t2 = new Thread(() -> {
            AmazonRDS rdsClient = RDSClientProvider.getClient(Regions.US_WEST_2);
            rdsClient.describeDBClusters();
        });
        
        t1.start();
        t2.start();
    }

    public void bad_case_9() {
        // Shared S3 client builder with async execution
        final AmazonS3ClientBuilder sharedBuilder = AmazonS3ClientBuilder.standard();
        
        Runnable task = () -> {
            for (int i = 0; i < 3; i++) {
                new Thread(() -> {
                    // ruleid: java-aws-client-builder-shared-instance
                    AmazonS3 s3Client = sharedBuilder
                            .withRegion(Regions.values()[i % Regions.values().length])
                            .build();
                    s3Client.listBuckets();
                }).start();
            }
        };
        
        task.run();
    }

    public void bad_case_10() {
        // Shared DynamoDB client builder with executor service and callable
        final AmazonDynamoDBClientBuilder sharedBuilder = AmazonDynamoDBClientBuilder.standard()
                .withRegion(Regions.AP_SOUTH_1);
        
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        
        for (int i = 0; i < 3; i++) {
            executorService.submit(() -> {
                // ruleid: java-aws-client-builder-shared-instance
                AmazonDynamoDB dynamoClient = sharedBuilder.build();
                return dynamoClient.listTables().getTableNames();
            });
        }
    }

    public void bad_case_11() {
        // Shared Lambda client builder with thread-local but still shared across threads
        final AWSLambdaClientBuilder sharedBuilder = AWSLambdaClientBuilder.standard();
        
        class LambdaInvoker implements Runnable {
            private final String functionName;
            
            LambdaInvoker(String functionName) {
                this.functionName = functionName;
            }
            
            @Override
            public void run() {
                // ruleid: java-aws-client-builder-shared-instance
                AWSLambda lambdaClient = sharedBuilder
                        .withRegion(Regions.US_EAST_1)
                        .build();
                lambdaClient.listFunctions();
            }
        }
        
        ExecutorService executor = Executors.newFixedThreadPool(5);
        executor.execute(new LambdaInvoker("function1"));
        executor.execute(new LambdaInvoker("function2"));
    }

    public void bad_case_12() {
        // Shared EC2 client builder with anonymous inner classes
        final AmazonEC2ClientBuilder sharedBuilder = AmazonEC2ClientBuilder.standard();
        
        Thread t1 = new Thread(new Runnable() {
            @Override
            public void run() {
                // ruleid: java-aws-client-builder-shared-instance
                AmazonEC2 ec2Client = sharedBuilder
                        .withRegion(Regions.EU_WEST_3)
                        .build();
                ec2Client.describeSecurityGroups();
            }
        });
        
        Thread t2 = new Thread(new Runnable() {
            @Override
            public void run() {
                // ruleid: java-aws-client-builder-shared-instance
                AmazonEC2 ec2Client = sharedBuilder
                        .withRegion(Regions.EU_NORTH_1)
                        .build();
                ec2Client.describeVpcs();
            }
        });
        
        t1.start();
        t2.start();
    }

    public void bad_case_13() {
        // Shared SNS client builder with lambda expressions
        final AmazonSNSClientBuilder sharedBuilder = AmazonSNSClientBuilder.standard()
                .withRegion(Regions.CA_CENTRAL_1);
        
        ExecutorService executor = Executors.newFixedThreadPool(2);
        
        executor.submit(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonSNS snsClient = sharedBuilder.build();
            snsClient.listTopics();
        });
        
        executor.submit(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonSNS snsClient = sharedBuilder.build();
            snsClient.listSubscriptions();
        });
    }

    public void bad_case_14() {
        // Shared SQS client builder with conditional thread creation
        final AmazonSQSClientBuilder sharedBuilder = AmazonSQSClientBuilder.standard();
        
        for (int i = 0; i < 3; i++) {
            final int region = i;
            if (i % 2 == 0) {
                new Thread(() -> {
                    // ruleid: java-aws-client-builder-shared-instance
                    AmazonSQS sqsClient = sharedBuilder
                            .withRegion(Regions.values()[region])
                            .build();
                    sqsClient.listQueues();
                }).start();
            } else {
                new Thread(() -> {
                    // ruleid: java-aws-client-builder-shared-instance
                    AmazonSQS sqsClient = sharedBuilder
                            .withRegion(Regions.values()[region])
                            .build();
                    sqsClient.listDeadLetterSourceQueues(null);
                }).start();
            }
        }
    }

    public void bad_case_15() {
        // Shared CloudWatch client builder with thread group
        final AmazonCloudWatchClientBuilder sharedBuilder = AmazonCloudWatchClientBuilder.standard();
        
        ThreadGroup threadGroup = new ThreadGroup("CloudWatchGroup");
        
        Thread t1 = new Thread(threadGroup, () -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonCloudWatch cloudWatchClient = sharedBuilder
                    .withRegion(Regions.AP_NORTHEAST_2)
                    .build();
            cloudWatchClient.listDashboards();
        });
        
        Thread t2 = new Thread(threadGroup, () -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonCloudWatch cloudWatchClient = sharedBuilder
                    .withRegion(Regions.AP_SOUTHEAST_1)
                    .build();
            cloudWatchClient.listMetrics();
        });
        
        t1.start();
        t2.start();
    }

    // True Negative Examples (Safe Code)

    public void good_case_1() {
        // Creating a new builder instance for each thread
        ExecutorService executorService = Executors.newFixedThreadPool(5);
        CountDownLatch latch = new CountDownLatch(5);
        
        for (int i = 0; i < 5; i++) {
            executorService.submit(() -> {
                try {
                    // ok: java-aws-client-builder-shared-instance
                    AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                            .withRegion(Regions.US_EAST_1)
                            .withCredentials(new DefaultAWSCredentialsProviderChain())
                            .build();
                    s3Client.listBuckets();
                } finally {
                    latch.countDown();
                }
            });
        }
    }

    public void good_case_2() {
        // Using separate builders for each thread
        Thread thread1 = new Thread(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonDynamoDB dynamoClient = AmazonDynamoDBClientBuilder.standard()
                    .withRegion(Regions.US_WEST_1)
                    .build();
            dynamoClient.listTables();
        });
        
        Thread thread2 = new Thread(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonDynamoDB dynamoClient = AmazonDynamoDBClientBuilder.standard()
                    .withRegion(Regions.US_EAST_2)
                    .build();
            dynamoClient.listTables();
        });
        
        thread1.start();
        thread2.start();
    }

    public void good_case_3() {
        // Creating new Lambda client builder in each thread
        class LambdaService {
            public void executeInThread(String functionName) {
                new Thread(() -> {
                    // ok: java-aws-client-builder-shared-instance
                    AWSLambda lambdaClient = AWSLambdaClientBuilder.standard()
                            .withRegion(Regions.EU_WEST_1)
                            .build();
                    lambdaClient.listFunctions();
                }).start();
            }
        }
        
        LambdaService service = new LambdaService();
        service.executeInThread("function1");
        service.executeInThread("function2");
    }

    public void good_case_4() {
        // Using new EC2 client builder in each thread
        ExecutorService executor = Executors.newCachedThreadPool();
        
        for (int i = 0; i < 3; i++) {
            executor.execute(() -> {
                // ok: java-aws-client-builder-shared-instance
                AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                        .withRegion(Regions.AP_NORTHEAST_1)
                        .build();
                ec2Client.describeInstances();
            });
        }
    }

    public void good_case_5() {
        // Creating new SNS client builder with endpoint configuration in each thread
        final AwsClientBuilder.EndpointConfiguration endpoint = 
                new AwsClientBuilder.EndpointConfiguration("sns.us-west-2.amazonaws.com", "us-west-2");
        
        Runnable task1 = () -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonSNS snsClient = AmazonSNSClientBuilder.standard()
                    .withEndpointConfiguration(endpoint)
                    .build();
            snsClient.listTopics();
        };
        
        Runnable task2 = () -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonSNS snsClient = AmazonSNSClientBuilder.standard()
                    .withEndpointConfiguration(endpoint)
                    .build();
            snsClient.listSubscriptions();
        };
        
        new Thread(task1).start();
        new Thread(task2).start();
    }

    public void good_case_6() {
        // Using new SQS client builder in each worker thread
        class SQSWorker implements Runnable {
            private final String queueUrl;
            
            SQSWorker(String queueUrl) {
                this.queueUrl = queueUrl;
            }
            
            @Override
            public void run() {
                // ok: java-aws-client-builder-shared-instance
                AmazonSQS sqsClient = AmazonSQSClientBuilder.standard()
                        .withRegion(Regions.SA_EAST_1)
                        .build();
                sqsClient.getQueueAttributes(queueUrl, null);
            }
        }
        
        new Thread(new SQSWorker("queue1")).start();
        new Thread(new SQSWorker("queue2")).start();
    }

    public void good_case_7() {
        // Creating new CloudWatch client builder with credentials in each thread
        final BasicAWSCredentials awsCreds = new BasicAWSCredentials("accessKey", "secretKey");
        final AWSStaticCredentialsProvider credProvider = new AWSStaticCredentialsProvider(awsCreds);
        
        ExecutorService executor = Executors.newFixedThreadPool(2);
        
        executor.submit(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonCloudWatch cloudWatchClient = AmazonCloudWatchClientBuilder.standard()
                    .withCredentials(credProvider)
                    .withRegion(Regions.EU_CENTRAL_1)
                    .build();
            cloudWatchClient.listDashboards();
        });
        
        executor.submit(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonCloudWatch cloudWatchClient = AmazonCloudWatchClientBuilder.standard()
                    .withCredentials(credProvider)
                    .withRegion(Regions.EU_WEST_2)
                    .build();
            cloudWatchClient.listMetrics();
        });
    }

    public void good_case_8() {
        // Using factory method that creates new RDS client builder each time
        class RDSClientProvider {
            public static AmazonRDS getClient(Regions region) {
                // ok: java-aws-client-builder-shared-instance
                return AmazonRDSClientBuilder.standard()
                        .withRegion(region)
                        .build();
            }
        }
        
        Thread t1 = new Thread(() -> {
            AmazonRDS rdsClient = RDSClientProvider.getClient(Regions.US_WEST_1);
            rdsClient.describeDBInstances();
        });
        
        Thread t2 = new Thread(() -> {
            AmazonRDS rdsClient = RDSClientProvider.getClient(Regions.US_WEST_2);
            rdsClient.describeDBClusters();
        });
        
        t1.start();
        t2.start();
    }

    public void good_case_9() {
        // Creating new S3 client builder in each thread
        Runnable task = () -> {
            for (int i = 0; i < 3; i++) {
                final int index = i;
                new Thread(() -> {
                    // ok: java-aws-client-builder-shared-instance
                    AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                            .withRegion(Regions.values()[index % Regions.values().length])
                            .build();
                    s3Client.listBuckets();
                }).start();
            }
        };
        
        task.run();
    }

    public void good_case_10() {
        // Using new DynamoDB client builder with executor service and callable
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        
        for (int i = 0; i < 3; i++) {
            executorService.submit(() -> {
                // ok: java-aws-client-builder-shared-instance
                AmazonDynamoDB dynamoClient = AmazonDynamoDBClientBuilder.standard()
                        .withRegion(Regions.AP_SOUTH_1)
                        .build();
                return dynamoClient.listTables().getTableNames();
            });
        }
    }

    public void good_case_11() {
        // Creating new Lambda client builder in each thread
        class LambdaInvoker implements Runnable {
            private final String functionName;
            
            LambdaInvoker(String functionName) {
                this.functionName = functionName;
            }
            
            @Override
            public void run() {
                // ok: java-aws-client-builder-shared-instance
                AWSLambda lambdaClient = AWSLambdaClientBuilder.standard()
                        .withRegion(Regions.US_EAST_1)
                        .build();
                lambdaClient.listFunctions();
            }
        }
        
        ExecutorService executor = Executors.newFixedThreadPool(5);
        executor.execute(new LambdaInvoker("function1"));
        executor.execute(new LambdaInvoker("function2"));
    }

    public void good_case_12() {
        // Using new EC2 client builder with anonymous inner classes
        Thread t1 = new Thread(new Runnable() {
            @Override
            public void run() {
                // ok: java-aws-client-builder-shared-instance
                AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                        .withRegion(Regions.EU_WEST_3)
                        .build();
                ec2Client.describeSecurityGroups();
            }
        });
        
        Thread t2 = new Thread(new Runnable() {
            @Override
            public void run() {
                // ok: java-aws-client-builder-shared-instance
                AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                        .withRegion(Regions.EU_NORTH_1)
                        .build();
                ec2Client.describeVpcs();
            }
        });
        
        t1.start();
        t2.start();
    }

    public void good_case_13() {
        // Creating new SNS client builder with lambda expressions
        ExecutorService executor = Executors.newFixedThreadPool(2);
        
        executor.submit(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonSNS snsClient = AmazonSNSClientBuilder.standard()
                    .withRegion(Regions.CA_CENTRAL_1)
                    .build();
            snsClient.listTopics();
        });
        
        executor.submit(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonSNS snsClient = AmazonSNSClientBuilder.standard()
                    .withRegion(Regions.CA_CENTRAL_1)
                    .build();
            snsClient.listSubscriptions();
        });
    }

    public void good_case_14() {
        // Using new SQS client builder with conditional thread creation
        for (int i = 0; i < 3; i++) {
            final int region = i;
            if (i % 2 == 0) {
                new Thread(() -> {
                    // ok: java-aws-client-builder-shared-instance
                    AmazonSQS sqsClient = AmazonSQSClientBuilder.standard()
                            .withRegion(Regions.values()[region])
                            .build();
                    sqsClient.listQueues();
                }).start();
            } else {
                new Thread(() -> {
                    // ok: java-aws-client-builder-shared-instance
                    AmazonSQS sqsClient = AmazonSQSClientBuilder.standard()
                            .withRegion(Regions.values()[region])
                            .build();
                    sqsClient.listDeadLetterSourceQueues(null);
                }).start();
            }
        }
    }

    public void good_case_15() {
        // Creating new CloudWatch client builder with thread group
        ThreadGroup threadGroup = new ThreadGroup("CloudWatchGroup");
        
        Thread t1 = new Thread(threadGroup, () -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonCloudWatch cloudWatchClient = AmazonCloudWatchClientBuilder.standard()
                    .withRegion(Regions.AP_NORTHEAST_2)
                    .build();
            cloudWatchClient.listDashboards();
        });
        
        Thread t2 = new Thread(threadGroup, () -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonCloudWatch cloudWatchClient = AmazonCloudWatchClientBuilder.standard()
                    .withRegion(Regions.AP_SOUTHEAST_1)
                    .build();
            cloudWatchClient.listMetrics();
        });
        
        t1.start();
        t2.start();
    }
}
// {/fact}