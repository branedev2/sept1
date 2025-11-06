import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.rds.AmazonRDS;
import com.amazonaws.services.rds.AmazonRDSClientBuilder;
import com.amazonaws.services.cloudwatch.AmazonCloudWatch;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClientBuilder;
import com.amazonaws.services.elasticbeanstalk.AWSElasticBeanstalk;
import com.amazonaws.services.elasticbeanstalk.AWSElasticBeanstalkClientBuilder;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.regions.Regions;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AwsClientBuilderExamples {

    // True Positives (Vulnerable Code)
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    public void bad_case_1() {
        // Shared builder instance at class level
        final AmazonS3ClientBuilder sharedBuilder = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_WEST_2);
        
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        
        for (int i = 0; i < 10; i++) {
            executorService.submit(() -> {
                // ruleid: java-aws-client-builder-shared-instance
                AmazonS3 s3Client = sharedBuilder
                        .withCredentials(new DefaultAWSCredentialsProviderChain())
                        .build();
                s3Client.listBuckets();
            });
        }
    }
    
    private final AmazonDynamoDBClientBuilder dynamoDbBuilder = AmazonDynamoDBClientBuilder.standard();
    
    public void bad_case_2() {
        ExecutorService executorService = Executors.newFixedThreadPool(5);
        
        for (int i = 0; i < 5; i++) {
            final int index = i;
            executorService.submit(() -> {
                // ruleid: java-aws-client-builder-shared-instance
                AmazonDynamoDB dynamoDbClient = dynamoDbBuilder
                        .withRegion(index % 2 == 0 ? Regions.US_EAST_1 : Regions.US_WEST_2)
                        .build();
                dynamoDbClient.listTables();
            });
        }
    }
    
    private static final AmazonSQSClientBuilder SQS_BUILDER = AmazonSQSClientBuilder.standard()
            .withRegion(Regions.EU_WEST_1);
    
    public void bad_case_3() {
        Thread thread1 = new Thread(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonSQS sqsClient = SQS_BUILDER
                    .withCredentials(new DefaultAWSCredentialsProviderChain())
                    .build();
            sqsClient.listQueues();
        });
        
        Thread thread2 = new Thread(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonSQS sqsClient = SQS_BUILDER
                    .withRegion(Regions.US_EAST_1)
                    .build();
            sqsClient.listQueues();
        });
        
        thread1.start();
        thread2.start();
    }
    
    public void bad_case_4() {
        final AmazonSNSClientBuilder snsBuilder = AmazonSNSClientBuilder.standard();
        
        Runnable task1 = () -> {
            snsBuilder.withRegion(Regions.US_WEST_1);
            // ruleid: java-aws-client-builder-shared-instance
            AmazonSNS snsClient = snsBuilder.build();
            snsClient.listTopics();
        };
        
        Runnable task2 = () -> {
            snsBuilder.withRegion(Regions.EU_CENTRAL_1);
            // ruleid: java-aws-client-builder-shared-instance
            AmazonSNS snsClient = snsBuilder.build();
            snsClient.listTopics();
        };
        
        new Thread(task1).start();
        new Thread(task2).start();
    }
    
    private final AWSLambdaClientBuilder lambdaBuilder = AWSLambdaClientBuilder.standard();
    
    public void bad_case_5() {
        ExecutorService executorService = Executors.newCachedThreadPool();
        
        for (int i = 0; i < 3; i++) {
            executorService.submit(() -> {
                // ruleid: java-aws-client-builder-shared-instance
                AWSLambda lambdaClient = lambdaBuilder
                        .withRegion(Regions.AP_NORTHEAST_1)
                        .build();
                lambdaClient.listFunctions();
            });
        }
    }
    
    private static final AmazonEC2ClientBuilder SHARED_EC2_BUILDER = AmazonEC2ClientBuilder.standard();
    
    public void bad_case_6() {
        Thread thread1 = new Thread(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonEC2 ec2Client = SHARED_EC2_BUILDER
                    .withRegion(Regions.SA_EAST_1)
                    .build();
            ec2Client.describeInstances();
        });
        
        Thread thread2 = new Thread(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonEC2 ec2Client = SHARED_EC2_BUILDER
                    .withRegion(Regions.CA_CENTRAL_1)
                    .build();
            ec2Client.describeSecurityGroups();
        });
        
        thread1.start();
        thread2.start();
    }
    
    private final AmazonRDSClientBuilder rdsBuilder = AmazonRDSClientBuilder.standard()
            .withRegion(Regions.US_EAST_2);
    
    public void bad_case_7() {
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        
        executorService.submit(() -> {
            BasicAWSCredentials credentials1 = new BasicAWSCredentials("AKIA111111111111111", "secretKey1");
            // ruleid: java-aws-client-builder-shared-instance
            AmazonRDS rdsClient = rdsBuilder
                    .withCredentials(new AWSStaticCredentialsProvider(credentials1))
                    .build();
            rdsClient.describeDBInstances();
        });
        
        executorService.submit(() -> {
            BasicAWSCredentials credentials2 = new BasicAWSCredentials("AKIA222222222222222", "secretKey2");
            // ruleid: java-aws-client-builder-shared-instance
            AmazonRDS rdsClient = rdsBuilder
                    .withCredentials(new AWSStaticCredentialsProvider(credentials2))
                    .build();
            rdsClient.describeDBClusters();
        });
    }
    
    private static final AmazonCloudWatchClientBuilder CLOUD_WATCH_BUILDER = 
            AmazonCloudWatchClientBuilder.standard();
    
    public void bad_case_8() {
        Thread thread1 = new Thread(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonCloudWatch cloudWatchClient = CLOUD_WATCH_BUILDER
                    .withRegion(Regions.AP_SOUTH_1)
                    .build();
            cloudWatchClient.listDashboards();
        });
        
        Thread thread2 = new Thread(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonCloudWatch cloudWatchClient = CLOUD_WATCH_BUILDER
                    .withRegion(Regions.AP_SOUTHEAST_2)
                    .build();
            cloudWatchClient.listMetrics();
        });
        
        thread1.start();
        thread2.start();
    }
    
    private final AWSElasticBeanstalkClientBuilder beanstalkBuilder = 
            AWSElasticBeanstalkClientBuilder.standard();
    
    public void bad_case_9() {
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        
        for (int i = 0; i < 3; i++) {
            final Regions region = i == 0 ? Regions.US_WEST_1 : 
                                  i == 1 ? Regions.EU_WEST_2 : Regions.AP_NORTHEAST_2;
            executorService.submit(() -> {
                // ruleid: java-aws-client-builder-shared-instance
                AWSElasticBeanstalk beanstalkClient = beanstalkBuilder
                        .withRegion(region)
                        .build();
                beanstalkClient.describeApplications();
            });
        }
    }
    
    private static final AmazonS3ClientBuilder S3_BUILDER_WITH_ENDPOINT = AmazonS3ClientBuilder.standard()
            .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(
                    "https://s3.amazonaws.com", "us-east-1"));
    
    public void bad_case_10() {
        Thread thread1 = new Thread(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonS3 s3Client = S3_BUILDER_WITH_ENDPOINT.build();
            s3Client.listBuckets();
        });
        
        Thread thread2 = new Thread(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonS3 s3Client = S3_BUILDER_WITH_ENDPOINT
                    .withPathStyleAccessEnabled(true)
                    .build();
            s3Client.listBuckets();
        });
        
        thread1.start();
        thread2.start();
    }
    
    private final AmazonDynamoDBClientBuilder dynamoDbBuilderWithCredentials = 
            AmazonDynamoDBClientBuilder.standard()
                .withCredentials(new DefaultAWSCredentialsProviderChain());
    
    public void bad_case_11() {
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        
        executorService.submit(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonDynamoDB dynamoDbClient = dynamoDbBuilderWithCredentials
                    .withRegion(Regions.EU_WEST_3)
                    .build();
            dynamoDbClient.listTables();
        });
        
        executorService.submit(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonDynamoDB dynamoDbClient = dynamoDbBuilderWithCredentials
                    .withRegion(Regions.EU_NORTH_1)
                    .build();
            dynamoDbClient.listTables();
        });
    }
    
    private static final AmazonSQSClientBuilder SHARED_SQS_BUILDER_WITH_CONFIG = 
            AmazonSQSClientBuilder.standard()
                .withClientConfiguration(new com.amazonaws.ClientConfiguration()
                        .withConnectionTimeout(5000)
                        .withSocketTimeout(6000));
    
    public void bad_case_12() {
        Thread thread1 = new Thread(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonSQS sqsClient = SHARED_SQS_BUILDER_WITH_CONFIG
                    .withRegion(Regions.US_EAST_1)
                    .build();
            sqsClient.listQueues();
        });
        
        Thread thread2 = new Thread(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonSQS sqsClient = SHARED_SQS_BUILDER_WITH_CONFIG
                    .withRegion(Regions.US_WEST_2)
                    .build();
            sqsClient.listQueues();
        });
        
        thread1.start();
        thread2.start();
    }
    
    private final AmazonSNSClientBuilder snsBuilderField = AmazonSNSClientBuilder.standard();
    
    public void bad_case_13() {
        ExecutorService executorService = Executors.newFixedThreadPool(4);
        
        for (int i = 0; i < 4; i++) {
            final int index = i;
            executorService.submit(() -> {
                Regions region = index == 0 ? Regions.US_EAST_1 :
                                 index == 1 ? Regions.US_WEST_1 :
                                 index == 2 ? Regions.EU_WEST_1 : Regions.AP_NORTHEAST_1;
                // ruleid: java-aws-client-builder-shared-instance
                AmazonSNS snsClient = snsBuilderField
                        .withRegion(region)
                        .build();
                snsClient.listTopics();
            });
        }
    }
    
    private static final AWSLambdaClientBuilder LAMBDA_BUILDER_STATIC = AWSLambdaClientBuilder.standard();
    
    public void bad_case_14() {
        Runnable task1 = () -> {
            // ruleid: java-aws-client-builder-shared-instance
            AWSLambda lambdaClient = LAMBDA_BUILDER_STATIC
                    .withRegion(Regions.US_EAST_1)
                    .build();
            lambdaClient.listFunctions();
        };
        
        Runnable task2 = () -> {
            // ruleid: java-aws-client-builder-shared-instance
            AWSLambda lambdaClient = LAMBDA_BUILDER_STATIC
                    .withRegion(Regions.US_WEST_2)
                    .build();
            lambdaClient.listFunctions();
        };
        
        new Thread(task1).start();
        new Thread(task2).start();
    }
    
    private final AmazonEC2ClientBuilder ec2BuilderWithTimeout = AmazonEC2ClientBuilder.standard()
            .withClientConfiguration(new com.amazonaws.ClientConfiguration()
                    .withConnectionTimeout(10000));
    
    public void bad_case_15() {
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        
        executorService.submit(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonEC2 ec2Client = ec2BuilderWithTimeout
                    .withRegion(Regions.US_EAST_1)
                    .build();
            ec2Client.describeInstances();
        });
        
        executorService.submit(() -> {
            // ruleid: java-aws-client-builder-shared-instance
            AmazonEC2 ec2Client = ec2BuilderWithTimeout
                    .withRegion(Regions.US_WEST_2)
                    .build();
            ec2Client.describeSecurityGroups();
        });
    }
    
    // True Negatives (Safe Code)
    
    public void good_case_1() {
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        
        for (int i = 0; i < 10; i++) {
            executorService.submit(() -> {
                // ok: java-aws-client-builder-shared-instance
                AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                        .withRegion(Regions.US_WEST_2)
                        .withCredentials(new DefaultAWSCredentialsProviderChain())
                        .build();
                s3Client.listBuckets();
            });
        }
    }
    
    public void good_case_2() {
        ExecutorService executorService = Executors.newFixedThreadPool(5);
        
        for (int i = 0; i < 5; i++) {
            final int index = i;
            executorService.submit(() -> {
                // ok: java-aws-client-builder-shared-instance
                AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard()
                        .withRegion(index % 2 == 0 ? Regions.US_EAST_1 : Regions.US_WEST_2)
                        .build();
                dynamoDbClient.listTables();
            });
        }
    }
    
    public void good_case_3() {
        Thread thread1 = new Thread(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonSQS sqsClient = AmazonSQSClientBuilder.standard()
                    .withRegion(Regions.EU_WEST_1)
                    .withCredentials(new DefaultAWSCredentialsProviderChain())
                    .build();
            sqsClient.listQueues();
        });
        
        Thread thread2 = new Thread(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonSQS sqsClient = AmazonSQSClientBuilder.standard()
                    .withRegion(Regions.US_EAST_1)
                    .build();
            sqsClient.listQueues();
        });
        
        thread1.start();
        thread2.start();
    }
    
    public void good_case_4() {
        Runnable task1 = () -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonSNS snsClient = AmazonSNSClientBuilder.standard()
                    .withRegion(Regions.US_WEST_1)
                    .build();
            snsClient.listTopics();
        };
        
        Runnable task2 = () -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonSNS snsClient = AmazonSNSClientBuilder.standard()
                    .withRegion(Regions.EU_CENTRAL_1)
                    .build();
            snsClient.listTopics();
        };
        
        new Thread(task1).start();
        new Thread(task2).start();
    }
    
    public void good_case_5() {
        ExecutorService executorService = Executors.newCachedThreadPool();
        
        for (int i = 0; i < 3; i++) {
            executorService.submit(() -> {
                // ok: java-aws-client-builder-shared-instance
                AWSLambda lambdaClient = AWSLambdaClientBuilder.standard()
                        .withRegion(Regions.AP_NORTHEAST_1)
                        .build();
                lambdaClient.listFunctions();
            });
        }
    }
    
    public void good_case_6() {
        Thread thread1 = new Thread(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                    .withRegion(Regions.SA_EAST_1)
                    .build();
            ec2Client.describeInstances();
        });
        
        Thread thread2 = new Thread(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                    .withRegion(Regions.CA_CENTRAL_1)
                    .build();
            ec2Client.describeSecurityGroups();
        });
        
        thread1.start();
        thread2.start();
    }
    
    public void good_case_7() {
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        
        executorService.submit(() -> {
            BasicAWSCredentials credentials1 = new BasicAWSCredentials("AKIA111111111111111", "secretKey1");
            // ok: java-aws-client-builder-shared-instance
            AmazonRDS rdsClient = AmazonRDSClientBuilder.standard()
                    .withRegion(Regions.US_EAST_2)
                    .withCredentials(new AWSStaticCredentialsProvider(credentials1))
                    .build();
            rdsClient.describeDBInstances();
        });
        
        executorService.submit(() -> {
            BasicAWSCredentials credentials2 = new BasicAWSCredentials("AKIA222222222222222", "secretKey2");
            // ok: java-aws-client-builder-shared-instance
            AmazonRDS rdsClient = AmazonRDSClientBuilder.standard()
                    .withRegion(Regions.US_EAST_2)
                    .withCredentials(new AWSStaticCredentialsProvider(credentials2))
                    .build();
            rdsClient.describeDBClusters();
        });
    }
    
    public void good_case_8() {
        Thread thread1 = new Thread(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonCloudWatch cloudWatchClient = AmazonCloudWatchClientBuilder.standard()
                    .withRegion(Regions.AP_SOUTH_1)
                    .build();
            cloudWatchClient.listDashboards();
        });
        
        Thread thread2 = new Thread(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonCloudWatch cloudWatchClient = AmazonCloudWatchClientBuilder.standard()
                    .withRegion(Regions.AP_SOUTHEAST_2)
                    .build();
            cloudWatchClient.listMetrics();
        });
        
        thread1.start();
        thread2.start();
    }
    
    public void good_case_9() {
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        
        for (int i = 0; i < 3; i++) {
            final Regions region = i == 0 ? Regions.US_WEST_1 : 
                                  i == 1 ? Regions.EU_WEST_2 : Regions.AP_NORTHEAST_2;
            executorService.submit(() -> {
                // ok: java-aws-client-builder-shared-instance
                AWSElasticBeanstalk beanstalkClient = AWSElasticBeanstalkClientBuilder.standard()
                        .withRegion(region)
                        .build();
                beanstalkClient.describeApplications();
            });
        }
    }
    
    public void good_case_10() {
        Thread thread1 = new Thread(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                    .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(
                            "https://s3.amazonaws.com", "us-east-1"))
                    .build();
            s3Client.listBuckets();
        });
        
        Thread thread2 = new Thread(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                    .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(
                            "https://s3.amazonaws.com", "us-east-1"))
                    .withPathStyleAccessEnabled(true)
                    .build();
            s3Client.listBuckets();
        });
        
        thread1.start();
        thread2.start();
    }
    
    public void good_case_11() {
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        
        executorService.submit(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard()
                    .withCredentials(new DefaultAWSCredentialsProviderChain())
                    .withRegion(Regions.EU_WEST_3)
                    .build();
            dynamoDbClient.listTables();
        });
        
        executorService.submit(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard()
                    .withCredentials(new DefaultAWSCredentialsProviderChain())
                    .withRegion(Regions.EU_NORTH_1)
                    .build();
            dynamoDbClient.listTables();
        });
    }
    
    public void good_case_12() {
        com.amazonaws.ClientConfiguration clientConfig = new com.amazonaws.ClientConfiguration()
                .withConnectionTimeout(5000)
                .withSocketTimeout(6000);
        
        Thread thread1 = new Thread(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonSQS sqsClient = AmazonSQSClientBuilder.standard()
                    .withClientConfiguration(clientConfig)
                    .withRegion(Regions.US_EAST_1)
                    .build();
            sqsClient.listQueues();
        });
        
        Thread thread2 = new Thread(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonSQS sqsClient = AmazonSQSClientBuilder.standard()
                    .withClientConfiguration(clientConfig)
                    .withRegion(Regions.US_WEST_2)
                    .build();
            sqsClient.listQueues();
        });
        
        thread1.start();
        thread2.start();
    }
    
    public void good_case_13() {
        ExecutorService executorService = Executors.newFixedThreadPool(4);
        
        for (int i = 0; i < 4; i++) {
            final int index = i;
            executorService.submit(() -> {
                Regions region = index == 0 ? Regions.US_EAST_1 :
                                 index == 1 ? Regions.US_WEST_1 :
                                 index == 2 ? Regions.EU_WEST_1 : Regions.AP_NORTHEAST_1;
                // ok: java-aws-client-builder-shared-instance
                AmazonSNS snsClient = AmazonSNSClientBuilder.standard()
                        .withRegion(region)
                        .build();
                snsClient.listTopics();
            });
        }
    }
    
    public void good_case_14() {
        Runnable task1 = () -> {
            // ok: java-aws-client-builder-shared-instance
            AWSLambda lambdaClient = AWSLambdaClientBuilder.standard()
                    .withRegion(Regions.US_EAST_1)
                    .build();
            lambdaClient.listFunctions();
        };
        
        Runnable task2 = () -> {
            // ok: java-aws-client-builder-shared-instance
            AWSLambda lambdaClient = AWSLambdaClientBuilder.standard()
                    .withRegion(Regions.US_WEST_2)
                    .build();
            lambdaClient.listFunctions();
        };
        
        new Thread(task1).start();
        new Thread(task2).start();
    }
    
    public void good_case_15() {
        com.amazonaws.ClientConfiguration clientConfig = new com.amazonaws.ClientConfiguration()
                .withConnectionTimeout(10000);
        
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        
        executorService.submit(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                    .withClientConfiguration(clientConfig)
                    .withRegion(Regions.US_EAST_1)
                    .build();
            ec2Client.describeInstances();
        });
        
        executorService.submit(() -> {
            // ok: java-aws-client-builder-shared-instance
            AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                    .withClientConfiguration(clientConfig)
                    .withRegion(Regions.US_WEST_2)
                    .build();
            ec2Client.describeSecurityGroups();
        });
    }
}
// {/fact}