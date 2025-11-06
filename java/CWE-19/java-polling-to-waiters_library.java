import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.BucketLifecycleConfiguration;
import com.amazonaws.services.s3.waiters.AmazonS3Waiters;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.DescribeInstancesRequest;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.InstanceState;
import com.amazonaws.services.ec2.waiters.AmazonEC2Waiters;
import com.amazonaws.services.rds.AmazonRDS;
import com.amazonaws.services.rds.AmazonRDSClientBuilder;
import com.amazonaws.services.rds.model.DBInstance;
import com.amazonaws.services.rds.model.DescribeDBInstancesRequest;
import com.amazonaws.services.rds.model.DescribeDBInstancesResult;
import com.amazonaws.services.rds.waiters.AmazonRDSWaiters;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.DescribeTableRequest;
import com.amazonaws.services.dynamodbv2.model.TableDescription;
import com.amazonaws.services.dynamodbv2.waiters.AmazonDynamoDBWaiters;
import com.amazonaws.services.elasticloadbalancing.AmazonElasticLoadBalancing;
import com.amazonaws.services.elasticloadbalancing.AmazonElasticLoadBalancingClientBuilder;
import com.amazonaws.services.elasticloadbalancing.model.DescribeLoadBalancersRequest;
import com.amazonaws.services.elasticloadbalancing.waiters.AmazonElasticLoadBalancingWaiters;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.GetFunctionRequest;
import com.amazonaws.services.lambda.waiters.AWSLambdaWaiters;
import com.amazonaws.services.cloudformation.AmazonCloudFormation;
import com.amazonaws.services.cloudformation.AmazonCloudFormationClientBuilder;
import com.amazonaws.services.cloudformation.model.DescribeStacksRequest;
import com.amazonaws.services.cloudformation.model.Stack;
import com.amazonaws.services.cloudformation.waiters.AmazonCloudFormationWaiters;
import com.amazonaws.services.elasticbeanstalk.AWSElasticBeanstalk;
import com.amazonaws.services.elasticbeanstalk.AWSElasticBeanstalkClientBuilder;
import com.amazonaws.services.elasticbeanstalk.model.DescribeEnvironmentsRequest;
import com.amazonaws.services.elasticbeanstalk.waiters.AWSElasticBeanstalkWaiters;
import com.amazonaws.services.ecs.AmazonECS;
import com.amazonaws.services.ecs.AmazonECSClientBuilder;
import com.amazonaws.services.ecs.model.DescribeServicesRequest;
import com.amazonaws.services.ecs.waiters.AmazonECSWaiters;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.GetQueueAttributesRequest;
import com.amazonaws.services.emr.AmazonEMR;
import com.amazonaws.services.emr.AmazonEMRClientBuilder;
import com.amazonaws.services.emr.model.DescribeClusterRequest;
import com.amazonaws.services.emr.waiters.AmazonEMRWaiters;
import com.amazonaws.services.batch.AWSBatch;
import com.amazonaws.services.batch.AWSBatchClientBuilder;
import com.amazonaws.services.batch.model.DescribeJobsRequest;
import com.amazonaws.services.batch.waiters.AWSBatchWaiters;
import com.amazonaws.services.redshift.AmazonRedshift;
import com.amazonaws.services.redshift.AmazonRedshiftClientBuilder;
import com.amazonaws.services.redshift.model.DescribeClustersRequest;
import com.amazonaws.services.redshift.waiters.AmazonRedshiftWaiters;
import com.amazonaws.services.elasticache.AmazonElastiCache;
import com.amazonaws.services.elasticache.AmazonElastiCacheClientBuilder;
import com.amazonaws.services.elasticache.model.DescribeCacheClustersRequest;
import com.amazonaws.services.elasticache.waiters.AmazonElastiCacheWaiters;
import com.amazonaws.services.stepfunctions.AWSStepFunctions;
import com.amazonaws.services.stepfunctions.AWSStepFunctionsClientBuilder;
import com.amazonaws.services.stepfunctions.model.DescribeExecutionRequest;
import com.amazonaws.waiters.WaiterParameters;

import java.util.concurrent.TimeUnit;

// Security Issue: Custom polling for AWS resources instead of using AWS waiters

// True Positive Examples (Vulnerable/Insecure Code)
public class AwsPollingExamples {

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    public void bad_case_1() {
        // S3 bucket creation with custom polling
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "my-new-bucket";
        s3Client.createBucket(bucketName);
        
        boolean bucketExists = false;
        int maxRetries = 20;
        int retryCount = 0;
        
        while (!bucketExists && retryCount < maxRetries) {
            try {
                // ruleid: java-polling-to-waiters
                if (s3Client.doesBucketExistV2(bucketName)) {
                    bucketExists = true;
                    System.out.println("Bucket created successfully");
                } else {
                    System.out.println("Waiting for bucket to be created...");
                    Thread.sleep(5000);
                    retryCount++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    public void bad_case_2() {
        // EC2 instance state polling
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        String instanceId = "i-1234567890abcdef0";
        
        boolean instanceRunning = false;
        int maxRetries = 30;
        int retryCount = 0;
        
        while (!instanceRunning && retryCount < maxRetries) {
            try {
                DescribeInstancesRequest request = new DescribeInstancesRequest().withInstanceIds(instanceId);
                // ruleid: java-polling-to-waiters
                DescribeInstancesResult result = ec2Client.describeInstances(request);
                Instance instance = result.getReservations().get(0).getInstances().get(0);
                InstanceState state = instance.getState();
                
                if (state.getName().equals("running")) {
                    instanceRunning = true;
                    System.out.println("Instance is now running");
                } else {
                    System.out.println("Instance state: " + state.getName() + ". Waiting...");
                    Thread.sleep(10000);
                    retryCount++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    public void bad_case_3() {
        // RDS database instance availability polling
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard().build();
        String dbInstanceId = "my-db-instance";
        
        boolean dbAvailable = false;
        int maxRetries = 60;
        int retryCount = 0;
        
        while (!dbAvailable && retryCount < maxRetries) {
            try {
                DescribeDBInstancesRequest request = new DescribeDBInstancesRequest().withDBInstanceIdentifier(dbInstanceId);
                // ruleid: java-polling-to-waiters
                DescribeDBInstancesResult result = rdsClient.describeDBInstances(request);
                DBInstance dbInstance = result.getDBInstances().get(0);
                
                if (dbInstance.getDBInstanceStatus().equals("available")) {
                    dbAvailable = true;
                    System.out.println("Database instance is now available");
                } else {
                    System.out.println("Database status: " + dbInstance.getDBInstanceStatus() + ". Waiting...");
                    Thread.sleep(30000);
                    retryCount++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    public void bad_case_4() {
        // DynamoDB table creation polling
        AmazonDynamoDB dynamoClient = AmazonDynamoDBClientBuilder.standard().build();
        String tableName = "my-table";
        
        boolean tableActive = false;
        int maxRetries = 25;
        int retryCount = 0;
        
        while (!tableActive && retryCount < maxRetries) {
            try {
                DescribeTableRequest request = new DescribeTableRequest().withTableName(tableName);
                // ruleid: java-polling-to-waiters
                TableDescription tableDescription = dynamoClient.describeTable(request).getTable();
                
                if (tableDescription.getTableStatus().equals("AC_REDACTED_TWILIO_ID")) {
                    tableActive = true;
                    System.out.println("Table is now active");
                } else {
                    System.out.println("Table status: " + tableDescription.getTableStatus() + ". Waiting...");
                    Thread.sleep(5000);
                    retryCount++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    public void bad_case_5() {
        // ELB load balancer creation polling
        AmazonElasticLoadBalancing elbClient = AmazonElasticLoadBalancingClientBuilder.standard().build();
        String loadBalancerName = "my-load-balancer";
        
        boolean lbAvailable = false;
        int maxRetries = 20;
        int retryCount = 0;
        
        while (!lbAvailable && retryCount < maxRetries) {
            try {
                DescribeLoadBalancersRequest request = new DescribeLoadBalancersRequest().withLoadBalancerNames(loadBalancerName);
                // ruleid: java-polling-to-waiters
                if (elbClient.describeLoadBalancers(request).getLoadBalancerDescriptions().size() > 0) {
                    lbAvailable = true;
                    System.out.println("Load balancer is now available");
                } else {
                    System.out.println("Waiting for load balancer to be available...");
                    Thread.sleep(15000);
                    retryCount++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    public void bad_case_6() {
        // Lambda function creation polling
        AWSLambda lambdaClient = AWSLambdaClientBuilder.standard().build();
        String functionName = "my-lambda-function";
        
        boolean functionReady = false;
        int maxRetries = 15;
        int retryCount = 0;
        
        while (!functionReady && retryCount < maxRetries) {
            try {
                GetFunctionRequest request = new GetFunctionRequest().withFunctionName(functionName);
                // ruleid: java-polling-to-waiters
                if (lambdaClient.getFunction(request).getConfiguration() != null) {
                    functionReady = true;
                    System.out.println("Lambda function is now ready");
                } else {
                    System.out.println("Waiting for Lambda function to be ready...");
                    Thread.sleep(2000);
                    retryCount++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    public void bad_case_7() {
        // CloudFormation stack creation polling
        AmazonCloudFormation cfClient = AmazonCloudFormationClientBuilder.standard().build();
        String stackName = "my-cf-stack";
        
        boolean stackComplete = false;
        int maxRetries = 60;
        int retryCount = 0;
        
        while (!stackComplete && retryCount < maxRetries) {
            try {
                DescribeStacksRequest request = new DescribeStacksRequest().withStackName(stackName);
                // ruleid: java-polling-to-waiters
                Stack stack = cfClient.describeStacks(request).getStacks().get(0);
                String status = stack.getStackStatus();
                
                if (status.equals("CREATE_COMPLETE")) {
                    stackComplete = true;
                    System.out.println("Stack creation completed successfully");
                } else if (status.equals("CREATE_FAILED") || status.equals("ROLLBAC_REDACTED_TWILIO_ID_COMPLETE")) {
                    System.out.println("Stack creation failed: " + status);
                    break;
                } else {
                    System.out.println("Stack status: " + status + ". Waiting...");
                    Thread.sleep(10000);
                    retryCount++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    public void bad_case_8() {
        // Elastic Beanstalk environment deployment polling
        AWSElasticBeanstalk ebClient = AWSElasticBeanstalkClientBuilder.standard().build();
        String environmentId = "e-abcdefghij";
        
        boolean environmentReady = false;
        int maxRetries = 40;
        int retryCount = 0;
        
        while (!environmentReady && retryCount < maxRetries) {
            try {
                DescribeEnvironmentsRequest request = new DescribeEnvironmentsRequest().withEnvironmentIds(environmentId);
                // ruleid: java-polling-to-waiters
                String status = ebClient.describeEnvironments(request).getEnvironments().get(0).getStatus();
                
                if (status.equals("Ready")) {
                    environmentReady = true;
                    System.out.println("Elastic Beanstalk environment is now ready");
                } else {
                    System.out.println("Environment status: " + status + ". Waiting...");
                    Thread.sleep(30000);
                    retryCount++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    public void bad_case_9() {
        // ECS service deployment polling
        AmazonECS ecsClient = AmazonECSClientBuilder.standard().build();
        String cluster = "my-ecs-cluster";
        String service = "my-ecs-service";
        
        boolean serviceStable = false;
        int maxRetries = 30;
        int retryCount = 0;
        
        while (!serviceStable && retryCount < maxRetries) {
            try {
                DescribeServicesRequest request = new DescribeServicesRequest().withCluster(cluster).withServices(service);
                // ruleid: java-polling-to-waiters
                String status = ecsClient.describeServices(request).getServices().get(0).getStatus();
                
                if (status.equals("AC_REDACTED_TWILIO_ID")) {
                    serviceStable = true;
                    System.out.println("ECS service is now stable");
                } else {
                    System.out.println("Service status: " + status + ". Waiting...");
                    Thread.sleep(10000);
                    retryCount++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    public void bad_case_10() {
        // SQS queue creation polling
        AmazonSQS sqsClient = AmazonSQSClientBuilder.standard().build();
        String queueUrl = "https://sqs.us-east-1.amazonaws.com/123456789012/my-queue";
        
        boolean queueAvailable = false;
        int maxRetries = 10;
        int retryCount = 0;
        
        while (!queueAvailable && retryCount < maxRetries) {
            try {
                GetQueueAttributesRequest request = new GetQueueAttributesRequest()
                    .withQueueUrl(queueUrl)
                    .withAttributeNames("All");
                
                // ruleid: java-polling-to-waiters
                if (sqsClient.getQueueAttributes(request) != null) {
                    queueAvailable = true;
                    System.out.println("SQS queue is now available");
                } else {
                    System.out.println("Waiting for SQS queue to be available...");
                    Thread.sleep(2000);
                    retryCount++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    public void bad_case_11() {
        // EMR cluster creation polling
        AmazonEMR emrClient = AmazonEMRClientBuilder.standard().build();
        String clusterId = "j-2AXXXXXXGAPLF";
        
        boolean clusterReady = false;
        int maxRetries = 60;
        int retryCount = 0;
        
        while (!clusterReady && retryCount < maxRetries) {
            try {
                DescribeClusterRequest request = new DescribeClusterRequest().withClusterId(clusterId);
                // ruleid: java-polling-to-waiters
                String state = emrClient.describeCluster(request).getCluster().getStatus().getState();
                
                if (state.equals("RUNNING") || state.equals("WAITING")) {
                    clusterReady = true;
                    System.out.println("EMR cluster is now ready");
                } else if (state.equals("TERMINATED") || state.equals("TERMINATED_WITH_ERRORS")) {
                    System.out.println("EMR cluster failed: " + state);
                    break;
                } else {
                    System.out.println("Cluster state: " + state + ". Waiting...");
                    Thread.sleep(60000);
                    retryCount++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    public void bad_case_12() {
        // AWS Batch job completion polling
        AWSBatch batchClient = AWSBatchClientBuilder.standard().build();
        String jobId = "job-12345678-abcd-efgh-ijkl-0123456789ab";
        
        boolean jobComplete = false;
        int maxRetries = 50;
        int retryCount = 0;
        
        while (!jobComplete && retryCount < maxRetries) {
            try {
                DescribeJobsRequest request = new DescribeJobsRequest().withJobs(jobId);
                // ruleid: java-polling-to-waiters
                String status = batchClient.describeJobs(request).getJobs().get(0).getStatus();
                
                if (status.equals("SUCCEEDED")) {
                    jobComplete = true;
                    System.out.println("Batch job completed successfully");
                } else if (status.equals("FAILED")) {
                    System.out.println("Batch job failed");
                    break;
                } else {
                    System.out.println("Job status: " + status + ". Waiting...");
                    Thread.sleep(10000);
                    retryCount++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    public void bad_case_13() {
        // Redshift cluster creation polling
        AmazonRedshift redshiftClient = AmazonRedshiftClientBuilder.standard().build();
        String clusterIdentifier = "my-redshift-cluster";
        
        boolean clusterAvailable = false;
        int maxRetries = 60;
        int retryCount = 0;
        
        while (!clusterAvailable && retryCount < maxRetries) {
            try {
                DescribeClustersRequest request = new DescribeClustersRequest().withClusterIdentifier(clusterIdentifier);
                // ruleid: java-polling-to-waiters
                String status = redshiftClient.describeClusters(request).getClusters().get(0).getClusterStatus();
                
                if (status.equals("available")) {
                    clusterAvailable = true;
                    System.out.println("Redshift cluster is now available");
                } else {
                    System.out.println("Cluster status: " + status + ". Waiting...");
                    Thread.sleep(30000);
                    retryCount++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    public void bad_case_14() {
        // ElastiCache cluster creation polling
        AmazonElastiCache elastiCacheClient = AmazonElastiCacheClientBuilder.standard().build();
        String cacheClusterId = "my-cache-cluster";
        
        boolean clusterAvailable = false;
        int maxRetries = 40;
        int retryCount = 0;
        
        while (!clusterAvailable && retryCount < maxRetries) {
            try {
                DescribeCacheClustersRequest request = new DescribeCacheClustersRequest()
                    .withCacheClusterId(cacheClusterId);
                // ruleid: java-polling-to-waiters
                String status = elastiCacheClient.describeCacheClusters(request)
                    .getCacheClusters().get(0).getCacheClusterStatus();
                
                if (status.equals("available")) {
                    clusterAvailable = true;
                    System.out.println("ElastiCache cluster is now available");
                } else {
                    System.out.println("Cluster status: " + status + ". Waiting...");
                    Thread.sleep(15000);
                    retryCount++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    public void bad_case_15() {
        // Step Functions execution completion polling
        AWSStepFunctions sfnClient = AWSStepFunctionsClientBuilder.standard().build();
        String executionArn = "arn:aws:states:us-east-1:123456789012:execution:MyStateMachine:execution1";
        
        boolean executionComplete = false;
        int maxRetries = 30;
        int retryCount = 0;
        
        while (!executionComplete && retryCount < maxRetries) {
            try {
                DescribeExecutionRequest request = new DescribeExecutionRequest().withExecutionArn(executionArn);
                // ruleid: java-polling-to-waiters
                String status = sfnClient.describeExecution(request).getStatus();
                
                if (status.equals("SUCCEEDED")) {
                    executionComplete = true;
                    System.out.println("Step Functions execution completed successfully");
                } else if (status.equals("FAILED") || status.equals("TIMED_OUT") || status.equals("ABORTED")) {
                    System.out.println("Step Functions execution failed: " + status);
                    break;
                } else {
                    System.out.println("Execution status: " + status + ". Waiting...");
                    Thread.sleep(5000);
                    retryCount++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    public void good_case_1() {
        // S3 bucket creation using waiter
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "my-new-bucket";
        s3Client.createBucket(bucketName);
        
        // ok: java-polling-to-waiters
        s3Client.waiters().bucketExists().run(new WaiterParameters<>()
            .withRequest(builder -> builder.bucketName(bucketName)));
        System.out.println("Bucket created successfully");
    }
    
    public void good_case_2() {
        // EC2 instance state using waiter
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        String instanceId = "i-1234567890abcdef0";
        AmazonEC2Waiters waiters = ec2Client.waiters();
        
        // ok: java-polling-to-waiters
        waiters.instanceRunning().run(new WaiterParameters<>(
            new DescribeInstancesRequest().withInstanceIds(instanceId)));
        System.out.println("Instance is now running");
    }
    
    public void good_case_3() {
        // RDS database instance availability using waiter
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard().build();
        String dbInstanceId = "my-db-instance";
        AmazonRDSWaiters waiters = rdsClient.waiters();
        
        // ok: java-polling-to-waiters
        waiters.dBInstanceAvailable().run(new WaiterParameters<>(
            new DescribeDBInstancesRequest().withDBInstanceIdentifier(dbInstanceId)));
        System.out.println("Database instance is now available");
    }
    
    public void good_case_4() {
        // DynamoDB table creation using waiter
        AmazonDynamoDB dynamoClient = AmazonDynamoDBClientBuilder.standard().build();
        String tableName = "my-table";
        AmazonDynamoDBWaiters waiters = dynamoClient.waiters();
        
        // ok: java-polling-to-waiters
        waiters.tableExists().run(new WaiterParameters<>(
            new DescribeTableRequest().withTableName(tableName)));
        System.out.println("Table is now active");
    }
    
    public void good_case_5() {
        // ELB load balancer creation using waiter
        AmazonElasticLoadBalancing elbClient = AmazonElasticLoadBalancingClientBuilder.standard().build();
        String loadBalancerName = "my-load-balancer";
        AmazonElasticLoadBalancingWaiters waiters = elbClient.waiters();
        
        // ok: java-polling-to-waiters
        waiters.loadBalancerExists().run(new WaiterParameters<>(
            new DescribeLoadBalancersRequest().withLoadBalancerNames(loadBalancerName)));
        System.out.println("Load balancer is now available");
    }
    
    public void good_case_6() {
        // Lambda function creation using waiter
        AWSLambda lambdaClient = AWSLambdaClientBuilder.standard().build();
        String functionName = "my-lambda-function";
        AWSLambdaWaiters waiters = lambdaClient.waiters();
        
        // ok: java-polling-to-waiters
        waiters.functionExists().run(new WaiterParameters<>(
            new GetFunctionRequest().withFunctionName(functionName)));
        System.out.println("Lambda function is now ready");
    }
    
    public void good_case_7() {
        // CloudFormation stack creation using waiter
        AmazonCloudFormation cfClient = AmazonCloudFormationClientBuilder.standard().build();
        String stackName = "my-cf-stack";
        AmazonCloudFormationWaiters waiters = cfClient.waiters();
        
        // ok: java-polling-to-waiters
        waiters.stackCreateComplete().run(new WaiterParameters<>(
            new DescribeStacksRequest().withStackName(stackName)));
        System.out.println("Stack creation completed successfully");
    }
    
    public void good_case_8() {
        // Elastic Beanstalk environment deployment using waiter
        AWSElasticBeanstalk ebClient = AWSElasticBeanstalkClientBuilder.standard().build();
        String environmentId = "e-abcdefghij";
        AWSElasticBeanstalkWaiters waiters = ebClient.waiters();
        
        // ok: java-polling-to-waiters
        waiters.environmentUpdated().run(new WaiterParameters<>(
            new DescribeEnvironmentsRequest().withEnvironmentIds(environmentId)));
        System.out.println("Elastic Beanstalk environment is now ready");
    }
    
    public void good_case_9() {
        // ECS service deployment using waiter
        AmazonECS ecsClient = AmazonECSClientBuilder.standard().build();
        String cluster = "my-ecs-cluster";
        String service = "my-ecs-service";
        AmazonECSWaiters waiters = ecsClient.waiters();
        
        // ok: java-polling-to-waiters
        waiters.servicesStable().run(new WaiterParameters<>(
            new DescribeServicesRequest().withCluster(cluster).withServices(service)));
        System.out.println("ECS service is now stable");
    }
    
    public void good_case_10() {
        // SQS queue creation - using appropriate delay instead of polling
        AmazonSQS sqsClient = AmazonSQSClientBuilder.standard().build();
        String queueUrl = sqsClient.createQueue("my-queue").getQueueUrl();
        
        // ok: java-polling-to-waiters
        // SQS doesn't have built-in waiters, but we can use a more efficient approach than polling
        // Wait a reasonable time for queue creation (SQS queues are typically available immediately)
        try {
            TimeUnit.SECONDS.sleep(2);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        System.out.println("SQS queue is now available at: " + queueUrl);
    }
    
    public void good_case_11() {
        // EMR cluster creation using waiter
        AmazonEMR emrClient = AmazonEMRClientBuilder.standard().build();
        String clusterId = "j-2AXXXXXXGAPLF";
        AmazonEMRWaiters waiters = emrClient.waiters();
        
        // ok: java-polling-to-waiters
        waiters.clusterRunning().run(new WaiterParameters<>(
            new DescribeClusterRequest().withClusterId(clusterId)));
        System.out.println("EMR cluster is now ready");
    }
    
    public void good_case_12() {
        // AWS Batch job completion using waiter
        AWSBatch batchClient = AWSBatchClientBuilder.standard().build();
        String jobId = "job-12345678-abcd-efgh-ijkl-0123456789ab";
        AWSBatchWaiters waiters = batchClient.waiters();
        
        // ok: java-polling-to-waiters
        waiters.jobComplete().run(new WaiterParameters<>(
            new DescribeJobsRequest().withJobs(jobId)));
        System.out.println("Batch job completed successfully");
    }
    
    public void good_case_13() {
        // Redshift cluster creation using waiter
        AmazonRedshift redshiftClient = AmazonRedshiftClientBuilder.standard().build();
        String clusterIdentifier = "my-redshift-cluster";
        AmazonRedshiftWaiters waiters = redshiftClient.waiters();
        
        // ok: java-polling-to-waiters
        waiters.clusterAvailable().run(new WaiterParameters<>(
            new DescribeClustersRequest().withClusterIdentifier(clusterIdentifier)));
        System.out.println("Redshift cluster is now available");
    }
    
    public void good_case_14() {
        // ElastiCache cluster creation using waiter
        AmazonElastiCache elastiCacheClient = AmazonElastiCacheClientBuilder.standard().build();
        String cacheClusterId = "my-cache-cluster";
        AmazonElastiCacheWaiters waiters = elastiCacheClient.waiters();
        
        // ok: java-polling-to-waiters
        waiters.cacheClusterAvailable().run(new WaiterParameters<>(
            new DescribeCacheClustersRequest().withCacheClusterId(cacheClusterId)));
        System.out.println("ElastiCache cluster is now available");
    }
    
    public void good_case_15() {
        // Step Functions execution completion - using appropriate approach
        AWSStepFunctions sfnClient = AWSStepFunctionsClientBuilder.standard().build();
        String executionArn = "arn:aws:states:us-east-1:123456789012:execution:MyStateMachine:execution1";
        
        // ok: java-polling-to-waiters
        // Step Functions doesn't have built-in waiters in the Java SDK, but we can use a more efficient approach
        // In a real application, you would use Step Functions' callback pattern or EventBridge integration
        // This is a simplified example showing how to avoid polling
        DescribeExecutionRequest request = new DescribeExecutionRequest().withExecutionArn(executionArn);
        sfnClient.describeExecution(request); // Initial check
        
        // In a real application, you would register a callback or use EventBridge
        System.out.println("Using Step Functions callback pattern instead of polling");
    }
}
// {/fact}