import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.dynamodb.AmazonDynamoDB;
import com.amazonaws.services.dynamodb.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodb.model.AttributeValue;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.GetQueueAttributesResult;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.GetFunctionResult;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.rds.AmazonRDS;
import com.amazonaws.services.rds.AmazonRDSClientBuilder;
import com.amazonaws.services.rds.model.DescribeDBInstancesResult;
import com.amazonaws.services.elasticache.AmazonElastiCache;
import com.amazonaws.services.elasticache.AmazonElastiCacheClientBuilder;
import com.amazonaws.services.elasticache.model.DescribeCacheClustersResult;
import com.amazonaws.services.cloudwatch.AmazonCloudWatch;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClientBuilder;
import com.amazonaws.services.cloudwatch.model.GetMetricDataResult;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import com.amazonaws.services.sns.model.GetTopicAttributesResult;
import com.amazonaws.services.efs.AmazonEFS;
import com.amazonaws.services.efs.AmazonEFSClientBuilder;
import com.amazonaws.services.efs.model.DescribeFileSystemsResult;
import com.amazonaws.services.glacier.AmazonGlacier;
import com.amazonaws.services.glacier.AmazonGlacierClientBuilder;
import com.amazonaws.services.glacier.model.GetVaultMetadataResult;
import com.amazonaws.services.redshift.AmazonRedshift;
import com.amazonaws.services.redshift.AmazonRedshiftClientBuilder;
import com.amazonaws.services.redshift.model.DescribeClustersResult;
import com.amazonaws.services.elasticbeanstalk.AWSElasticBeanstalk;
import com.amazonaws.services.elasticbeanstalk.AWSElasticBeanstalkClientBuilder;
import com.amazonaws.services.elasticbeanstalk.model.DescribeEnvironmentsResult;
import com.amazonaws.services.elasticloadbalancing.AmazonElasticLoadBalancing;
import com.amazonaws.services.elasticloadbalancing.AmazonElasticLoadBalancingClientBuilder;
import com.amazonaws.services.elasticloadbalancing.model.DescribeLoadBalancersResult;
import com.amazonaws.services.cloudformation.AmazonCloudFormation;
import com.amazonaws.services.cloudformation.AmazonCloudFormationClientBuilder;
import com.amazonaws.services.cloudformation.model.DescribeStacksResult;
import com.amazonaws.services.route53.AmazonRoute53;
import com.amazonaws.services.route53.AmazonRoute53ClientBuilder;
import com.amazonaws.services.route53.model.GetHostedZoneResult;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;

// Security Issue: Dereferencing a potentially null cached response metadata without a null check can lead to a null pointer exception

// True Positive Examples (Vulnerable/Insecure Code)
public class NullCheckCacheResponseMetadataExamples {

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    public void bad_case_1() {
        // AWS S3 Client - Vulnerable implementation
        AmazonS3 s3Client = new AmazonS3Client();
        ObjectMetadata metadata = s3Client.getObject("bucket", "key").getObjectMetadata();
        
        // ruleid: java-null-check-cache-response-metadata
        String contentType = metadata.getContentType();
        System.out.println("Content Type: " + contentType);
    }

    public void bad_case_2() {
        // AWS DynamoDB Client - Vulnerable implementation
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> item = dynamoDBClient.getItem("table", Map.of("id", new AttributeValue("123"))).getItem();
        
        // ruleid: java-null-check-cache-response-metadata
        AttributeValue nameAttribute = item.get("name");
        String name = nameAttribute.getS();
        System.out.println("Name: " + name);
    }

    public void bad_case_3() {
        // AWS SQS Client - Vulnerable implementation
        AmazonSQS sqsClient = AmazonSQSClientBuilder.standard().build();
        GetQueueAttributesResult result = sqsClient.getQueueAttributes("queueUrl", java.util.Collections.singletonList("QueueArn"));
        
        // ruleid: java-null-check-cache-response-metadata
        Map<String, String> attributes = result.getAttributes();
        String queueArn = attributes.get("QueueArn");
        System.out.println("Queue ARN: " + queueArn);
    }

    public void bad_case_4() {
        // AWS Lambda Client - Vulnerable implementation
        AWSLambda lambdaClient = AWSLambdaClientBuilder.standard().build();
        GetFunctionResult result = lambdaClient.getFunction("functionName");
        
        // ruleid: java-null-check-cache-response-metadata
        String runtime = result.getConfiguration().getRuntime();
        System.out.println("Runtime: " + runtime);
    }

    public void bad_case_5() {
        // AWS EC2 Client - Vulnerable implementation
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        DescribeInstancesResult result = ec2Client.describeInstances();
        
        // ruleid: java-null-check-cache-response-metadata
        String instanceId = result.getReservations().get(0).getInstances().get(0).getInstanceId();
        System.out.println("Instance ID: " + instanceId);
    }

    public void bad_case_6() {
        // AWS RDS Client - Vulnerable implementation
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard().build();
        DescribeDBInstancesResult result = rdsClient.describeDBInstances();
        
        // ruleid: java-null-check-cache-response-metadata
        String endpoint = result.getDBInstances().get(0).getEndpoint().getAddress();
        System.out.println("DB Endpoint: " + endpoint);
    }

    public void bad_case_7() {
        // AWS ElastiCache Client - Vulnerable implementation
        AmazonElastiCache elastiCacheClient = AmazonElastiCacheClientBuilder.standard().build();
        DescribeCacheClustersResult result = elastiCacheClient.describeCacheClusters();
        
        // ruleid: java-null-check-cache-response-metadata
        String clusterStatus = result.getCacheClusters().get(0).getCacheClusterStatus();
        System.out.println("Cluster Status: " + clusterStatus);
    }

    public void bad_case_8() {
        // AWS CloudWatch Client - Vulnerable implementation
        AmazonCloudWatch cloudWatchClient = AmazonCloudWatchClientBuilder.standard().build();
        GetMetricDataResult result = cloudWatchClient.getMetricData(null);
        
        // ruleid: java-null-check-cache-response-metadata
        double value = result.getMetricDataResults().get(0).getValues().get(0);
        System.out.println("Metric Value: " + value);
    }

    public void bad_case_9() {
        // AWS SNS Client - Vulnerable implementation
        AmazonSNS snsClient = AmazonSNSClientBuilder.standard().build();
        GetTopicAttributesResult result = snsClient.getTopicAttributes("topicArn");
        
        // ruleid: java-null-check-cache-response-metadata
        String owner = result.getAttributes().get("Owner");
        System.out.println("Topic Owner: " + owner);
    }

    public void bad_case_10() {
        // AWS EFS Client - Vulnerable implementation
        AmazonEFS efsClient = AmazonEFSClientBuilder.standard().build();
        DescribeFileSystemsResult result = efsClient.describeFileSystems();
        
        // ruleid: java-null-check-cache-response-metadata
        String fileSystemId = result.getFileSystems().get(0).getFileSystemId();
        System.out.println("File System ID: " + fileSystemId);
    }

    public void bad_case_11() {
        // AWS Glacier Client - Vulnerable implementation
        AmazonGlacier glacierClient = AmazonGlacierClientBuilder.standard().build();
        GetVaultMetadataResult result = glacierClient.getVaultMetadata("accountId", "vaultName");
        
        // ruleid: java-null-check-cache-response-metadata
        long size = result.getSizeInBytes();
        System.out.println("Vault Size: " + size);
    }

    public void bad_case_12() {
        // AWS Redshift Client - Vulnerable implementation
        AmazonRedshift redshiftClient = AmazonRedshiftClientBuilder.standard().build();
        DescribeClustersResult result = redshiftClient.describeClusters();
        
        // ruleid: java-null-check-cache-response-metadata
        String clusterStatus = result.getClusters().get(0).getClusterStatus();
        System.out.println("Cluster Status: " + clusterStatus);
    }

    public void bad_case_13() {
        // AWS Elastic Beanstalk Client - Vulnerable implementation
        AWSElasticBeanstalk beanstalkClient = AWSElasticBeanstalkClientBuilder.standard().build();
        DescribeEnvironmentsResult result = beanstalkClient.describeEnvironments();
        
        // ruleid: java-null-check-cache-response-metadata
        String environmentId = result.getEnvironments().get(0).getEnvironmentId();
        System.out.println("Environment ID: " + environmentId);
    }

    public void bad_case_14() {
        // AWS Elastic Load Balancing Client - Vulnerable implementation
        AmazonElasticLoadBalancing elbClient = AmazonElasticLoadBalancingClientBuilder.standard().build();
        DescribeLoadBalancersResult result = elbClient.describeLoadBalancers();
        
        // ruleid: java-null-check-cache-response-metadata
        String dnsName = result.getLoadBalancerDescriptions().get(0).getDNSName();
        System.out.println("Load Balancer DNS: " + dnsName);
    }

    public void bad_case_15() {
        // AWS CloudFormation Client - Vulnerable implementation
        AmazonCloudFormation cfnClient = AmazonCloudFormationClientBuilder.standard().build();
        DescribeStacksResult result = cfnClient.describeStacks();
        
        // ruleid: java-null-check-cache-response-metadata
        String stackStatus = result.getStacks().get(0).getStackStatus();
        System.out.println("Stack Status: " + stackStatus);
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1() {
        // AWS S3 Client - Safe implementation with null check
        AmazonS3 s3Client = new AmazonS3Client();
        ObjectMetadata metadata = s3Client.getObject("bucket", "key").getObjectMetadata();
        
        // ok: java-null-check-cache-response-metadata
        if (metadata != null) {
            String contentType = metadata.getContentType();
            System.out.println("Content Type: " + contentType);
        }
    }

    public void good_case_2() {
        // AWS DynamoDB Client - Safe implementation with null check
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> item = dynamoDBClient.getItem("table", Map.of("id", new AttributeValue("123"))).getItem();
        
        // ok: java-null-check-cache-response-metadata
        if (item != null && item.get("name") != null) {
            AttributeValue nameAttribute = item.get("name");
            String name = nameAttribute.getS();
            System.out.println("Name: " + name);
        }
    }

    public void good_case_3() {
        // AWS SQS Client - Safe implementation with null check
        AmazonSQS sqsClient = AmazonSQSClientBuilder.standard().build();
        GetQueueAttributesResult result = sqsClient.getQueueAttributes("queueUrl", java.util.Collections.singletonList("QueueArn"));
        
        // ok: java-null-check-cache-response-metadata
        Map<String, String> attributes = result.getAttributes();
        if (attributes != null) {
            String queueArn = attributes.get("QueueArn");
            System.out.println("Queue ARN: " + queueArn);
        }
    }

    public void good_case_4() {
        // AWS Lambda Client - Safe implementation with null check
        AWSLambda lambdaClient = AWSLambdaClientBuilder.standard().build();
        GetFunctionResult result = lambdaClient.getFunction("functionName");
        
        // ok: java-null-check-cache-response-metadata
        if (result != null && result.getConfiguration() != null) {
            String runtime = result.getConfiguration().getRuntime();
            System.out.println("Runtime: " + runtime);
        }
    }

    public void good_case_5() {
        // AWS EC2 Client - Safe implementation with null check
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        DescribeInstancesResult result = ec2Client.describeInstances();
        
        // ok: java-null-check-cache-response-metadata
        if (result != null && !result.getReservations().isEmpty() && 
            !result.getReservations().get(0).getInstances().isEmpty()) {
            String instanceId = result.getReservations().get(0).getInstances().get(0).getInstanceId();
            System.out.println("Instance ID: " + instanceId);
        }
    }

    public void good_case_6() {
        // AWS RDS Client - Safe implementation with null check
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard().build();
        DescribeDBInstancesResult result = rdsClient.describeDBInstances();
        
        // ok: java-null-check-cache-response-metadata
        if (result != null && !result.getDBInstances().isEmpty() && 
            result.getDBInstances().get(0).getEndpoint() != null) {
            String endpoint = result.getDBInstances().get(0).getEndpoint().getAddress();
            System.out.println("DB Endpoint: " + endpoint);
        }
    }

    public void good_case_7() {
        // AWS ElastiCache Client - Safe implementation with null check
        AmazonElastiCache elastiCacheClient = AmazonElastiCacheClientBuilder.standard().build();
        DescribeCacheClustersResult result = elastiCacheClient.describeCacheClusters();
        
        // ok: java-null-check-cache-response-metadata
        if (result != null && !result.getCacheClusters().isEmpty()) {
            String clusterStatus = result.getCacheClusters().get(0).getCacheClusterStatus();
            System.out.println("Cluster Status: " + clusterStatus);
        }
    }

    public void good_case_8() {
        // AWS CloudWatch Client - Safe implementation with null check
        AmazonCloudWatch cloudWatchClient = AmazonCloudWatchClientBuilder.standard().build();
        GetMetricDataResult result = cloudWatchClient.getMetricData(null);
        
        // ok: java-null-check-cache-response-metadata
        if (result != null && !result.getMetricDataResults().isEmpty() && 
            !result.getMetricDataResults().get(0).getValues().isEmpty()) {
            double value = result.getMetricDataResults().get(0).getValues().get(0);
            System.out.println("Metric Value: " + value);
        }
    }

    public void good_case_9() {
        // AWS SNS Client - Safe implementation with null check
        AmazonSNS snsClient = AmazonSNSClientBuilder.standard().build();
        GetTopicAttributesResult result = snsClient.getTopicAttributes("topicArn");
        
        // ok: java-null-check-cache-response-metadata
        Map<String, String> attributes = result.getAttributes();
        if (attributes != null && attributes.containsKey("Owner")) {
            String owner = attributes.get("Owner");
            System.out.println("Topic Owner: " + owner);
        }
    }

    public void good_case_10() {
        // AWS EFS Client - Safe implementation with null check
        AmazonEFS efsClient = AmazonEFSClientBuilder.standard().build();
        DescribeFileSystemsResult result = efsClient.describeFileSystems();
        
        // ok: java-null-check-cache-response-metadata
        if (result != null && !result.getFileSystems().isEmpty()) {
            String fileSystemId = result.getFileSystems().get(0).getFileSystemId();
            System.out.println("File System ID: " + fileSystemId);
        }
    }

    public void good_case_11() {
        // AWS Glacier Client - Safe implementation with Optional
        AmazonGlacier glacierClient = AmazonGlacierClientBuilder.standard().build();
        GetVaultMetadataResult result = glacierClient.getVaultMetadata("accountId", "vaultName");
        
        // ok: java-null-check-cache-response-metadata
        Optional.ofNullable(result)
            .ifPresent(r -> System.out.println("Vault Size: " + r.getSizeInBytes()));
    }

    public void good_case_12() {
        // AWS Redshift Client - Safe implementation with try-catch
        AmazonRedshift redshiftClient = AmazonRedshiftClientBuilder.standard().build();
        DescribeClustersResult result = redshiftClient.describeClusters();
        
        // ok: java-null-check-cache-response-metadata
        try {
            if (result != null && !result.getClusters().isEmpty()) {
                String clusterStatus = result.getClusters().get(0).getClusterStatus();
                System.out.println("Cluster Status: " + clusterStatus);
            }
        } catch (NullPointerException e) {
            System.out.println("Cluster information is not available");
        }
    }

    public void good_case_13() {
        // AWS Elastic Beanstalk Client - Safe implementation with default value
        AWSElasticBeanstalk beanstalkClient = AWSElasticBeanstalkClientBuilder.standard().build();
        DescribeEnvironmentsResult result = beanstalkClient.describeEnvironments();
        
        // ok: java-null-check-cache-response-metadata
        String environmentId = "unknown";
        if (result != null && !result.getEnvironments().isEmpty()) {
            environmentId = result.getEnvironments().get(0).getEnvironmentId();
        }
        System.out.println("Environment ID: " + environmentId);
    }

    public void good_case_14() {
        // AWS Elastic Load Balancing Client - Safe implementation with early return
        AmazonElasticLoadBalancing elbClient = AmazonElasticLoadBalancingClientBuilder.standard().build();
        DescribeLoadBalancersResult result = elbClient.describeLoadBalancers();
        
        // ok: java-null-check-cache-response-metadata
        if (result == null || result.getLoadBalancerDescriptions().isEmpty()) {
            System.out.println("No load balancers found");
            return;
        }
        
        String dnsName = result.getLoadBalancerDescriptions().get(0).getDNSName();
        System.out.println("Load Balancer DNS: " + dnsName);
    }

    public void good_case_15() {
        // AWS Route53 Client - Safe implementation with null-safe getter
        AmazonRoute53 route53Client = AmazonRoute53ClientBuilder.standard().build();
        GetHostedZoneResult result = route53Client.getHostedZone("hostedZoneId");
        
        // ok: java-null-check-cache-response-metadata
        Map<String, String> tags = result != null && result.getHostedZone() != null ? 
            result.getHostedZone().getTags() : new HashMap<>();
        
        System.out.println("Zone Tags: " + tags);
    }
}
// {/fact}