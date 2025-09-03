import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.lambda.AWSLambdaClient;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.sqs.AmazonSQSClient;
import com.amazonaws.services.sns.AmazonSNSClient;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClient;
import com.amazonaws.services.elasticache.AmazonElastiCacheClient;
import com.amazonaws.services.rds.AmazonRDSClient;
import com.amazonaws.services.kinesis.AmazonKinesisClient;
import com.amazonaws.services.elasticloadbalancing.AmazonElasticLoadBalancingClient;
import com.amazonaws.services.elasticbeanstalk.AWSElasticBeanstalkClient;
import com.amazonaws.services.glacier.AmazonGlacierClient;
import com.amazonaws.services.redshift.AmazonRedshiftClient;
import com.amazonaws.services.cloudformation.AmazonCloudFormationClient;
import com.amazonaws.services.elasticmapreduce.AmazonElasticMapReduceClient;
import com.amazonaws.services.opsworks.AWSOpsWorksClient;
import com.amazonaws.services.route53.AmazonRoute53Client;
import com.amazonaws.services.iam.AmazonIdentityManagementClient;
import com.amazonaws.services.sts.AWSSecurityTokenServiceClient;
import com.amazonaws.services.cloudfront.AmazonCloudFrontClient;
import com.amazonaws.services.simpleworkflow.AmazonSimpleWorkflowClient;
import com.amazonaws.services.storagegateway.AWSStorageGatewayClient;
import com.amazonaws.services.directconnect.AmazonDirectConnectClient;
import com.amazonaws.services.elastictranscoder.AmazonElasticTranscoderClient;
import com.amazonaws.services.datapipeline.DataPipelineClient;
import com.amazonaws.services.opsworks.AWSOpsWorksClient;
import com.amazonaws.services.support.AWSSupportClient;
import com.amazonaws.services.simpledb.AmazonSimpleDBClient;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.auth.InstanceProfileCredentialsProvider;
import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;
import com.amazonaws.auth.SystemPropertiesCredentialsProvider;
import com.amazonaws.auth.ClasspathPropertiesFileCredentialsProvider;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.auth.WebIdentityFederationSessionCredentialsProvider;
import com.amazonaws.auth.STSSessionCredentialsProvider;
import com.amazonaws.auth.TransitiveAuthCredentialsProvider;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.services.securitytoken.model.GetSessionTokenRequest;
import com.amazonaws.services.securitytoken.model.GetSessionTokenResult;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;

// Security Issue: Services authenticating users without performing transitive authentication

// True Positive Examples (Vulnerable/Insecure Code)
public class TransitiveAuthExamples {

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        String accessKey = request.getParameter("accessKey");
        String secretKey = request.getParameter("secretKey");
        
        // ruleid: java-transitive-auth
        AWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);
        AmazonS3Client s3Client = new AmazonS3Client(credentials);
        
        // Use the client to perform operations
        s3Client.listBuckets();
    }

    public void bad_case_2(HttpServletRequest request) {
        // Using direct credentials with DynamoDB
        String accessKey = request.getHeader("X-AWS-Access-Key");
        String secretKey = request.getHeader("X-AWS-Secret-Key");
        
        // ruleid: java-transitive-auth
        AmazonDynamoDBClient dynamoClient = new AmazonDynamoDBClient(
            new BasicAWSCredentials(accessKey, secretKey)
        );
        
        dynamoClient.listTables();
    }

    public void bad_case_3(HttpServletRequest request) {
        // Using Lambda client without transitive auth
        String accessKey = request.getParameter("key");
        String secretKey = request.getParameter("secret");
        
        // ruleid: java-transitive-auth
        AWSLambdaClient lambdaClient = new AWSLambdaClient(
            new BasicAWSCredentials(accessKey, secretKey)
        );
        
        lambdaClient.listFunctions();
    }

    public void bad_case_4(HttpServletRequest request) {
        // Using EC2 client with default provider chain
        // ruleid: java-transitive-auth
        AmazonEC2Client ec2Client = new AmazonEC2Client(
            new DefaultAWSCredentialsProviderChain()
        );
        
        ec2Client.describeInstances();
    }

    public void bad_case_5(HttpServletRequest request) {
        // Using SQS client with profile credentials
        // ruleid: java-transitive-auth
        AmazonSQSClient sqsClient = new AmazonSQSClient(
            new ProfileCredentialsProvider("default")
        );
        
        sqsClient.listQueues();
    }

    public void bad_case_6(HttpServletRequest request) {
        // Using SNS client with instance profile
        // ruleid: java-transitive-auth
        AmazonSNSClient snsClient = new AmazonSNSClient(
            new InstanceProfileCredentialsProvider()
        );
        
        snsClient.listTopics();
    }

    public void bad_case_7(HttpServletRequest request) {
        // Using CloudWatch client with environment variables
        // ruleid: java-transitive-auth
        AmazonCloudWatchClient cloudWatchClient = new AmazonCloudWatchClient(
            new EnvironmentVariableCredentialsProvider()
        );
        
        cloudWatchClient.listMetrics();
    }

    public void bad_case_8(HttpServletRequest request) {
        // Using ElastiCache client with system properties
        // ruleid: java-transitive-auth
        AmazonElastiCacheClient elastiCacheClient = new AmazonElastiCacheClient(
            new SystemPropertiesCredentialsProvider()
        );
        
        elastiCacheClient.describeCacheClusters();
    }

    public void bad_case_9(HttpServletRequest request) {
        // Using RDS client with classpath properties
        // ruleid: java-transitive-auth
        AmazonRDSClient rdsClient = new AmazonRDSClient(
            new ClasspathPropertiesFileCredentialsProvider()
        );
        
        rdsClient.describeDBInstances();
    }

    public void bad_case_10(HttpServletRequest request) {
        // Using Kinesis client with STS assume role
        String roleArn = request.getParameter("roleArn");
        String sessionName = request.getParameter("sessionName");
        
        // ruleid: java-transitive-auth
        AmazonKinesisClient kinesisClient = new AmazonKinesisClient(
            new STSAssumeRoleSessionCredentialsProvider(roleArn, sessionName)
        );
        
        kinesisClient.listStreams();
    }

    public void bad_case_11(HttpServletRequest request) {
        // Using ELB client with web identity federation
        String roleArn = request.getParameter("roleArn");
        String webIdentityToken = request.getParameter("token");
        String sessionName = "web-session";
        
        // ruleid: java-transitive-auth
        AmazonElasticLoadBalancingClient elbClient = new AmazonElasticLoadBalancingClient(
            new WebIdentityFederationSessionCredentialsProvider(roleArn, sessionName, webIdentityToken)
        );
        
        elbClient.describeLoadBalancers();
    }

    public void bad_case_12(HttpServletRequest request) {
        // Using Elastic Beanstalk client with STS session
        // ruleid: java-transitive-auth
        AWSElasticBeanstalkClient beanstalkClient = new AWSElasticBeanstalkClient(
            new STSSessionCredentialsProvider()
        );
        
        beanstalkClient.describeApplications();
    }

    public void bad_case_13(HttpServletRequest request) {
        // Using Glacier client with custom credentials provider
        String accessKey = request.getParameter("accessKey");
        String secretKey = request.getParameter("secretKey");
        
        AWSCredentialsProvider customProvider = new AWSCredentialsProvider() {
            @Override
            public AWSCredentials getCredentials() {
                return new BasicAWSCredentials(accessKey, secretKey);
            }
            
            @Override
            public void refresh() {
                // No refresh logic
            }
        };
        
        // ruleid: java-transitive-auth
        AmazonGlacierClient glacierClient = new AmazonGlacierClient(customProvider);
        
        glacierClient.listVaults();
    }

    public void bad_case_14(HttpServletRequest request) {
        // Using Redshift client with STS temporary credentials
        AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.defaultClient();
        GetSessionTokenRequest tokenRequest = new GetSessionTokenRequest();
        GetSessionTokenResult tokenResult = stsClient.getSessionToken(tokenRequest);
        Credentials stsCredentials = tokenResult.getCredentials();
        
        AWSCredentials tempCredentials = new BasicAWSCredentials(
            stsCredentials.getAccessKeyId(),
            stsCredentials.getSecretAccessKey()
        );
        
        // ruleid: java-transitive-auth
        AmazonRedshiftClient redshiftClient = new AmazonRedshiftClient(tempCredentials);
        
        redshiftClient.describeClusters();
    }

    public void bad_case_15(HttpServletRequest request) {
        // Using CloudFormation client with assumed role
        String roleArn = request.getParameter("roleArn");
        String roleSessionName = "session-" + System.currentTimeMillis();
        
        AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.defaultClient();
        AssumeRoleRequest roleRequest = new AssumeRoleRequest()
            .withRoleArn(roleArn)
            .withRoleSessionName(roleSessionName);
        
        AssumeRoleResult roleResult = stsClient.assumeRole(roleRequest);
        Credentials credentials = roleResult.getCredentials();
        
        AWSCredentials tempCredentials = new BasicAWSCredentials(
            credentials.getAccessKeyId(),
            credentials.getSecretAccessKey()
        );
        
        // ruleid: java-transitive-auth
        AmazonCloudFormationClient cfClient = new AmazonCloudFormationClient(tempCredentials);
        
        cfClient.describeStacks();
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1(HttpServletRequest request) {
        // Using S3 client with transitive auth credentials provider
        // ok: java-transitive-auth
        AmazonS3Client s3Client = new AmazonS3Client(
            new TransitiveAuthCredentialsProvider()
        );
        
        s3Client.listBuckets();
    }

    public void good_case_2(HttpServletRequest request) {
        // Using DynamoDB client with transitive auth
        // ok: java-transitive-auth
        AmazonDynamoDBClient dynamoClient = new AmazonDynamoDBClient(
            new TransitiveAuthCredentialsProvider("DynamoDBService")
        );
        
        dynamoClient.listTables();
    }

    public void good_case_3(HttpServletRequest request) {
        // Using Lambda client with transitive auth and custom configuration
        TransitiveAuthCredentialsProvider provider = new TransitiveAuthCredentialsProvider();
        provider.setServiceName("LambdaService");
        
        // ok: java-transitive-auth
        AWSLambdaClient lambdaClient = new AWSLambdaClient(provider);
        
        lambdaClient.listFunctions();
    }

    public void good_case_4(HttpServletRequest request) {
        // Using EC2 client with transitive auth and region
        // ok: java-transitive-auth
        AmazonEC2Client ec2Client = new AmazonEC2Client(
            new TransitiveAuthCredentialsProvider("EC2Service")
        );
        ec2Client.setRegion(com.amazonaws.regions.Region.getRegion(com.amazonaws.regions.Regions.US_WEST_2));
        
        ec2Client.describeInstances();
    }

    public void good_case_5(HttpServletRequest request) {
        // Using SQS client with transitive auth and endpoint
        // ok: java-transitive-auth
        AmazonSQSClient sqsClient = new AmazonSQSClient(
            new TransitiveAuthCredentialsProvider("SQSService")
        );
        sqsClient.setEndpoint("https://sqs.us-east-1.amazonaws.com");
        
        sqsClient.listQueues();
    }

    public void good_case_6(HttpServletRequest request) {
        // Using SNS client with transitive auth and client configuration
        com.amazonaws.ClientConfiguration clientConfig = new com.amazonaws.ClientConfiguration();
        clientConfig.setConnectionTimeout(5000);
        
        // ok: java-transitive-auth
        AmazonSNSClient snsClient = new AmazonSNSClient(
            new TransitiveAuthCredentialsProvider("SNSService"),
            clientConfig
        );
        
        snsClient.listTopics();
    }

    public void good_case_7(HttpServletRequest request) {
        // Using CloudWatch client with transitive auth and request metrics
        com.amazonaws.ClientConfiguration clientConfig = new com.amazonaws.ClientConfiguration();
        clientConfig.setRequestMetricCollectorFactory(new com.amazonaws.metrics.RequestMetricCollectorFactory() {
            @Override
            public com.amazonaws.metrics.RequestMetricCollector getRequestMetricCollector() {
                return com.amazonaws.metrics.RequestMetricCollector.NONE;
            }
        });
        
        // ok: java-transitive-auth
        AmazonCloudWatchClient cloudWatchClient = new AmazonCloudWatchClient(
            new TransitiveAuthCredentialsProvider("CloudWatchService"),
            clientConfig
        );
        
        cloudWatchClient.listMetrics();
    }

    public void good_case_8(HttpServletRequest request) {
        // Using ElastiCache client with transitive auth and custom user agent
        com.amazonaws.ClientConfiguration clientConfig = new com.amazonaws.ClientConfiguration();
        clientConfig.setUserAgent("CustomApp/1.0");
        
        // ok: java-transitive-auth
        AmazonElastiCacheClient elastiCacheClient = new AmazonElastiCacheClient(
            new TransitiveAuthCredentialsProvider("ElastiCacheService"),
            clientConfig
        );
        
        elastiCacheClient.describeCacheClusters();
    }

    public void good_case_9(HttpServletRequest request) {
        // Using RDS client with transitive auth and proxy configuration
        com.amazonaws.ClientConfiguration clientConfig = new com.amazonaws.ClientConfiguration();
        clientConfig.setProxyHost("proxy.example.com");
        clientConfig.setProxyPort(8080);
        
        // ok: java-transitive-auth
        AmazonRDSClient rdsClient = new AmazonRDSClient(
            new TransitiveAuthCredentialsProvider("RDSService"),
            clientConfig
        );
        
        rdsClient.describeDBInstances();
    }

    public void good_case_10(HttpServletRequest request) {
        // Using Kinesis client with transitive auth and socket timeout
        com.amazonaws.ClientConfiguration clientConfig = new com.amazonaws.ClientConfiguration();
        clientConfig.setSocketTimeout(10000);
        
        // ok: java-transitive-auth
        AmazonKinesisClient kinesisClient = new AmazonKinesisClient(
            new TransitiveAuthCredentialsProvider("KinesisService"),
            clientConfig
        );
        
        kinesisClient.listStreams();
    }

    public void good_case_11(HttpServletRequest request) {
        // Using ELB client with transitive auth and retry policy
        com.amazonaws.ClientConfiguration clientConfig = new com.amazonaws.ClientConfiguration();
        clientConfig.setRetryPolicy(new com.amazonaws.retry.RetryPolicy(
            new com.amazonaws.retry.PredefinedRetryPolicies.SDKDefaultRetryCondition(),
            new com.amazonaws.retry.PredefinedBackoffStrategies.SDKDefaultBackoffStrategy(),
            5, // Max error retry
            true // Honor max error retry set in retry policy
        ));
        
        // ok: java-transitive-auth
        AmazonElasticLoadBalancingClient elbClient = new AmazonElasticLoadBalancingClient(
            new TransitiveAuthCredentialsProvider("ELBService"),
            clientConfig
        );
        
        elbClient.describeLoadBalancers();
    }

    public void good_case_12(HttpServletRequest request) {
        // Using Elastic Beanstalk client with transitive auth and custom headers
        Map<String, String> headers = new HashMap<>();
        headers.put("Custom-Header", "Value");
        
        com.amazonaws.ClientConfiguration clientConfig = new com.amazonaws.ClientConfiguration();
        clientConfig.addHeader("Custom-Header", "Value");
        
        // ok: java-transitive-auth
        AWSElasticBeanstalkClient beanstalkClient = new AWSElasticBeanstalkClient(
            new TransitiveAuthCredentialsProvider("BeanstalkService"),
            clientConfig
        );
        
        beanstalkClient.describeApplications();
    }

    public void good_case_13(HttpServletRequest request) {
        // Using Glacier client with transitive auth and DNS resolver
        com.amazonaws.ClientConfiguration clientConfig = new com.amazonaws.ClientConfiguration();
        clientConfig.setDnsResolver(new com.amazonaws.DnsResolver() {
            @Override
            public java.util.List<String> resolve(String host) {
                return java.util.Arrays.asList("192.168.1.1");
            }
        });
        
        // ok: java-transitive-auth
        AmazonGlacierClient glacierClient = new AmazonGlacierClient(
            new TransitiveAuthCredentialsProvider("GlacierService"),
            clientConfig
        );
        
        glacierClient.listVaults();
    }

    public void good_case_14(HttpServletRequest request) {
        // Using Redshift client with transitive auth and connection TTL
        com.amazonaws.ClientConfiguration clientConfig = new com.amazonaws.ClientConfiguration();
        clientConfig.setConnectionTTL(60000L); // 60 seconds
        
        // ok: java-transitive-auth
        AmazonRedshiftClient redshiftClient = new AmazonRedshiftClient(
            new TransitiveAuthCredentialsProvider("RedshiftService"),
            clientConfig
        );
        
        redshiftClient.describeClusters();
    }

    public void good_case_15(HttpServletRequest request) {
        // Using CloudFormation client with transitive auth and secure protocol
        com.amazonaws.ClientConfiguration clientConfig = new com.amazonaws.ClientConfiguration();
        clientConfig.setProtocol(com.amazonaws.Protocol.HTTPS);
        clientConfig.setSocketTimeout(30000);
        
        // ok: java-transitive-auth
        AmazonCloudFormationClient cfClient = new AmazonCloudFormationClient(
            new TransitiveAuthCredentialsProvider("CloudFormationService"),
            clientConfig
        );
        
        cfClient.describeStacks();
    }
}
// {/fact}