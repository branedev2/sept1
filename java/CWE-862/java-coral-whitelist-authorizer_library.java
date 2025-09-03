import com.amazonaws.coral.authorize.WhitelistAuthorizer;
import com.amazonaws.coral.authorize.Authorizer;
import com.amazonaws.coral.authorize.AuthorizationResult;
import com.amazonaws.coral.authorize.AuthorizationRequest;
import com.amazonaws.coral.service.Operation;
import com.amazonaws.coral.service.Service;
import com.amazonaws.coral.service.ServiceOperation;
import com.amazonaws.coral.service.HealthcheckOperation;
import com.amazonaws.coral.service.StandardOperation;
import com.amazonaws.coral.service.OperationType;
import com.amazonaws.coral.service.OperationBuilder;
import com.amazonaws.coral.service.ServiceBuilder;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.lambda.AWSLambdaClient;
import com.amazonaws.services.sqs.AmazonSQSClient;
import com.amazonaws.services.sns.AmazonSNSClient;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClient;
import com.amazonaws.services.elasticache.AmazonElastiCacheClient;
import com.amazonaws.services.rds.AmazonRDSClient;
import com.amazonaws.services.elasticbeanstalk.AWSElasticBeanstalkClient;
import com.amazonaws.services.elasticloadbalancing.AmazonElasticLoadBalancingClient;
import com.amazonaws.services.cloudformation.AmazonCloudFormationClient;
import com.amazonaws.services.redshift.AmazonRedshiftClient;
import com.amazonaws.services.route53.AmazonRoute53Client;
import com.amazonaws.services.kinesis.AmazonKinesisClient;
import com.amazonaws.services.glacier.AmazonGlacierClient;
import com.amazonaws.services.iam.AmazonIdentityManagementClient;
import com.amazonaws.services.opsworks.AWSOpsWorksClient;
import com.amazonaws.services.elastictranscoder.AmazonElasticTranscoderClient;
import com.amazonaws.services.datapipeline.DataPipelineClient;
import com.amazonaws.services.simpleworkflow.AmazonSimpleWorkflowClient;
import com.amazonaws.services.storagegateway.AWSStorageGatewayClient;
import com.amazonaws.services.directconnect.AmazonDirectConnectClient;
import com.amazonaws.services.cloudtrail.AWSCloudTrailClient;
import com.amazonaws.services.cloudfront.AmazonCloudFrontClient;
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentityClient;
import com.amazonaws.services.elasticmapreduce.AmazonElasticMapReduceClient;
import com.amazonaws.services.autoscaling.AmazonAutoScalingClient;
import com.amazonaws.services.ecs.AmazonECSClient;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.workspaces.AmazonWorkspacesClient;
import com.amazonaws.services.machinelearning.AmazonMachineLearningClient;
import com.amazonaws.services.directory.AmazonDirectoryServiceClient;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.Collections;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;

// Security Issue: WhitelistAuthorizer is instantiated with non-healthcheck operations, which could lead to authorization bypass (CWE-862, CWE-306)

// True Positive Examples (Vulnerable/Insecure Code)
public class WhitelistAuthorizerExamples {

// {fact rule=missing-authorization@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        // S3 service with non-healthcheck operations in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonS3Client s3Client = new AmazonS3Client(credentials);
        
        Set<Operation> operations = new HashSet<>();
        operations.add(new StandardOperation("ListBuckets"));
        operations.add(new StandardOperation("GetObject"));
        operations.add(new StandardOperation("PutObject"));
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation("ListBuckets");
        AuthorizationResult result = authorizer.authorize(authRequest);
    }

    public void bad_case_2(HttpServletRequest request) {
        // DynamoDB service with non-healthcheck operations in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonDynamoDBClient dynamoClient = new AmazonDynamoDBClient(credentials);
        
        List<Operation> operations = new ArrayList<>();
        operations.add(new StandardOperation("CreateTable"));
        operations.add(new StandardOperation("DeleteTable"));
        
        // ruleid: java-coral-whitelist-authorizer
        Authorizer authorizer = new WhitelistAuthorizer(new HashSet<>(operations));
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation("CreateTable");
        authorizer.authorize(authRequest);
    }

    public void bad_case_3(HttpServletRequest request) {
        // EC2 service with mixed operations including non-healthcheck in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonEC2Client ec2Client = new AmazonEC2Client(credentials);
        
        Set<Operation> operations = new HashSet<>();
        operations.add(new HealthcheckOperation("HealthCheck"));
        operations.add(new StandardOperation("RunInstances"));  // This is not a healthcheck
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation(request.getParameter("operation"));
        authorizer.authorize(authRequest);
    }

    public void bad_case_4(HttpServletRequest request) {
        // Lambda service with operations from user input in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AWSLambdaClient lambdaClient = new AWSLambdaClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        String[] requestedOps = request.getParameterValues("operations");
        for (String op : requestedOps) {
            operations.add(new StandardOperation(op));
        }
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation("InvokeFunction");
        authorizer.authorize(authRequest);
    }

    public void bad_case_5(HttpServletRequest request) {
        // SQS service with programmatically created operations in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonSQSClient sqsClient = new AmazonSQSClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        for (String queueOperation : Arrays.asList("CreateQueue", "DeleteQueue", "SendMessage")) {
            operations.add(new StandardOperation(queueOperation));
        }
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation(request.getParameter("queueOperation"));
        authorizer.authorize(authRequest);
    }

    public void bad_case_6(HttpServletRequest request) {
        // SNS service with operations from builder in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonSNSClient snsClient = new AmazonSNSClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        Operation publishOp = new OperationBuilder()
            .withName("Publish")
            .withType(OperationType.STANDARD)
            .build();
        operations.add(publishOp);
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation("Publish");
        authorizer.authorize(authRequest);
    }

    public void bad_case_7(HttpServletRequest request) {
        // CloudWatch service with service operations in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonCloudWatchClient cloudWatchClient = new AmazonCloudWatchClient(credentials);
        
        Service cloudWatchService = new ServiceBuilder()
            .withName("CloudWatch")
            .build();
        
        Set<Operation> operations = new HashSet<>();
        operations.add(new ServiceOperation(cloudWatchService, "PutMetricData"));
        operations.add(new ServiceOperation(cloudWatchService, "GetMetricData"));
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation(request.getParameter("metricOperation"));
        authorizer.authorize(authRequest);
    }

    public void bad_case_8(HttpServletRequest request) {
        // ElastiCache service with empty set then adding operations in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonElastiCacheClient elastiCacheClient = new AmazonElastiCacheClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        // Adding operations after creation
        operations.add(new StandardOperation("CreateCacheCluster"));
        operations.add(new StandardOperation("DeleteCacheCluster"));
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation("CreateCacheCluster");
        authorizer.authorize(authRequest);
    }

    public void bad_case_9(HttpServletRequest request) {
        // RDS service with operations from request parameters in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonRDSClient rdsClient = new AmazonRDSClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        String operationName = request.getParameter("operation");
        operations.add(new StandardOperation(operationName));
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation(operationName);
        authorizer.authorize(authRequest);
    }

    public void bad_case_10(HttpServletRequest request) {
        // ElasticBeanstalk service with operations collection in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AWSElasticBeanstalkClient beanstalkClient = new AWSElasticBeanstalkClient(credentials);
        
        Set<Operation> operations = Collections.singleton(new StandardOperation("CreateEnvironment"));
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation("CreateEnvironment");
        authorizer.authorize(authRequest);
    }

    public void bad_case_11(HttpServletRequest request) {
        // ELB service with operations array in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonElasticLoadBalancingClient elbClient = new AmazonElasticLoadBalancingClient(credentials);
        
        Operation[] operationsArray = {
            new StandardOperation("CreateLoadBalancer"),
            new StandardOperation("DeleteLoadBalancer")
        };
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(new HashSet<>(Arrays.asList(operationsArray)));
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation("CreateLoadBalancer");
        authorizer.authorize(authRequest);
    }

    public void bad_case_12(HttpServletRequest request) {
        // CloudFormation service with conditional operations in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonCloudFormationClient cfClient = new AmazonCloudFormationClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        boolean isAdmin = Boolean.parseBoolean(request.getParameter("isAdmin"));
        
        if (isAdmin) {
            operations.add(new StandardOperation("CreateStack"));
            operations.add(new StandardOperation("DeleteStack"));
        } else {
            operations.add(new StandardOperation("DescribeStacks"));
        }
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation(request.getParameter("stackOperation"));
        authorizer.authorize(authRequest);
    }

    public void bad_case_13(HttpServletRequest request) {
        // Redshift service with operations from different sources in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonRedshiftClient redshiftClient = new AmazonRedshiftClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        operations.add(new StandardOperation("CreateCluster"));
        
        if (request.getParameter("allowDelete") != null) {
            operations.add(new StandardOperation("DeleteCluster"));
        }
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation("CreateCluster");
        authorizer.authorize(authRequest);
    }

    public void bad_case_14(HttpServletRequest request) {
        // Route53 service with operations from configuration in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonRoute53Client route53Client = new AmazonRoute53Client(credentials);
        
        Set<Operation> operations = new HashSet<>();
        String[] configOps = request.getParameterValues("configuredOperations");
        
        if (configOps != null) {
            for (String op : configOps) {
                operations.add(new StandardOperation(op));
            }
        } else {
            operations.add(new StandardOperation("ListHostedZones"));
        }
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation(request.getParameter("dnsOperation"));
        authorizer.authorize(authRequest);
    }

    public void bad_case_15(HttpServletRequest request) {
        // Kinesis service with dynamic operations in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonKinesisClient kinesisClient = new AmazonKinesisClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        String role = request.getParameter("userRole");
        
        if ("producer".equals(role)) {
            operations.add(new StandardOperation("PutRecord"));
            operations.add(new StandardOperation("PutRecords"));
        } else if ("consumer".equals(role)) {
            operations.add(new StandardOperation("GetRecords"));
            operations.add(new StandardOperation("GetShardIterator"));
        } else if ("admin".equals(role)) {
            operations.add(new StandardOperation("CreateStream"));
            operations.add(new StandardOperation("DeleteStream"));
        }
        
        // ruleid: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation(request.getParameter("streamOperation"));
        authorizer.authorize(authRequest);
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1(HttpServletRequest request) {
        // Glacier service with only healthcheck operations in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonGlacierClient glacierClient = new AmazonGlacierClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        operations.add(new HealthcheckOperation("HealthCheck"));
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation("HealthCheck");
        authorizer.authorize(authRequest);
    }

    public void good_case_2(HttpServletRequest request) {
        // IAM service with empty set of operations in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonIdentityManagementClient iamClient = new AmazonIdentityManagementClient(credentials);
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(Collections.emptySet());
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation("ListUsers");
        authorizer.authorize(authRequest);
    }

    public void good_case_3(HttpServletRequest request) {
        // OpsWorks service with only healthcheck operations from builder in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AWSOpsWorksClient opsWorksClient = new AWSOpsWorksClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        Operation healthOp = new OperationBuilder()
            .withName("HealthCheck")
            .withType(OperationType.HEALTHCHECK)
            .build();
        operations.add(healthOp);
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation("HealthCheck");
        authorizer.authorize(authRequest);
    }

    public void good_case_4(HttpServletRequest request) {
        // ElasticTranscoder service with multiple healthcheck operations in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonElasticTranscoderClient transcoderClient = new AmazonElasticTranscoderClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        operations.add(new HealthcheckOperation("ServiceHealthCheck"));
        operations.add(new HealthcheckOperation("SystemHealthCheck"));
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation(request.getParameter("healthCheckType"));
        authorizer.authorize(authRequest);
    }

    public void good_case_5(HttpServletRequest request) {
        // DataPipeline service with service healthcheck operations in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        DataPipelineClient dataPipelineClient = new DataPipelineClient(credentials);
        
        Service dataPipelineService = new ServiceBuilder()
            .withName("DataPipeline")
            .build();
        
        Set<Operation> operations = new HashSet<>();
        operations.add(new ServiceOperation(dataPipelineService, "HealthCheck", OperationType.HEALTHCHECK));
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation("HealthCheck");
        authorizer.authorize(authRequest);
    }

    public void good_case_6(HttpServletRequest request) {
        // SimpleWorkflow service with healthcheck operations array in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonSimpleWorkflowClient swfClient = new AmazonSimpleWorkflowClient(credentials);
        
        Operation[] operationsArray = {
            new HealthcheckOperation("PrimaryHealthCheck"),
            new HealthcheckOperation("SecondaryHealthCheck")
        };
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(new HashSet<>(Arrays.asList(operationsArray)));
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation("PrimaryHealthCheck");
        authorizer.authorize(authRequest);
    }

    public void good_case_7(HttpServletRequest request) {
        // StorageGateway service with conditional healthcheck operations in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AWSStorageGatewayClient gatewayClient = new AWSStorageGatewayClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        boolean isPrimary = Boolean.parseBoolean(request.getParameter("isPrimary"));
        
        if (isPrimary) {
            operations.add(new HealthcheckOperation("PrimaryHealthCheck"));
        } else {
            operations.add(new HealthcheckOperation("SecondaryHealthCheck"));
        }
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation(isPrimary ? "PrimaryHealthCheck" : "SecondaryHealthCheck");
        authorizer.authorize(authRequest);
    }

    public void good_case_8(HttpServletRequest request) {
        // DirectConnect service with healthcheck operations from different sources in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonDirectConnectClient directConnectClient = new AmazonDirectConnectClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        operations.add(new HealthcheckOperation("BasicHealthCheck"));
        
        if (request.getParameter("includeAdvanced") != null) {
            operations.add(new HealthcheckOperation("AdvancedHealthCheck"));
        }
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation("BasicHealthCheck");
        authorizer.authorize(authRequest);
    }

    public void good_case_9(HttpServletRequest request) {
        // CloudTrail service with healthcheck operations from configuration in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AWSCloudTrailClient cloudTrailClient = new AWSCloudTrailClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        String[] configOps = request.getParameterValues("configuredHealthChecks");
        
        if (configOps != null) {
            for (String op : configOps) {
                operations.add(new HealthcheckOperation(op));
            }
        } else {
            operations.add(new HealthcheckOperation("DefaultHealthCheck"));
        }
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation(request.getParameter("healthCheckOperation"));
        authorizer.authorize(authRequest);
    }

    public void good_case_10(HttpServletRequest request) {
        // CloudFront service with dynamic healthcheck operations in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonCloudFrontClient cloudFrontClient = new AmazonCloudFrontClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        String region = request.getParameter("region");
        
        if ("us-east-1".equals(region)) {
            operations.add(new HealthcheckOperation("USEastHealthCheck"));
        } else if ("eu-west-1".equals(region)) {
            operations.add(new HealthcheckOperation("EUWestHealthCheck"));
        } else {
            operations.add(new HealthcheckOperation("GlobalHealthCheck"));
        }
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation(request.getParameter("healthCheckName"));
        authorizer.authorize(authRequest);
    }

    public void good_case_11(HttpServletRequest request) {
        // Cognito service with healthcheck operations from request parameters in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonCognitoIdentityClient cognitoClient = new AmazonCognitoIdentityClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        String healthCheckName = request.getParameter("healthCheckName");
        operations.add(new HealthcheckOperation(healthCheckName));
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation(healthCheckName);
        authorizer.authorize(authRequest);
    }

    public void good_case_12(HttpServletRequest request) {
        // EMR service with healthcheck operations collection in WhitelistAuthorizer
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonElasticMapReduceClient emrClient = new AmazonElasticMapReduceClient(credentials);
        
        Set<Operation> operations = Collections.singleton(new HealthcheckOperation("EMRHealthCheck"));
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation("EMRHealthCheck");
        authorizer.authorize(authRequest);
    }

    public void good_case_13(HttpServletRequest request) {
        // AutoScaling service with healthcheck operations in WhitelistAuthorizer and custom authorization logic
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonAutoScalingClient autoScalingClient = new AmazonAutoScalingClient(credentials);
        
        Set<Operation> operations = new HashSet<>();
        operations.add(new HealthcheckOperation("AutoScalingHealthCheck"));
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer authorizer = new WhitelistAuthorizer(operations);
        
        // Additional authorization logic for non-healthcheck operations
        String requestedOperation = request.getParameter("operation");
        if (!"AutoScalingHealthCheck".equals(requestedOperation)) {
            // Use a different authorization mechanism for non-healthcheck operations
            // This is safe because we're not using WhitelistAuthorizer for non-healthcheck operations
            customAuthorize(requestedOperation, request.getParameter("userId"));
        } else {
            AuthorizationRequest authRequest = new AuthorizationRequest();
            authRequest.setOperation(requestedOperation);
            authorizer.authorize(authRequest);
        }
    }

    private void customAuthorize(String operation, String userId) {
        // Custom authorization logic for non-healthcheck operations
    }

    public void good_case_14(HttpServletRequest request) {
        // ECS service with healthcheck operations in WhitelistAuthorizer and separate authorizer for other operations
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AmazonECSClient ecsClient = new AmazonECSClient(credentials);
        
        Set<Operation> healthcheckOps = new HashSet<>();
        healthcheckOps.add(new HealthcheckOperation("ECSHealthCheck"));
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer healthcheckAuthorizer = new WhitelistAuthorizer(healthcheckOps);
        
        // For non-healthcheck operations, use a different authorizer (not WhitelistAuthorizer)
        Authorizer standardAuthorizer = createStandardAuthorizer();
        
        String requestedOperation = request.getParameter("operation");
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.setOperation(requestedOperation);
        
        if ("ECSHealthCheck".equals(requestedOperation)) {
            healthcheckAuthorizer.authorize(authRequest);
        } else {
            standardAuthorizer.authorize(authRequest);
        }
    }

    private Authorizer createStandardAuthorizer() {
        // Create a non-WhitelistAuthorizer for standard operations
        return new Authorizer() {
            @Override
            public AuthorizationResult authorize(AuthorizationRequest request) {
                // Custom authorization logic
                return new AuthorizationResult(true, "Authorized");
            }
        };
    }

    public void good_case_15(HttpServletRequest request) {
        // KMS service with alternative authorization approach for non-healthcheck operations
        AWSCredentials credentials = new BasicAWSCredentials(request.getParameter("accessKey"), request.getParameter("secretKey"));
        AWSKMSClient kmsClient = new AWSKMSClient(credentials);
        
        // For healthcheck operations only
        Set<Operation> healthcheckOps = new HashSet<>();
        healthcheckOps.add(new HealthcheckOperation("KMSHealthCheck"));
        
        // ok: java-coral-whitelist-authorizer
        WhitelistAuthorizer healthcheckAuthorizer = new WhitelistAuthorizer(healthcheckOps);
        
        // For all operations including non-healthcheck, use proper role-based authorization
        String requestedOperation = request.getParameter("operation");
        String userRole = request.getParameter("userRole");
        
        if ("KMSHealthCheck".equals(requestedOperation)) {
            AuthorizationRequest authRequest = new AuthorizationRequest();
            authRequest.setOperation(requestedOperation);
            healthcheckAuthorizer.authorize(authRequest);
        } else {
            // Use role-based authorization for non-healthcheck operations
            boolean isAuthorized = isUserAuthorizedForOperation(userRole, requestedOperation);
            if (!isAuthorized) {
                throw new SecurityException("User not authorized for operation: " + requestedOperation);
            }
        }
    }

    private boolean isUserAuthorizedForOperation(String userRole, String operation) {
        // Role-based authorization logic
        return true; // Simplified for example
    }
}
// {/fact}