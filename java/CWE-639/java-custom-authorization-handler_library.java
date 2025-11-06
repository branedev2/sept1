import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.amazonaws.services.apigateway.AmazonApiGateway;
import com.amazonaws.services.apigateway.AmazonApiGatewayClientBuilder;
import com.amazonaws.services.apigateway.model.*;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.*;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.dynamodb.AmazonDynamoDB;
import com.amazonaws.services.dynamodb.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodb.model.*;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import com.amazonaws.services.cloudformation.AmazonCloudFormation;
import com.amazonaws.services.cloudformation.AmazonCloudFormationClientBuilder;
import com.amazonaws.services.cloudwatch.AmazonCloudWatch;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClientBuilder;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.elasticbeanstalk.AWSElasticBeanstalk;
import com.amazonaws.services.elasticbeanstalk.AWSElasticBeanstalkClientBuilder;
import com.amazonaws.services.elasticloadbalancing.AmazonElasticLoadBalancing;
import com.amazonaws.services.elasticloadbalancing.AmazonElasticLoadBalancingClientBuilder;
import com.amazonaws.services.rds.AmazonRDS;
import com.amazonaws.services.rds.AmazonRDSClientBuilder;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.*;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.io.IOException;
import java.util.UUID;

// Security Issue: Confused Deputy Problem in Custom Authorization Handlers

// True Positive Examples (Vulnerable/Insecure Code)

public class CustomAuthorizationHandlerExamples {

    // True Positive Examples (Vulnerable/Insecure Code)
    
// {fact rule=insecure-direct-object-ref@v1.0 defects=1}
    public static void bad_case_1(APIGatewayProxyRequestEvent request, Context context) {
        // Using AWS API Gateway with vulnerable custom authorizer
        AmazonApiGateway apiGatewayClient = AmazonApiGatewayClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        String accountId = request.getPathParameters().get("accountId");
        
        // ruleid: java-custom-authorization-handler
        GetResourcesRequest resourcesRequest = new GetResourcesRequest()
                .withRestApiId("api-id")
                .withEmbedCredentials(true)
                .withLimit(500);
        
        // Using the accountId from the request to determine resource ownership
        // ruleid: java-custom-authorization-handler
        resourcesRequest.addPathSegmentsItem(accountId);
        
        GetResourcesResult result = apiGatewayClient.getResources(resourcesRequest);
    }
    
    public static void bad_case_2(HttpServletRequest request) {
        // Using AWS Lambda with vulnerable custom authorizer
        AWSLambda lambdaClient = AWSLambdaClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        String accountId = request.getParameter("accountId");
        
        // ruleid: java-custom-authorization-handler
        AddPermissionRequest permissionRequest = new AddPermissionRequest()
                .withFunctionName("my-function")
                .withStatementId(UUID.randomUUID().toString())
                .withAction("lambda:InvokeFunction")
                .withPrincipal("apigateway.amazonaws.com");
        
        // Using the accountId from the request to set resource policy
        // ruleid: java-custom-authorization-handler
        permissionRequest.withSourceAccount(accountId);
        
        lambdaClient.addPermission(permissionRequest);
    }
    
    public static void bad_case_3(HttpServletRequest request) {
        // Using AWS S3 with vulnerable custom authorizer
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        String accountId = request.getParameter("accountId");
        String bucketName = request.getParameter("bucketName");
        
        // Creating a bucket policy based on user-provided accountId
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::" 
                + accountId + ":root\"},\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::" + bucketName + "/*\"}]}";
        
        // ruleid: java-custom-authorization-handler
        s3Client.setBucketPolicy(bucketName, policy);
    }
    
    public static void bad_case_4(HttpServletRequest request) {
        // Using AWS DynamoDB with vulnerable custom authorizer
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        String accountId = request.getParameter("accountId");
        
        // ruleid: java-custom-authorization-handler
        CreateTableRequest createTableRequest = new CreateTableRequest()
                .withTableName("Table-" + accountId)
                .withKeySchema(new KeySchemaElement("id", KeyType.HASH))
                .withAttributeDefinitions(new AttributeDefinition("id", ScalarAttributeType.S))
                .withProvisionedThroughput(new ProvisionedThroughput(5L, 5L));
        
        dynamoDbClient.createTable(createTableRequest);
    }
    
    public static void bad_case_5(HttpServletRequest request) {
        // Using AWS SQS with vulnerable custom authorizer
        AmazonSQS sqsClient = AmazonSQSClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        String accountId = request.getParameter("accountId");
        
        // Creating a queue with permissions based on user input
        Map<String, String> attributes = new HashMap<>();
        
        // ruleid: java-custom-authorization-handler
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"" 
                + accountId + "\"},\"Action\":\"sqs:*\",\"Resource\":\"*\"}]}";
        attributes.put("Policy", policy);
        
        sqsClient.createQueue(new com.amazonaws.services.sqs.model.CreateQueueRequest()
                .withQueueName("MyQueue")
                .withAttributes(attributes));
    }
    
    public static void bad_case_6(HttpServletRequest request) {
        // Using AWS SNS with vulnerable custom authorizer
        AmazonSNS snsClient = AmazonSNSClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        String accountId = request.getParameter("accountId");
        String topicArn = "arn:aws:sns:us-east-1:123456789012:MyTopic";
        
        // ruleid: java-custom-authorization-handler
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"" 
                + accountId + "\"},\"Action\":\"sns:*\",\"Resource\":\"" + topicArn + "\"}]}";
        
        Map<String, String> attributes = new HashMap<>();
        attributes.put("Policy", policy);
        
        snsClient.setTopicAttributes(topicArn, "Policy", policy);
    }
    
    public static void bad_case_7(HttpServletRequest request) {
        // Using AWS CloudFormation with vulnerable custom authorizer
        AmazonCloudFormation cfClient = AmazonCloudFormationClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        String accountId = request.getParameter("accountId");
        
        // ruleid: java-custom-authorization-handler
        com.amazonaws.services.cloudformation.model.CreateStackRequest createStackRequest = 
            new com.amazonaws.services.cloudformation.model.CreateStackRequest()
                .withStackName("MyStack")
                .withTemplateURL("https://s3.amazonaws.com/bucket/template.json")
                .withParameters(
                    new com.amazonaws.services.cloudformation.model.Parameter()
                        .withParameterKey("AccountId")
                        .withParameterValue(accountId)
                );
        
        cfClient.createStack(createStackRequest);
    }
    
    public static void bad_case_8(HttpServletRequest request) {
        // Using AWS CloudWatch with vulnerable custom authorizer
        AmazonCloudWatch cwClient = AmazonCloudWatchClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        String accountId = request.getParameter("accountId");
        
        // ruleid: java-custom-authorization-handler
        com.amazonaws.services.cloudwatch.model.PutDashboardRequest dashboardRequest = 
            new com.amazonaws.services.cloudwatch.model.PutDashboardRequest()
                .withDashboardName("Dashboard-" + accountId)
                .withDashboardBody("{\"widgets\":[{\"type\":\"text\",\"x\":0,\"y\":0,\"width\":6,\"height\":6," +
                        "\"properties\":{\"markdown\":\"Account: " + accountId + "\"}}]}");
        
        cwClient.putDashboard(dashboardRequest);
    }
    
    public static void bad_case_9(HttpServletRequest request) {
        // Using AWS EC2 with vulnerable custom authorizer
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        String accountId = request.getParameter("accountId");
        
        // ruleid: java-custom-authorization-handler
        com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressRequest ingressRequest = 
            new com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressRequest()
                .withGroupId("sg-12345")
                .withIpPermissions(
                    new com.amazonaws.services.ec2.model.IpPermission()
                        .withIpProtocol("tcp")
                        .withFromPort(22)
                        .withToPort(22)
                        .withUserIdGroupPairs(
                            new com.amazonaws.services.ec2.model.UserIdGroupPair()
                                .withUserId(accountId)
                                .withGroupId("sg-67890")
                        )
                );
        
        ec2Client.authorizeSecurityGroupIngress(ingressRequest);
    }
    
    public static void bad_case_10(HttpServletRequest request) {
        // Using AWS Elastic Beanstalk with vulnerable custom authorizer
        AWSElasticBeanstalk ebClient = AWSElasticBeanstalkClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        String accountId = request.getParameter("accountId");
        
        // ruleid: java-custom-authorization-handler
        com.amazonaws.services.elasticbeanstalk.model.CreateApplicationRequest appRequest = 
            new com.amazonaws.services.elasticbeanstalk.model.CreateApplicationRequest()
                .withApplicationName("App-" + accountId)
                .withDescription("Application for account " + accountId);
        
        ebClient.createApplication(appRequest);
    }
    
    public static void bad_case_11(HttpServletRequest request) {
        // Using AWS Elastic Load Balancing with vulnerable custom authorizer
        AmazonElasticLoadBalancing elbClient = AmazonElasticLoadBalancingClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        String accountId = request.getParameter("accountId");
        
        // ruleid: java-custom-authorization-handler
        com.amazonaws.services.elasticloadbalancing.model.CreateLoadBalancerPolicyRequest policyRequest = 
            new com.amazonaws.services.elasticloadbalancing.model.CreateLoadBalancerPolicyRequest()
                .withLoadBalancerName("MyLoadBalancer")
                .withPolicyName("Policy-" + accountId)
                .withPolicyTypeName("SSLNegotiationPolicyType")
                .withPolicyAttributes(
                    new com.amazonaws.services.elasticloadbalancing.model.PolicyAttribute()
                        .withAttributeName("Reference-Security-Policy")
                        .withAttributeValue("ELBSecurityPolicy-" + accountId)
                );
        
        elbClient.createLoadBalancerPolicy(policyRequest);
    }
    
    public static void bad_case_12(HttpServletRequest request) {
        // Using AWS RDS with vulnerable custom authorizer
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        String accountId = request.getParameter("accountId");
        
        // ruleid: java-custom-authorization-handler
        com.amazonaws.services.rds.model.CreateDBInstanceRequest dbRequest = 
            new com.amazonaws.services.rds.model.CreateDBInstanceRequest()
                .withDBInstanceIdentifier("db-" + accountId)
                .withEngine("mysql")
                .withDBInstanceClass("db.t2.micro")
                .withMasterUsername("admin")
                .withMasterUserPassword("password")
                .withAllocatedStorage(20)
                .withTags(
                    new com.amazonaws.services.rds.model.Tag()
                        .withKey("AccountId")
                        .withValue(accountId)
                );
        
        rdsClient.createDBInstance(dbRequest);
    }
    
    public static void bad_case_13(HttpServletRequest request) {
        // Using AWS Secrets Manager with vulnerable custom authorizer
        AWSSecretsManager secretsClient = AWSSecretsManagerClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        String accountId = request.getParameter("accountId");
        
        // ruleid: java-custom-authorization-handler
        com.amazonaws.services.secretsmanager.model.CreateSecretRequest secretRequest = 
            new com.amazonaws.services.secretsmanager.model.CreateSecretRequest()
                .withName("secret/" + accountId + "/api-key")
                .withSecretString("{\"apiKey\":\"my-api-key\"}")
                .withTags(
                    new com.amazonaws.services.secretsmanager.model.Tag()
                        .withKey("AccountId")
                        .withValue(accountId)
                );
        
        secretsClient.createSecret(secretRequest);
    }
    
    public static void bad_case_14(HttpServletRequest request) {
        // Using AWS Cognito with vulnerable custom authorizer
        AWSCognitoIdentityProvider cognitoClient = AWSCognitoIdentityProviderClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        String accountId = request.getParameter("accountId");
        
        // ruleid: java-custom-authorization-handler
        AdminCreateUserRequest createUserRequest = new AdminCreateUserRequest()
                .withUserPoolId("us-east-1_abcdef123")
                .withUsername("user-" + accountId)
                .withUserAttributes(
                    new AttributeType().withName("custom:accountId").withValue(accountId)
                );
        
        cognitoClient.adminCreateUser(createUserRequest);
    }
    
    public static void bad_case_15(HttpServletRequest request) {
        // Using Spring Boot REST controller with vulnerable custom authorizer
        String accountId = request.getParameter("accountId");
        
        // Creating a custom authorization handler that uses the accountId from the request
        // ruleid: java-custom-authorization-handler
        String authToken = "Bearer " + accountId + "-token";
        
        // Making an authenticated request to another service using the accountId from the request
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", authToken);
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(
            "https://api.example.com/resources", 
            HttpMethod.GET, 
            entity, 
            String.class
        );
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    public static void good_case_1(APIGatewayProxyRequestEvent request, Context context) {
        // Using AWS API Gateway with secure custom authorizer
        AmazonApiGateway apiGatewayClient = AmazonApiGatewayClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Ignore the accountId from the request
        String accountId = request.getPathParameters().get("accountId");
        
        // Instead, get the authenticated identity from the context
        // ok: java-custom-authorization-handler
        String authenticatedIdentity = context.getIdentity().getIdentityId();
        
        GetResourcesRequest resourcesRequest = new GetResourcesRequest()
                .withRestApiId("api-id")
                .withEmbedCredentials(true)
                .withLimit(500);
        
        // Using the authenticated identity to determine resource ownership
        // ok: java-custom-authorization-handler
        resourcesRequest.addPathSegmentsItem(authenticatedIdentity);
        
        GetResourcesResult result = apiGatewayClient.getResources(resourcesRequest);
    }
    
    public static void good_case_2(HttpServletRequest request, Context lambdaContext) {
        // Using AWS Lambda with secure custom authorizer
        AWSLambda lambdaClient = AWSLambdaClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Ignore the accountId from the request
        String accountId = request.getParameter("accountId");
        
        // Use AWS credentials provider chain to get the authenticated account
        // ok: java-custom-authorization-handler
        String authenticatedAccount = lambdaContext.getInvokedFunctionArn().split(":")[4];
        
        AddPermissionRequest permissionRequest = new AddPermissionRequest()
                .withFunctionName("my-function")
                .withStatementId(UUID.randomUUID().toString())
                .withAction("lambda:InvokeFunction")
                .withPrincipal("apigateway.amazonaws.com");
        
        // Using the authenticated account to set resource policy
        // ok: java-custom-authorization-handler
        permissionRequest.withSourceAccount(authenticatedAccount);
        
        lambdaClient.addPermission(permissionRequest);
    }
    
    public static void good_case_3(HttpServletRequest request, Context lambdaContext) {
        // Using AWS S3 with secure custom authorizer
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Ignore user-provided accountId
        String accountId = request.getParameter("accountId");
        String bucketName = request.getParameter("bucketName");
        
        // Use AWS credentials provider chain to get the authenticated account
        // ok: java-custom-authorization-handler
        String authenticatedAccount = lambdaContext.getInvokedFunctionArn().split(":")[4];
        
        // Creating a bucket policy based on authenticated account
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::" 
                + authenticatedAccount + ":root\"},\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::" + bucketName + "/*\"}]}";
        
        // ok: java-custom-authorization-handler
        s3Client.setBucketPolicy(bucketName, policy);
    }
    
    public static void good_case_4(HttpServletRequest request) {
        // Using AWS DynamoDB with secure custom authorizer
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Ignore user-provided accountId
        String accountId = request.getParameter("accountId");
        
        // Use a fixed table name or derive it from authenticated identity
        // ok: java-custom-authorization-handler
        String tableName = "SecureTable";
        
        CreateTableRequest createTableRequest = new CreateTableRequest()
                .withTableName(tableName)
                .withKeySchema(new KeySchemaElement("id", KeyType.HASH))
                .withAttributeDefinitions(new AttributeDefinition("id", ScalarAttributeType.S))
                .withProvisionedThroughput(new ProvisionedThroughput(5L, 5L));
        
        dynamoDbClient.createTable(createTableRequest);
    }
    
    public static void good_case_5(HttpServletRequest request, Context lambdaContext) {
        // Using AWS SQS with secure custom authorizer
        AmazonSQS sqsClient = AmazonSQSClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Ignore user-provided accountId
        String accountId = request.getParameter("accountId");
        
        // Use AWS credentials provider chain to get the authenticated account
        // ok: java-custom-authorization-handler
        String authenticatedAccount = lambdaContext.getInvokedFunctionArn().split(":")[4];
        
        // Creating a queue with permissions based on authenticated identity
        Map<String, String> attributes = new HashMap<>();
        
        // ok: java-custom-authorization-handler
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"" 
                + authenticatedAccount + "\"},\"Action\":\"sqs:*\",\"Resource\":\"*\"}]}";
        attributes.put("Policy", policy);
        
        sqsClient.createQueue(new com.amazonaws.services.sqs.model.CreateQueueRequest()
                .withQueueName("MyQueue")
                .withAttributes(attributes));
    }
    
    public static void good_case_6(HttpServletRequest request, Context lambdaContext) {
        // Using AWS SNS with secure custom authorizer
        AmazonSNS snsClient = AmazonSNSClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Ignore user-provided accountId
        String accountId = request.getParameter("accountId");
        String topicArn = "arn:aws:sns:us-east-1:123456789012:MyTopic";
        
        // Use AWS credentials provider chain to get the authenticated account
        // ok: java-custom-authorization-handler
        String authenticatedAccount = lambdaContext.getInvokedFunctionArn().split(":")[4];
        
        // ok: java-custom-authorization-handler
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"" 
                + authenticatedAccount + "\"},\"Action\":\"sns:*\",\"Resource\":\"" + topicArn + "\"}]}";
        
        Map<String, String> attributes = new HashMap<>();
        attributes.put("Policy", policy);
        
        snsClient.setTopicAttributes(topicArn, "Policy", policy);
    }
    
    public static void good_case_7(HttpServletRequest request, Context lambdaContext) {
        // Using AWS CloudFormation with secure custom authorizer
        AmazonCloudFormation cfClient = AmazonCloudFormationClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Ignore user-provided accountId
        String accountId = request.getParameter("accountId");
        
        // Use AWS credentials provider chain to get the authenticated account
        // ok: java-custom-authorization-handler
        String authenticatedAccount = lambdaContext.getInvokedFunctionArn().split(":")[4];
        
        com.amazonaws.services.cloudformation.model.CreateStackRequest createStackRequest = 
            new com.amazonaws.services.cloudformation.model.CreateStackRequest()
                .withStackName("MyStack")
                .withTemplateURL("https://s3.amazonaws.com/bucket/template.json")
                .withParameters(
                    new com.amazonaws.services.cloudformation.model.Parameter()
                        .withParameterKey("AccountId")
                        .withParameterValue(authenticatedAccount)
                );
        
        cfClient.createStack(createStackRequest);
    }
    
    public static void good_case_8(HttpServletRequest request, Context lambdaContext) {
        // Using AWS CloudWatch with secure custom authorizer
        AmazonCloudWatch cwClient = AmazonCloudWatchClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Ignore user-provided accountId
        String accountId = request.getParameter("accountId");
        
        // Use AWS credentials provider chain to get the authenticated account
        // ok: java-custom-authorization-handler
        String authenticatedAccount = lambdaContext.getInvokedFunctionArn().split(":")[4];
        
        com.amazonaws.services.cloudwatch.model.PutDashboardRequest dashboardRequest = 
            new com.amazonaws.services.cloudwatch.model.PutDashboardRequest()
                .withDashboardName("Dashboard-" + authenticatedAccount)
                .withDashboardBody("{\"widgets\":[{\"type\":\"text\",\"x\":0,\"y\":0,\"width\":6,\"height\":6," +
                        "\"properties\":{\"markdown\":\"Account: " + authenticatedAccount + "\"}}]}");
        
        cwClient.putDashboard(dashboardRequest);
    }
    
    public static void good_case_9(HttpServletRequest request, Context lambdaContext) {
        // Using AWS EC2 with secure custom authorizer
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Ignore user-provided accountId
        String accountId = request.getParameter("accountId");
        
        // Use AWS credentials provider chain to get the authenticated account
        // ok: java-custom-authorization-handler
        String authenticatedAccount = lambdaContext.getInvokedFunctionArn().split(":")[4];
        
        com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressRequest ingressRequest = 
            new com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressRequest()
                .withGroupId("sg-12345")
                .withIpPermissions(
                    new com.amazonaws.services.ec2.model.IpPermission()
                        .withIpProtocol("tcp")
                        .withFromPort(22)
                        .withToPort(22)
                        .withUserIdGroupPairs(
                            new com.amazonaws.services.ec2.model.UserIdGroupPair()
                                .withUserId(authenticatedAccount)
                                .withGroupId("sg-67890")
                        )
                );
        
        ec2Client.authorizeSecurityGroupIngress(ingressRequest);
    }
    
    public static void good_case_10(HttpServletRequest request, Context lambdaContext) {
        // Using AWS Elastic Beanstalk with secure custom authorizer
        AWSElasticBeanstalk ebClient = AWSElasticBeanstalkClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Ignore user-provided accountId
        String accountId = request.getParameter("accountId");
        
        // Use AWS credentials provider chain to get the authenticated account
        // ok: java-custom-authorization-handler
        String authenticatedAccount = lambdaContext.getInvokedFunctionArn().split(":")[4];
        
        com.amazonaws.services.elasticbeanstalk.model.CreateApplicationRequest appRequest = 
            new com.amazonaws.services.elasticbeanstalk.model.CreateApplicationRequest()
                .withApplicationName("App-" + authenticatedAccount)
                .withDescription("Application for account " + authenticatedAccount);
        
        ebClient.createApplication(appRequest);
    }
    
    public static void good_case_11(HttpServletRequest request, Context lambdaContext) {
        // Using AWS Elastic Load Balancing with secure custom authorizer
        AmazonElasticLoadBalancing elbClient = AmazonElasticLoadBalancingClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Ignore user-provided accountId
        String accountId = request.getParameter("accountId");
        
        // Use AWS credentials provider chain to get the authenticated account
        // ok: java-custom-authorization-handler
        String authenticatedAccount = lambdaContext.getInvokedFunctionArn().split(":")[4];
        
        com.amazonaws.services.elasticloadbalancing.model.CreateLoadBalancerPolicyRequest policyRequest = 
            new com.amazonaws.services.elasticloadbalancing.model.CreateLoadBalancerPolicyRequest()
                .withLoadBalancerName("MyLoadBalancer")
                .withPolicyName("Policy-" + authenticatedAccount)
                .withPolicyTypeName("SSLNegotiationPolicyType")
                .withPolicyAttributes(
                    new com.amazonaws.services.elasticloadbalancing.model.PolicyAttribute()
                        .withAttributeName("Reference-Security-Policy")
                        .withAttributeValue("ELBSecurityPolicy-TLS-1-2-2017-01")
                );
        
        elbClient.createLoadBalancerPolicy(policyRequest);
    }
    
    public static void good_case_12(HttpServletRequest request, Context lambdaContext) {
        // Using AWS RDS with secure custom authorizer
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Ignore user-provided accountId
        String accountId = request.getParameter("accountId");
        
        // Use AWS credentials provider chain to get the authenticated account
        // ok: java-custom-authorization-handler
        String authenticatedAccount = lambdaContext.getInvokedFunctionArn().split(":")[4];
        
        com.amazonaws.services.rds.model.CreateDBInstanceRequest dbRequest = 
            new com.amazonaws.services.rds.model.CreateDBInstanceRequest()
                .withDBInstanceIdentifier("db-" + authenticatedAccount)
                .withEngine("mysql")
                .withDBInstanceClass("db.t2.micro")
                .withMasterUsername("admin")
                .withMasterUserPassword("password")
                .withAllocatedStorage(20)
                .withTags(
                    new com.amazonaws.services.rds.model.Tag()
                        .withKey("AccountId")
                        .withValue(authenticatedAccount)
                );
        
        rdsClient.createDBInstance(dbRequest);
    }
    
    public static void good_case_13(HttpServletRequest request, Context lambdaContext) {
        // Using AWS Secrets Manager with secure custom authorizer
        AWSSecretsManager secretsClient = AWSSecretsManagerClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Ignore user-provided accountId
        String accountId = request.getParameter("accountId");
        
        // Use AWS credentials provider chain to get the authenticated account
        // ok: java-custom-authorization-handler
        String authenticatedAccount = lambdaContext.getInvokedFunctionArn().split(":")[4];
        
        com.amazonaws.services.secretsmanager.model.CreateSecretRequest secretRequest = 
            new com.amazonaws.services.secretsmanager.model.CreateSecretRequest()
                .withName("secret/" + authenticatedAccount + "/api-key")
                .withSecretString("{\"apiKey\":\"my-api-key\"}")
                .withTags(
                    new com.amazonaws.services.secretsmanager.model.Tag()
                        .withKey("AccountId")
                        .withValue(authenticatedAccount)
                );
        
        secretsClient.createSecret(secretRequest);
    }
    
    public static void good_case_14(HttpServletRequest request, Context lambdaContext) {
        // Using AWS Cognito with secure custom authorizer
        AWSCognitoIdentityProvider cognitoClient = AWSCognitoIdentityProviderClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Ignore user-provided accountId
        String accountId = request.getParameter("accountId");
        
        // Use AWS credentials provider chain to get the authenticated account
        // ok: java-custom-authorization-handler
        String authenticatedAccount = lambdaContext.getInvokedFunctionArn().split(":")[4];
        
        AdminCreateUserRequest createUserRequest = new AdminCreateUserRequest()
                .withUserPoolId("us-east-1_abcdef123")
                .withUsername("user-" + authenticatedAccount)
                .withUserAttributes(
                    new AttributeType().withName("custom:accountId").withValue(authenticatedAccount)
                );
        
        cognitoClient.adminCreateUser(createUserRequest);
    }
    
    public static void good_case_15(HttpServletRequest request, Context lambdaContext) {
        // Using Spring Boot REST controller with secure custom authorizer
        // Ignore user-provided accountId
        String accountId = request.getParameter("accountId");
        
        // Use AWS credentials provider chain to get the authenticated account
        // ok: java-custom-authorization-handler
        String authenticatedAccount = lambdaContext.getInvokedFunctionArn().split(":")[4];
        
        // Creating a custom authorization handler that uses the authenticated account
        String authToken = "Bearer " + authenticatedAccount + "-token";
        
        // Making an authenticated request to another service using the authenticated account
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", authToken);
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(
            "https://api.example.com/resources", 
            HttpMethod.GET, 
            entity, 
            String.class
        );
    }
}
// {/fact}