import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.dynamodb.AmazonDynamoDB;
import com.amazonaws.services.dynamodb.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodb.model.ScanRequest;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.DescribeInstancesRequest;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import com.amazonaws.services.sns.model.PublishRequest;
import com.amazonaws.services.cloudwatch.AmazonCloudWatch;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClientBuilder;
import com.amazonaws.services.cloudwatch.model.GetMetricDataRequest;
import com.amazonaws.services.rds.AmazonRDS;
import com.amazonaws.services.rds.AmazonRDSClientBuilder;
import com.amazonaws.services.rds.model.DescribeDBInstancesRequest;
import com.amazonaws.services.elasticbeanstalk.AWSElasticBeanstalk;
import com.amazonaws.services.elasticbeanstalk.AWSElasticBeanstalkClientBuilder;
import com.amazonaws.services.elasticbeanstalk.model.DescribeEnvironmentsRequest;
import com.amazonaws.services.glacier.AmazonGlacier;
import com.amazonaws.services.glacier.AmazonGlacierClientBuilder;
import com.amazonaws.services.glacier.model.ListVaultsRequest;
import com.amazonaws.services.apigateway.AmazonApiGateway;
import com.amazonaws.services.apigateway.AmazonApiGatewayClientBuilder;
import com.amazonaws.services.apigateway.model.GetApiKeysRequest;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.ListUserPoolsRequest;
import com.amazonaws.services.route53.AmazonRoute53;
import com.amazonaws.services.route53.AmazonRoute53ClientBuilder;
import com.amazonaws.services.route53.model.ListHostedZonesRequest;
import com.amazonaws.services.cloudformation.AmazonCloudFormation;
import com.amazonaws.services.cloudformation.AmazonCloudFormationClientBuilder;
import com.amazonaws.services.cloudformation.model.DescribeStacksRequest;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.AmazonClientException;
import com.amazonaws.SdkClientException;
import com.amazonaws.services.s3.model.AmazonS3Exception;
import com.amazonaws.services.dynamodb.model.AmazonDynamoDBException;
import com.amazonaws.services.lambda.model.AWSLambdaException;
import com.amazonaws.services.ec2.model.AmazonEC2Exception;
import com.amazonaws.services.sqs.model.AmazonSQSException;
import com.amazonaws.services.sns.model.AmazonSNSException;
import com.amazonaws.services.cloudwatch.model.AmazonCloudWatchException;
import com.amazonaws.services.rds.model.AmazonRDSException;
import com.amazonaws.services.elasticbeanstalk.model.AWSElasticBeanstalkException;
import com.amazonaws.services.glacier.model.AmazonGlacierException;
import com.amazonaws.services.apigateway.model.AmazonApiGatewayException;
import com.amazonaws.services.cognitoidp.model.AWSCognitoIdentityProviderException;
import com.amazonaws.services.route53.model.AmazonRoute53Exception;
import com.amazonaws.services.cloudformation.model.AmazonCloudFormationException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import spark.Request;
import spark.Response;
import io.javalin.http.Context;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.quarkus.vertx.web.Route;
import ratpack.handling.Context;
import ratpack.http.Request;
import ratpack.http.Response;
import java.util.Map;
import java.util.HashMap;
import java.util.logging.Logger;
import java.util.logging.Level;

// Security Issue: Uncaught AWS API exceptions can lead to unexpected application behavior and potential security vulnerabilities

// True Positive Examples (Vulnerable/Insecure Code)
public class UncaughtAwsExceptionExamples {
    private static final Logger logger = Logger.getLogger(UncaughtAwsExceptionExamples.class.getName());

    // Example 1: S3 Client with uncaught exception
// {fact rule=check-uncaught-exceptions@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) {
        String bucketName = request.getParameter("bucket");
        String objectKey = request.getParameter("key");
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // ruleid: java-check-uncaught-exceptions
        S3Object s3Object = s3Client.getObject(new GetObjectRequest(bucketName, objectKey));
        
        // Process the object without exception handling
        response.setContentType("application/json");
        // Further processing...
    }

    // Example 2: DynamoDB Client with uncaught exception
    public void bad_case_2(@RequestParam String tableName, @RequestBody Map<String, Object> requestBody) {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        ScanRequest scanRequest = new ScanRequest().withTableName(tableName);
        
        // ruleid: java-check-uncaught-exceptions
        dynamoDBClient.scan(scanRequest);
        
        // Process the scan results without exception handling
    }

    // Example 3: Lambda Client with uncaught exception
    public void bad_case_3(spark.Request request, spark.Response response) {
        String functionName = request.queryParams("function");
        String payload = request.body();
        
        AWSLambda lambdaClient = AWSLambdaClientBuilder.standard().build();
        InvokeRequest invokeRequest = new InvokeRequest()
                .withFunctionName(functionName)
                .withPayload(payload);
        
        // ruleid: java-check-uncaught-exceptions
        lambdaClient.invoke(invokeRequest);
        
        response.status(200);
        response.type("application/json");
        response.body("{\"status\":\"success\"}");
    }

    // Example 4: EC2 Client with uncaught exception
    public void bad_case_4(io.javalin.http.Context ctx) {
        String instanceId = ctx.queryParam("instanceId");
        
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        DescribeInstancesRequest request = new DescribeInstancesRequest();
        
        if (instanceId != null) {
            request.withInstanceIds(instanceId);
        }
        
        // ruleid: java-check-uncaught-exceptions
        ec2Client.describeInstances(request);
        
        ctx.json(Map.of("status", "success"));
    }

    // Example 5: SQS Client with uncaught exception
    public void bad_case_5(io.micronaut.http.HttpRequest<?> request, io.micronaut.http.HttpResponse<?> response) {
        String queueUrl = request.getParameters().get("queueUrl");
        String messageBody = request.getBody().map(Object::toString).orElse("");
        
        AmazonSQS sqsClient = AmazonSQSClientBuilder.standard().build();
        SendMessageRequest sendMessageRequest = new SendMessageRequest()
                .withQueueUrl(queueUrl)
                .withMessageBody(messageBody);
        
        // ruleid: java-check-uncaught-exceptions
        sqsClient.sendMessage(sendMessageRequest);
    }

    // Example 6: SNS Client with uncaught exception
    public void bad_case_6(HttpServerRequest request, HttpServerResponse response) {
        String topicArn = request.getParam("topicArn");
        String message = request.getParam("message");
        
        AmazonSNS snsClient = AmazonSNSClientBuilder.standard().build();
        PublishRequest publishRequest = new PublishRequest()
                .withTopicArn(topicArn)
                .withMessage(message);
        
        // ruleid: java-check-uncaught-exceptions
        snsClient.publish(publishRequest);
        
        response.setStatusCode(200).end("Message published");
    }

    // Example 7: CloudWatch Client with uncaught exception
    public void bad_case_7(ratpack.handling.Context ctx) {
        String metricName = ctx.getRequest().getQueryParams().get("metricName");
        
        AmazonCloudWatch cloudWatchClient = AmazonCloudWatchClientBuilder.standard().build();
        GetMetricDataRequest request = new GetMetricDataRequest();
        // Configure request with metric name
        
        // ruleid: java-check-uncaught-exceptions
        cloudWatchClient.getMetricData(request);
        
        ctx.render("Metric data retrieved");
    }

    // Example 8: RDS Client with uncaught exception
    @GetMapping("/rds-instances")
    public ResponseEntity<?> bad_case_8(HttpServletRequest request) {
        String dbInstanceId = request.getParameter("dbInstanceId");
        
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard().build();
        DescribeDBInstancesRequest describeRequest = new DescribeDBInstancesRequest();
        
        if (dbInstanceId != null) {
            describeRequest.withDBInstanceIdentifier(dbInstanceId);
        }
        
        // ruleid: java-check-uncaught-exceptions
        rdsClient.describeDBInstances(describeRequest);
        
        return ResponseEntity.ok().body("RDS instances retrieved");
    }

    // Example 9: Elastic Beanstalk Client with uncaught exception
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) {
        String environmentId = request.getParameter("environmentId");
        
        AWSElasticBeanstalk beanstalkClient = AWSElasticBeanstalkClientBuilder.standard().build();
        DescribeEnvironmentsRequest describeRequest = new DescribeEnvironmentsRequest();
        
        if (environmentId != null) {
            describeRequest.withEnvironmentIds(environmentId);
        }
        
        // ruleid: java-check-uncaught-exceptions
        beanstalkClient.describeEnvironments(describeRequest);
    }

    // Example 10: Glacier Client with uncaught exception
    public void bad_case_10(spark.Request request, spark.Response response) {
        String accountId = request.queryParams("accountId");
        
        AmazonGlacier glacierClient = AmazonGlacierClientBuilder.standard().build();
        ListVaultsRequest listVaultsRequest = new ListVaultsRequest()
                .withAccountId(accountId);
        
        // ruleid: java-check-uncaught-exceptions
        glacierClient.listVaults(listVaultsRequest);
        
        response.type("application/json");
        response.body("{\"status\":\"success\"}");
    }

    // Example 11: API Gateway Client with uncaught exception
    @Route(path = "/api-keys")
    public void bad_case_11(HttpServerRequest request, HttpServerResponse response) {
        String position = request.getParam("position");
        
        AmazonApiGateway apiGatewayClient = AmazonApiGatewayClientBuilder.standard().build();
        GetApiKeysRequest getApiKeysRequest = new GetApiKeysRequest();
        
        if (position != null) {
            getApiKeysRequest.withPosition(position);
        }
        
        // ruleid: java-check-uncaught-exceptions
        apiGatewayClient.getApiKeys(getApiKeysRequest);
        
        response.end("API keys retrieved");
    }

    // Example 12: Cognito Client with uncaught exception
    public void bad_case_12(io.javalin.http.Context ctx) {
        String maxResults = ctx.queryParam("maxResults");
        
        AWSCognitoIdentityProvider cognitoClient = AWSCognitoIdentityProviderClientBuilder.standard().build();
        ListUserPoolsRequest listUserPoolsRequest = new ListUserPoolsRequest();
        
        if (maxResults != null) {
            listUserPoolsRequest.withMaxResults(Integer.parseInt(maxResults));
        }
        
        // ruleid: java-check-uncaught-exceptions
        cognitoClient.listUserPools(listUserPoolsRequest);
        
        ctx.result("User pools retrieved");
    }

    // Example 13: Route53 Client with uncaught exception
    public void bad_case_13(io.micronaut.http.HttpRequest<?> request) {
        String marker = request.getParameters().get("marker");
        
        AmazonRoute53 route53Client = AmazonRoute53ClientBuilder.standard().build();
        ListHostedZonesRequest listHostedZonesRequest = new ListHostedZonesRequest();
        
        if (marker != null) {
            listHostedZonesRequest.withMarker(marker);
        }
        
        // ruleid: java-check-uncaught-exceptions
        route53Client.listHostedZones(listHostedZonesRequest);
    }

    // Example 14: CloudFormation Client with uncaught exception
    public void bad_case_14(ratpack.handling.Context ctx) {
        String stackName = ctx.getRequest().getQueryParams().get("stackName");
        
        AmazonCloudFormation cloudFormationClient = AmazonCloudFormationClientBuilder.standard().build();
        DescribeStacksRequest describeStacksRequest = new DescribeStacksRequest();
        
        if (stackName != null) {
            describeStacksRequest.withStackName(stackName);
        }
        
        // ruleid: java-check-uncaught-exceptions
        cloudFormationClient.describeStacks(describeStacksRequest);
        
        ctx.render("Stacks described");
    }

    // Example 15: S3 Client with multiple uncaught exceptions
    @PostMapping("/upload")
    public ResponseEntity<?> bad_case_15(@RequestParam String bucketName, @RequestParam String objectKey) {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // ruleid: java-check-uncaught-exceptions
        s3Client.doesBucketExistV2(bucketName);
        
        // ruleid: java-check-uncaught-exceptions
        s3Client.putObject(bucketName, objectKey, "Sample content");
        
        return ResponseEntity.ok().body("Object uploaded successfully");
    }

    // True Negative Examples (Safe/Secure Code)
    
    // Example 1: S3 Client with proper exception handling
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) {
        String bucketName = request.getParameter("bucket");
        String objectKey = request.getParameter("key");
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        try {
            // ok: java-check-uncaught-exceptions
            S3Object s3Object = s3Client.getObject(new GetObjectRequest(bucketName, objectKey));
            
            // Process the object
            response.setContentType("application/json");
            // Further processing...
        } catch (AmazonS3Exception e) {
            logger.log(Level.SEVERE, "Error accessing S3 object: " + e.getMessage(), e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } catch (SdkClientException e) {
            logger.log(Level.SEVERE, "AWS SDK client error: " + e.getMessage(), e);
            response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
        }
    }

    // Example 2: DynamoDB Client with proper exception handling
    public ResponseEntity<?> good_case_2(@RequestParam String tableName, @RequestBody Map<String, Object> requestBody) {
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard().build();
        
        ScanRequest scanRequest = new ScanRequest().withTableName(tableName);
        
        try {
            // ok: java-check-uncaught-exceptions
            dynamoDBClient.scan(scanRequest);
            
            return ResponseEntity.ok().body("Scan completed successfully");
        } catch (AmazonDynamoDBException e) {
            logger.log(Level.SEVERE, "DynamoDB error: " + e.getMessage(), e);
            return ResponseEntity.status(500).body("Error scanning DynamoDB table: " + e.getMessage());
        } catch (AmazonServiceException e) {
            logger.log(Level.SEVERE, "AWS service error: " + e.getMessage(), e);
            return ResponseEntity.status(502).body("AWS service error: " + e.getMessage());
        } catch (AmazonClientException e) {
            logger.log(Level.SEVERE, "AWS client error: " + e.getMessage(), e);
            return ResponseEntity.status(500).body("AWS client error: " + e.getMessage());
        }
    }

    // Example 3: Lambda Client with proper exception handling
    public void good_case_3(spark.Request request, spark.Response response) {
        String functionName = request.queryParams("function");
        String payload = request.body();
        
        AWSLambda lambdaClient = AWSLambdaClientBuilder.standard().build();
        InvokeRequest invokeRequest = new InvokeRequest()
                .withFunctionName(functionName)
                .withPayload(payload);
        
        try {
            // ok: java-check-uncaught-exceptions
            lambdaClient.invoke(invokeRequest);
            
            response.status(200);
            response.type("application/json");
            response.body("{\"status\":\"success\"}");
        } catch (AWSLambdaException e) {
            logger.log(Level.SEVERE, "Lambda error: " + e.getMessage(), e);
            response.status(500);
            response.body("{\"status\":\"error\",\"message\":\"" + e.getMessage() + "\"}");
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected error: " + e.getMessage(), e);
            response.status(500);
            response.body("{\"status\":\"error\",\"message\":\"Unexpected error\"}");
        }
    }

    // Example 4: EC2 Client with proper exception handling
    public void good_case_4(io.javalin.http.Context ctx) {
        String instanceId = ctx.queryParam("instanceId");
        
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        DescribeInstancesRequest request = new DescribeInstancesRequest();
        
        if (instanceId != null) {
            request.withInstanceIds(instanceId);
        }
        
        try {
            // ok: java-check-uncaught-exceptions
            ec2Client.describeInstances(request);
            
            ctx.json(Map.of("status", "success"));
        } catch (AmazonEC2Exception e) {
            logger.log(Level.SEVERE, "EC2 error: " + e.getMessage(), e);
            ctx.status(500);
            ctx.json(Map.of("status", "error", "message", e.getMessage()));
        } catch (AmazonServiceException e) {
            logger.log(Level.SEVERE, "AWS service error: " + e.getMessage(), e);
            ctx.status(502);
            ctx.json(Map.of("status", "error", "message", "AWS service error: " + e.getMessage()));
        }
    }

    // Example 5: SQS Client with proper exception handling
    public HttpResponse<?> good_case_5(io.micronaut.http.HttpRequest<?> request) {
        String queueUrl = request.getParameters().get("queueUrl");
        String messageBody = request.getBody().map(Object::toString).orElse("");
        
        AmazonSQS sqsClient = AmazonSQSClientBuilder.standard().build();
        SendMessageRequest sendMessageRequest = new SendMessageRequest()
                .withQueueUrl(queueUrl)
                .withMessageBody(messageBody);
        
        try {
            // ok: java-check-uncaught-exceptions
            sqsClient.sendMessage(sendMessageRequest);
            
            return HttpResponse.ok(Map.of("status", "success"));
        } catch (AmazonSQSException e) {
            logger.log(Level.SEVERE, "SQS error: " + e.getMessage(), e);
            return HttpResponse.serverError(Map.of("status", "error", "message", e.getMessage()));
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected error: " + e.getMessage(), e);
            return HttpResponse.serverError(Map.of("status", "error", "message", "Unexpected error"));
        }
    }

    // Example 6: SNS Client with proper exception handling
    public void good_case_6(HttpServerRequest request, HttpServerResponse response) {
        String topicArn = request.getParam("topicArn");
        String message = request.getParam("message");
        
        AmazonSNS snsClient = AmazonSNSClientBuilder.standard().build();
        PublishRequest publishRequest = new PublishRequest()
                .withTopicArn(topicArn)
                .withMessage(message);
        
        try {
            // ok: java-check-uncaught-exceptions
            snsClient.publish(publishRequest);
            
            response.setStatusCode(200).end("Message published");
        } catch (AmazonSNSException e) {
            logger.log(Level.SEVERE, "SNS error: " + e.getMessage(), e);
            response.setStatusCode(500).end("Error publishing message: " + e.getMessage());
        } catch (AmazonServiceException e) {
            logger.log(Level.SEVERE, "AWS service error: " + e.getMessage(), e);
            response.setStatusCode(502).end("AWS service error: " + e.getMessage());
        }
    }

    // Example 7: CloudWatch Client with proper exception handling
    public void good_case_7(ratpack.handling.Context ctx) {
        String metricName = ctx.getRequest().getQueryParams().get("metricName");
        
        AmazonCloudWatch cloudWatchClient = AmazonCloudWatchClientBuilder.standard().build();
        GetMetricDataRequest request = new GetMetricDataRequest();
        // Configure request with metric name
        
        try {
            // ok: java-check-uncaught-exceptions
            cloudWatchClient.getMetricData(request);
            
            ctx.render("Metric data retrieved");
        } catch (AmazonCloudWatchException e) {
            logger.log(Level.SEVERE, "CloudWatch error: " + e.getMessage(), e);
            ctx.getResponse().status(500);
            ctx.render("Error retrieving metric data: " + e.getMessage());
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected error: " + e.getMessage(), e);
            ctx.getResponse().status(500);
            ctx.render("Unexpected error occurred");
        }
    }

    // Example 8: RDS Client with proper exception handling
    @GetMapping("/rds-instances-safe")
    public ResponseEntity<?> good_case_8(HttpServletRequest request) {
        String dbInstanceId = request.getParameter("dbInstanceId");
        
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard().build();
        DescribeDBInstancesRequest describeRequest = new DescribeDBInstancesRequest();
        
        if (dbInstanceId != null) {
            describeRequest.withDBInstanceIdentifier(dbInstanceId);
        }
        
        try {
            // ok: java-check-uncaught-exceptions
            rdsClient.describeDBInstances(describeRequest);
            
            return ResponseEntity.ok().body("RDS instances retrieved");
        } catch (AmazonRDSException e) {
            logger.log(Level.SEVERE, "RDS error: " + e.getMessage(), e);
            return ResponseEntity.status(500).body("Error retrieving RDS instances: " + e.getMessage());
        } catch (AmazonServiceException e) {
            logger.log(Level.SEVERE, "AWS service error: " + e.getMessage(), e);
            return ResponseEntity.status(502).body("AWS service error: " + e.getMessage());
        }
    }

    // Example 9: Elastic Beanstalk Client with proper exception handling
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) {
        String environmentId = request.getParameter("environmentId");
        
        AWSElasticBeanstalk beanstalkClient = AWSElasticBeanstalkClientBuilder.standard().build();
        DescribeEnvironmentsRequest describeRequest = new DescribeEnvironmentsRequest();
        
        if (environmentId != null) {
            describeRequest.withEnvironmentIds(environmentId);
        }
        
        try {
            // ok: java-check-uncaught-exceptions
            beanstalkClient.describeEnvironments(describeRequest);
            
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().write("Environments described successfully");
        } catch (AWSElasticBeanstalkException e) {
            logger.log(Level.SEVERE, "Elastic Beanstalk error: " + e.getMessage(), e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("Error describing environments: " + e.getMessage());
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected error: " + e.getMessage(), e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("Unexpected error occurred");
        }
    }

    // Example 10: Glacier Client with proper exception handling
    public void good_case_10(spark.Request request, spark.Response response) {
        String accountId = request.queryParams("accountId");
        
        AmazonGlacier glacierClient = AmazonGlacierClientBuilder.standard().build();
        ListVaultsRequest listVaultsRequest = new ListVaultsRequest()
                .withAccountId(accountId);
        
        try {
            // ok: java-check-uncaught-exceptions
            glacierClient.listVaults(listVaultsRequest);
            
            response.type("application/json");
            response.body("{\"status\":\"success\"}");
        } catch (AmazonGlacierException e) {
            logger.log(Level.SEVERE, "Glacier error: " + e.getMessage(), e);
            response.status(500);
            response.body("{\"status\":\"error\",\"message\":\"" + e.getMessage() + "\"}");
        } catch (AmazonServiceException e) {
            logger.log(Level.SEVERE, "AWS service error: " + e.getMessage(), e);
            response.status(502);
            response.body("{\"status\":\"error\",\"message\":\"AWS service error\"}");
        }
    }

    // Example 11: API Gateway Client with proper exception handling
    @Route(path = "/api-keys-safe")
    public void good_case_11(HttpServerRequest request, HttpServerResponse response) {
        String position = request.getParam("position");
        
        AmazonApiGateway apiGatewayClient = AmazonApiGatewayClientBuilder.standard().build();
        GetApiKeysRequest getApiKeysRequest = new GetApiKeysRequest();
        
        if (position != null) {
            getApiKeysRequest.withPosition(position);
        }
        
        try {
            // ok: java-check-uncaught-exceptions
            apiGatewayClient.getApiKeys(getApiKeysRequest);
            
            response.setStatusCode(200).end("API keys retrieved");
        } catch (AmazonApiGatewayException e) {
            logger.log(Level.SEVERE, "API Gateway error: " + e.getMessage(), e);
            response.setStatusCode(500).end("Error retrieving API keys: " + e.getMessage());
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected error: " + e.getMessage(), e);
            response.setStatusCode(500).end("Unexpected error occurred");
        }
    }

    // Example 12: Cognito Client with proper exception handling
    public void good_case_12(io.javalin.http.Context ctx) {
        String maxResults = ctx.queryParam("maxResults");
        
        AWSCognitoIdentityProvider cognitoClient = AWSCognitoIdentityProviderClientBuilder.standard().build();
        ListUserPoolsRequest listUserPoolsRequest = new ListUserPoolsRequest();
        
        if (maxResults != null) {
            listUserPoolsRequest.withMaxResults(Integer.parseInt(maxResults));
        }
        
        try {
            // ok: java-check-uncaught-exceptions
            cognitoClient.listUserPools(listUserPoolsRequest);
            
            ctx.result("User pools retrieved");
        } catch (AWSCognitoIdentityProviderException e) {
            logger.log(Level.SEVERE, "Cognito error: " + e.getMessage(), e);
            ctx.status(500);
            ctx.result("Error retrieving user pools: " + e.getMessage());
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected error: " + e.getMessage(), e);
            ctx.status(500);
            ctx.result("Unexpected error occurred");
        }
    }

    // Example 13: Route53 Client with proper exception handling
    public HttpResponse<?> good_case_13(io.micronaut.http.HttpRequest<?> request) {
        String marker = request.getParameters().get("marker");
        
        AmazonRoute53 route53Client = AmazonRoute53ClientBuilder.standard().build();
        ListHostedZonesRequest listHostedZonesRequest = new ListHostedZonesRequest();
        
        if (marker != null) {
            listHostedZonesRequest.withMarker(marker);
        }
        
        try {
            // ok: java-check-uncaught-exceptions
            route53Client.listHostedZones(listHostedZonesRequest);
            
            return HttpResponse.ok(Map.of("status", "success"));
        } catch (AmazonRoute53Exception e) {
            logger.log(Level.SEVERE, "Route53 error: " + e.getMessage(), e);
            return HttpResponse.serverError(Map.of("status", "error", "message", e.getMessage()));
        } catch (AmazonServiceException e) {
            logger.log(Level.SEVERE, "AWS service error: " + e.getMessage(), e);
            return HttpResponse.serverError(Map.of("status", "error", "message", "AWS service error"));
        }
    }

    // Example 14: CloudFormation Client with proper exception handling
    public void good_case_14(ratpack.handling.Context ctx) {
        String stackName = ctx.getRequest().getQueryParams().get("stackName");
        
        AmazonCloudFormation cloudFormationClient = AmazonCloudFormationClientBuilder.standard().build();
        DescribeStacksRequest describeStacksRequest = new DescribeStacksRequest();
        
        if (stackName != null) {
            describeStacksRequest.withStackName(stackName);
        }
        
        try {
            // ok: java-check-uncaught-exceptions
            cloudFormationClient.describeStacks(describeStacksRequest);
            
            ctx.render("Stacks described");
        } catch (AmazonCloudFormationException e) {
            logger.log(Level.SEVERE, "CloudFormation error: " + e.getMessage(), e);
            ctx.getResponse().status(500);
            ctx.render("Error describing stacks: " + e.getMessage());
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected error: " + e.getMessage(), e);
            ctx.getResponse().status(500);
            ctx.render("Unexpected error occurred");
        }
    }

    // Example 15: S3 Client with proper exception handling for multiple operations
    @PostMapping("/upload-safe")
    public ResponseEntity<?> good_case_15(@RequestParam String bucketName, @RequestParam String objectKey) {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        try {
            // ok: java-check-uncaught-exceptions
            boolean bucketExists = s3Client.doesBucketExistV2(bucketName);
            
            if (!bucketExists) {
                return ResponseEntity.badRequest().body("Bucket does not exist");
            }
            
            // ok: java-check-uncaught-exceptions
            s3Client.putObject(bucketName, objectKey, "Sample content");
            
            return ResponseEntity.ok().body("Object uploaded successfully");
        } catch (AmazonS3Exception e) {
            logger.log(Level.SEVERE, "S3 error: " + e.getMessage(), e);
            return ResponseEntity.status(500).body("Error uploading object: " + e.getMessage());
        } catch (SdkClientException e) {
            logger.log(Level.SEVERE, "AWS SDK client error: " + e.getMessage(), e);
            return ResponseEntity.status(502).body("AWS SDK client error: " + e.getMessage());
        }
    }
}
// {/fact}