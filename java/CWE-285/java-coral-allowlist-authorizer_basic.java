import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.model.*;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.amazonaws.services.lambda.model.InvokeResult;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import com.amazonaws.services.sns.model.PublishRequest;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.DescribeInstancesRequest;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.cloudwatch.AmazonCloudWatch;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClientBuilder;
import com.amazonaws.services.cloudwatch.model.GetMetricDataRequest;
import com.amazonaws.services.cloudwatch.model.GetMetricDataResult;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvokeResponse;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageResponse;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.PublishResponse;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesResponse;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.model.GetMetricDataResponse;

import com.amazonaws.coral.authorize.AllowlistAuthorizer;
import com.amazonaws.coral.authorize.WhitelistAuthorizer;
import com.amazonaws.coral.service.Operation;
import com.amazonaws.coral.service.ServiceOperations;
import com.amazonaws.coral.service.Context;
import com.amazonaws.coral.authorize.Authorizer;
import com.amazonaws.coral.authorize.RoleBasedAuthorizer;
import com.amazonaws.coral.authorize.JwtAuthorizer;
import com.amazonaws.coral.authorize.OAuthAuthorizer;
import com.amazonaws.coral.authorize.PolicyBasedAuthorizer;
import com.amazonaws.coral.service.HealthCheckOperation;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.nio.ByteBuffer;
import java.io.IOException;
import java.util.concurrent.CompletableFuture;

public class AllowlistAuthorizerExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=improper-authentication@v1.0 defects=1}
    public void bad_case_1() {
        // Using AllowlistAuthorizer for DynamoDB operations
        Set<String> allowedOperations = new HashSet<>(Arrays.asList(
            "GetItem", "PutItem", "UpdateItem", "DeleteItem", "Query", "Scan"
        ));
        
        // ruleid: java-coral-allowlist-authorizer
        Authorizer authorizer = new AllowlistAuthorizer(allowedOperations);
        
        // Configure service with insecure authorizer for sensitive operations
        DynamoDBService service = new DynamoDBService();
        service.setAuthorizer(authorizer);
        service.processUserRequest("GetItem", new Context("user123"));
    }

    public void bad_case_2() {
        // Using WhitelistAuthorizer (old name) for S3 operations
        Set<String> allowedOperations = new HashSet<>();
        allowedOperations.add("GetObject");
        allowedOperations.add("PutObject");
        allowedOperations.add("DeleteObject");
        
        // ruleid: java-coral-allowlist-authorizer
        Authorizer authorizer = new WhitelistAuthorizer(allowedOperations);
        
        // Configure S3 service with insecure authorizer
        S3Service s3Service = new S3Service();
        s3Service.setAuthorizer(authorizer);
        s3Service.handleRequest("GetObject", new Context("user456"));
    }

    public void bad_case_3() {
        // Using AllowlistAuthorizer for Lambda invocation
        Set<String> allowedOps = new HashSet<>();
        allowedOps.add("InvokeFunction");
        allowedOps.add("ListFunctions");
        
        // ruleid: java-coral-allowlist-authorizer
        AllowlistAuthorizer authorizer = new AllowlistAuthorizer(allowedOps);
        
        // Using insecure authorizer for Lambda operations
        LambdaService lambdaService = new LambdaService();
        lambdaService.configureAuthorizer(authorizer);
        lambdaService.invokeFunction("myFunction", "{\"data\":\"value\"}", new Context("user789"));
    }

    public void bad_case_4() {
        // Using AllowlistAuthorizer for SQS message operations
        Set<String> allowedOperations = new HashSet<>(Arrays.asList(
            "SendMessage", "ReceiveMessage", "DeleteMessage"
        ));
        
        // ruleid: java-coral-allowlist-authorizer
        Authorizer sqsAuthorizer = new AllowlistAuthorizer(allowedOperations);
        
        // Configure message queue service with weak authorizer
        MessageQueueService queueService = new MessageQueueService();
        queueService.setAuthorizer(sqsAuthorizer);
        queueService.sendMessage("myQueue", "Hello world", new Context("user101"));
    }

    public void bad_case_5() {
        // Using AllowlistAuthorizer for SNS publishing
        Set<String> allowedOperations = new HashSet<>();
        allowedOperations.add("Publish");
        allowedOperations.add("Subscribe");
        allowedOperations.add("Unsubscribe");
        
        // ruleid: java-coral-allowlist-authorizer
        AllowlistAuthorizer snsAuthorizer = new AllowlistAuthorizer(allowedOperations);
        
        // Using weak authorizer for notification service
        NotificationService notificationService = new NotificationService();
        notificationService.setAuthorizer(snsAuthorizer);
        notificationService.publishMessage("myTopic", "Alert message", new Context("user202"));
    }

    public void bad_case_6() {
        // Using AllowlistAuthorizer for EC2 instance management
        Set<String> allowedEc2Ops = new HashSet<>(Arrays.asList(
            "StartInstances", "StopInstances", "TerminateInstances", "DescribeInstances"
        ));
        
        // ruleid: java-coral-allowlist-authorizer
        Authorizer ec2Authorizer = new AllowlistAuthorizer(allowedEc2Ops);
        
        // Configure EC2 service with weak authorizer
        EC2Service ec2Service = new EC2Service();
        ec2Service.setAuthorizer(ec2Authorizer);
        ec2Service.performOperation("StartInstances", "i-1234567890abcdef0", new Context("admin"));
    }

    public void bad_case_7() {
        // Using AllowlistAuthorizer with programmatically added operations
        Set<String> allowedOperations = new HashSet<>();
        
        // Adding operations programmatically
        for (String op : new String[]{"CreateUser", "UpdateUser", "DeleteUser", "GetUser"}) {
            allowedOperations.add(op);
        }
        
        // ruleid: java-coral-allowlist-authorizer
        Authorizer userAuthorizer = new AllowlistAuthorizer(allowedOperations);
        
        // Using weak authorizer for user management service
        UserManagementService userService = new UserManagementService();
        userService.setAuthorizer(userAuthorizer);
        userService.executeOperation("CreateUser", "{\"name\":\"John\"}", new Context("admin"));
    }

    public void bad_case_8() {
        // Using AllowlistAuthorizer with operations from configuration
        ConfigurationService configService = new ConfigurationService();
        Set<String> allowedOperations = configService.getAllowedOperations("payment-service");
        
        // ruleid: java-coral-allowlist-authorizer
        Authorizer paymentAuthorizer = new AllowlistAuthorizer(allowedOperations);
        
        // Using weak authorizer for payment processing
        PaymentService paymentService = new PaymentService();
        paymentService.setAuthorizer(paymentAuthorizer);
        paymentService.processPayment("12345", 100.00, "USD", new Context("merchant"));
    }

    public void bad_case_9() {
        // Using AllowlistAuthorizer for CloudWatch metrics access
        Set<String> allowedMetricOps = new HashSet<>();
        allowedMetricOps.add("GetMetricData");
        allowedMetricOps.add("PutMetricData");
        allowedMetricOps.add("ListMetrics");
        
        // ruleid: java-coral-allowlist-authorizer
        Authorizer metricsAuthorizer = new AllowlistAuthorizer(allowedMetricOps);
        
        // Configure metrics service with weak authorizer
        MetricsService metricsService = new MetricsService();
        metricsService.setAuthorizer(metricsAuthorizer);
        metricsService.getMetricData("CPU_Utilization", "1h", new Context("monitor"));
    }

    public void bad_case_10() {
        // Using AllowlistAuthorizer with conditional operation addition
        Set<String> allowedOperations = new HashSet<>();
        allowedOperations.add("ReadData");
        
        boolean isAdmin = checkUserRole("admin");
        if (isAdmin) {
            allowedOperations.add("WriteData");
            allowedOperations.add("DeleteData");
        }
        
        // ruleid: java-coral-allowlist-authorizer
        Authorizer dataAuthorizer = new AllowlistAuthorizer(allowedOperations);
        
        // Using weak authorizer for data access
        DataAccessService dataService = new DataAccessService();
        dataService.setAuthorizer(dataAuthorizer);
        dataService.performOperation("WriteData", "sensitive-data", new Context("admin"));
    }

    public void bad_case_11() {
        // Using AllowlistAuthorizer for API Gateway operations
        Set<String> allowedApiOps = new HashSet<>(Arrays.asList(
            "GET", "POST", "PUT", "DELETE"
        ));
        
        // ruleid: java-coral-allowlist-authorizer
        Authorizer apiAuthorizer = new AllowlistAuthorizer(allowedApiOps);
        
        // Configure API Gateway service with weak authorizer
        ApiGatewayService apiService = new ApiGatewayService();
        apiService.setAuthorizer(apiAuthorizer);
        apiService.handleRequest("POST", "/users", "{\"name\":\"Alice\"}", new Context("client"));
    }

    public void bad_case_12() {
        // Using AllowlistAuthorizer for database schema operations
        Set<String> allowedSchemaOps = new HashSet<>();
        allowedSchemaOps.add("CreateTable");
        allowedSchemaOps.add("AlterTable");
        allowedSchemaOps.add("DropTable");
        allowedSchemaOps.add("DescribeTable");
        
        // ruleid: java-coral-allowlist-authorizer
        Authorizer schemaAuthorizer = new AllowlistAuthorizer(allowedSchemaOps);
        
        // Using weak authorizer for database schema management
        DatabaseSchemaService schemaService = new DatabaseSchemaService();
        schemaService.setAuthorizer(schemaAuthorizer);
        schemaService.executeOperation("CreateTable", "CREATE TABLE users (id INT, name VARCHAR(255))", new Context("dba"));
    }

    public void bad_case_13() {
        // Using AllowlistAuthorizer for file operations
        Set<String> allowedFileOps = new HashSet<>(Arrays.asList(
            "ReadFile", "WriteFile", "DeleteFile", "ListFiles"
        ));
        
        // ruleid: java-coral-allowlist-authorizer
        Authorizer fileAuthorizer = new AllowlistAuthorizer(allowedFileOps);
        
        // Configure file service with weak authorizer
        FileService fileService = new FileService();
        fileService.setAuthorizer(fileAuthorizer);
        fileService.performOperation("WriteFile", "/etc/passwd", "new content", new Context("root"));
    }

    public void bad_case_14() {
        // Using AllowlistAuthorizer with dynamic operation set
        Set<String> allowedOperations = new HashSet<>();
        
        // Dynamically determine allowed operations based on environment
        String env = System.getProperty("environment");
        if ("production".equals(env)) {
            allowedOperations.add("ReadOnly");
        } else {
            allowedOperations.add("ReadOnly");
            allowedOperations.add("ReadWrite");
            allowedOperations.add("Admin");
        }
        
        // ruleid: java-coral-allowlist-authorizer
        Authorizer configAuthorizer = new AllowlistAuthorizer(allowedOperations);
        
        // Using weak authorizer for configuration service
        ConfigService configService = new ConfigService();
        configService.setAuthorizer(configAuthorizer);
        configService.updateConfig("system.settings", "{\"debug\":true}", new Context("sysadmin"));
    }

    public void bad_case_15() {
        // Using AllowlistAuthorizer for authentication operations
        Set<String> allowedAuthOps = new HashSet<>();
        allowedAuthOps.add("Login");
        allowedAuthOps.add("Logout");
        allowedAuthOps.add("ResetPassword");
        allowedAuthOps.add("ChangePassword");
        
        // ruleid: java-coral-allowlist-authorizer
        Authorizer authServiceAuthorizer = new AllowlistAuthorizer(allowedAuthOps);
        
        // Using weak authorizer for authentication service
        AuthenticationService authService = new AuthenticationService();
        authService.setAuthorizer(authServiceAuthorizer);
        authService.processRequest("ResetPassword", "user@example.com", new Context("support"));
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        // Using RoleBasedAuthorizer for DynamoDB operations
        Set<String> roles = new HashSet<>(Arrays.asList("admin", "dbManager"));
        Map<String, Set<String>> rolePermissions = new HashMap<>();
        rolePermissions.put("admin", new HashSet<>(Arrays.asList("GetItem", "PutItem", "UpdateItem", "DeleteItem")));
        rolePermissions.put("dbManager", new HashSet<>(Arrays.asList("GetItem", "Query", "Scan")));
        
        // ok: java-coral-allowlist-authorizer
        Authorizer authorizer = new RoleBasedAuthorizer(rolePermissions);
        
        // Configure service with secure authorizer for sensitive operations
        DynamoDBService service = new DynamoDBService();
        service.setAuthorizer(authorizer);
        service.processUserRequest("GetItem", new Context("user123"));
    }

    public void good_case_2() {
        // Using JwtAuthorizer for S3 operations
        String jwtSecret = System.getenv("JWT_SECRET");
        Set<String> requiredClaims = new HashSet<>(Arrays.asList("sub", "role"));
        
        // ok: java-coral-allowlist-authorizer
        Authorizer authorizer = new JwtAuthorizer(jwtSecret, requiredClaims);
        
        // Configure S3 service with secure authorizer
        S3Service s3Service = new S3Service();
        s3Service.setAuthorizer(authorizer);
        s3Service.handleRequest("GetObject", new Context("user456"));
    }

    public void good_case_3() {
        // Using OAuthAuthorizer for Lambda invocation
        String authServerUrl = "https://auth.example.com";
        Set<String> requiredScopes = new HashSet<>(Arrays.asList("lambda:invoke", "lambda:list"));
        
        // ok: java-coral-allowlist-authorizer
        OAuthAuthorizer authorizer = new OAuthAuthorizer(authServerUrl, requiredScopes);
        
        // Using secure authorizer for Lambda operations
        LambdaService lambdaService = new LambdaService();
        lambdaService.configureAuthorizer(authorizer);
        lambdaService.invokeFunction("myFunction", "{\"data\":\"value\"}", new Context("user789"));
    }

    public void good_case_4() {
        // Using PolicyBasedAuthorizer for SQS message operations
        PolicyProvider policyProvider = new PolicyProvider();
        
        // ok: java-coral-allowlist-authorizer
        Authorizer sqsAuthorizer = new PolicyBasedAuthorizer(policyProvider);
        
        // Configure message queue service with secure authorizer
        MessageQueueService queueService = new MessageQueueService();
        queueService.setAuthorizer(sqsAuthorizer);
        queueService.sendMessage("myQueue", "Hello world", new Context("user101"));
    }

    public void good_case_5() {
        // Using AllowlistAuthorizer ONLY for healthcheck operations
        Set<String> healthCheckOps = new HashSet<>();
        healthCheckOps.add("HealthCheck");
        
        // ok: java-coral-allowlist-authorizer
        AllowlistAuthorizer healthCheckAuthorizer = new AllowlistAuthorizer(healthCheckOps);
        
        // Using allowlist authorizer only for healthcheck operations is acceptable
        HealthCheckService healthService = new HealthCheckService();
        healthService.setAuthorizer(healthCheckAuthorizer);
        
        // This is a health check operation, which is acceptable to use with AllowlistAuthorizer
        HealthCheckOperation healthOp = new HealthCheckOperation();
        healthService.performHealthCheck(healthOp, new Context("monitor"));
    }

    public void good_case_6() {
        // Using custom robust authorizer for EC2 instance management
        PermissionService permissionService = new PermissionService();
        AuditLogger auditLogger = new AuditLogger();
        
        // ok: java-coral-allowlist-authorizer
        Authorizer ec2Authorizer = new CustomRobustAuthorizer(permissionService, auditLogger);
        
        // Configure EC2 service with secure authorizer
        EC2Service ec2Service = new EC2Service();
        ec2Service.setAuthorizer(ec2Authorizer);
        ec2Service.performOperation("StartInstances", "i-1234567890abcdef0", new Context("admin"));
    }

    public void good_case_7() {
        // Using different authorizers for different operation types
        Set<String> healthCheckOps = new HashSet<>();
        healthCheckOps.add("HealthCheck");
        
        // Health check operations use AllowlistAuthorizer (acceptable)
        AllowlistAuthorizer healthAuthorizer = new AllowlistAuthorizer(healthCheckOps);
        
        // ok: java-coral-allowlist-authorizer
        // Non-health check operations use robust authorizer
        Authorizer robustAuthorizer = new RoleBasedAuthorizer(getRolePermissionsMap());
        
        // Service uses appropriate authorizer based on operation type
        MultiAuthorizerService service = new MultiAuthorizerService();
        service.setHealthCheckAuthorizer(healthAuthorizer);
        service.setStandardAuthorizer(robustAuthorizer);
        
        // Process both types of operations with appropriate authorizers
        service.processHealthCheck(new HealthCheckOperation(), new Context("monitor"));
        service.processStandardOperation("UpdateUser", new Context("admin"));
    }

    public void good_case_8() {
        // Using JwtAuthorizer with role validation for payment operations
        String jwtSecret = getSecretFromVault("jwt-signing-key");
        Set<String> requiredClaims = new HashSet<>(Arrays.asList("sub", "role", "permissions"));
        
        // ok: java-coral-allowlist-authorizer
        JwtAuthorizer paymentAuthorizer = new JwtAuthorizer(jwtSecret, requiredClaims);
        paymentAuthorizer.setRoleValidator(new StrictRoleValidator());
        
        // Using secure authorizer for payment processing
        PaymentService paymentService = new PaymentService();
        paymentService.setAuthorizer(paymentAuthorizer);
        paymentService.processPayment("12345", 100.00, "USD", new Context("merchant"));
    }

    public void good_case_9() {
        // Using OAuthAuthorizer with scope validation for CloudWatch metrics access
        String authServerUrl = "https://auth.example.com";
        Set<String> requiredScopes = new HashSet<>(Arrays.asList("metrics:read", "metrics:write"));
        
        // ok: java-coral-allowlist-authorizer
        OAuthAuthorizer metricsAuthorizer = new OAuthAuthorizer(authServerUrl, requiredScopes);
        metricsAuthorizer.setScopeValidator(new CloudWatchScopeValidator());
        
        // Configure metrics service with secure authorizer
        MetricsService metricsService = new MetricsService();
        metricsService.setAuthorizer(metricsAuthorizer);
        metricsService.getMetricData("CPU_Utilization", "1h", new Context("monitor"));
    }

    public void good_case_10() {
        // Using combination of authorizers for different security levels
        AuthorizationChain authChain = new AuthorizationChain();
        
        // Add multiple robust authorizers to the chain
        // ok: java-coral-allowlist-authorizer
        authChain.addAuthorizer(new JwtAuthorizer(getJwtSecret(), getRequiredClaims()));
        authChain.addAuthorizer(new PolicyBasedAuthorizer(new PolicyProvider()));
        authChain.addAuthorizer(new RoleBasedAuthorizer(getRolePermissionsMap()));
        
        // Using secure authorization chain for data access
        DataAccessService dataService = new DataAccessService();
        dataService.setAuthorizer(authChain);
        dataService.performOperation("WriteData", "sensitive-data", new Context("admin"));
    }

    public void good_case_11() {
        // Using custom API Gateway authorizer with request validation
        RequestValidator validator = new RequestValidator();
        TokenVerifier tokenVerifier = new TokenVerifier();
        
        // ok: java-coral-allowlist-authorizer
        Authorizer apiAuthorizer = new ApiGatewayCustomAuthorizer(validator, tokenVerifier);
        
        // Configure API Gateway service with secure authorizer
        ApiGatewayService apiService = new ApiGatewayService();
        apiService.setAuthorizer(apiAuthorizer);
        apiService.handleRequest("POST", "/users", "{\"name\":\"Alice\"}", new Context("client"));
    }

    public void good_case_12() {
        // Using database-specific authorizer with permission checks
        DatabasePermissionProvider permProvider = new DatabasePermissionProvider();
        AuditLogger auditLogger = new AuditLogger();
        
        // ok: java-coral-allowlist-authorizer
        Authorizer dbAuthorizer = new DatabaseAuthorizer(permProvider, auditLogger);
        
        // Using secure authorizer for database schema management
        DatabaseSchemaService schemaService = new DatabaseSchemaService();
        schemaService.setAuthorizer(dbAuthorizer);
        schemaService.executeOperation("CreateTable", "CREATE TABLE users (id INT, name VARCHAR(255))", new Context("dba"));
    }

    public void good_case_13() {
        // Using file system authorizer with path validation
        FileSystemPermissionChecker permChecker = new FileSystemPermissionChecker();
        PathValidator pathValidator = new PathValidator();
        
        // ok: java-coral-allowlist-authorizer
        Authorizer fileAuthorizer = new FileSystemAuthorizer(permChecker, pathValidator);
        
        // Configure file service with secure authorizer
        FileService fileService = new FileService();
        fileService.setAuthorizer(fileAuthorizer);
        fileService.performOperation("WriteFile", "/etc/passwd", "new content", new Context("root"));
    }

    public void good_case_14() {
        // Using environment-specific authorizer with audit logging
        String env = System.getProperty("environment");
        AuditLogger auditLogger = new AuditLogger();
        
        // ok: java-coral-allowlist-authorizer
        Authorizer configAuthorizer;
        if ("production".equals(env)) {
            configAuthorizer = new StrictProductionAuthorizer(auditLogger);
        } else {
            configAuthorizer = new DevelopmentAuthorizer(auditLogger);
        }
        
        // Using appropriate authorizer for configuration service
        ConfigService configService = new ConfigService();
        configService.setAuthorizer(configAuthorizer);
        configService.updateConfig("system.settings", "{\"debug\":true}", new Context("sysadmin"));
    }

    public void good_case_15() {
        // Using specialized authentication authorizer with MFA validation
        MfaValidator mfaValidator = new MfaValidator();
        PasswordPolicyEnforcer policyEnforcer = new PasswordPolicyEnforcer();
        
        // ok: java-coral-allowlist-authorizer
        Authorizer authServiceAuthorizer = new AuthenticationServiceAuthorizer(mfaValidator, policyEnforcer);
        
        // Using secure authorizer for authentication service
        AuthenticationService authService = new AuthenticationService();
        authService.setAuthorizer(authServiceAuthorizer);
        authService.processRequest("ResetPassword", "user@example.com", new Context("support"));
    }

    // Helper methods and classes to support the examples
    private boolean checkUserRole(String role) {
        return true; // Simplified for example
    }
    
    private Map<String, Set<String>> getRolePermissionsMap() {
        Map<String, Set<String>> rolePermissions = new HashMap<>();
        rolePermissions.put("admin", new HashSet<>(Arrays.asList("ReadData", "WriteData", "DeleteData")));
        rolePermissions.put("user", new HashSet<>(Arrays.asList("ReadData")));
        return rolePermissions;
    }
    
    private String getSecretFromVault(String secretName) {
        return "secret-value"; // Simplified for example
    }
    
    private String getJwtSecret() {
        return System.getenv("JWT_SECRET");
    }
    
    private Set<String> getRequiredClaims() {
        return new HashSet<>(Arrays.asList("sub", "role", "exp"));
    }
    
    // Mock service classes for examples
    class DynamoDBService {
        private Authorizer authorizer;
        public void setAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void processUserRequest(String operation, Context context) { /* Implementation */ }
    }
    
    class S3Service {
        private Authorizer authorizer;
        public void setAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void handleRequest(String operation, Context context) { /* Implementation */ }
    }
    
    class LambdaService {
        private Authorizer authorizer;
        public void configureAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void invokeFunction(String function, String payload, Context context) { /* Implementation */ }
    }
    
    class MessageQueueService {
        private Authorizer authorizer;
        public void setAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void sendMessage(String queue, String message, Context context) { /* Implementation */ }
    }
    
    class NotificationService {
        private Authorizer authorizer;
        public void setAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void publishMessage(String topic, String message, Context context) { /* Implementation */ }
    }
    
    class EC2Service {
        private Authorizer authorizer;
        public void setAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void performOperation(String operation, String instanceId, Context context) { /* Implementation */ }
    }
    
    class UserManagementService {
        private Authorizer authorizer;
        public void setAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void executeOperation(String operation, String data, Context context) { /* Implementation */ }
    }
    
    class ConfigurationService {
        public Set<String> getAllowedOperations(String serviceName) {
            return new HashSet<>(Arrays.asList("ReadConfig", "WriteConfig", "DeleteConfig"));
        }
    }
    
    class PaymentService {
        private Authorizer authorizer;
        public void setAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void processPayment(String id, double amount, String currency, Context context) { /* Implementation */ }
    }
    
    class MetricsService {
        private Authorizer authorizer;
        public void setAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void getMetricData(String metric, String timeRange, Context context) { /* Implementation */ }
    }
    
    class DataAccessService {
        private Authorizer authorizer;
        public void setAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void performOperation(String operation, String data, Context context) { /* Implementation */ }
    }
    
    class ApiGatewayService {
        private Authorizer authorizer;
        public void setAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void handleRequest(String method, String path, String body, Context context) { /* Implementation */ }
    }
    
    class DatabaseSchemaService {
        private Authorizer authorizer;
        public void setAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void executeOperation(String operation, String sql, Context context) { /* Implementation */ }
    }
    
    class FileService {
        private Authorizer authorizer;
        public void setAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void performOperation(String operation, String path, String content, Context context) { /* Implementation */ }
    }
    
    class ConfigService {
        private Authorizer authorizer;
        public void setAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void updateConfig(String key, String value, Context context) { /* Implementation */ }
    }
    
    class AuthenticationService {
        private Authorizer authorizer;
        public void setAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void processRequest(String operation, String user, Context context) { /* Implementation */ }
    }
    
    class HealthCheckService {
        private Authorizer authorizer;
        public void setAuthorizer(Authorizer authorizer) { this.authorizer = authorizer; }
        public void performHealthCheck(HealthCheckOperation operation, Context context) { /* Implementation */ }
    }
    
    class MultiAuthorizerService {
        private Authorizer healthCheckAuthorizer;
        private Authorizer standardAuthorizer;
        
        public void setHealthCheckAuthorizer(Authorizer authorizer) { this.healthCheckAuthorizer = authorizer; }
        public void setStandardAuthorizer(Authorizer authorizer) { this.standardAuthorizer = authorizer; }
        
        public void processHealthCheck(HealthCheckOperation operation, Context context) { /* Implementation */ }
        public void processStandardOperation(String operation, Context context) { /* Implementation */ }
    }
    
    // Mock custom authorizer implementations
    class CustomRobustAuthorizer implements Authorizer {
        private PermissionService permissionService;
        private AuditLogger auditLogger;
        
        public CustomRobustAuthorizer(PermissionService permissionService, AuditLogger auditLogger) {
            this.permissionService = permissionService;
            this.auditLogger = auditLogger;
        }
        
        @Override
        public boolean authorize(Operation operation, Context context) {
            return false; // Simplified for example
        }
    }
    
    class AuthorizationChain implements Authorizer {
        private List<Authorizer> authorizers = new ArrayList<>();
        
        public void addAuthorizer(Authorizer authorizer) {
            authorizers.add(authorizer);
        }
        
        @Override
        public boolean authorize(Operation operation, Context context) {
            return false; // Simplified for example
        }
    }
    
    class ApiGatewayCustomAuthorizer implements Authorizer {
        private RequestValidator validator;
        private TokenVerifier tokenVerifier;
        
        public ApiGatewayCustomAuthorizer(RequestValidator validator, TokenVerifier tokenVerifier) {
            this.validator = validator;
            this.tokenVerifier = tokenVerifier;
        }
        
        @Override
        public boolean authorize(Operation operation, Context context) {
            return false; // Simplified for example
        }
    }
    
    class DatabaseAuthorizer implements Authorizer {
        private DatabasePermissionProvider permProvider;
        private AuditLogger auditLogger;
        
        public DatabaseAuthorizer(DatabasePermissionProvider permProvider, AuditLogger auditLogger) {
            this.permProvider = permProvider;
            this.auditLogger = auditLogger;
        }
        
        @Override
        public boolean authorize(Operation operation, Context context) {
            return false; // Simplified for example
        }
    }
    
    class FileSystemAuthorizer implements Authorizer {
        private FileSystemPermissionChecker permChecker;
        private PathValidator pathValidator;
        
        public FileSystemAuthorizer(FileSystemPermissionChecker permChecker, PathValidator pathValidator) {
            this.permChecker = permChecker;
            this.pathValidator = pathValidator;
        }
        
        @Override
        public boolean authorize(Operation operation, Context context) {
            return false; // Simplified for example
        }
    }
    
    class StrictProductionAuthorizer implements Authorizer {
        private AuditLogger auditLogger;
        
        public StrictProductionAuthorizer(AuditLogger auditLogger) {
            this.auditLogger = auditLogger;
        }
        
        @Override
        public boolean authorize(Operation operation, Context context) {
            return false; // Simplified for example
        }
    }
    
    class DevelopmentAuthorizer implements Authorizer {
        private AuditLogger auditLogger;
        
        public DevelopmentAuthorizer(AuditLogger auditLogger) {
            this.auditLogger = auditLogger;
        }
        
        @Override
        public boolean authorize(Operation operation, Context context) {
            return false; // Simplified for example
        }
    }
    
    class AuthenticationServiceAuthorizer implements Authorizer {
        private MfaValidator mfaValidator;
        private PasswordPolicyEnforcer policyEnforcer;
        
        public AuthenticationServiceAuthorizer(MfaValidator mfaValidator, PasswordPolicyEnforcer policyEnforcer) {
            this.mfaValidator = mfaValidator;
            this.policyEnforcer = policyEnforcer;
        }
        
        @Override
        public boolean authorize(Operation operation, Context context) {
            return false; // Simplified for example
        }
    }
    
    // Mock supporting classes
    class PolicyProvider {}
    class PermissionService {}
    class AuditLogger {}
    class StrictRoleValidator {}
    class CloudWatchScopeValidator {}
    class RequestValidator {}
    class TokenVerifier {}
    class DatabasePermissionProvider {}
    class FileSystemPermissionChecker {}
    class PathValidator {}
    class MfaValidator {}
    class PasswordPolicyEnforcer {}
}
// {/fact}