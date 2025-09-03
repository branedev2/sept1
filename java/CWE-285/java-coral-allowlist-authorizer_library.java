import com.amazonaws.services.coral.model.*;
import com.amazonaws.services.coral.authorizer.*;
import com.amazonaws.services.coral.*;
import com.amazonaws.services.coral.client.*;
import com.amazonaws.services.coral.filter.*;
import com.amazonaws.auth.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.dynamodb.*;
import com.amazonaws.services.lambda.*;
import com.amazonaws.services.ec2.*;
import com.amazonaws.services.sqs.*;
import com.amazonaws.services.sns.*;
import com.amazonaws.services.rds.*;
import com.amazonaws.services.cloudwatch.*;
import com.amazonaws.services.elasticache.*;
import com.amazonaws.services.elasticbeanstalk.*;
import com.amazonaws.services.elasticloadbalancing.*;
import com.amazonaws.services.elasticmapreduce.*;
import com.amazonaws.services.glacier.*;
import com.amazonaws.services.kinesis.*;
import com.amazonaws.services.kms.*;
import com.amazonaws.services.redshift.*;
import com.amazonaws.services.route53.*;
import com.amazonaws.services.simpleemail.*;
import com.amazonaws.services.simpledb.*;
import com.amazonaws.services.simpleworkflow.*;
import com.amazonaws.services.storagegateway.*;
import com.amazonaws.services.support.*;
import com.amazonaws.services.identitymanagement.*;
import com.amazonaws.services.cloudformation.*;
import com.amazonaws.services.cloudfront.*;
import com.amazonaws.services.cloudsearch.*;
import com.amazonaws.services.cloudtrail.*;
import com.amazonaws.services.codecommit.*;
import com.amazonaws.services.codedeploy.*;
import com.amazonaws.services.directconnect.*;
import java.util.*;
import javax.servlet.http.*;
import org.springframework.web.bind.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import org.springframework.stereotype.*;
import org.springframework.web.servlet.*;
import org.apache.http.*;
import org.apache.http.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.apache.http.util.*;
import java.io.*;
import java.net.*;

// Security Issue: Using AllowlistAuthorizer with non-healthcheck operations can lead to insufficient security controls

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    String operationName = request.getParameter("operation");
    
    CoralService coralService = new CoralServiceBuilder().build();
    
    // ruleid: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("GetUserProfile");
    authorizer.addAllowedOperation("UpdateUserProfile");
    
    coralService.setAuthorizer(authorizer);
    coralService.performOperation(operationName);
}

public void bad_case_2(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    
    AmazonS3Client s3Client = new AmazonS3Client();
    CoralServiceWrapper wrapper = new CoralServiceWrapper(s3Client);
    
    // ruleid: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("GetObject");
    authorizer.addAllowedOperation("PutObject");
    authorizer.addAllowedOperation("DeleteObject");
    
    wrapper.setAuthorizer(authorizer);
    wrapper.executeOperation("GetObject", userId);
}

public void bad_case_3(@RequestBody Map<String, String> requestBody) {
    String operation = requestBody.get("operation");
    
    AmazonDynamoDBClient dynamoClient = new AmazonDynamoDBClient();
    CoralDynamoDBAdapter adapter = new CoralDynamoDBAdapter(dynamoClient);
    
    // ruleid: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("Query");
    authorizer.addAllowedOperation("Scan");
    authorizer.addAllowedOperation("PutItem");
    
    adapter.setAuthorizer(authorizer);
    adapter.executeOperation(operation);
}

public void bad_case_4(@RequestParam String action) {
    AmazonLambdaClient lambdaClient = new AmazonLambdaClient();
    CoralLambdaService lambdaService = new CoralLambdaService(lambdaClient);
    
    // ruleid: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("InvokeFunction");
    authorizer.addAllowedOperation("CreateFunction");
    authorizer.addAllowedOperation("DeleteFunction");
    
    lambdaService.setAuthorizer(authorizer);
    lambdaService.performAction(action);
}

public void bad_case_5(HttpServletRequest request) {
    String operation = request.getParameter("op");
    
    AmazonEC2Client ec2Client = new AmazonEC2Client();
    CoralEC2Service ec2Service = new CoralEC2Service(ec2Client);
    
    // ruleid: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("StartInstances");
    authorizer.addAllowedOperation("StopInstances");
    authorizer.addAllowedOperation("TerminateInstances");
    
    ec2Service.setAuthorizer(authorizer);
    ec2Service.executeOperation(operation);
}

public void bad_case_6(@RequestHeader("X-Operation") String operation) {
    AmazonSQSClient sqsClient = new AmazonSQSClient();
    CoralSQSAdapter sqsAdapter = new CoralSQSAdapter(sqsClient);
    
    // ruleid: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("SendMessage");
    authorizer.addAllowedOperation("ReceiveMessage");
    authorizer.addAllowedOperation("DeleteMessage");
    
    sqsAdapter.setAuthorizer(authorizer);
    sqsAdapter.processOperation(operation);
}

public void bad_case_7(HttpServletRequest request) {
    String action = request.getParameter("action");
    
    AmazonSNSClient snsClient = new AmazonSNSClient();
    CoralSNSService snsService = new CoralSNSService(snsClient);
    
    // ruleid: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("Publish");
    authorizer.addAllowedOperation("CreateTopic");
    authorizer.addAllowedOperation("DeleteTopic");
    
    snsService.setAuthorizer(authorizer);
    snsService.executeAction(action);
}

public void bad_case_8(@RequestBody OperationRequest operationRequest) {
    String operation = operationRequest.getOperationName();
    
    AmazonRDSClient rdsClient = new AmazonRDSClient();
    CoralRDSService rdsService = new CoralRDSService(rdsClient);
    
    // ruleid: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("CreateDBInstance");
    authorizer.addAllowedOperation("DeleteDBInstance");
    authorizer.addAllowedOperation("ModifyDBInstance");
    
    rdsService.setAuthorizer(authorizer);
    rdsService.performOperation(operation);
}

public void bad_case_9(HttpServletRequest request) {
    String operation = request.getParameter("operation");
    
    AmazonCloudWatchClient cloudWatchClient = new AmazonCloudWatchClient();
    CoralCloudWatchAdapter adapter = new CoralCloudWatchAdapter(cloudWatchClient);
    
    // ruleid: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("PutMetricData");
    authorizer.addAllowedOperation("GetMetricStatistics");
    authorizer.addAllowedOperation("PutMetricAlarm");
    
    adapter.setAuthorizer(authorizer);
    adapter.executeOperation(operation);
}

public void bad_case_10(@RequestParam String action) {
    AmazonElastiCacheClient elastiCacheClient = new AmazonElastiCacheClient();
    CoralElastiCacheService service = new CoralElastiCacheService(elastiCacheClient);
    
    // ruleid: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("CreateCacheCluster");
    authorizer.addAllowedOperation("DeleteCacheCluster");
    authorizer.addAllowedOperation("ModifyCacheCluster");
    
    service.setAuthorizer(authorizer);
    service.performAction(action);
}

public void bad_case_11(HttpServletRequest request) {
    String operation = request.getParameter("op");
    
    AmazonElasticBeanstalkClient beanstalkClient = new AmazonElasticBeanstalkClient();
    CoralBeanstalkService service = new CoralBeanstalkService(beanstalkClient);
    
    // ruleid: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("CreateEnvironment");
    authorizer.addAllowedOperation("UpdateEnvironment");
    authorizer.addAllowedOperation("TerminateEnvironment");
    
    service.setAuthorizer(authorizer);
    service.executeOperation(operation);
}

public void bad_case_12(@RequestBody Map<String, String> requestBody) {
    String action = requestBody.get("action");
    
    AmazonElasticLoadBalancingClient elbClient = new AmazonElasticLoadBalancingClient();
    CoralELBService elbService = new CoralELBService(elbClient);
    
    // ruleid: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("CreateLoadBalancer");
    authorizer.addAllowedOperation("DeleteLoadBalancer");
    authorizer.addAllowedOperation("ConfigureHealthCheck");
    
    elbService.setAuthorizer(authorizer);
    elbService.performAction(action);
}

public void bad_case_13(HttpServletRequest request) {
    String operation = request.getParameter("operation");
    
    AmazonElasticMapReduceClient emrClient = new AmazonElasticMapReduceClient();
    CoralEMRService emrService = new CoralEMRService(emrClient);
    
    // ruleid: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("RunJobFlow");
    authorizer.addAllowedOperation("TerminateJobFlows");
    authorizer.addAllowedOperation("AddJobFlowSteps");
    
    emrService.setAuthorizer(authorizer);
    emrService.executeOperation(operation);
}

public void bad_case_14(@RequestHeader("X-Action") String action) {
    AmazonGlacierClient glacierClient = new AmazonGlacierClient();
    CoralGlacierService glacierService = new CoralGlacierService(glacierClient);
    
    // ruleid: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("CreateVault");
    authorizer.addAllowedOperation("DeleteVault");
    authorizer.addAllowedOperation("UploadArchive");
    
    glacierService.setAuthorizer(authorizer);
    glacierService.performAction(action);
}

public void bad_case_15(HttpServletRequest request) {
    String operation = request.getParameter("op");
    
    AmazonKinesisClient kinesisClient = new AmazonKinesisClient();
    CoralKinesisService kinesisService = new CoralKinesisService(kinesisClient);
    
    // ruleid: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("CreateStream");
    authorizer.addAllowedOperation("DeleteStream");
    authorizer.addAllowedOperation("PutRecord");
    
    kinesisService.setAuthorizer(authorizer);
    kinesisService.executeOperation(operation);
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    String operationName = request.getParameter("operation");
    
    CoralService coralService = new CoralServiceBuilder().build();
    
    // ok: java-coral-allowlist-authorizer
    RoleBasedAuthorizer authorizer = new RoleBasedAuthorizer();
    authorizer.addRolePermission("admin", "GetUserProfile");
    authorizer.addRolePermission("admin", "UpdateUserProfile");
    
    coralService.setAuthorizer(authorizer);
    coralService.performOperation(operationName);
}

public void good_case_2(HttpServletRequest request) {
    String userId = request.getParameter("userId");
    
    AmazonS3Client s3Client = new AmazonS3Client();
    CoralServiceWrapper wrapper = new CoralServiceWrapper(s3Client);
    
    // ok: java-coral-allowlist-authorizer
    OAuthAuthorizer authorizer = new OAuthAuthorizer();
    authorizer.setTokenValidator(new JWTTokenValidator());
    authorizer.setPermissionChecker(new S3PermissionChecker());
    
    wrapper.setAuthorizer(authorizer);
    wrapper.executeOperation("GetObject", userId);
}

public void good_case_3(@RequestBody Map<String, String> requestBody) {
    String operation = requestBody.get("operation");
    
    AmazonDynamoDBClient dynamoClient = new AmazonDynamoDBClient();
    CoralDynamoDBAdapter adapter = new CoralDynamoDBAdapter(dynamoClient);
    
    // ok: java-coral-allowlist-authorizer
    PolicyBasedAuthorizer authorizer = new PolicyBasedAuthorizer();
    authorizer.loadPolicyFromFile("dynamodb-access-policy.json");
    
    adapter.setAuthorizer(authorizer);
    adapter.executeOperation(operation);
}

public void good_case_4(@RequestParam String action) {
    AmazonLambdaClient lambdaClient = new AmazonLambdaClient();
    CoralLambdaService lambdaService = new CoralLambdaService(lambdaClient);
    
    // ok: java-coral-allowlist-authorizer
    IAMRoleAuthorizer authorizer = new IAMRoleAuthorizer();
    authorizer.setRoleArn("arn:aws:iam::123456789012:role/lambda-execution-role");
    
    lambdaService.setAuthorizer(authorizer);
    lambdaService.performAction(action);
}

public void good_case_5(HttpServletRequest request) {
    String operation = request.getParameter("op");
    
    AmazonEC2Client ec2Client = new AmazonEC2Client();
    CoralEC2Service ec2Service = new CoralEC2Service(ec2Client);
    
    // ok: java-coral-allowlist-authorizer
    ResourceBasedAuthorizer authorizer = new ResourceBasedAuthorizer();
    authorizer.addResourcePermission("instance-i-12345", "StartInstances", "admin");
    authorizer.addResourcePermission("instance-i-12345", "StopInstances", "operator");
    
    ec2Service.setAuthorizer(authorizer);
    ec2Service.executeOperation(operation);
}

public void good_case_6(@RequestHeader("X-Operation") String operation) {
    AmazonSQSClient sqsClient = new AmazonSQSClient();
    CoralSQSAdapter sqsAdapter = new CoralSQSAdapter(sqsClient);
    
    // ok: java-coral-allowlist-authorizer
    ScopeBasedAuthorizer authorizer = new ScopeBasedAuthorizer();
    authorizer.addScope("sqs:send", "SendMessage");
    authorizer.addScope("sqs:receive", "ReceiveMessage");
    authorizer.addScope("sqs:admin", "DeleteMessage");
    
    sqsAdapter.setAuthorizer(authorizer);
    sqsAdapter.processOperation(operation);
}

public void good_case_7(HttpServletRequest request) {
    String action = request.getParameter("action");
    
    AmazonSNSClient snsClient = new AmazonSNSClient();
    CoralSNSService snsService = new CoralSNSService(snsClient);
    
    // ok: java-coral-allowlist-authorizer
    MultiFactorAuthorizer authorizer = new MultiFactorAuthorizer();
    authorizer.setTokenValidator(new MFATokenValidator());
    authorizer.setPermissionChecker(new SNSPermissionChecker());
    
    snsService.setAuthorizer(authorizer);
    snsService.executeAction(action);
}

public void good_case_8(@RequestBody OperationRequest operationRequest) {
    String operation = operationRequest.getOperationName();
    
    AmazonRDSClient rdsClient = new AmazonRDSClient();
    CoralRDSService rdsService = new CoralRDSService(rdsClient);
    
    // ok: java-coral-allowlist-authorizer
    DatabaseRoleAuthorizer authorizer = new DatabaseRoleAuthorizer();
    authorizer.addRolePermission("db-admin", "CreateDBInstance");
    authorizer.addRolePermission("db-admin", "DeleteDBInstance");
    authorizer.addRolePermission("db-operator", "ModifyDBInstance");
    
    rdsService.setAuthorizer(authorizer);
    rdsService.performOperation(operation);
}

public void good_case_9(HttpServletRequest request) {
    String operation = request.getParameter("operation");
    
    AmazonCloudWatchClient cloudWatchClient = new AmazonCloudWatchClient();
    CoralCloudWatchAdapter adapter = new CoralCloudWatchAdapter(cloudWatchClient);
    
    // ok: java-coral-allowlist-authorizer
    ContextAwareAuthorizer authorizer = new ContextAwareAuthorizer();
    authorizer.setContextProvider(new RequestContextProvider());
    authorizer.setPolicyEnforcer(new CloudWatchPolicyEnforcer());
    
    adapter.setAuthorizer(authorizer);
    adapter.executeOperation(operation);
}

public void good_case_10(@RequestParam String action) {
    AmazonElastiCacheClient elastiCacheClient = new AmazonElastiCacheClient();
    CoralElastiCacheService service = new CoralElastiCacheService(elastiCacheClient);
    
    // ok: java-coral-allowlist-authorizer
    AttributeBasedAuthorizer authorizer = new AttributeBasedAuthorizer();
    authorizer.addAttributeRule("department", "IT", "CreateCacheCluster");
    authorizer.addAttributeRule("role", "CacheAdmin", "DeleteCacheCluster");
    
    service.setAuthorizer(authorizer);
    service.performAction(action);
}

public void good_case_11(HttpServletRequest request) {
    String operation = request.getParameter("op");
    
    AmazonElasticBeanstalkClient beanstalkClient = new AmazonElasticBeanstalkClient();
    CoralBeanstalkService service = new CoralBeanstalkService(beanstalkClient);
    
    // ok: java-coral-allowlist-authorizer
    JWTAuthorizer authorizer = new JWTAuthorizer();
    authorizer.setJwtSecret(System.getenv("JWT_SECRET"));
    authorizer.setPermissionMapper(new BeanstalkPermissionMapper());
    
    service.setAuthorizer(authorizer);
    service.executeOperation(operation);
}

public void good_case_12(@RequestBody Map<String, String> requestBody) {
    String action = requestBody.get("action");
    
    AmazonElasticLoadBalancingClient elbClient = new AmazonElasticLoadBalancingClient();
    CoralELBService elbService = new CoralELBService(elbClient);
    
    // ok: java-coral-allowlist-authorizer
    GroupBasedAuthorizer authorizer = new GroupBasedAuthorizer();
    authorizer.addGroupPermission("network-admins", "CreateLoadBalancer");
    authorizer.addGroupPermission("network-admins", "DeleteLoadBalancer");
    authorizer.addGroupPermission("operators", "ConfigureHealthCheck");
    
    elbService.setAuthorizer(authorizer);
    elbService.performAction(action);
}

public void good_case_13(HttpServletRequest request) {
    String operation = request.getParameter("operation");
    
    AmazonElasticMapReduceClient emrClient = new AmazonElasticMapReduceClient();
    CoralEMRService emrService = new CoralEMRService(emrClient);
    
    // ok: java-coral-allowlist-authorizer
    LDAPAuthorizer authorizer = new LDAPAuthorizer();
    authorizer.setLdapServer("ldap://company.com:389");
    authorizer.setBindDN("cn=admin,dc=company,dc=com");
    authorizer.setBindPassword(System.getenv("LDAP_PASSWORD"));
    
    emrService.setAuthorizer(authorizer);
    emrService.executeOperation(operation);
}

public void good_case_14(@RequestHeader("X-Action") String action) {
    AmazonGlacierClient glacierClient = new AmazonGlacierClient();
    CoralGlacierService glacierService = new CoralGlacierService(glacierClient);
    
    // ok: java-coral-allowlist-authorizer
    OAuth2Authorizer authorizer = new OAuth2Authorizer();
    authorizer.setAuthServer("https://auth.company.com");
    authorizer.setClientId(System.getenv("OAUTH_CLIENT_ID"));
    authorizer.setClientSecret(System.getenv("OAUTH_CLIENT_SECRET"));
    
    glacierService.setAuthorizer(authorizer);
    glacierService.performAction(action);
}

public void good_case_15(HttpServletRequest request) {
    String operation = request.getParameter("op");
    
    AmazonKinesisClient kinesisClient = new AmazonKinesisClient();
    CoralKinesisService kinesisService = new CoralKinesisService(kinesisClient);
    
    // ok: java-coral-allowlist-authorizer
    AllowlistAuthorizer authorizer = new AllowlistAuthorizer();
    authorizer.addAllowedOperation("DescribeStream");
    authorizer.addAllowedOperation("HealthCheck");
    
    // This is safe because it only allows health check operations
    kinesisService.setHealthCheckAuthorizer(authorizer);
    kinesisService.executeHealthCheck(operation);
}