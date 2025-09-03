import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClientBuilder;
import com.amazonaws.services.identitymanagement.model.*;
import org.json.JSONObject;
import org.json.JSONArray;
import java.util.Map;
import java.util.HashMap;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import com.amazonaws.auth.policy.Policy;
import com.amazonaws.auth.policy.Statement;
import com.amazonaws.auth.policy.Principal;
import com.amazonaws.auth.policy.Resource;
import com.amazonaws.auth.policy.actions.S3Actions;
import com.amazonaws.auth.policy.conditions.StringCondition;
import com.amazonaws.auth.policy.conditions.StringCondition.StringComparisonType;

@RestController
public class IAMPolicyExamples {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=aws-iam-error-prone-policy@v1.0 defects=1}
    @RequestMapping(value = "/bad1", method = RequestMethod.GET)
    public void bad_case_1(HttpServletRequest request) {
        String bucketName = request.getParameter("bucket");
        String userName = request.getParameter("user");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ruleid: java-handcrafted-policies
        String policyDocument = "{\"Version\": \"2012-10-17\", \"Statement\": [{" +
                                "\"Effect\": \"Allow\", " +
                                "\"Action\": \"s3:*\", " +
                                "\"Resource\": \"arn:aws:s3:::" + bucketName + "/*\"}]}";
        
        CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest()
                .withPolicyName("S3BucketAccessPolicy-" + userName)
                .withPolicyDocument(policyDocument);
        
        iamClient.createPolicy(createPolicyRequest);
    }
    
    @RequestMapping(value = "/bad2", method = RequestMethod.GET)
    public void bad_case_2(HttpServletRequest request) {
        String roleName = request.getParameter("role");
        String accountId = request.getParameter("account");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ruleid: java-handcrafted-policies
        StringBuilder policyBuilder = new StringBuilder();
        policyBuilder.append("{\"Version\": \"2012-10-17\", \"Statement\": [");
        policyBuilder.append("{\"Effect\": \"Allow\", \"Principal\": {\"AWS\": \"arn:aws:iam::");
        policyBuilder.append(accountId);
        policyBuilder.append(":root\"}, \"Action\": \"sts:AssumeRole\"}]}");
        
        CreateRoleRequest request = new CreateRoleRequest()
                .withRoleName(roleName)
                .withAssumeRolePolicyDocument(policyBuilder.toString());
        
        iamClient.createRole(request);
    }
    
    @RequestMapping(value = "/bad3", method = RequestMethod.POST)
    public void bad_case_3(HttpServletRequest request) {
        String userName = request.getParameter("username");
        String[] services = request.getParameterValues("services");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ruleid: java-handcrafted-policies
        String policyStart = "{\"Version\": \"2012-10-17\", \"Statement\": [";
        String policyEnd = "]}";
        StringBuilder statements = new StringBuilder();
        
        for (String service : services) {
            if (statements.length() > 0) {
                statements.append(",");
            }
            statements.append("{\"Effect\": \"Allow\", \"Action\": \"");
            statements.append(service);
            statements.append(":*\", \"Resource\": \"*\"}");
        }
        
        String policyDocument = policyStart + statements.toString() + policyEnd;
        
        CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest()
                .withPolicyName("ServiceAccess-" + userName)
                .withPolicyDocument(policyDocument);
        
        iamClient.createPolicy(createPolicyRequest);
    }
    
    @RequestMapping(value = "/bad4", method = RequestMethod.POST)
    public void bad_case_4(HttpServletRequest request) {
        String region = request.getParameter("region");
        String instanceId = request.getParameter("instanceId");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ruleid: java-handcrafted-policies
        String policy = String.format(
            "{\"Version\":\"2012-10-17\",\"Statement\":[{" +
            "\"Effect\":\"Allow\"," +
            "\"Action\":[\"ec2:StartInstances\",\"ec2:StopInstances\"]," +
            "\"Resource\":\"arn:aws:ec2:%s:*:instance/%s\"" +
            "}]}", region, instanceId);
        
        PutRolePolicyRequest putRolePolicyRequest = new PutRolePolicyRequest()
            .withRoleName("EC2InstanceManager")
            .withPolicyName("StartStopPolicy")
            .withPolicyDocument(policy);
        
        iamClient.putRolePolicy(putRolePolicyRequest);
    }
    
    @RequestMapping(value = "/bad5", method = RequestMethod.GET)
    public void bad_case_5(HttpServletRequest request) {
        String tableName = request.getParameter("table");
        String accountId = request.getParameter("account");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ruleid: java-handcrafted-policies
        String resource = "arn:aws:dynamodb:us-east-1:" + accountId + ":table/" + tableName;
        String policyDoc = "{\"Version\":\"2012-10-17\",\"Statement\":[{" +
                          "\"Effect\":\"Allow\"," +
                          "\"Action\":[\"dynamodb:GetItem\",\"dynamodb:PutItem\"]," +
                          "\"Resource\":\"" + resource + "\"" +
                          "}]}";
        
        CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest()
            .withPolicyName("DynamoDBTableAccess")
            .withPolicyDocument(policyDoc);
        
        iamClient.createPolicy(createPolicyRequest);
    }
    
    @RequestMapping(value = "/bad6", method = RequestMethod.POST)
    public void bad_case_6(HttpServletRequest request) {
        String userName = request.getParameter("username");
        String path = request.getParameter("path");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ruleid: java-handcrafted-policies
        String policyJson = "{"
            + "\"Version\": \"2012-10-17\","
            + "\"Statement\": ["
            + "  {"
            + "    \"Effect\": \"Allow\","
            + "    \"Action\": [\"s3:GetObject\"],"
            + "    \"Resource\": \"arn:aws:s3:::" + path + "/*\""
            + "  }"
            + "]"
            + "}";
        
        AttachUserPolicyRequest attachPolicyRequest = new AttachUserPolicyRequest()
            .withUserName(userName)
            .withPolicyArn(createPolicy(iamClient, "S3ReadAccess-" + userName, policyJson));
        
        iamClient.attachUserPolicy(attachPolicyRequest);
    }
    
    private String createPolicy(AmazonIdentityManagement iamClient, String policyName, String policyDocument) {
        CreatePolicyRequest request = new CreatePolicyRequest()
            .withPolicyName(policyName)
            .withPolicyDocument(policyDocument);
        CreatePolicyResult response = iamClient.createPolicy(request);
        return response.getPolicy().getArn();
    }
    
    @RequestMapping(value = "/bad7", method = RequestMethod.POST)
    public void bad_case_7(HttpServletRequest request) {
        String functionName = request.getParameter("function");
        String region = request.getParameter("region");
        String accountId = request.getParameter("account");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ruleid: java-handcrafted-policies
        String lambdaArn = "arn:aws:lambda:" + region + ":" + accountId + ":function:" + functionName;
        String policyDocument = "{\"Version\":\"2012-10-17\",\"Statement\":[{" +
                               "\"Effect\":\"Allow\"," +
                               "\"Action\":\"lambda:InvokeFunction\"," +
                               "\"Resource\":\"" + lambdaArn + "\"" +
                               "}]}";
        
        CreatePolicyRequest request = new CreatePolicyRequest()
            .withPolicyName("LambdaInvokePolicy-" + functionName)
            .withPolicyDocument(policyDocument);
        
        iamClient.createPolicy(request);
    }
    
    @RequestMapping(value = "/bad8", method = RequestMethod.POST)
    public void bad_case_8(HttpServletRequest request) {
        String userName = request.getParameter("username");
        String[] buckets = request.getParameterValues("buckets");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ruleid: java-handcrafted-policies
        JSONObject policyJson = new JSONObject();
        policyJson.put("Version", "2012-10-17");
        
        JSONArray statements = new JSONArray();
        JSONObject statement = new JSONObject();
        statement.put("Effect", "Allow");
        statement.put("Action", "s3:ListBucket");
        
        JSONArray resources = new JSONArray();
        for (String bucket : buckets) {
            resources.put("arn:aws:s3:::" + bucket);
        }
        statement.put("Resource", resources);
        
        statements.put(statement);
        policyJson.put("Statement", statements);
        
        CreatePolicyRequest request = new CreatePolicyRequest()
            .withPolicyName("S3ListPolicy-" + userName)
            .withPolicyDocument(policyJson.toString());
        
        iamClient.createPolicy(request);
    }
    
    @RequestMapping(value = "/bad9", method = RequestMethod.POST)
    public void bad_case_9(HttpServletRequest request) {
        String roleName = request.getParameter("role");
        String topicArn = request.getParameter("topicArn");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ruleid: java-handcrafted-policies
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{" +
                       "\"Effect\":\"Allow\"," +
                       "\"Action\":[\"sns:Publish\"]," +
                       "\"Resource\":\"" + topicArn + "\"" +
                       "}]}";
        
        PutRolePolicyRequest putRolePolicyRequest = new PutRolePolicyRequest()
            .withRoleName(roleName)
            .withPolicyName("SNSPublishPolicy")
            .withPolicyDocument(policy);
        
        iamClient.putRolePolicy(putRolePolicyRequest);
    }
    
    @RequestMapping(value = "/bad10", method = RequestMethod.POST)
    public void bad_case_10(HttpServletRequest request) {
        String queueUrl = request.getParameter("queueUrl");
        String accountId = request.getParameter("accountId");
        String queueName = queueUrl.substring(queueUrl.lastIndexOf('/') + 1);
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ruleid: java-handcrafted-policies
        String resource = "arn:aws:sqs:us-east-1:" + accountId + ":" + queueName;
        String policyDoc = "{\"Version\":\"2012-10-17\",\"Statement\":[{" +
                          "\"Effect\":\"Allow\"," +
                          "\"Action\":[\"sqs:SendMessage\",\"sqs:ReceiveMessage\"]," +
                          "\"Resource\":\"" + resource + "\"" +
                          "}]}";
        
        CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest()
            .withPolicyName("SQSAccessPolicy-" + queueName)
            .withPolicyDocument(policyDoc);
        
        iamClient.createPolicy(createPolicyRequest);
    }
    
    @RequestMapping(value = "/bad11", method = RequestMethod.POST)
    public void bad_case_11(HttpServletRequest request) {
        String userName = request.getParameter("username");
        String ipAddress = request.getParameter("ipAddress");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ruleid: java-handcrafted-policies
        String policyDoc = "{\"Version\":\"2012-10-17\",\"Statement\":[{" +
                          "\"Effect\":\"Allow\"," +
                          "\"Action\":\"ec2:*\"," +
                          "\"Resource\":\"*\"," +
                          "\"Condition\":{\"IpAddress\":{\"aws:SourceIp\":\"" + ipAddress + "\"}}}" +
                          "]}";
        
        CreatePolicyRequest request = new CreatePolicyRequest()
            .withPolicyName("EC2AccessFromIP-" + userName)
            .withPolicyDocument(policyDoc);
        
        iamClient.createPolicy(request);
    }
    
    @RequestMapping(value = "/bad12", method = RequestMethod.POST)
    public void bad_case_12(HttpServletRequest request) {
        String projectId = request.getParameter("projectId");
        String region = request.getParameter("region");
        String accountId = request.getParameter("accountId");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ruleid: java-handcrafted-policies
        String policyDoc = "{\"Version\":\"2012-10-17\",\"Statement\":[" +
                          "{\"Effect\":\"Allow\",\"Action\":[\"logs:CreateLogGroup\",\"logs:CreateLogStream\",\"logs:PutLogEvents\"]," +
                          "\"Resource\":\"arn:aws:logs:" + region + ":" + accountId + ":log-group:/aws/lambda/" + projectId + ":*\"}]}";
        
        CreatePolicyRequest request = new CreatePolicyRequest()
            .withPolicyName("CloudWatchLogsAccess-" + projectId)
            .withPolicyDocument(policyDoc);
        
        iamClient.createPolicy(request);
    }
    
    @RequestMapping(value = "/bad13", method = RequestMethod.POST)
    public void bad_case_13(HttpServletRequest request) {
        String userName = request.getParameter("username");
        String dbName = request.getParameter("dbName");
        String region = request.getParameter("region");
        String accountId = request.getParameter("accountId");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ruleid: java-handcrafted-policies
        String resource = "arn:aws:rds:" + region + ":" + accountId + ":db:" + dbName;
        String policyDoc = "{\"Version\":\"2012-10-17\",\"Statement\":[{" +
                          "\"Effect\":\"Allow\"," +
                          "\"Action\":[\"rds:CreateDBSnapshot\",\"rds:DeleteDBSnapshot\"]," +
                          "\"Resource\":\"" + resource + "\"" +
                          "}]}";
        
        CreatePolicyRequest request = new CreatePolicyRequest()
            .withPolicyName("RDSSnapshotPolicy-" + userName)
            .withPolicyDocument(policyDoc);
        
        iamClient.createPolicy(request);
    }
    
    @RequestMapping(value = "/bad14", method = RequestMethod.POST)
    public void bad_case_14(HttpServletRequest request) {
        String userName = request.getParameter("username");
        String[] actions = request.getParameterValues("actions");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ruleid: java-handcrafted-policies
        StringBuilder actionsJson = new StringBuilder("[");
        for (int i = 0; i < actions.length; i++) {
            if (i > 0) {
                actionsJson.append(",");
            }
            actionsJson.append("\"").append(actions[i]).append("\"");
        }
        actionsJson.append("]");
        
        String policyDoc = "{\"Version\":\"2012-10-17\",\"Statement\":[{" +
                          "\"Effect\":\"Allow\"," +
                          "\"Action\":" + actionsJson.toString() + "," +
                          "\"Resource\":\"*\"" +
                          "}]}";
        
        CreatePolicyRequest request = new CreatePolicyRequest()
            .withPolicyName("CustomActionsPolicy-" + userName)
            .withPolicyDocument(policyDoc);
        
        iamClient.createPolicy(request);
    }
    
    @RequestMapping(value = "/bad15", method = RequestMethod.POST)
    public void bad_case_15(HttpServletRequest request) {
        String roleName = request.getParameter("role");
        String principal = request.getParameter("principal");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ruleid: java-handcrafted-policies
        String trustPolicy = "{\"Version\":\"2012-10-17\",\"Statement\":[{" +
                            "\"Effect\":\"Allow\"," +
                            "\"Principal\":{\"Service\":\"" + principal + ".amazonaws.com\"}," +
                            "\"Action\":\"sts:AssumeRole\"" +
                            "}]}";
        
        CreateRoleRequest createRoleRequest = new CreateRoleRequest()
            .withRoleName(roleName)
            .withAssumeRolePolicyDocument(trustPolicy);
        
        iamClient.createRole(createRoleRequest);
    }
    
    // True Negative Examples (Secure Code)
    
    @RequestMapping(value = "/good1", method = RequestMethod.GET)
    public void good_case_1(HttpServletRequest request) {
        String bucketName = request.getParameter("bucket");
        String userName = request.getParameter("user");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ok: java-handcrafted-policies
        Policy policy = new Policy();
        Statement statement = new Statement(Statement.Effect.Allow)
            .withActions(S3Actions.ListObjects)
            .withResources(new Resource("arn:aws:s3:::" + bucketName + "/*"));
        
        policy.withStatements(statement);
        
        CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest()
            .withPolicyName("S3BucketAccessPolicy-" + userName)
            .withPolicyDocument(policy.toJson());
        
        iamClient.createPolicy(createPolicyRequest);
    }
    
    @RequestMapping(value = "/good2", method = RequestMethod.GET)
    public void good_case_2(HttpServletRequest request) {
        String roleName = request.getParameter("role");
        String accountId = request.getParameter("account");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ok: java-handcrafted-policies
        Policy trustPolicy = new Policy();
        Statement statement = new Statement(Statement.Effect.Allow)
            .withPrincipals(new Principal("AWS", "arn:aws:iam::" + accountId + ":root"))
            .withActions("sts:AssumeRole");
        
        trustPolicy.withStatements(statement);
        
        CreateRoleRequest createRoleRequest = new CreateRoleRequest()
            .withRoleName(roleName)
            .withAssumeRolePolicyDocument(trustPolicy.toJson());
        
        iamClient.createRole(createRoleRequest);
    }
    
    @RequestMapping(value = "/good3", method = RequestMethod.POST)
    public void good_case_3(HttpServletRequest request) {
        String userName = request.getParameter("username");
        String[] services = request.getParameterValues("services");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ok: java-handcrafted-policies
        Policy policy = new Policy();
        policy.setId("ServiceAccessPolicy");
        
        for (String service : services) {
            Statement statement = new Statement(Statement.Effect.Allow)
                .withActions(service + ":*")
                .withResources(new Resource("*"));
            
            policy.withStatements(statement);
        }
        
        CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest()
            .withPolicyName("ServiceAccess-" + userName)
            .withPolicyDocument(policy.toJson());
        
        iamClient.createPolicy(createPolicyRequest);
    }
    
    @RequestMapping(value = "/good4", method = RequestMethod.POST)
    public void good_case_4(HttpServletRequest request) {
        String region = request.getParameter("region");
        String instanceId = request.getParameter("instanceId");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ok: java-handcrafted-policies
        Policy policy = new Policy();
        Statement statement = new Statement(Statement.Effect.Allow)
            .withActions("ec2:StartInstances", "ec2:StopInstances")
            .withResources(new Resource("arn:aws:ec2:" + region + ":*:instance/" + instanceId));
        
        policy.withStatements(statement);
        
        PutRolePolicyRequest putRolePolicyRequest = new PutRolePolicyRequest()
            .withRoleName("EC2InstanceManager")
            .withPolicyName("StartStopPolicy")
            .withPolicyDocument(policy.toJson());
        
        iamClient.putRolePolicy(putRolePolicyRequest);
    }
    
    @RequestMapping(value = "/good5", method = RequestMethod.GET)
    public void good_case_5(HttpServletRequest request) {
        String tableName = request.getParameter("table");
        String accountId = request.getParameter("account");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ok: java-handcrafted-policies
        Policy policy = new Policy();
        Statement statement = new Statement(Statement.Effect.Allow)
            .withActions("dynamodb:GetItem", "dynamodb:PutItem")
            .withResources(new Resource("arn:aws:dynamodb:us-east-1:" + accountId + ":table/" + tableName));
        
        policy.withStatements(statement);
        
        CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest()
            .withPolicyName("DynamoDBTableAccess")
            .withPolicyDocument(policy.toJson());
        
        iamClient.createPolicy(createPolicyRequest);
    }
    
    @RequestMapping(value = "/good6", method = RequestMethod.POST)
    public void good_case_6(HttpServletRequest request) {
        String userName = request.getParameter("username");
        String path = request.getParameter("path");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ok: java-handcrafted-policies
        Policy policy = new Policy();
        Statement statement = new Statement(Statement.Effect.Allow)
            .withActions(S3Actions.GetObject)
            .withResources(new Resource("arn:aws:s3:::" + path + "/*"));
        
        policy.withStatements(statement);
        
        CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest()
            .withPolicyName("S3ReadAccess-" + userName)
            .withPolicyDocument(policy.toJson());
        
        CreatePolicyResult result = iamClient.createPolicy(createPolicyRequest);
        
        AttachUserPolicyRequest attachPolicyRequest = new AttachUserPolicyRequest()
            .withUserName(userName)
            .withPolicyArn(result.getPolicy().getArn());
        
        iamClient.attachUserPolicy(attachPolicyRequest);
    }
    
    @RequestMapping(value = "/good7", method = RequestMethod.POST)
    public void good_case_7(HttpServletRequest request) {
        String functionName = request.getParameter("function");
        String region = request.getParameter("region");
        String accountId = request.getParameter("account");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ok: java-handcrafted-policies
        String lambdaArn = "arn:aws:lambda:" + region + ":" + accountId + ":function:" + functionName;
        
        Policy policy = new Policy();
        Statement statement = new Statement(Statement.Effect.Allow)
            .withActions("lambda:InvokeFunction")
            .withResources(new Resource(lambdaArn));
        
        policy.withStatements(statement);
        
        CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest()
            .withPolicyName("LambdaInvokePolicy-" + functionName)
            .withPolicyDocument(policy.toJson());
        
        iamClient.createPolicy(createPolicyRequest);
    }
    
    @RequestMapping(value = "/good8", method = RequestMethod.POST)
    public void good_case_8(HttpServletRequest request) {
        String userName = request.getParameter("username");
        String[] buckets = request.getParameterValues("buckets");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ok: java-handcrafted-policies
        Policy policy = new Policy();
        Statement statement = new Statement(Statement.Effect.Allow)
            .withActions(S3Actions.ListBucket);
        
        Resource[] resources = new Resource[buckets.length];
        for (int i = 0; i < buckets.length; i++) {
            resources[i] = new Resource("arn:aws:s3:::" + buckets[i]);
        }
        statement.withResources(resources);
        
        policy.withStatements(statement);
        
        CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest()
            .withPolicyName("S3ListPolicy-" + userName)
            .withPolicyDocument(policy.toJson());
        
        iamClient.createPolicy(createPolicyRequest);
    }
    
    @RequestMapping(value = "/good9", method = RequestMethod.POST)
    public void good_case_9(HttpServletRequest request) {
        String roleName = request.getParameter("role");
        String topicArn = request.getParameter("topicArn");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ok: java-handcrafted-policies
        Policy policy = new Policy();
        Statement statement = new Statement(Statement.Effect.Allow)
            .withActions("sns:Publish")
            .withResources(new Resource(topicArn));
        
        policy.withStatements(statement);
        
        PutRolePolicyRequest putRolePolicyRequest = new PutRolePolicyRequest()
            .withRoleName(roleName)
            .withPolicyName("SNSPublishPolicy")
            .withPolicyDocument(policy.toJson());
        
        iamClient.putRolePolicy(putRolePolicyRequest);
    }
    
    @RequestMapping(value = "/good10", method = RequestMethod.POST)
    public void good_case_10(HttpServletRequest request) {
        String queueUrl = request.getParameter("queueUrl");
        String accountId = request.getParameter("accountId");
        String queueName = queueUrl.substring(queueUrl.lastIndexOf('/') + 1);
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ok: java-handcrafted-policies
        String resource = "arn:aws:sqs:us-east-1:" + accountId + ":" + queueName;
        
        Policy policy = new Policy();
        Statement statement = new Statement(Statement.Effect.Allow)
            .withActions("sqs:SendMessage", "sqs:ReceiveMessage")
            .withResources(new Resource(resource));
        
        policy.withStatements(statement);
        
        CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest()
            .withPolicyName("SQSAccessPolicy-" + queueName)
            .withPolicyDocument(policy.toJson());
        
        iamClient.createPolicy(createPolicyRequest);
    }
    
    @RequestMapping(value = "/good11", method = RequestMethod.POST)
    public void good_case_11(HttpServletRequest request) {
        String userName = request.getParameter("username");
        String ipAddress = request.getParameter("ipAddress");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ok: java-handcrafted-policies
        Policy policy = new Policy();
        Statement statement = new Statement(Statement.Effect.Allow)
            .withActions("ec2:*")
            .withResources(new Resource("*"));
        
        statement.withConditions(new StringCondition(
            StringComparisonType.IP_ADDRESS, 
            "aws:SourceIp", 
            ipAddress
        ));
        
        policy.withStatements(statement);
        
        CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest()
            .withPolicyName("EC2AccessFromIP-" + userName)
            .withPolicyDocument(policy.toJson());
        
        iamClient.createPolicy(createPolicyRequest);
    }
    
    @RequestMapping(value = "/good12", method = RequestMethod.POST)
    public void good_case_12(HttpServletRequest request) {
        String projectId = request.getParameter("projectId");
        String region = request.getParameter("region");
        String accountId = request.getParameter("accountId");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ok: java-handcrafted-policies
        String logGroupArn = "arn:aws:logs:" + region + ":" + accountId + ":log-group:/aws/lambda/" + projectId + ":*";
        
        Policy policy = new Policy();
        Statement statement = new Statement(Statement.Effect.Allow)
            .withActions("logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents")
            .withResources(new Resource(logGroupArn));
        
        policy.withStatements(statement);
        
        CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest()
            .withPolicyName("CloudWatchLogsAccess-" + projectId)
            .withPolicyDocument(policy.toJson());
        
        iamClient.createPolicy(createPolicyRequest);
    }
    
    @RequestMapping(value = "/good13", method = RequestMethod.POST)
    public void good_case_13(HttpServletRequest request) {
        String userName = request.getParameter("username");
        String dbName = request.getParameter("dbName");
        String region = request.getParameter("region");
        String accountId = request.getParameter("accountId");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ok: java-handcrafted-policies
        String resource = "arn:aws:rds:" + region + ":" + accountId + ":db:" + dbName;
        
        Policy policy = new Policy();
        Statement statement = new Statement(Statement.Effect.Allow)
            .withActions("rds:CreateDBSnapshot", "rds:DeleteDBSnapshot")
            .withResources(new Resource(resource));
        
        policy.withStatements(statement);
        
        CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest()
            .withPolicyName("RDSSnapshotPolicy-" + userName)
            .withPolicyDocument(policy.toJson());
        
        iamClient.createPolicy(createPolicyRequest);
    }
    
    @RequestMapping(value = "/good14", method = RequestMethod.POST)
    public void good_case_14(HttpServletRequest request) {
        String userName = request.getParameter("username");
        String[] actions = request.getParameterValues("actions");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ok: java-handcrafted-policies
        Policy policy = new Policy();
        Statement statement = new Statement(Statement.Effect.Allow)
            .withResources(new Resource("*"));
        
        for (String action : actions) {
            statement.withActions(action);
        }
        
        policy.withStatements(statement);
        
        CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest()
            .withPolicyName("CustomActionsPolicy-" + userName)
            .withPolicyDocument(policy.toJson());
        
        iamClient.createPolicy(createPolicyRequest);
    }
    
    @RequestMapping(value = "/good15", method = RequestMethod.POST)
    public void good_case_15(HttpServletRequest request) {
        String roleName = request.getParameter("role");
        String principal = request.getParameter("principal");
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        // ok: java-handcrafted-policies
        Policy trustPolicy = new Policy();
        Statement statement = new Statement(Statement.Effect.Allow)
            .withPrincipals(new Principal("Service", principal + ".amazonaws.com"))
            .withActions("sts:AssumeRole");
        
        trustPolicy.withStatements(statement);
        
        CreateRoleRequest createRoleRequest = new CreateRoleRequest()
            .withRoleName(roleName)
            .withAssumeRolePolicyDocument(trustPolicy.toJson());
        
        iamClient.createRole(createRoleRequest);
    }
}
// {/fact}