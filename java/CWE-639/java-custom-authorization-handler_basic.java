import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.AdminGetUserRequest;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.json.JSONObject;

public class CustomAuthorizationHandlerExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=insecure-direct-object-ref@v1.0 defects=1}
    public APIGatewayProxyResponseEvent bad_case_1(APIGatewayProxyRequestEvent request, Context context) {
        String accountId = request.getPathParameters().get("accountId");
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ruleid: java-custom-authorization-handler
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("resourceOwner", new AttributeValue(accountId));
        dynamoDbClient.putItem("Resources", item);
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent bad_case_2(APIGatewayProxyRequestEvent request, Context context) {
        JSONObject body = new JSONObject(request.getBody());
        String accountId = body.getString("accountId");
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // ruleid: java-custom-authorization-handler
        s3Client.putObject(accountId + "-bucket", "file.txt", "Content based on user input");
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent bad_case_3(APIGatewayProxyRequestEvent request, Context context) {
        String accountId = request.getQueryStringParameters().get("accountId");
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        
        Map<String, AttributeValue> expressionValues = new HashMap<>();
        expressionValues.put(":accountId", new AttributeValue(accountId));
        
        // ruleid: java-custom-authorization-handler
        Map<String, String> expressionNames = new HashMap<>();
        expressionNames.put("#owner", "resourceOwner");
        
        dynamoDbClient.updateItem("Resources", 
                                  Map.of("id", new AttributeValue("resource-123")),
                                  "SET #owner = :accountId",
                                  expressionNames,
                                  expressionValues);
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent bad_case_4(APIGatewayProxyRequestEvent request, Context context) {
        Map<String, String> headers = request.getHeaders();
        String accountId = headers.get("X-Account-Id");
        
        // ruleid: java-custom-authorization-handler
        String resourceArn = "arn:aws:s3:::" + accountId + "-resources/data.json";
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        s3Client.getObject(resourceArn.split(":")[5].split("/")[0], "data.json");
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent bad_case_5(APIGatewayProxyRequestEvent request, Context context) {
        JSONObject body = new JSONObject(request.getBody());
        String accountId = body.getString("accountId");
        String resourceId = body.getString("resourceId");
        
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // ruleid: java-custom-authorization-handler
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("id", new AttributeValue(resourceId));
        item.put("owner", new AttributeValue(accountId));
        item.put("permissions", new AttributeValue("full-access"));
        
        dynamoDbClient.putItem("ResourcePermissions", item);
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent bad_case_6(APIGatewayProxyRequestEvent request, Context context) {
        String accountId = request.getPathParameters().get("accountId");
        String action = request.getQueryStringParameters().get("action");
        
        // ruleid: java-custom-authorization-handler
        if (action.equals("grant-admin")) {
            AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("accountId", new AttributeValue(accountId));
            item.put("role", new AttributeValue("ADMIN"));
            dynamoDbClient.putItem("AccountRoles", item);
        }
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent bad_case_7(APIGatewayProxyRequestEvent request, Context context) {
        JSONObject body = new JSONObject(request.getBody());
        String targetAccountId = body.getString("targetAccountId");
        String permission = body.getString("permission");
        
        // ruleid: java-custom-authorization-handler
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketPolicy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"" 
            + targetAccountId + "\"},\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::shared-bucket/*\"}]}";
        
        s3Client.setBucketPolicy("shared-bucket", bucketPolicy);
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent bad_case_8(APIGatewayProxyRequestEvent request, Context context) {
        String accountId = request.getQueryStringParameters().get("accountId");
        String resourceType = request.getQueryStringParameters().get("resourceType");
        
        // ruleid: java-custom-authorization-handler
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> key = new HashMap<>();
        key.put("resourceType", new AttributeValue(resourceType));
        
        Map<String, AttributeValue> expressionValues = new HashMap<>();
        expressionValues.put(":owner", new AttributeValue(accountId));
        
        dynamoDbClient.updateItem("ResourceRegistry", key, "SET resourceOwner = :owner", null, expressionValues);
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent bad_case_9(APIGatewayProxyRequestEvent request, Context context) {
        Map<String, String> headers = request.getHeaders();
        String accountId = headers.get("X-Account-Id");
        String resourceName = request.getPathParameters().get("resourceName");
        
        // ruleid: java-custom-authorization-handler
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("resourceName", new AttributeValue(resourceName));
        item.put("accountId", new AttributeValue(accountId));
        item.put("accessLevel", new AttributeValue("OWNER"));
        
        dynamoDbClient.putItem("AccessControl", item);
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent bad_case_10(APIGatewayProxyRequestEvent request, Context context) {
        JSONObject body = new JSONObject(request.getBody());
        String accountId = body.getString("accountId");
        String lambdaArn = "arn:aws:lambda:us-east-1:" + accountId + ":function:resource-manager";
        
        // ruleid: java-custom-authorization-handler
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("lambdaArn", new AttributeValue(lambdaArn));
        item.put("permission", new AttributeValue("invoke"));
        
        dynamoDbClient.putItem("LambdaPermissions", item);
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent bad_case_11(APIGatewayProxyRequestEvent request, Context context) {
        String accountId = request.getPathParameters().get("accountId");
        String resourceId = UUID.randomUUID().toString();
        
        // ruleid: java-custom-authorization-handler
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        Map<String, String> metadata = new HashMap<>();
        metadata.put("owner-account", accountId);
        
        s3Client.putObject("resources-bucket", resourceId + ".json", "{}");
        s3Client.setObjectTagging("resources-bucket", resourceId + ".json", 
                                  Map.of("owner", accountId));
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent bad_case_12(APIGatewayProxyRequestEvent request, Context context) {
        String accountId = request.getQueryStringParameters().get("accountId");
        String resourcePath = request.getPathParameters().get("resourcePath");
        
        // ruleid: java-custom-authorization-handler
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("resourcePath", new AttributeValue(resourcePath));
        item.put("ownerAccount", new AttributeValue(accountId));
        item.put("accessControl", new AttributeValue("private"));
        
        dynamoDbClient.putItem("ResourceRegistry", item);
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent bad_case_13(APIGatewayProxyRequestEvent request, Context context) {
        JSONObject body = new JSONObject(request.getBody());
        String accountId = body.getString("accountId");
        String policyName = body.getString("policyName");
        
        // ruleid: java-custom-authorization-handler
        String policyDocument = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::" 
            + accountId + "-resources/*\"}]}";
        
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("policyName", new AttributeValue(policyName));
        item.put("policyDocument", new AttributeValue(policyDocument));
        item.put("ownerAccount", new AttributeValue(accountId));
        
        dynamoDbClient.putItem("IAMPolicies", item);
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent bad_case_14(APIGatewayProxyRequestEvent request, Context context) {
        String accountId = request.getHeaders().get("X-Account-Id");
        String userName = request.getPathParameters().get("userName");
        
        // ruleid: java-custom-authorization-handler
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("userName", new AttributeValue(userName));
        item.put("accountId", new AttributeValue(accountId));
        item.put("isAdmin", new AttributeValue("true"));
        
        dynamoDbClient.putItem("UserRoles", item);
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent bad_case_15(APIGatewayProxyRequestEvent request, Context context) {
        Map<String, String> queryParams = request.getQueryStringParameters();
        String accountId = queryParams.get("accountId");
        String resourceType = queryParams.get("resourceType");
        
        // ruleid: java-custom-authorization-handler
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> key = new HashMap<>();
        key.put("resourceType", new AttributeValue(resourceType));
        
        Map<String, AttributeValue> expressionValues = new HashMap<>();
        expressionValues.put(":acct", new AttributeValue(accountId));
        
        dynamoDbClient.updateItem("ResourceOwnership", 
                                  key,
                                  "SET owningAccount = :acct", 
                                  null, 
                                  expressionValues);
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    // True Negative Examples (Secure Code)

    public APIGatewayProxyResponseEvent good_case_1(APIGatewayProxyRequestEvent request, Context context) {
        String requestedAccountId = request.getPathParameters().get("accountId");
        
        // Verify the caller's identity using AWS STS
        AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard().build();
        GetCallerIdentityResult callerIdentity = stsClient.getCallerIdentity(new GetCallerIdentityRequest());
        String actualAccountId = callerIdentity.getAccount();
        
        // ok: java-custom-authorization-handler
        if (actualAccountId.equals(requestedAccountId)) {
            AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("resourceOwner", new AttributeValue(actualAccountId));
            dynamoDbClient.putItem("Resources", item);
        } else {
            throw new SecurityException("Account ID mismatch");
        }
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent good_case_2(APIGatewayProxyRequestEvent request, Context context) {
        JSONObject body = new JSONObject(request.getBody());
        String requestedAccountId = body.getString("accountId");
        
        // Get the authenticated user from the context
        String authenticatedUser = context.getIdentity().getIdentityId();
        
        // ok: java-custom-authorization-handler
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> userItem = dynamoDbClient.getItem("Users", 
                                                                     Map.of("userId", new AttributeValue(authenticatedUser)))
                                                            .getItem();
        
        String userAccountId = userItem.get("accountId").getS();
        
        if (userAccountId.equals(requestedAccountId)) {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            s3Client.putObject(userAccountId + "-bucket", "file.txt", "Content based on verified user");
        } else {
            throw new SecurityException("Unauthorized access attempt");
        }
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent good_case_3(APIGatewayProxyRequestEvent request, Context context) {
        String token = request.getHeaders().get("Authorization");
        
        // Verify token and extract claims
        // (simplified for example - in real code, use a proper JWT library)
        String[] parts = token.split("\\.");
        String payload = new String(java.util.Base64.getDecoder().decode(parts[1]));
        JSONObject claims = new JSONObject(payload);
        
        String authenticatedAccountId = claims.getString("account_id");
        String requestedAccountId = request.getQueryStringParameters().get("accountId");
        
        // ok: java-custom-authorization-handler
        if (authenticatedAccountId.equals(requestedAccountId)) {
            AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
            Map<String, AttributeValue> expressionValues = new HashMap<>();
            expressionValues.put(":accountId", new AttributeValue(authenticatedAccountId));
            
            Map<String, String> expressionNames = new HashMap<>();
            expressionNames.put("#owner", "resourceOwner");
            
            dynamoDbClient.updateItem("Resources", 
                                     Map.of("id", new AttributeValue("resource-123")),
                                     "SET #owner = :accountId",
                                     expressionNames,
                                     expressionValues);
        } else {
            throw new SecurityException("Account ID mismatch");
        }
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent good_case_4(APIGatewayProxyRequestEvent request, Context context) {
        // Get authenticated user from Cognito
        String accessToken = request.getHeaders().get("Authorization").replace("Bearer ", "");
        
        AWSCognitoIdentityProvider cognitoClient = AWSCognitoIdentityProviderClientBuilder.standard().build();
        AdminGetUserRequest userRequest = new AdminGetUserRequest()
            .withUserPoolId("us-east-1_poolId")
            .withUsername(context.getIdentity().getIdentityId());
        
        // ok: java-custom-authorization-handler
        String userAccountId = cognitoClient.adminGetUser(userRequest)
            .getUserAttributes().stream()
            .filter(attr -> attr.getName().equals("custom:accountId"))
            .findFirst()
            .orElseThrow(() -> new SecurityException("Account ID not found"))
            .getValue();
        
        String resourceArn = "arn:aws:s3:::" + userAccountId + "-resources/data.json";
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        s3Client.getObject(resourceArn.split(":")[5].split("/")[0], "data.json");
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent good_case_5(APIGatewayProxyRequestEvent request, Context context) {
        // Extract the JWT token from the Authorization header
        String token = request.getHeaders().get("Authorization").replace("Bearer ", "");
        
        // In a real implementation, use a proper JWT library to verify the token
        // and extract claims
        String[] parts = token.split("\\.");
        String payload = new String(java.util.Base64.getDecoder().decode(parts[1]));
        JSONObject claims = new JSONObject(payload);
        
        String authenticatedAccountId = claims.getString("sub");
        String resourceId = request.getPathParameters().get("resourceId");
        
        // ok: java-custom-authorization-handler
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        
        // First check if the user has permission to access this resource
        Map<String, AttributeValue> key = new HashMap<>();
        key.put("resourceId", new AttributeValue(resourceId));
        
        Map<String, AttributeValue> resource = dynamoDbClient.getItem("Resources", key).getItem();
        
        if (resource != null && resource.get("ownerAccountId").getS().equals(authenticatedAccountId)) {
            // User is authorized to modify the resource
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("id", new AttributeValue(resourceId));
            item.put("owner", new AttributeValue(authenticatedAccountId));
            item.put("permissions", new AttributeValue("full-access"));
            
            dynamoDbClient.putItem("ResourcePermissions", item);
        } else {
            throw new SecurityException("Unauthorized access attempt");
        }
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent good_case_6(APIGatewayProxyRequestEvent request, Context context) {
        // Get the authenticated user from context
        String authenticatedUser = context.getIdentity().getIdentityId();
        
        // ok: java-custom-authorization-handler
        // Check if the user has admin privileges
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> userKey = new HashMap<>();
        userKey.put("userId", new AttributeValue(authenticatedUser));
        
        Map<String, AttributeValue> user = dynamoDbClient.getItem("Users", userKey).getItem();
        
        if (user != null && user.containsKey("isAdmin") && user.get("isAdmin").getBOOL()) {
            String targetAccountId = request.getPathParameters().get("accountId");
            String action = request.getQueryStringParameters().get("action");
            
            if (action.equals("grant-admin")) {
                Map<String, AttributeValue> item = new HashMap<>();
                item.put("accountId", new AttributeValue(targetAccountId));
                item.put("role", new AttributeValue("ADMIN"));
                item.put("grantedBy", new AttributeValue(authenticatedUser));
                dynamoDbClient.putItem("AccountRoles", item);
            }
        } else {
            throw new SecurityException("Unauthorized: Admin privileges required");
        }
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent good_case_7(APIGatewayProxyRequestEvent request, Context context) {
        // Verify the caller's identity using AWS STS
        AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard().build();
        GetCallerIdentityResult callerIdentity = stsClient.getCallerIdentity(new GetCallerIdentityRequest());
        String authenticatedAccountId = callerIdentity.getAccount();
        
        JSONObject body = new JSONObject(request.getBody());
        String targetAccountId = body.getString("targetAccountId");
        String permission = body.getString("permission");
        
        // ok: java-custom-authorization-handler
        // Check if the authenticated account has permission to grant access
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> permissionKey = new HashMap<>();
        permissionKey.put("bucketOwner", new AttributeValue(authenticatedAccountId));
        
        Map<String, AttributeValue> bucketPermissions = dynamoDbClient.getItem("BucketPermissions", permissionKey).getItem();
        
        if (bucketPermissions != null && bucketPermissions.get("canShareWith").getS().contains(targetAccountId)) {
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketPolicy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"" 
                + targetAccountId + "\"},\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::shared-bucket/*\"}]}";
            
            s3Client.setBucketPolicy("shared-bucket", bucketPolicy);
        } else {
            throw new SecurityException("Unauthorized: Cannot share with the specified account");
        }
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent good_case_8(APIGatewayProxyRequestEvent request, Context context) {
        String token = request.getHeaders().get("Authorization");
        
        // In a real implementation, use a proper JWT library to verify the token
        // and extract claims
        String[] parts = token.split("\\.");
        String payload = new String(java.util.Base64.getDecoder().decode(parts[1]));
        JSONObject claims = new JSONObject(payload);
        
        String authenticatedAccountId = claims.getString("account_id");
        String resourceType = request.getQueryStringParameters().get("resourceType");
        
        // ok: java-custom-authorization-handler
        // Check if the user has permission to modify this resource type
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> permissionKey = new HashMap<>();
        permissionKey.put("accountId", new AttributeValue(authenticatedAccountId));
        permissionKey.put("resourceType", new AttributeValue(resourceType));
        
        Map<String, AttributeValue> permission = dynamoDbClient.getItem("ResourceTypePermissions", permissionKey).getItem();
        
        if (permission != null && permission.get("canModify").getBOOL()) {
            Map<String, AttributeValue> key = new HashMap<>();
            key.put("resourceType", new AttributeValue(resourceType));
            
            Map<String, AttributeValue> expressionValues = new HashMap<>();
            expressionValues.put(":owner", new AttributeValue(authenticatedAccountId));
            
            dynamoDbClient.updateItem("ResourceRegistry", key, "SET resourceOwner = :owner", null, expressionValues);
        } else {
            throw new SecurityException("Unauthorized: Cannot modify this resource type");
        }
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent good_case_9(APIGatewayProxyRequestEvent request, Context context) {
        // Get authenticated user from context
        String authenticatedUser = context.getIdentity().getIdentityId();
        
        // ok: java-custom-authorization-handler
        // Retrieve the user's account ID from a trusted source
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> userKey = new HashMap<>();
        userKey.put("userId", new AttributeValue(authenticatedUser));
        
        Map<String, AttributeValue> user = dynamoDbClient.getItem("Users", userKey).getItem();
        
        if (user != null && user.containsKey("accountId")) {
            String accountId = user.get("accountId").getS();
            String resourceName = request.getPathParameters().get("resourceName");
            
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("resourceName", new AttributeValue(resourceName));
            item.put("accountId", new AttributeValue(accountId));
            item.put("accessLevel", new AttributeValue("OWNER"));
            
            dynamoDbClient.putItem("AccessControl", item);
        } else {
            throw new SecurityException("User not found or missing account ID");
        }
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent good_case_10(APIGatewayProxyRequestEvent request, Context context) {
        // Verify the caller's identity using AWS STS
        AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard().build();
        GetCallerIdentityResult callerIdentity = stsClient.getCallerIdentity(new GetCallerIdentityRequest());
        String authenticatedAccountId = callerIdentity.getAccount();
        
        JSONObject body = new JSONObject(request.getBody());
        String requestedAccountId = body.getString("accountId");
        
        // ok: java-custom-authorization-handler
        if (authenticatedAccountId.equals(requestedAccountId)) {
            String lambdaArn = "arn:aws:lambda:us-east-1:" + authenticatedAccountId + ":function:resource-manager";
            
            AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("lambdaArn", new AttributeValue(lambdaArn));
            item.put("permission", new AttributeValue("invoke"));
            
            dynamoDbClient.putItem("LambdaPermissions", item);
        } else {
            throw new SecurityException("Account ID mismatch");
        }
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent good_case_11(APIGatewayProxyRequestEvent request, Context context) {
        // Extract and verify JWT token
        String token = request.getHeaders().get("Authorization").replace("Bearer ", "");
        
        // In a real implementation, use a proper JWT library to verify the token
        // and extract claims
        String[] parts = token.split("\\.");
        String payload = new String(java.util.Base64.getDecoder().decode(parts[1]));
        JSONObject claims = new JSONObject(payload);
        
        String authenticatedAccountId = claims.getString("account_id");
        
        // ok: java-custom-authorization-handler
        // Verify the token's signature and claims before proceeding
        // (simplified for example)
        boolean isTokenValid = true; // In real code, this would be the result of token validation
        
        if (isTokenValid) {
            String resourceId = UUID.randomUUID().toString();
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            Map<String, String> metadata = new HashMap<>();
            metadata.put("owner-account", authenticatedAccountId);
            
            s3Client.putObject("resources-bucket", resourceId + ".json", "{}");
            s3Client.setObjectTagging("resources-bucket", resourceId + ".json", 
                                     Map.of("owner", authenticatedAccountId));
        } else {
            throw new SecurityException("Invalid token");
        }
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent good_case_12(APIGatewayProxyRequestEvent request, Context context) {
        // Get authenticated user from Cognito
        String accessToken = request.getHeaders().get("Authorization").replace("Bearer ", "");
        
        AWSCognitoIdentityProvider cognitoClient = AWSCognitoIdentityProviderClientBuilder.standard().build();
        AdminGetUserRequest userRequest = new AdminGetUserRequest()
            .withUserPoolId("us-east-1_poolId")
            .withUsername(context.getIdentity().getIdentityId());
        
        // ok: java-custom-authorization-handler
        String userAccountId = cognitoClient.adminGetUser(userRequest)
            .getUserAttributes().stream()
            .filter(attr -> attr.getName().equals("custom:accountId"))
            .findFirst()
            .orElseThrow(() -> new SecurityException("Account ID not found"))
            .getValue();
        
        String resourcePath = request.getPathParameters().get("resourcePath");
        
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("resourcePath", new AttributeValue(resourcePath));
        item.put("ownerAccount", new AttributeValue(userAccountId));
        item.put("accessControl", new AttributeValue("private"));
        
        dynamoDbClient.putItem("ResourceRegistry", item);
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent good_case_13(APIGatewayProxyRequestEvent request, Context context) {
        // Verify the caller's identity using AWS STS
        AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard().build();
        GetCallerIdentityResult callerIdentity = stsClient.getCallerIdentity(new GetCallerIdentityRequest());
        String authenticatedAccountId = callerIdentity.getAccount();
        
        JSONObject body = new JSONObject(request.getBody());
        String requestedAccountId = body.getString("accountId");
        String policyName = body.getString("policyName");
        
        // ok: java-custom-authorization-handler
        if (authenticatedAccountId.equals(requestedAccountId)) {
            String policyDocument = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::" 
                + authenticatedAccountId + "-resources/*\"}]}";
            
            AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("policyName", new AttributeValue(policyName));
            item.put("policyDocument", new AttributeValue(policyDocument));
            item.put("ownerAccount", new AttributeValue(authenticatedAccountId));
            
            dynamoDbClient.putItem("IAMPolicies", item);
        } else {
            throw new SecurityException("Account ID mismatch");
        }
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent good_case_14(APIGatewayProxyRequestEvent request, Context context) {
        // Get authenticated user from context
        String authenticatedUser = context.getIdentity().getIdentityId();
        
        // ok: java-custom-authorization-handler
        // Check if the user has admin privileges
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        Map<String, AttributeValue> userKey = new HashMap<>();
        userKey.put("userId", new AttributeValue(authenticatedUser));
        
        Map<String, AttributeValue> user = dynamoDbClient.getItem("Users", userKey).getItem();
        
        if (user != null && user.containsKey("isAdmin") && user.get("isAdmin").getBOOL()) {
            String accountId = user.get("accountId").getS();
            String userName = request.getPathParameters().get("userName");
            
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("userName", new AttributeValue(userName));
            item.put("accountId", new AttributeValue(accountId));
            item.put("isAdmin", new AttributeValue("true"));
            
            dynamoDbClient.putItem("UserRoles", item);
        } else {
            throw new SecurityException("Unauthorized: Admin privileges required");
        }
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }

    public APIGatewayProxyResponseEvent good_case_15(APIGatewayProxyRequestEvent request, Context context) {
        // Verify the caller's identity using AWS STS
        AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard().build();
        GetCallerIdentityResult callerIdentity = stsClient.getCallerIdentity(new GetCallerIdentityRequest());
        String authenticatedAccountId = callerIdentity.getAccount();
        
        Map<String, String> queryParams = request.getQueryStringParameters();
        String requestedAccountId = queryParams.get("accountId");
        String resourceType = queryParams.get("resourceType");
        
        // ok: java-custom-authorization-handler
        if (authenticatedAccountId.equals(requestedAccountId)) {
            AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
            Map<String, AttributeValue> key = new HashMap<>();
            key.put("resourceType", new AttributeValue(resourceType));
            
            Map<String, AttributeValue> expressionValues = new HashMap<>();
            expressionValues.put(":acct", new AttributeValue(authenticatedAccountId));
            
            dynamoDbClient.updateItem("ResourceOwnership", 
                                     key,
                                     "SET owningAccount = :acct", 
                                     null, 
                                     expressionValues);
        } else {
            throw new SecurityException("Account ID mismatch");
        }
        
        return new APIGatewayProxyResponseEvent().withStatusCode(200);
    }
}
// {/fact}