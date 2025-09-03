import com.amazonaws.auth.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.regions.*;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.regions.*;
import software.amazon.awssdk.services.s3.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import javax.servlet.http.*;
import java.io.*;
import java.util.*;
import okhttp3.*;
import com.squareup.okhttp.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.apache.http.HttpResponse;
import org.apache.commons.io.IOUtils;
import java.nio.charset.StandardCharsets;
import com.google.gson.Gson;
import org.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.URI;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClientBuilder;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;

// Security Issue: Using non-recommended classes for AWS credentials management can introduce security vulnerabilities

// True Positive Examples (Vulnerable/Insecure Code)

public class AwsCredentialsExamples {

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        // Using BasicAWSCredentials with hardcoded credentials in S3 client
        String accessKey = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .withRegion(Regions.US_EAST_1)
                .build();
        
        s3Client.listBuckets();
    }
    
    public void bad_case_2() {
        // Using BasicSessionCredentials with hardcoded credentials in DynamoDB client
        String accessKey = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        String sessionToken = "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4OlgkBN9bkUDNCJiBeb/AXlzBBko7b15fjrBs2+cTQtpZ3CYWFXG8C5zqx37wnOE49mRl/+OtkIKGO7fAE";
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSSessionCredentials sessionCredentials = new BasicSessionCredentials(
                accessKey, secretKey, sessionToken);
        
        AmazonDynamoDBClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(sessionCredentials))
                .withRegion(Regions.US_WEST_2)
                .build();
    }
    
    @RestController
    public void bad_case_3(HttpServletRequest request) {
        // Using PropertiesCredentials with credentials file in EC2 client
        try {
            String filePath = request.getParameter("credentialsPath");
            File credentialsFile = new File(filePath);
            
            // ruleid: java-not-recommended-aws-credentials-classes
            AWSCredentials credentials = new PropertiesCredentials(credentialsFile);
            
            AmazonEC2ClientBuilder.standard()
                    .withCredentials(new AWSStaticCredentialsProvider(credentials))
                    .withRegion(Regions.EU_WEST_1)
                    .build();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_4() {
        // Using SystemPropertiesCredentialsProvider in Lambda client
        System.setProperty("aws.accessKeyId", "AKIAIOSFODNN7EXAMPLE");
        System.setProperty("aws.secretKey", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new SystemPropertiesCredentialsProvider();
        
        AWSLambdaClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.AP_NORTHEAST_1)
                .build();
    }
    
    public void bad_case_5(HttpServletRequest request) {
        // Using EnvironmentVariableCredentialsProvider in CloudWatch client
        // Environment variables should be set securely, not from user input
        String accessKey = request.getParameter("accessKey");
        String secretKey = request.getParameter("secretKey");
        
        System.setenv("AWS_AC_REDACTED_TWILIO_ID_KEY_ID", accessKey);
        System.setenv("AWS_SECRET_AC_REDACTED_TWILIO_ID_KEY", secretKey);
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new EnvironmentVariableCredentialsProvider();
        
        AmazonCloudWatchClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.SA_EAST_1)
                .build();
    }
    
    public void bad_case_6() {
        // Using ClasspathPropertiesFileCredentialsProvider in S3 client
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new ClasspathPropertiesFileCredentialsProvider("/aws.properties");
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.US_WEST_1)
                .build();
    }
    
    @PostMapping("/aws-config")
    public void bad_case_7(@RequestBody Map<String, String> requestBody) {
        // Using AwsCredentials in AWS SDK v2 with user-provided credentials
        String accessKey = requestBody.get("accessKey");
        String secretKey = requestBody.get("secretKey");
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AwsCredentials awsCredentials = AwsBasicCredentials.create(accessKey, secretKey);
        
        S3Client s3Client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(awsCredentials))
                .region(Region.US_EAST_1)
                .build();
    }
    
    public void bad_case_8(HttpServletRequest request) {
        // Using ProfileCredentialsProvider with user-specified profile
        String profileName = request.getParameter("profile");
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new ProfileCredentialsProvider(profileName);
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.AP_SOUTHEAST_2)
                .build();
    }
    
    public void bad_case_9() {
        // Using AWSCredentialsProviderChain with insecure providers
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new AWSCredentialsProviderChain(
                new EnvironmentVariableCredentialsProvider(),
                new SystemPropertiesCredentialsProvider(),
                new ProfileCredentialsProvider()
        );
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.EU_CENTRAL_1)
                .build();
    }
    
    @GetMapping("/aws-service")
    public void bad_case_10(@RequestParam String accessKey, @RequestParam String secretKey) {
        // Using AnonymousAWSCredentials for public access
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentials credentials = new AnonymousAWSCredentials();
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .withRegion(Regions.US_EAST_2)
                .build();
    }
    
    public void bad_case_11() {
        // Using AWSCredentialsProvider directly instantiated
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new AWSCredentialsProvider() {
            @Override
            public AWSCredentials getCredentials() {
                return new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
            }
            
            @Override
            public void refresh() {
                // No implementation needed
            }
        };
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.AP_SOUTH_1)
                .build();
    }
    
    public void bad_case_12(HttpServletRequest request) {
        // Using InstanceProfileCredentialsProvider with custom endpoint
        String endpoint = request.getParameter("endpoint");
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new InstanceProfileCredentialsProvider(false);
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(endpoint, Regions.US_EAST_1.getName()))
                .build();
    }
    
    public void bad_case_13() {
        // Using StaticCredentialsProvider with AWS SDK v1
        String accessKey = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new AWSStaticCredentialsProvider(
                new BasicAWSCredentials(accessKey, secretKey));
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.CA_CENTRAL_1)
                .build();
    }
    
    @PostMapping("/configure-aws")
    public void bad_case_14(@RequestBody Map<String, String> requestBody) {
        // Using AwsSessionCredentials in AWS SDK v2
        String accessKey = requestBody.get("accessKey");
        String secretKey = requestBody.get("secretKey");
        String sessionToken = requestBody.get("sessionToken");
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AwsSessionCredentials sessionCredentials = AwsSessionCredentials.create(
                accessKey, secretKey, sessionToken);
        
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
                .credentialsProvider(StaticCredentialsProvider.create(sessionCredentials))
                .region(Region.US_WEST_2)
                .build();
    }
    
    public void bad_case_15() {
        // Using custom credentials provider that extends AWSCredentialsProvider
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new AWSCredentialsProvider() {
            private BasicAWSCredentials credentials = new BasicAWSCredentials(
                    "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
            
            @Override
            public AWSCredentials getCredentials() {
                return credentials;
            }
            
            @Override
            public void refresh() {
                // Implementation for credential refresh
            }
        };
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.EU_WEST_2)
                .build();
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    public void good_case_1() {
        // Using DefaultCredentialsProvider in AWS SDK v1
        
        // ok: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = DefaultAWSCredentialsProviderChain.getInstance();
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.US_EAST_1)
                .build();
    }
    
    public void good_case_2() {
        // Using DefaultCredentialsProvider in AWS SDK v2
        
        // ok: java-not-recommended-aws-credentials-classes
        S3Client s3Client = S3Client.builder()
                .credentialsProvider(DefaultCredentialsProvider.create())
                .region(Region.US_EAST_1)
                .build();
    }
    
    public void good_case_3() {
        // Using ContainerCredentialsProvider in AWS SDK v2
        
        // ok: java-not-recommended-aws-credentials-classes
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
                .credentialsProvider(ContainerCredentialsProvider.builder().build())
                .region(Region.US_WEST_2)
                .build();
    }
    
    public void good_case_4() {
        // Using WebIdentityTokenFileCredentialsProvider in AWS SDK v1
        
        // ok: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = WebIdentityTokenCredentialsProvider.builder()
                .roleArn("arn:aws:iam::123456789012:role/example-role")
                .roleSessionName("example-session")
                .webIdentityTokenFile("/path/to/token/file")
                .build();
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.EU_WEST_1)
                .build();
    }
    
    public void good_case_5() {
        // Using WebIdentityTokenCredentialsProvider in AWS SDK v2
        
        // ok: java-not-recommended-aws-credentials-classes
        Ec2Client ec2Client = Ec2Client.builder()
                .credentialsProvider(WebIdentityTokenFileCredentialsProvider.create())
                .region(Region.EU_CENTRAL_1)
                .build();
    }
    
    public void good_case_6() {
        // Using StsAssumeRoleCredentialsProvider in AWS SDK v2
        
        // ok: java-not-recommended-aws-credentials-classes
        LambdaClient lambdaClient = LambdaClient.builder()
                .credentialsProvider(StsAssumeRoleCredentialsProvider.builder()
                        .refreshRequest(r -> r.roleArn("arn:aws:iam::123456789012:role/example-role")
                                .roleSessionName("example-session"))
                        .stsClient(StsClient.create())
                        .build())
                .region(Region.AP_NORTHEAST_1)
                .build();
    }
    
    public void good_case_7() {
        // Using STSAssumeRoleSessionCredentialsProvider in AWS SDK v1
        
        // ok: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new STSAssumeRoleSessionCredentialsProvider.Builder(
                "arn:aws:iam::123456789012:role/example-role", "example-session")
                .build();
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.SA_EAST_1)
                .build();
    }
    
    public void good_case_8() {
        // Using AWS SDK v2 with default client builder
        
        // ok: java-not-recommended-aws-credentials-classes
        CloudWatchClient cloudWatchClient = CloudWatchClient.create();
    }
    
    public void good_case_9() {
        // Using AWS SDK v1 with default client builder
        
        // ok: java-not-recommended-aws-credentials-classes
        AmazonS3 s3Client = AmazonS3ClientBuilder.defaultClient();
    }
    
    public void good_case_10() {
        // Using InstanceProfileCredentialsProvider with AWS SDK v1 in EC2 environment
        
        // ok: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = InstanceProfileCredentialsProvider.getInstance();
        
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.US_WEST_1)
                .build();
    }
    
    public void good_case_11() {
        // Using ProcessCredentialsProvider in AWS SDK v2
        
        // ok: java-not-recommended-aws-credentials-classes
        ProcessCredentialsProvider credentialsProvider = ProcessCredentialsProvider.builder()
                .command("credential-process-command --parameters")
                .build();
        
        S3Client s3Client = S3Client.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.US_EAST_2)
                .build();
    }
    
    public void good_case_12() {
        // Using AWS SDK v2 with custom HTTP client
        
        // ok: java-not-recommended-aws-credentials-classes
        S3Client s3Client = S3Client.builder()
                .region(Region.AP_SOUTHEAST_2)
                .httpClientBuilder(ApacheHttpClient.builder())
                .build();
    }
    
    public void good_case_13() {
        // Using EnvironmentVariableCredentialsProvider in AWS SDK v2
        
        // ok: java-not-recommended-aws-credentials-classes
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
                .credentialsProvider(EnvironmentVariableCredentialsProvider.create())
                .region(Region.EU_WEST_2)
                .build();
    }
    
    public void good_case_14() {
        // Using ProfileCredentialsProvider in AWS SDK v2 with default profile
        
        // ok: java-not-recommended-aws-credentials-classes
        ProfileCredentialsProvider credentialsProvider = ProfileCredentialsProvider.create();
        
        Ec2Client ec2Client = Ec2Client.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.AP_SOUTH_1)
                .build();
    }
    
    public void good_case_15() {
        // Using AWS SDK v2 with URL connection HTTP client
        
        // ok: java-not-recommended-aws-credentials-classes
        S3Client s3Client = S3Client.builder()
                .region(Region.CA_CENTRAL_1)
                .httpClient(UrlConnectionHttpClient.builder().build())
                .build();
    }
}
// {/fact}