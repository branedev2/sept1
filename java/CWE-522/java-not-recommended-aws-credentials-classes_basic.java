import com.amazonaws.auth.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.dynamodbv2.*;
import com.amazonaws.services.ec2.*;
import com.amazonaws.regions.Regions;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.ec2.Ec2Client;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.Map;
import java.util.HashMap;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;

public class AwsCredentialsExamples {

    // True Positives (Bad Cases)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        // Using BasicAWSCredentials (not recommended)
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .withRegion(Regions.US_WEST_2)
                .build();
        s3Client.listBuckets();
    }

    public void bad_case_2() {
        // Using BasicSessionCredentials (not recommended)
        // ruleid: java-not-recommended-aws-credentials-classes
        BasicSessionCredentials sessionCredentials = new BasicSessionCredentials(
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4OlgkBN9bkUDNCJiBeb/AXlzBBko7b15fjrBs2+cTQtpZ3CYWFXG8C5zqx37wnOE49mRl/+OtkIKGO7fAE"
        );
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(sessionCredentials))
                .withRegion(Regions.US_EAST_1)
                .build();
        dynamoDbClient.listTables();
    }

    public void bad_case_3() {
        // Using PropertiesCredentials with file (not recommended)
        try {
            // ruleid: java-not-recommended-aws-credentials-classes
            AWSCredentials credentials = new PropertiesCredentials(
                    new FileInputStream("/path/to/credentials.properties"));
            AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                    .withCredentials(new AWSStaticCredentialsProvider(credentials))
                    .withRegion(Regions.EU_WEST_1)
                    .build();
            ec2Client.describeInstances();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        // Using AWSStaticCredentialsProvider with BasicAWSCredentials (not recommended)
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new AWSStaticCredentialsProvider(
                new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        );
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.AP_NORTHEAST_1)
                .build();
        s3Client.listBuckets();
    }

    public void bad_case_5() {
        // Using AnonymousAWSCredentials (not recommended for production)
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentials anonymousCredentials = new AnonymousAWSCredentials();
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(anonymousCredentials))
                .withRegion(Regions.US_WEST_1)
                .build();
        s3Client.listBuckets();
    }

    public void bad_case_6() {
        // Using BasicAWSCredentials in a configuration class (not recommended)
        String accessKey = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .withRegion(Regions.EU_CENTRAL_1)
                .build();
        dynamoDbClient.listTables();
    }

    public void bad_case_7() {
        // Using BasicAWSCredentials with variables from another source (still not recommended)
        Properties props = new Properties();
        try {
            props.load(new FileInputStream("config.properties"));
            String accessKey = props.getProperty("aws.accessKey");
            String secretKey = props.getProperty("aws.secretKey");
            
            // ruleid: java-not-recommended-aws-credentials-classes
            AWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);
            AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                    .withCredentials(new AWSStaticCredentialsProvider(credentials))
                    .withRegion(Regions.SA_EAST_1)
                    .build();
            ec2Client.describeInstances();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        // Using BasicSessionCredentials with token from environment (not recommended)
        String accessKey = System.getenv("AWS_AC_REDACTED_TWILIO_ID_KEY");
        String secretKey = System.getenv("AWS_SECRET_KEY");
        String sessionToken = System.getenv("AWS_SESSION_TOKEN");
        
        // ruleid: java-not-recommended-aws-credentials-classes
        BasicSessionCredentials sessionCredentials = new BasicSessionCredentials(
                accessKey, secretKey, sessionToken);
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(sessionCredentials))
                .withRegion(Regions.AP_SOUTH_1)
                .build();
        s3Client.listBuckets();
    }

    public void bad_case_9() {
        // Using AWSStaticCredentialsProvider with BasicSessionCredentials (not recommended)
        String accessKey = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        String sessionToken = "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c";
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new AWSStaticCredentialsProvider(
                new BasicSessionCredentials(accessKey, secretKey, sessionToken)
        );
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.US_EAST_2)
                .build();
        dynamoDbClient.listTables();
    }

    public void bad_case_10() {
        // Using PropertiesFileCredentialsProvider (not recommended)
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new PropertiesFileCredentialsProvider("credentials.properties");
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.AP_SOUTHEAST_1)
                .build();
        ec2Client.describeInstances();
    }

    public void bad_case_11() {
        // Using SystemPropertiesCredentialsProvider (not recommended)
        System.setProperty("aws.accessKeyId", "AKIAIOSFODNN7EXAMPLE");
        System.setProperty("aws.secretKey", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new SystemPropertiesCredentialsProvider();
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.CA_CENTRAL_1)
                .build();
        s3Client.listBuckets();
    }

    public void bad_case_12() {
        // Using EnvironmentVariableCredentialsProvider explicitly (not recommended)
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new EnvironmentVariableCredentialsProvider();
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.EU_WEST_2)
                .build();
        dynamoDbClient.listTables();
    }

    public void bad_case_13() {
        // Using ClasspathPropertiesFileCredentialsProvider (not recommended)
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new ClasspathPropertiesFileCredentialsProvider("/aws.properties");
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.AP_NORTHEAST_2)
                .build();
        ec2Client.describeInstances();
    }

    public void bad_case_14() {
        // Using AWSCredentialsProviderChain with non-recommended providers (not recommended)
        // ruleid: java-not-recommended-aws-credentials-classes
        AWSCredentialsProviderChain providerChain = new AWSCredentialsProviderChain(
                new EnvironmentVariableCredentialsProvider(),
                new SystemPropertiesCredentialsProvider(),
                new PropertiesFileCredentialsProvider("credentials.properties")
        );
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(providerChain)
                .withRegion(Regions.EU_WEST_3)
                .build();
        s3Client.listBuckets();
    }

    public void bad_case_15() {
        // Using StaticCredentialsProvider from AWS SDK v2 with AwsBasicCredentials (not recommended)
        String accessKey = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        
        // ruleid: java-not-recommended-aws-credentials-classes
        AwsCredentials awsCredentials = AwsBasicCredentials.create(accessKey, secretKey);
        AwsCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(awsCredentials);
        S3Client s3Client = S3Client.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.US_WEST_2)
                .build();
        s3Client.listBuckets();
    }

    // True Negatives (Good Cases)

    public void good_case_1() {
        // Using DefaultAWSCredentialsProviderChain (recommended)
        // ok: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new DefaultAWSCredentialsProviderChain();
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.US_WEST_2)
                .build();
        s3Client.listBuckets();
    }

    public void good_case_2() {
        // Using DefaultCredentialsProvider from AWS SDK v2 (recommended)
        // ok: java-not-recommended-aws-credentials-classes
        AwsCredentialsProvider credentialsProvider = DefaultCredentialsProvider.create();
        S3Client s3Client = S3Client.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.US_EAST_1)
                .build();
        s3Client.listBuckets();
    }

    public void good_case_3() {
        // Using ProfileCredentialsProvider (recommended)
        // ok: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new ProfileCredentialsProvider("myProfile");
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.EU_WEST_1)
                .build();
        dynamoDbClient.listTables();
    }

    public void good_case_4() {
        // Using ProfileCredentialsProvider from AWS SDK v2 (recommended)
        // ok: java-not-recommended-aws-credentials-classes
        AwsCredentialsProvider credentialsProvider = ProfileCredentialsProvider.create("myProfile");
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.EU_CENTRAL_1)
                .build();
        dynamoDbClient.listTables();
    }

    public void good_case_5() {
        // Using STSAssumeRoleSessionCredentialsProvider (recommended)
        // ok: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new STSAssumeRoleSessionCredentialsProvider.Builder("arn:aws:iam::123456789012:role/role-name", "session-name")
                .build();
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.AP_NORTHEAST_1)
                .build();
        ec2Client.describeInstances();
    }

    public void good_case_6() {
        // Using WebIdentityTokenCredentialsProvider (recommended)
        // ok: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = WebIdentityTokenCredentialsProvider.builder()
                .roleArn("arn:aws:iam::123456789012:role/role-name")
                .roleSessionName("session-name")
                .webIdentityTokenFile("/path/to/token/file")
                .build();
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.US_WEST_1)
                .build();
        s3Client.listBuckets();
    }

    public void good_case_7() {
        // Using ContainerCredentialsProvider (recommended)
        // ok: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new ContainerCredentialsProvider();
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.EU_CENTRAL_1)
                .build();
        dynamoDbClient.listTables();
    }

    public void good_case_8() {
        // Using EC2ContainerCredentialsProviderWrapper (recommended)
        // ok: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new EC2ContainerCredentialsProviderWrapper();
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.SA_EAST_1)
                .build();
        ec2Client.describeInstances();
    }

    public void good_case_9() {
        // Using InstanceProfileCredentialsProvider (recommended)
        // ok: java-not-recommended-aws-credentials-classes
        AWSCredentialsProvider credentialsProvider = new InstanceProfileCredentialsProvider(false);
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.AP_SOUTH_1)
                .build();
        s3Client.listBuckets();
    }

    public void good_case_10() {
        // Using default client builder without explicit credentials (recommended)
        // ok: java-not-recommended-aws-credentials-classes
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_2)
                .build();
        s3Client.listBuckets();
    }

    public void good_case_11() {
        // Using AWS SDK v2 default client builder without explicit credentials (recommended)
        // ok: java-not-recommended-aws-credentials-classes
        S3Client s3Client = S3Client.builder()
                .region(Region.US_EAST_2)
                .build();
        s3Client.listBuckets();
    }

    public void good_case_12() {
        // Using AWS SDK v2 WebIdentityTokenCredentialsProvider (recommended)
        // ok: java-not-recommended-aws-credentials-classes
        AwsCredentialsProvider credentialsProvider = WebIdentityTokenCredentialsProvider.create();
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.AP_SOUTHEAST_1)
                .build();
        dynamoDbClient.listTables();
    }

    public void good_case_13() {
        // Using AWS SDK v2 ContainerCredentialsProvider (recommended)
        // ok: java-not-recommended-aws-credentials-classes
        AwsCredentialsProvider credentialsProvider = ContainerCredentialsProvider.builder().build();
        Ec2Client ec2Client = Ec2Client.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.CA_CENTRAL_1)
                .build();
        ec2Client.describeInstances();
    }

    public void good_case_14() {
        // Using AWS SDK v2 EnvironmentVariableCredentialsProvider (recommended)
        // ok: java-not-recommended-aws-credentials-classes
        AwsCredentialsProvider credentialsProvider = EnvironmentVariableCredentialsProvider.create();
        S3Client s3Client = S3Client.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.EU_WEST_2)
                .build();
        s3Client.listBuckets();
    }

    public void good_case_15() {
        // Using AWS SDK v2 InstanceProfileCredentialsProvider (recommended)
        // ok: java-not-recommended-aws-credentials-classes
        AwsCredentialsProvider credentialsProvider = InstanceProfileCredentialsProvider.create();
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.AP_NORTHEAST_2)
                .build();
        dynamoDbClient.listTables();
    }
}
// {/fact}