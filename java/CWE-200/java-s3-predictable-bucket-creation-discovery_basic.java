import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.CreateBucketRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.regions.Regions;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.util.UUID;
import java.util.Random;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Properties;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class S3BucketCreationExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=sensitive-information-leak@v1.0 defects=1}
    public void bad_case_1() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        // ruleid: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket("company-backup-files");
    }

    public void bad_case_2() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_WEST_2)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String bucketName = "user-uploads-bucket";
        // ruleid: java-s3-predictable-bucket-creation-discovery
        Bucket bucket = s3Client.createBucket(bucketName);
        System.out.println("Created bucket: " + bucket.getName());
    }

    public void bad_case_3() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.EU_WEST_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String companyName = "acme";
        String environment = "production";
        // ruleid: java-s3-predictable-bucket-creation-discovery
        String bucketName = companyName + "-" + environment + "-data";
        s3Client.createBucket(bucketName);
    }

    public void bad_case_4() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        CreateBucketRequest createBucketRequest = new CreateBucketRequest(
                // ruleid: java-s3-predictable-bucket-creation-discovery
                "customer-invoice-storage");
        s3Client.createBucket(createBucketRequest);
    }

    public void bad_case_5() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.AP_NORTHEAST_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        final String BUCKET_NAME = "app-logs-archive";
        // ruleid: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket(BUCKET_NAME);
    }

    public void bad_case_6() {
        String region = "us-west-2";
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(region)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        // ruleid: java-s3-predictable-bucket-creation-discovery
        String bucketName = "company-" + region + "-backups";
        s3Client.createBucket(bucketName);
    }

    public void bad_case_7() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_2)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        int year = 2023;
        // ruleid: java-s3-predictable-bucket-creation-discovery
        String bucketName = "financial-reports-" + year;
        s3Client.createBucket(bucketName);
    }

    public void bad_case_8() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.EU_CENTRAL_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String department = "marketing";
        String purpose = "campaigns";
        // ruleid: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket(department + "-" + purpose);
    }

    public void bad_case_9() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.SA_EAST_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String environment = System.getProperty("env", "dev");
        // ruleid: java-s3-predictable-bucket-creation-discovery
        String bucketName = "myapp-" + environment + "-storage";
        s3Client.createBucket(bucketName);
    }

    public void bad_case_10() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String projectId = "project123";
        // ruleid: java-s3-predictable-bucket-creation-discovery
        CreateBucketRequest request = new CreateBucketRequest(projectId + "-assets");
        s3Client.createBucket(request);
    }

    public void bad_case_11() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.AP_SOUTH_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String[] bucketParts = {"user", "profile", "images"};
        // ruleid: java-s3-predictable-bucket-creation-discovery
        String bucketName = String.join("-", bucketParts);
        s3Client.createBucket(bucketName);
    }

    public void bad_case_12() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.CA_CENTRAL_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        StringBuilder bucketNameBuilder = new StringBuilder();
        bucketNameBuilder.append("company");
        bucketNameBuilder.append("-");
        bucketNameBuilder.append("data");
        bucketNameBuilder.append("-");
        bucketNameBuilder.append("archive");
        
        // ruleid: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket(bucketNameBuilder.toString());
    }

    public void bad_case_13() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_WEST_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String customerName = "acme-corp";
        String bucketType = "documents";
        // ruleid: java-s3-predictable-bucket-creation-discovery
        String bucketName = String.format("%s-%s-storage", customerName, bucketType);
        s3Client.createBucket(bucketName);
    }

    public void bad_case_14() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.EU_WEST_2)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String month = "january";
        String year = "2023";
        // ruleid: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket("financial-reports-" + month + "-" + year);
    }

    public void bad_case_15() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.AP_NORTHEAST_2)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        try {
            Properties props = new Properties();
            props.load(new FileInputStream("config.properties"));
            String appName = props.getProperty("app.name", "myapp");
            
            // ruleid: java-s3-predictable-bucket-creation-discovery
            String bucketName = appName + "-media-files";
            s3Client.createBucket(bucketName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        // ok: java-s3-predictable-bucket-creation-discovery
        String bucketName = "company-backup-" + UUID.randomUUID().toString();
        s3Client.createBucket(bucketName);
    }

    public void good_case_2() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_WEST_2)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String prefix = "user-uploads";
        // ok: java-s3-predictable-bucket-creation-discovery
        String randomSuffix = UUID.randomUUID().toString().substring(0, 8);
        Bucket bucket = s3Client.createBucket(prefix + "-" + randomSuffix);
    }

    public void good_case_3() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.EU_WEST_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String companyName = "acme";
        String environment = "production";
        // ok: java-s3-predictable-bucket-creation-discovery
        String bucketName = companyName + "-" + environment + "-" + System.currentTimeMillis();
        s3Client.createBucket(bucketName);
    }

    public void good_case_4() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String basePrefix = "customer-invoice";
        Random random = new Random();
        // ok: java-s3-predictable-bucket-creation-discovery
        String randomId = String.valueOf(Math.abs(random.nextLong()));
        CreateBucketRequest createBucketRequest = new CreateBucketRequest(
                basePrefix + "-" + randomId);
        s3Client.createBucket(createBucketRequest);
    }

    public void good_case_5() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.AP_NORTHEAST_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        final String BUCKET_PREFIX = "app-logs";
        // ok: java-s3-predictable-bucket-creation-discovery
        String uniqueId = UUID.randomUUID().toString();
        s3Client.createBucket(BUCKET_PREFIX + "-" + uniqueId);
    }

    public void good_case_6() {
        String region = "us-west-2";
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(region)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");
        // ok: java-s3-predictable-bucket-creation-discovery
        String bucketName = "company-" + region + "-" + now.format(formatter) + "-" + UUID.randomUUID().toString().substring(0, 6);
        s3Client.createBucket(bucketName);
    }

    public void good_case_7() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_2)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        int year = 2023;
        // ok: java-s3-predictable-bucket-creation-discovery
        String bucketName = "financial-reports-" + year + "-" + UUID.randomUUID().toString();
        s3Client.createBucket(bucketName);
    }

    public void good_case_8() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.EU_CENTRAL_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String department = "marketing";
        String purpose = "campaigns";
        Random random = new Random();
        // ok: java-s3-predictable-bucket-creation-discovery
        String randomSuffix = String.valueOf(Math.abs(random.nextInt(1000000)));
        s3Client.createBucket(department + "-" + purpose + "-" + randomSuffix);
    }

    public void good_case_9() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.SA_EAST_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String environment = System.getProperty("env", "dev");
        // ok: java-s3-predictable-bucket-creation-discovery
        String timestamp = String.valueOf(System.nanoTime());
        String bucketName = "myapp-" + environment + "-" + timestamp;
        s3Client.createBucket(bucketName);
    }

    public void good_case_10() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String projectId = "project123";
        // ok: java-s3-predictable-bucket-creation-discovery
        String uniqueId = UUID.randomUUID().toString();
        CreateBucketRequest request = new CreateBucketRequest(projectId + "-assets-" + uniqueId);
        s3Client.createBucket(request);
    }

    public void good_case_11() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.AP_SOUTH_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String[] bucketParts = {"user", "profile", "images"};
        // ok: java-s3-predictable-bucket-creation-discovery
        String bucketName = String.join("-", bucketParts) + "-" + UUID.randomUUID().toString();
        s3Client.createBucket(bucketName);
    }

    public void good_case_12() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.CA_CENTRAL_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        StringBuilder bucketNameBuilder = new StringBuilder();
        bucketNameBuilder.append("company");
        bucketNameBuilder.append("-");
        bucketNameBuilder.append("data");
        bucketNameBuilder.append("-");
        bucketNameBuilder.append("archive");
        bucketNameBuilder.append("-");
        // ok: java-s3-predictable-bucket-creation-discovery
        bucketNameBuilder.append(UUID.randomUUID().toString());
        
        s3Client.createBucket(bucketNameBuilder.toString());
    }

    public void good_case_13() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_WEST_1)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        String customerName = "acme-corp";
        String bucketType = "documents";
        // ok: java-s3-predictable-bucket-creation-discovery
        String uniqueId = UUID.randomUUID().toString();
        String bucketName = String.format("%s-%s-%s", customerName, bucketType, uniqueId);
        s3Client.createBucket(bucketName);
    }

    public void good_case_14() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.EU_WEST_2)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        try {
            // ok: java-s3-predictable-bucket-creation-discovery
            String bucketName = "financial-reports-" + UUID.randomUUID().toString();
            s3Client.createBucket(bucketName);
            
            // Now use the bucket
            String content = "Report content";
            InputStream inputStream = new ByteArrayInputStream(content.getBytes());
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(content.length());
            s3Client.putObject(bucketName, "report.txt", inputStream, metadata);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.AP_NORTHEAST_2)
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
        
        try {
            Properties props = new Properties();
            props.load(new FileInputStream("config.properties"));
            String appName = props.getProperty("app.name", "myapp");
            
            // ok: java-s3-predictable-bucket-creation-discovery
            String bucketId = new String(Files.readAllBytes(Paths.get("/dev/urandom"))).substring(0, 10);
            String bucketName = appName + "-media-" + bucketId + "-" + System.currentTimeMillis();
            s3Client.createBucket(bucketName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}