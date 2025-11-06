import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.*;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.regions.Region;
import com.google.cloud.storage.*;
import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import org.apache.commons.io.FileUtils;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.util.UUID;
import java.time.Instant;
import java.util.Random;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Scanner;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.options.CreateContainerOptions;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.BlobContainerClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import java.security.SecureRandom;
import java.util.Base64;

// Security Issue: Predictable S3 bucket names make them vulnerable to unauthorized access attempts

// True Positive Examples (Vulnerable/Insecure Code)
class S3BucketVulnerabilities {

// {fact rule=sensitive-information-leak@v1.0 defects=1}
    public void bad_case_1() {
        // AWS SDK v1 with hardcoded bucket name
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // ruleid: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket("company-backup-files");
    }

    public void bad_case_2() {
        // AWS SDK v2 with hardcoded bucket name
        S3Client s3 = S3Client.builder()
                .region(Region.US_WEST_2)
                .build();
        
        // ruleid: java-s3-predictable-bucket-creation-discovery
        s3.createBucket(CreateBucketRequest.builder().bucket("user-uploads-bucket").build());
    }

    public void bad_case_3() {
        // MinIO client with hardcoded bucket name
        try {
            MinioClient minioClient = MinioClient.builder()
                    .endpoint("https://play.min.io")
                    .credentials("Q3AM3UQ867SPQQA43P2F", "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG")
                    .build();
            
            // ruleid: java-s3-predictable-bucket-creation-discovery
            minioClient.makeBucket(MakeBucketArgs.builder().bucket("customer-data-2023").build());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        // Google Cloud Storage with hardcoded bucket name
        Storage storage = StorageOptions.getDefaultInstance().getService();
        
        // ruleid: java-s3-predictable-bucket-creation-discovery
        storage.create(BucketInfo.of("company-financial-reports"));
    }

    public void bad_case_5(HttpServletRequest request) {
        // AWS SDK with concatenated predictable name
        String env = "production";
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // ruleid: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket("app-logs-" + env);
    }

    public void bad_case_6() {
        // JClouds with hardcoded container name (equivalent to bucket)
        BlobStoreContext context = ContextBuilder.newBuilder("aws-s3")
                .credentials("identity", "credential")
                .buildView(BlobStoreContext.class);
        
        // ruleid: java-s3-predictable-bucket-creation-discovery
        context.getBlobStore().createContainerInLocation(null, "application-backups");
    }

    public void bad_case_7(HttpServletRequest request) {
        // Azure Blob Storage with predictable container name
        String connectionString = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;EndpointSuffix=core.windows.net";
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder().connectionString(connectionString).buildClient();
        
        // ruleid: java-s3-predictable-bucket-creation-discovery
        BlobContainerClient containerClient = blobServiceClient.createBlobContainer("customer-invoices");
    }

    public void bad_case_8() {
        // AWS SDK with predictable name based on date
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String year = "2023";
        String month = "11";
        
        // ruleid: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket("backup-" + year + "-" + month);
    }

    @PostMapping("/create-bucket")
    public void bad_case_9(@RequestParam String companyId) {
        // AWS SDK with predictable name based on user input
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // ruleid: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket("company-" + companyId + "-data");
    }

    public void bad_case_10() {
        // AWS SDK with predictable name based on environment
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String environment = System.getenv("ENVIRONMENT");
        
        // ruleid: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket("app-" + environment);
    }

    public void bad_case_11() {
        try {
            // AWS SDK with name from a configuration file
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String bucketName = FileUtils.readFileToString(new File("config/bucket-name.txt"), "UTF-8").trim();
            
            // ruleid: java-s3-predictable-bucket-creation-discovery
            s3Client.createBucket(bucketName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @GetMapping("/setup-storage")
    public void bad_case_12(HttpServletRequest request) {
        // AWS SDK with name based on tenant ID
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String tenantId = request.getParameter("tenantId");
        
        // ruleid: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket("tenant-" + tenantId + "-storage");
    }

    public void bad_case_13() {
        // AWS SDK with name based on project and environment
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String project = "ecommerce";
        String env = "staging";
        
        // ruleid: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket(project + "-" + env + "-data");
    }

    public void bad_case_14() {
        try {
            // AWS SDK with name from an HTTP request
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://api.example.com/bucket-config");
            CloseableHttpResponse response = httpClient.execute(request);
            HttpEntity entity = response.getEntity();
            String bucketName = EntityUtils.toString(entity);
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            
            // ruleid: java-s3-predictable-bucket-creation-discovery
            s3Client.createBucket(bucketName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        // AWS SDK with name based on sequential numbering
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        int bucketNumber = 42;
        
        // ruleid: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket("data-bucket-" + bucketNumber);
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1() {
        // AWS SDK v1 with UUID for randomness
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String baseName = "company-backup";
        String uniqueId = UUID.randomUUID().toString();
        
        // ok: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket(baseName + "-" + uniqueId);
    }

    public void good_case_2() {
        // AWS SDK v2 with timestamp and random component
        S3Client s3 = S3Client.builder()
                .region(Region.US_WEST_2)
                .build();
        
        String timestamp = String.valueOf(Instant.now().getEpochSecond());
        String randomPart = UUID.randomUUID().toString().substring(0, 8);
        
        // ok: java-s3-predictable-bucket-creation-discovery
        s3.createBucket(CreateBucketRequest.builder()
                .bucket("user-uploads-" + timestamp + "-" + randomPart)
                .build());
    }

    public void good_case_3() {
        // MinIO client with secure random component
        try {
            MinioClient minioClient = MinioClient.builder()
                    .endpoint("https://play.min.io")
                    .credentials("Q3AM3UQ867SPQQA43P2F", "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG")
                    .build();
            
            byte[] randomBytes = new byte[8];
            new SecureRandom().nextBytes(randomBytes);
            String randomString = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
            
            // ok: java-s3-predictable-bucket-creation-discovery
            minioClient.makeBucket(MakeBucketArgs.builder()
                    .bucket("customer-data-" + randomString)
                    .build());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        // Google Cloud Storage with UUID
        Storage storage = StorageOptions.getDefaultInstance().getService();
        String uniqueId = UUID.randomUUID().toString();
        
        // ok: java-s3-predictable-bucket-creation-discovery
        storage.create(BucketInfo.of("financial-" + uniqueId));
    }

    public void good_case_5(HttpServletRequest request) {
        // AWS SDK with timestamp and environment
        String env = "production";
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        long timestamp = System.currentTimeMillis();
        
        // ok: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket("app-logs-" + env + "-" + timestamp);
    }

    public void good_case_6() {
        // JClouds with random component
        BlobStoreContext context = ContextBuilder.newBuilder("aws-s3")
                .credentials("identity", "credential")
                .buildView(BlobStoreContext.class);
        
        String randomPart = UUID.randomUUID().toString().substring(0, 12);
        
        // ok: java-s3-predictable-bucket-creation-discovery
        context.getBlobStore().createContainerInLocation(null, "backups-" + randomPart);
    }

    public void good_case_7() {
        // Azure Blob Storage with timestamp and random string
        String connectionString = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;EndpointSuffix=core.windows.net";
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder().connectionString(connectionString).buildClient();
        
        long timestamp = System.currentTimeMillis();
        String randomString = UUID.randomUUID().toString().substring(0, 8);
        
        // ok: java-s3-predictable-bucket-creation-discovery
        BlobContainerClient containerClient = blobServiceClient.createBlobContainer("invoices-" + timestamp + "-" + randomString);
    }

    public void good_case_8() {
        // AWS SDK with secure random number
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        SecureRandom random = new SecureRandom();
        String randomValue = String.valueOf(Math.abs(random.nextLong()));
        
        // ok: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket("backup-" + randomValue);
    }

    @PostMapping("/create-bucket")
    public void good_case_9(@RequestParam String companyId) {
        // AWS SDK with user input and random component
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String uniqueId = UUID.randomUUID().toString();
        
        // ok: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket("company-" + companyId + "-" + uniqueId);
    }

    public void good_case_10() {
        // AWS SDK with environment and random string
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String environment = System.getenv("ENVIRONMENT");
        String randomString = UUID.randomUUID().toString();
        
        // ok: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket("app-" + environment + "-" + randomString);
    }

    public void good_case_11() {
        try {
            // AWS SDK with name from config and random component
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            String baseName = FileUtils.readFileToString(new File("config/bucket-name.txt"), "UTF-8").trim();
            String uniqueId = UUID.randomUUID().toString();
            
            // ok: java-s3-predictable-bucket-creation-discovery
            s3Client.createBucket(baseName + "-" + uniqueId);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @GetMapping("/setup-storage")
    public void good_case_12(HttpServletRequest request) {
        // AWS SDK with tenant ID and timestamp
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String tenantId = request.getParameter("tenantId");
        long timestamp = System.currentTimeMillis();
        
        // ok: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket("tenant-" + tenantId + "-" + timestamp);
    }

    public void good_case_13() {
        // AWS SDK with project, environment and random string
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String project = "ecommerce";
        String env = "staging";
        String randomString = UUID.randomUUID().toString().substring(0, 8);
        
        // ok: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket(project + "-" + env + "-" + randomString);
    }

    public void good_case_14() {
        try {
            // AWS SDK with name from HTTP request plus random component
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url("https://api.example.com/bucket-config")
                    .build();
            
            Response response = client.newCall(request).execute();
            String baseNameFromApi = response.body().string();
            String uniqueId = UUID.randomUUID().toString();
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            
            // ok: java-s3-predictable-bucket-creation-discovery
            s3Client.createBucket(baseNameFromApi + "-" + uniqueId);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        // AWS SDK with base name and secure random bytes
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        byte[] randomBytes = new byte[16];
        new SecureRandom().nextBytes(randomBytes);
        String randomHex = "";
        for (byte b : randomBytes) {
            randomHex += String.format("%02x", b);
        }
        
        // ok: java-s3-predictable-bucket-creation-discovery
        s3Client.createBucket("data-bucket-" + randomHex);
    }
}
// {/fact}