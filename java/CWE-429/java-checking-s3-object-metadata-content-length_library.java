import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.*;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import org.apache.commons.io.IOUtils;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import javax.servlet.http.HttpServletRequest;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import com.google.cloud.storage.*;
import io.minio.*;
import io.minio.errors.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import com.azure.storage.blob.*;
import com.azure.storage.blob.models.*;
import com.azure.storage.blob.specialized.*;
import com.azure.core.http.rest.Response;
import reactor.core.publisher.Mono;
import java.util.concurrent.CompletableFuture;

// Security Issue: Uploading objects to Amazon S3 without setting the content length can lead to excessive memory consumption

// True Positive Examples (Vulnerable/Insecure Code)
public void bad_case_1(HttpServletRequest request) {
    try {
        // Get input stream from HTTP request
        InputStream inputStream = request.getInputStream();
        
        // AWS SDK v1: Creating S3 client
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Create object metadata without content length
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/octet-stream");
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject("my-bucket", "my-key", inputStream, metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_2(@RequestParam("file") MultipartFile file) {
    try {
        // Spring MultipartFile as source
        InputStream fileInputStream = file.getInputStream();
        
        // AWS SDK v1: Using AmazonS3Client
        BasicAWSCredentials credentials = new BasicAWSCredentials("accessKey", "secretKey");
        AmazonS3 s3Client = new AmazonS3Client(credentials);
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType(file.getContentType());
        // Missing content length
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject(new PutObjectRequest("bucket-name", file.getOriginalFilename(), fileInputStream, metadata));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3(HttpServletRequest request) {
    try {
        // AWS SDK v2: Using S3Client
        S3Client s3 = S3Client.builder()
                .region(Region.US_EAST_1)
                .build();
        
        // Get input stream from HTTP request
        InputStream inputStream = request.getInputStream();
        byte[] bytes = IOUtils.toByteArray(inputStream);
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3.putObject(PutObjectRequest.builder()
                .bucket("my-bucket")
                .key("my-key")
                .build(), 
                RequestBody.fromBytes(bytes));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4(@RequestBody String requestBody) {
    try {
        // AWS SDK v1: Using TransferManager for large uploads
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Convert request body to input stream
        InputStream inputStream = new ByteArrayInputStream(requestBody.getBytes());
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("text/plain");
        // Missing content length
        
        // ruleid: java-checking-s3-object-metadata-content-length
        Upload upload = new TransferManager(s3Client).upload("my-bucket", "my-key", inputStream, metadata);
        upload.waitForCompletion();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5(@RequestParam("url") String url) {
    try {
        // OkHttp to download file from URL provided in request
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder().url(url).build();
        Response response = client.newCall(request).execute();
        
        if (response.isSuccessful() && response.body() != null) {
            InputStream inputStream = response.body().byteStream();
            
            // AWS SDK v1
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                    .withRegion(Regions.US_EAST_1)
                    .build();
            
            ObjectMetadata metadata = new ObjectMetadata();
            // Missing content length
            
            // ruleid: java-checking-s3-object-metadata-content-length
            s3Client.putObject("my-bucket", "downloaded-file", inputStream, metadata);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6(HttpServletRequest request) {
    try {
        // AWS SDK v2: Using S3AsyncClient
        S3AsyncClient s3Async = S3AsyncClient.builder()
                .region(Region.US_EAST_1)
                .build();
        
        // Get input stream from HTTP request
        InputStream inputStream = request.getInputStream();
        byte[] bytes = IOUtils.toByteArray(inputStream);
        
        // ruleid: java-checking-s3-object-metadata-content-length
        CompletableFuture<PutObjectResponse> future = s3Async.putObject(
                PutObjectRequest.builder()
                        .bucket("my-bucket")
                        .key("my-key")
                        .build(),
                AsyncRequestBody.fromBytes(bytes));
        future.join();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7(@RequestParam("file") MultipartFile file) {
    try {
        // MinIO client for S3-compatible storage
        MinioClient minioClient = MinioClient.builder()
                .endpoint("https://play.min.io")
                .credentials("Q3AM3UQ867SPQQA43P2F", "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG")
                .build();
        
        // Get input stream from uploaded file
        InputStream inputStream = file.getInputStream();
        
        // ruleid: java-checking-s3-object-metadata-content-length
        minioClient.putObject(
                PutObjectArgs.builder()
                        .bucket("my-bucket")
                        .object(file.getOriginalFilename())
                        .stream(inputStream, -1, 10485760) // -1 means unknown size
                        .contentType(file.getContentType())
                        .build());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    try {
        // Apache HttpClient to get content from URL
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(request.getParameter("url"));
        CloseableHttpResponse response = httpClient.execute(httpGet);
        HttpEntity entity = response.getEntity();
        
        if (entity != null) {
            InputStream inputStream = entity.getContent();
            
            // AWS SDK v1
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                    .withRegion(Regions.US_EAST_1)
                    .build();
            
            ObjectMetadata metadata = new ObjectMetadata();
            // Missing content length
            
            // ruleid: java-checking-s3-object-metadata-content-length
            s3Client.putObject("my-bucket", "downloaded-file", inputStream, metadata);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9(@RequestParam("data") String data) {
    try {
        // AWS SDK v1: Using presigned URL
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Convert request data to input stream
        InputStream inputStream = new ByteArrayInputStream(data.getBytes());
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("text/plain");
        // Missing content length
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject(new PutObjectRequest("my-bucket", "my-key", inputStream, metadata)
                .withCannedAcl(CannedAccessControlList.PublicRead));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    try {
        // Google Cloud Storage with S3 compatibility layer
        Storage storage = StorageOptions.newBuilder()
                .setProjectId("my-project")
                .build()
                .getService();
        
        // Get input stream from HTTP request
        InputStream inputStream = request.getInputStream();
        byte[] bytes = IOUtils.toByteArray(inputStream);
        
        // ruleid: java-checking-s3-object-metadata-content-length
        BlobId blobId = BlobId.of("my-bucket", "my-object");
        BlobInfo blobInfo = BlobInfo.newBuilder(blobId)
                .setContentType("application/octet-stream")
                .build();
        storage.create(blobInfo, bytes);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11(@RequestParam("file") MultipartFile file) {
    try {
        // Azure Blob Storage client
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                .connectionString("DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;EndpointSuffix=core.windows.net")
                .buildClient();
        
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("my-container");
        BlobClient blobClient = containerClient.getBlobClient(file.getOriginalFilename());
        
        // Get input stream from uploaded file
        InputStream inputStream = file.getInputStream();
        
        // ruleid: java-checking-s3-object-metadata-content-length
        blobClient.upload(inputStream, null);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    try {
        // AWS SDK v1 with custom S3 endpoint
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration("https://s3.custom-domain.com", "us-east-1"))
                .withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials("accessKey", "secretKey")))
                .build();
        
        // Get input stream from HTTP request
        InputStream inputStream = request.getInputStream();
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/json");
        // Missing content length
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject("my-bucket", "my-key", inputStream, metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13(@RequestParam("fileUrl") String fileUrl) {
    try {
        // Java 11 HTTP Client to download file
        java.net.http.HttpClient httpClient = java.net.http.HttpClient.newHttpClient();
        java.net.http.HttpRequest httpRequest = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI.create(fileUrl))
                .build();
        
        java.net.http.HttpResponse<InputStream> response = httpClient.send(
                httpRequest, java.net.http.HttpResponse.BodyHandlers.ofInputStream());
        
        InputStream inputStream = response.body();
        
        // AWS SDK v1
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        ObjectMetadata metadata = new ObjectMetadata();
        // Missing content length
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject("my-bucket", "downloaded-file", inputStream, metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) {
    try {
        // AWS SDK v2 with custom configuration
        S3Client s3 = S3Client.builder()
                .region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("accessKey", "secretKey")))
                .build();
        
        // Get input stream from HTTP request
        InputStream inputStream = request.getInputStream();
        byte[] bytes = IOUtils.toByteArray(inputStream);
        
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-meta-custom", "value");
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3.putObject(PutObjectRequest.builder()
                .bucket("my-bucket")
                .key("my-key")
                .metadata(metadata)
                .build(), 
                RequestBody.fromBytes(bytes));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15(@RequestParam("file") MultipartFile file) {
    try {
        // AWS SDK v1 with server-side encryption
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Get input stream from uploaded file
        InputStream inputStream = file.getInputStream();
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setSSEAlgorithm(ObjectMetadata.AES_256_SERVER_SIDE_ENCRYPTION);
        metadata.setContentType(file.getContentType());
        // Missing content length
        
        // ruleid: java-checking-s3-object-metadata-content-length
        s3Client.putObject("my-bucket", file.getOriginalFilename(), inputStream, metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)
public void good_case_1(HttpServletRequest request) {
    try {
        // Get input stream from HTTP request
        InputStream inputStream = request.getInputStream();
        byte[] bytes = IOUtils.toByteArray(inputStream);
        
        // AWS SDK v1: Creating S3 client
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Create object metadata with content length
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/octet-stream");
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(bytes.length);
        
        s3Client.putObject("my-bucket", "my-key", new ByteArrayInputStream(bytes), metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2(@RequestParam("file") MultipartFile file) {
    try {
        // Spring MultipartFile as source
        InputStream fileInputStream = file.getInputStream();
        
        // AWS SDK v1: Using AmazonS3Client
        BasicAWSCredentials credentials = new BasicAWSCredentials("accessKey", "secretKey");
        AmazonS3 s3Client = new AmazonS3Client(credentials);
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType(file.getContentType());
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(file.getSize());
        
        s3Client.putObject(new PutObjectRequest("bucket-name", file.getOriginalFilename(), fileInputStream, metadata));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3(HttpServletRequest request) {
    try {
        // AWS SDK v2: Using S3Client with known content length
        S3Client s3 = S3Client.builder()
                .region(Region.US_EAST_1)
                .build();
        
        // Get input stream from HTTP request and determine size
        InputStream inputStream = request.getInputStream();
        byte[] bytes = IOUtils.toByteArray(inputStream);
        
        // ok: java-checking-s3-object-metadata-content-length
        s3.putObject(PutObjectRequest.builder()
                .bucket("my-bucket")
                .key("my-key")
                .contentLength((long) bytes.length)
                .build(), 
                RequestBody.fromBytes(bytes));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4(@RequestBody String requestBody) {
    try {
        // AWS SDK v1: Using TransferManager for large uploads
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Convert request body to input stream
        byte[] bytes = requestBody.getBytes();
        InputStream inputStream = new ByteArrayInputStream(bytes);
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("text/plain");
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(bytes.length);
        
        Upload upload = new TransferManager(s3Client).upload("my-bucket", "my-key", inputStream, metadata);
        upload.waitForCompletion();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5(@RequestParam("url") String url) {
    try {
        // OkHttp to download file from URL provided in request
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder().url(url).build();
        Response response = client.newCall(request).execute();
        
        if (response.isSuccessful() && response.body() != null) {
            byte[] bytes = response.body().bytes(); // Get bytes and close the response
            InputStream inputStream = new ByteArrayInputStream(bytes);
            
            // AWS SDK v1
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                    .withRegion(Regions.US_EAST_1)
                    .build();
            
            ObjectMetadata metadata = new ObjectMetadata();
            // ok: java-checking-s3-object-metadata-content-length
            metadata.setContentLength(bytes.length);
            
            s3Client.putObject("my-bucket", "downloaded-file", inputStream, metadata);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6(HttpServletRequest request) {
    try {
        // AWS SDK v2: Using S3AsyncClient with content length
        S3AsyncClient s3Async = S3AsyncClient.builder()
                .region(Region.US_EAST_1)
                .build();
        
        // Get input stream from HTTP request
        InputStream inputStream = request.getInputStream();
        byte[] bytes = IOUtils.toByteArray(inputStream);
        
        // ok: java-checking-s3-object-metadata-content-length
        CompletableFuture<PutObjectResponse> future = s3Async.putObject(
                PutObjectRequest.builder()
                        .bucket("my-bucket")
                        .key("my-key")
                        .contentLength((long) bytes.length)
                        .build(),
                AsyncRequestBody.fromBytes(bytes));
        future.join();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7(@RequestParam("file") MultipartFile file) {
    try {
        // MinIO client for S3-compatible storage
        MinioClient minioClient = MinioClient.builder()
                .endpoint("https://play.min.io")
                .credentials("Q3AM3UQ867SPQQA43P2F", "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG")
                .build();
        
        // Get input stream and size from uploaded file
        InputStream inputStream = file.getInputStream();
        long size = file.getSize();
        
        // ok: java-checking-s3-object-metadata-content-length
        minioClient.putObject(
                PutObjectArgs.builder()
                        .bucket("my-bucket")
                        .object(file.getOriginalFilename())
                        .stream(inputStream, size, -1) // Specify size
                        .contentType(file.getContentType())
                        .build());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    try {
        // Apache HttpClient to get content from URL
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(request.getParameter("url"));
        CloseableHttpResponse response = httpClient.execute(httpGet);
        HttpEntity entity = response.getEntity();
        
        if (entity != null) {
            // Read all bytes to determine length
            byte[] bytes = IOUtils.toByteArray(entity.getContent());
            InputStream inputStream = new ByteArrayInputStream(bytes);
            
            // AWS SDK v1
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                    .withRegion(Regions.US_EAST_1)
                    .build();
            
            ObjectMetadata metadata = new ObjectMetadata();
            // ok: java-checking-s3-object-metadata-content-length
            metadata.setContentLength(bytes.length);
            
            s3Client.putObject("my-bucket", "downloaded-file", inputStream, metadata);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9(@RequestParam("data") String data) {
    try {
        // AWS SDK v1: Using presigned URL
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Convert request data to input stream
        byte[] bytes = data.getBytes();
        InputStream inputStream = new ByteArrayInputStream(bytes);
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("text/plain");
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(bytes.length);
        
        s3Client.putObject(new PutObjectRequest("my-bucket", "my-key", inputStream, metadata)
                .withCannedAcl(CannedAccessControlList.PublicRead));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    try {
        // Google Cloud Storage with S3 compatibility layer
        Storage storage = StorageOptions.newBuilder()
                .setProjectId("my-project")
                .build()
                .getService();
        
        // Get input stream from HTTP request
        InputStream inputStream = request.getInputStream();
        byte[] bytes = IOUtils.toByteArray(inputStream);
        
        // ok: java-checking-s3-object-metadata-content-length
        BlobId blobId = BlobId.of("my-bucket", "my-object");
        BlobInfo blobInfo = BlobInfo.newBuilder(blobId)
                .setContentType("application/octet-stream")
                .build();
        storage.create(blobInfo, bytes, Storage.BlobTargetOption.detectContentType());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11(@RequestParam("file") MultipartFile file) {
    try {
        // Azure Blob Storage client
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                .connectionString("DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;EndpointSuffix=core.windows.net")
                .buildClient();
        
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("my-container");
        BlobClient blobClient = containerClient.getBlobClient(file.getOriginalFilename());
        
        // Get input stream and length from uploaded file
        InputStream inputStream = file.getInputStream();
        long length = file.getSize();
        
        // ok: java-checking-s3-object-metadata-content-length
        BlobHttpHeaders headers = new BlobHttpHeaders()
                .setContentType(file.getContentType());
        
        blobClient.upload(inputStream, length, true);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    try {
        // AWS SDK v1 with custom S3 endpoint
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration("https://s3.custom-domain.com", "us-east-1"))
                .withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials("accessKey", "secretKey")))
                .build();
        
        // Get input stream from HTTP request
        InputStream inputStream = request.getInputStream();
        byte[] bytes = IOUtils.toByteArray(inputStream);
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/json");
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(bytes.length);
        
        s3Client.putObject("my-bucket", "my-key", new ByteArrayInputStream(bytes), metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13(@RequestParam("fileUrl") String fileUrl) {
    try {
        // Java 11 HTTP Client to download file
        java.net.http.HttpClient httpClient = java.net.http.HttpClient.newHttpClient();
        java.net.http.HttpRequest httpRequest = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI.create(fileUrl))
                .build();
        
        // Get bytes directly
        java.net.http.HttpResponse<byte[]> response = httpClient.send(
                httpRequest, java.net.http.HttpResponse.BodyHandlers.ofByteArray());
        
        byte[] bytes = response.body();
        InputStream inputStream = new ByteArrayInputStream(bytes);
        
        // AWS SDK v1
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        ObjectMetadata metadata = new ObjectMetadata();
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(bytes.length);
        
        s3Client.putObject("my-bucket", "downloaded-file", inputStream, metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) {
    try {
        // AWS SDK v2 with custom configuration
        S3Client s3 = S3Client.builder()
                .region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("accessKey", "secretKey")))
                .build();
        
        // Get input stream from HTTP request
        InputStream inputStream = request.getInputStream();
        byte[] bytes = IOUtils.toByteArray(inputStream);
        
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-meta-custom", "value");
        
        // ok: java-checking-s3-object-metadata-content-length
        s3.putObject(PutObjectRequest.builder()
                .bucket("my-bucket")
                .key("my-key")
                .contentLength((long) bytes.length)
                .metadata(metadata)
                .build(), 
                RequestBody.fromBytes(bytes));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15(@RequestParam("file") MultipartFile file) {
    try {
        // AWS SDK v1 with server-side encryption
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        // Get input stream from uploaded file
        InputStream inputStream = file.getInputStream();
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setSSEAlgorithm(ObjectMetadata.AES_256_SERVER_SIDE_ENCRYPTION);
        metadata.setContentType(file.getContentType());
        // ok: java-checking-s3-object-metadata-content-length
        metadata.setContentLength(file.getSize());
        
        s3Client.putObject("my-bucket", file.getOriginalFilename(), inputStream, metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}