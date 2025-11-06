import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.*;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.PutObjectPresignRequest;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import org.apache.hadoop.fs.s3a.S3AFileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.conf.Configuration;
import org.apache.commons.io.IOUtils;
import com.ibm.cloud.objectstorage.services.s3.AmazonS3;
import com.ibm.cloud.objectstorage.services.s3.AmazonS3ClientBuilder;
import com.ibm.cloud.objectstorage.services.s3.model.ObjectMetadata;
import com.oracle.bmc.objectstorage.ObjectStorage;
import com.oracle.bmc.objectstorage.ObjectStorageClient;
import com.oracle.bmc.objectstorage.requests.PutObjectRequest;
import com.oracle.bmc.objectstorage.model.PutObjectRequest.Builder;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.models.BlobHttpHeaders;
import com.azure.storage.blob.specialized.BlockBlobClient;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.domain.BlobBuilder;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.RequestHeader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.net.URL;
import java.time.Duration;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import java.util.Enumeration;

// Security Issue: User metadata keys containing uppercase characters in S3 object metadata can lead to data inconsistency and potential security risks

// True Positive Examples (Vulnerable/Insecure Code)
public void bad_case_1(HttpServletRequest request) {
    // AWS SDK v1 - Using uppercase in metadata key
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = request.getParameter("metadataValue");
    
    ObjectMetadata metadata = new ObjectMetadata();
    // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.addUserMetadata("UserID", metadataValue);
    
    ByteArrayInputStream inputStream = new ByteArrayInputStream("content".getBytes());
    s3Client.putObject(bucketName, objectKey, inputStream, metadata);
}

public void bad_case_2(@RequestParam("file") MultipartFile file, HttpServletRequest request) {
    // AWS SDK v2 - Using uppercase in metadata key
    software.amazon.awssdk.services.s3.S3Client s3Client = S3Client.builder().build();
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = request.getParameter("metadataValue");
    
    Map<String, String> metadata = new HashMap<>();
    // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.put("Content-Owner", metadataValue);
    
    try {
        software.amazon.awssdk.services.s3.model.PutObjectRequest putObjectRequest = 
            software.amazon.awssdk.services.s3.model.PutObjectRequest.builder()
                .bucket(bucketName)
                .key(objectKey)
                .metadata(metadata)
                .build();
                
        s3Client.putObject(putObjectRequest, RequestBody.fromBytes(file.getBytes()));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3(HttpServletRequest request) {
    // MinIO Client - Using uppercase in metadata key
    try {
        MinioClient minioClient = MinioClient.builder()
            .endpoint("https://minio-server.com")
            .credentials("accessKey", "secretKey")
            .build();
        
        String bucketName = "my-bucket";
        String objectKey = "my-object";
        String metadataValue = request.getParameter("metadataValue");
        
        Map<String, String> headers = new HashMap<>();
        // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
        headers.put("X-Amz-Meta-CustomData", metadataValue);
        
        minioClient.putObject(
            PutObjectArgs.builder()
                .bucket(bucketName)
                .object(objectKey)
                .stream(new ByteArrayInputStream("content".getBytes()), -1, 10485760)
                .headers(headers)
                .build());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4(HttpServletRequest request) {
    // Google Cloud Storage - Using uppercase in metadata key
    Storage storage = StorageOptions.getDefaultInstance().getService();
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = request.getParameter("metadataValue");
    
    Map<String, String> metadata = new HashMap<>();
    // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.put("LastModifiedBy", metadataValue);
    
    BlobInfo blobInfo = BlobInfo.newBuilder(bucketName, objectKey)
        .setMetadata(metadata)
        .build();
    
    storage.create(blobInfo, "content".getBytes());
}

public void bad_case_5(HttpServletRequest request) {
    // IBM Cloud Object Storage - Using uppercase in metadata key
    com.ibm.cloud.objectstorage.services.s3.AmazonS3 s3Client = 
        com.ibm.cloud.objectstorage.services.s3.AmazonS3ClientBuilder.standard().build();
    
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = request.getParameter("metadataValue");
    
    com.ibm.cloud.objectstorage.services.s3.model.ObjectMetadata metadata = 
        new com.ibm.cloud.objectstorage.services.s3.model.ObjectMetadata();
    // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.addUserMetadata("FileType", metadataValue);
    
    ByteArrayInputStream inputStream = new ByteArrayInputStream("content".getBytes());
    s3Client.putObject(bucketName, objectKey, inputStream, metadata);
}

public void bad_case_6(@RequestHeader HttpHeaders headers) {
    // Oracle Cloud Infrastructure Object Storage - Using uppercase in metadata key
    ObjectStorage objectStorage = ObjectStorageClient.builder().build();
    String namespaceName = "my-namespace";
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = headers.getFirst("X-Custom-Value");
    
    Map<String, String> metadata = new HashMap<>();
    // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.put("SourceSystem", metadataValue);
    
    PutObjectRequest request = PutObjectRequest.builder()
        .namespaceName(namespaceName)
        .bucketName(bucketName)
        .objectName(objectKey)
        .opcMeta(metadata)
        .build();
    
    objectStorage.putObject(request, new ByteArrayInputStream("content".getBytes()));
}

public void bad_case_7(HttpServletRequest request) {
    // Azure Blob Storage - Using uppercase in metadata key
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
        .connectionString("connection-string")
        .buildClient();
    
    BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("my-container");
    BlobClient blobClient = containerClient.getBlobClient("my-blob");
    String metadataValue = request.getParameter("metadataValue");
    
    Map<String, String> metadata = new HashMap<>();
    // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.put("OwnerID", metadataValue);
    
    blobClient.setMetadata(metadata);
}

public void bad_case_8(@RequestBody String requestBody) {
    // JClouds BlobStore - Using uppercase in metadata key
    BlobStoreContext context = ContextBuilder.newBuilder("aws-s3")
        .credentials("accessKey", "secretKey")
        .buildView(BlobStoreContext.class);
    
    BlobStore blobStore = context.getBlobStore();
    String containerName = "my-container";
    String blobName = "my-blob";
    
    Blob blob = blobStore.blobBuilder(blobName)
        .payload(requestBody)
        .contentLength(requestBody.length())
        .build();
    
    // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
    blob.getMetadata().getUserMetadata().put("CreatedBy", "user");
    
    blobStore.putBlob(containerName, blob);
}

public void bad_case_9(HttpServletRequest request) {
    // AWS S3 Presigner - Using uppercase in metadata key
    S3Presigner presigner = S3Presigner.create();
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = request.getParameter("metadataValue");
    
    Map<String, String> metadata = new HashMap<>();
    // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.put("AppVersion", metadataValue);
    
    software.amazon.awssdk.services.s3.model.PutObjectRequest objectRequest = 
        software.amazon.awssdk.services.s3.model.PutObjectRequest.builder()
            .bucket(bucketName)
            .key(objectKey)
            .metadata(metadata)
            .build();
    
    PutObjectPresignRequest presignRequest = PutObjectPresignRequest.builder()
        .signatureDuration(Duration.ofMinutes(10))
        .putObjectRequest(objectRequest)
        .build();
    
    presigner.presignPutObject(presignRequest);
}

public void bad_case_10(HttpServletRequest request) {
    // Apache Hadoop S3A - Using uppercase in metadata key
    try {
        Configuration conf = new Configuration();
        conf.set("fs.s3a.access.key", "accessKey");
        conf.set("fs.s3a.secret.key", "secretKey");
        
        S3AFileSystem fs = new S3AFileSystem();
        fs.initialize(new java.net.URI("s3a://my-bucket"), conf);
        
        Path path = new Path("s3a://my-bucket/my-object");
        String metadataValue = request.getParameter("metadataValue");
        
        Map<String, String> metadata = new HashMap<>();
        // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.put("DataSource", metadataValue);
        
        // Using reflection to set metadata since S3AFileSystem doesn't expose direct metadata methods
        java.lang.reflect.Method method = S3AFileSystem.class.getDeclaredMethod("setMetadata", Path.class, Map.class);
        method.setAccessible(true);
        method.invoke(fs, path, metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
public void bad_case_11(@RequestParam("file") MultipartFile file, HttpServletRequest request) {
    // Spring Boot with AWS SDK - Using uppercase in metadata key
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    
    ObjectMetadata metadata = new ObjectMetadata();
    // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.addUserMetadata("X-Custom-Header", request.getHeader("X-Custom-Value"));
    
    try {
        s3Client.putObject(bucketName, objectKey, file.getInputStream(), metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    // AWS Transfer Manager - Using uppercase in metadata key
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    com.amazonaws.services.s3.transfer.TransferManager transferManager = 
        com.amazonaws.services.s3.transfer.TransferManagerBuilder.standard()
            .withS3Client(s3Client)
            .build();
    
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    File file = new File("/path/to/file");
    String metadataValue = request.getParameter("metadataValue");
    
    ObjectMetadata metadata = new ObjectMetadata();
    // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.addUserMetadata("ProcessID", metadataValue);
    
    try {
        transferManager.upload(bucketName, objectKey, file, metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13(@RequestParam Map<String, String> params) {
    // AWS SDK v1 with TransferUtility - Using uppercase in metadata key
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    com.amazonaws.services.s3.transfer.TransferUtility transferUtility = 
        com.amazonaws.services.s3.transfer.TransferUtility.builder()
            .s3Client(s3Client)
            .build();
    
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    File file = new File("/path/to/file");
    
    ObjectMetadata metadata = new ObjectMetadata();
    // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.addUserMetadata("ClientID", params.get("clientId"));
    
    transferUtility.upload(bucketName, objectKey, file, metadata);
}

public void bad_case_14(HttpServletRequest request) {
    // AWS SDK v2 with multipart upload - Using uppercase in metadata key
    S3Client s3Client = S3Client.builder().build();
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = request.getParameter("metadataValue");
    
    Map<String, String> metadata = new HashMap<>();
    // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.put("SecurityLevel", metadataValue);
    
    software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest createMultipartUploadRequest = 
        software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest.builder()
            .bucket(bucketName)
            .key(objectKey)
            .metadata(metadata)
            .build();
    
    s3Client.createMultipartUpload(createMultipartUploadRequest);
}

public void bad_case_15(HttpServletRequest request) {
    // AWS SDK v1 with PutObjectRequest - Using uppercase in metadata key
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = request.getParameter("metadataValue");
    
    ObjectMetadata metadata = new ObjectMetadata();
    // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.addUserMetadata("X-Amz-Meta-Department", metadataValue);
    
    PutObjectRequest putObjectRequest = new PutObjectRequest(
        bucketName, 
        objectKey, 
        new ByteArrayInputStream("content".getBytes()), 
        metadata
    );
    
    s3Client.putObject(putObjectRequest);
}

// True Negative Examples (Safe/Secure Code)
public void good_case_1(HttpServletRequest request) {
    // AWS SDK v1 - Using lowercase in metadata key
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = request.getParameter("metadataValue");
    
    ObjectMetadata metadata = new ObjectMetadata();
    // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.addUserMetadata("userid", metadataValue);
    
    ByteArrayInputStream inputStream = new ByteArrayInputStream("content".getBytes());
    s3Client.putObject(bucketName, objectKey, inputStream, metadata);
}

public void good_case_2(@RequestParam("file") MultipartFile file, HttpServletRequest request) {
    // AWS SDK v2 - Using lowercase in metadata key
    software.amazon.awssdk.services.s3.S3Client s3Client = S3Client.builder().build();
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = request.getParameter("metadataValue");
    
    Map<String, String> metadata = new HashMap<>();
    // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.put("content-owner", metadataValue);
    
    try {
        software.amazon.awssdk.services.s3.model.PutObjectRequest putObjectRequest = 
            software.amazon.awssdk.services.s3.model.PutObjectRequest.builder()
                .bucket(bucketName)
                .key(objectKey)
                .metadata(metadata)
                .build();
                
        s3Client.putObject(putObjectRequest, RequestBody.fromBytes(file.getBytes()));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3(HttpServletRequest request) {
    // MinIO Client - Using lowercase in metadata key
    try {
        MinioClient minioClient = MinioClient.builder()
            .endpoint("https://minio-server.com")
            .credentials("accessKey", "secretKey")
            .build();
        
        String bucketName = "my-bucket";
        String objectKey = "my-object";
        String metadataValue = request.getParameter("metadataValue");
        
        Map<String, String> headers = new HashMap<>();
        // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
        headers.put("x-amz-meta-customdata", metadataValue);
        
        minioClient.putObject(
            PutObjectArgs.builder()
                .bucket(bucketName)
                .object(objectKey)
                .stream(new ByteArrayInputStream("content".getBytes()), -1, 10485760)
                .headers(headers)
                .build());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4(HttpServletRequest request) {
    // Google Cloud Storage - Using lowercase in metadata key
    Storage storage = StorageOptions.getDefaultInstance().getService();
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = request.getParameter("metadataValue");
    
    Map<String, String> metadata = new HashMap<>();
    // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.put("lastmodifiedby", metadataValue);
    
    BlobInfo blobInfo = BlobInfo.newBuilder(bucketName, objectKey)
        .setMetadata(metadata)
        .build();
    
    storage.create(blobInfo, "content".getBytes());
}

public void good_case_5(HttpServletRequest request) {
    // IBM Cloud Object Storage - Using lowercase in metadata key
    com.ibm.cloud.objectstorage.services.s3.AmazonS3 s3Client = 
        com.ibm.cloud.objectstorage.services.s3.AmazonS3ClientBuilder.standard().build();
    
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = request.getParameter("metadataValue");
    
    com.ibm.cloud.objectstorage.services.s3.model.ObjectMetadata metadata = 
        new com.ibm.cloud.objectstorage.services.s3.model.ObjectMetadata();
    // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.addUserMetadata("filetype", metadataValue);
    
    ByteArrayInputStream inputStream = new ByteArrayInputStream("content".getBytes());
    s3Client.putObject(bucketName, objectKey, inputStream, metadata);
}

public void good_case_6(@RequestHeader HttpHeaders headers) {
    // Oracle Cloud Infrastructure Object Storage - Using lowercase in metadata key
    ObjectStorage objectStorage = ObjectStorageClient.builder().build();
    String namespaceName = "my-namespace";
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = headers.getFirst("X-Custom-Value");
    
    Map<String, String> metadata = new HashMap<>();
    // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.put("sourcesystem", metadataValue);
    
    PutObjectRequest request = PutObjectRequest.builder()
        .namespaceName(namespaceName)
        .bucketName(bucketName)
        .objectName(objectKey)
        .opcMeta(metadata)
        .build();
    
    objectStorage.putObject(request, new ByteArrayInputStream("content".getBytes()));
}

public void good_case_7(HttpServletRequest request) {
    // Azure Blob Storage - Using lowercase in metadata key
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
        .connectionString("connection-string")
        .buildClient();
    
    BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("my-container");
    BlobClient blobClient = containerClient.getBlobClient("my-blob");
    String metadataValue = request.getParameter("metadataValue");
    
    Map<String, String> metadata = new HashMap<>();
    // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.put("ownerid", metadataValue);
    
    blobClient.setMetadata(metadata);
}

public void good_case_8(@RequestBody String requestBody) {
    // JClouds BlobStore - Using lowercase in metadata key
    BlobStoreContext context = ContextBuilder.newBuilder("aws-s3")
        .credentials("accessKey", "secretKey")
        .buildView(BlobStoreContext.class);
    
    BlobStore blobStore = context.getBlobStore();
    String containerName = "my-container";
    String blobName = "my-blob";
    
    Blob blob = blobStore.blobBuilder(blobName)
        .payload(requestBody)
        .contentLength(requestBody.length())
        .build();
    
    // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
    blob.getMetadata().getUserMetadata().put("createdby", "user");
    
    blobStore.putBlob(containerName, blob);
}

public void good_case_9(HttpServletRequest request) {
    // AWS S3 Presigner - Using lowercase in metadata key
    S3Presigner presigner = S3Presigner.create();
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = request.getParameter("metadataValue");
    
    Map<String, String> metadata = new HashMap<>();
    // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.put("appversion", metadataValue);
    
    software.amazon.awssdk.services.s3.model.PutObjectRequest objectRequest = 
        software.amazon.awssdk.services.s3.model.PutObjectRequest.builder()
            .bucket(bucketName)
            .key(objectKey)
            .metadata(metadata)
            .build();
    
    PutObjectPresignRequest presignRequest = PutObjectPresignRequest.builder()
        .signatureDuration(Duration.ofMinutes(10))
        .putObjectRequest(objectRequest)
        .build();
    
    presigner.presignPutObject(presignRequest);
}

public void good_case_10(HttpServletRequest request) {
    // Apache Hadoop S3A - Using lowercase in metadata key
    try {
        Configuration conf = new Configuration();
        conf.set("fs.s3a.access.key", "accessKey");
        conf.set("fs.s3a.secret.key", "secretKey");
        
        S3AFileSystem fs = new S3AFileSystem();
        fs.initialize(new java.net.URI("s3a://my-bucket"), conf);
        
        Path path = new Path("s3a://my-bucket/my-object");
        String metadataValue = request.getParameter("metadataValue");
        
        Map<String, String> metadata = new HashMap<>();
        // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.put("datasource", metadataValue);
        
        // Using reflection to set metadata since S3AFileSystem doesn't expose direct metadata methods
        java.lang.reflect.Method method = S3AFileSystem.class.getDeclaredMethod("setMetadata", Path.class, Map.class);
        method.setAccessible(true);
        method.invoke(fs, path, metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
public void good_case_11(@RequestParam("file") MultipartFile file, HttpServletRequest request) {
    // Spring Boot with AWS SDK - Using lowercase in metadata key
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    
    ObjectMetadata metadata = new ObjectMetadata();
    // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.addUserMetadata("x-custom-header", request.getHeader("X-Custom-Value"));
    
    try {
        s3Client.putObject(bucketName, objectKey, file.getInputStream(), metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    // AWS Transfer Manager - Using lowercase in metadata key
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    com.amazonaws.services.s3.transfer.TransferManager transferManager = 
        com.amazonaws.services.s3.transfer.TransferManagerBuilder.standard()
            .withS3Client(s3Client)
            .build();
    
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    File file = new File("/path/to/file");
    String metadataValue = request.getParameter("metadataValue");
    
    ObjectMetadata metadata = new ObjectMetadata();
    // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.addUserMetadata("processid", metadataValue);
    
    try {
        transferManager.upload(bucketName, objectKey, file, metadata);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13(@RequestParam Map<String, String> params) {
    // AWS SDK v1 with TransferUtility - Using lowercase in metadata key
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    com.amazonaws.services.s3.transfer.TransferUtility transferUtility = 
        com.amazonaws.services.s3.transfer.TransferUtility.builder()
            .s3Client(s3Client)
            .build();
    
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    File file = new File("/path/to/file");
    
    ObjectMetadata metadata = new ObjectMetadata();
    // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.addUserMetadata("clientid", params.get("clientId"));
    
    transferUtility.upload(bucketName, objectKey, file, metadata);
}

public void good_case_14(HttpServletRequest request) {
    // AWS SDK v2 with multipart upload - Using lowercase in metadata key
    S3Client s3Client = S3Client.builder().build();
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = request.getParameter("metadataValue");
    
    Map<String, String> metadata = new HashMap<>();
    // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.put("securitylevel", metadataValue);
    
    software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest createMultipartUploadRequest = 
        software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest.builder()
            .bucket(bucketName)
            .key(objectKey)
            .metadata(metadata)
            .build();
    
    s3Client.createMultipartUpload(createMultipartUploadRequest);
}

public void good_case_15(HttpServletRequest request) {
    // AWS SDK v1 with PutObjectRequest - Using lowercase in metadata key
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    String bucketName = "my-bucket";
    String objectKey = "my-object";
    String metadataValue = request.getParameter("metadataValue");
    
    ObjectMetadata metadata = new ObjectMetadata();
    // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
    metadata.addUserMetadata("x-amz-meta-department", metadataValue);
    
    PutObjectRequest putObjectRequest = new PutObjectRequest(
        bucketName, 
        objectKey, 
        new ByteArrayInputStream("content".getBytes()), 
        metadata
    );
    
    s3Client.putObject(putObjectRequest);
}