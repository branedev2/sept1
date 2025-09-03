import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.*;
import java.io.File;
import java.util.HashMap;
import java.util.Map;

public class S3MetadataExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    public void bad_case_1() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        PutObjectRequest request = new PutObjectRequest("mybucket", "mykey", new File("/path/to/file"));
        
        ObjectMetadata metadata = new ObjectMetadata();
        // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata("Content-Type", "application/json");
        request.setMetadata(metadata);
        
        s3Client.putObject(request);
    }

    public void bad_case_2() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        ObjectMetadata metadata = new ObjectMetadata();
        // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata("UserID", "12345");
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void bad_case_3() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        Map<String, String> userMetadata = new HashMap<>();
        // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
        userMetadata.put("LastModified", "2023-01-01");
        
        ObjectMetadata metadata = new ObjectMetadata();
        for (Map.Entry<String, String> entry : userMetadata.entrySet()) {
            metadata.addUserMetadata(entry.getKey(), entry.getValue());
        }
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void bad_case_4() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        PutObjectRequest request = new PutObjectRequest("mybucket", "mykey", new File("/path/to/file"));
        
        ObjectMetadata metadata = new ObjectMetadata();
        String metadataKey = "FileOwner";
        // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata(metadataKey, "admin");
        request.setMetadata(metadata);
        
        s3Client.putObject(request);
    }

    public void bad_case_5() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        ObjectMetadata metadata = new ObjectMetadata();
        // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata("AccessLevel", "restricted");
        metadata.addUserMetadata("department", "finance");
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void bad_case_6() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        ObjectMetadata metadata = new ObjectMetadata();
        String key = "DocumentID";
        String value = "DOC-12345";
        // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata(key, value);
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void bad_case_7() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        PutObjectRequest request = new PutObjectRequest("mybucket", "mykey", new File("/path/to/file"));
        
        ObjectMetadata metadata = new ObjectMetadata();
        Map<String, String> metadataMap = new HashMap<>();
        // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadataMap.put("CreatedBy", "system");
        metadataMap.put("CreatedAt", "2023-05-15");
        
        for (Map.Entry<String, String> entry : metadataMap.entrySet()) {
            metadata.addUserMetadata(entry.getKey(), entry.getValue());
        }
        
        request.setMetadata(metadata);
        s3Client.putObject(request);
    }

    public void bad_case_8() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        ObjectMetadata metadata = new ObjectMetadata();
        // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata("FileName", "report.pdf");
        // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata("FileSize", "1024");
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void bad_case_9() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        String metadataKeyPrefix = "Project";
        String metadataKeySuffix = "ID";
        String metadataKey = metadataKeyPrefix + metadataKeySuffix;
        
        ObjectMetadata metadata = new ObjectMetadata();
        // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata(metadataKey, "PRJ-789");
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void bad_case_10() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        PutObjectRequest request = new PutObjectRequest("mybucket", "mykey", new File("/path/to/file"));
        
        ObjectMetadata metadata = new ObjectMetadata();
        for (int i = 0; i < 3; i++) {
            // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
            metadata.addUserMetadata("Tag" + i, "value" + i);
        }
        
        request.setMetadata(metadata);
        s3Client.putObject(request);
    }

    public void bad_case_11() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        ObjectMetadata metadata = new ObjectMetadata();
        if (System.currentTimeMillis() % 2 == 0) {
            // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
            metadata.addUserMetadata("ProcessID", "12345");
        } else {
            // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
            metadata.addUserMetadata("JobID", "67890");
        }
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void bad_case_12() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        String[] metadataKeys = {"UserName", "UserRole", "UserDepartment"};
        String[] metadataValues = {"john", "admin", "IT"};
        
        ObjectMetadata metadata = new ObjectMetadata();
        for (int i = 0; i < metadataKeys.length; i++) {
            // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
            metadata.addUserMetadata(metadataKeys[i], metadataValues[i]);
        }
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void bad_case_13() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        PutObjectRequest request = new PutObjectRequest("mybucket", "mykey", new File("/path/to/file"));
        
        ObjectMetadata metadata = new ObjectMetadata();
        // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata("X-Custom-Header", "custom-value");
        request.setMetadata(metadata);
        
        s3Client.putObject(request);
    }

    public void bad_case_14() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        ObjectMetadata metadata = new ObjectMetadata();
        String metadataKey = "SecurityLevel";
        String metadataValue = "confidential";
        
        try {
            // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
            metadata.addUserMetadata(metadataKey, metadataValue);
            s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        Map<String, String> userMetadata = new HashMap<>();
        // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
        userMetadata.put("VersionNumber", "1.0");
        // ruleid: java-checking-s3-object-user-metadata-key-case-sensitivity
        userMetadata.put("RevisionHistory", "Initial version");
        
        ObjectMetadata metadata = new ObjectMetadata();
        for (Map.Entry<String, String> entry : userMetadata.entrySet()) {
            metadata.addUserMetadata(entry.getKey(), entry.getValue());
        }
        
        s3Client.putObject(new PutObjectRequest("mybucket", "mykey", new File("/path/to/file")).withMetadata(metadata));
    }

    // True Negative Examples (Safe Code)

    public void good_case_1() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        PutObjectRequest request = new PutObjectRequest("mybucket", "mykey", new File("/path/to/file"));
        
        ObjectMetadata metadata = new ObjectMetadata();
        // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata("content-type", "application/json");
        request.setMetadata(metadata);
        
        s3Client.putObject(request);
    }

    public void good_case_2() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        ObjectMetadata metadata = new ObjectMetadata();
        // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata("userid", "12345");
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void good_case_3() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        Map<String, String> userMetadata = new HashMap<>();
        // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
        userMetadata.put("last-modified", "2023-01-01");
        
        ObjectMetadata metadata = new ObjectMetadata();
        for (Map.Entry<String, String> entry : userMetadata.entrySet()) {
            metadata.addUserMetadata(entry.getKey(), entry.getValue());
        }
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void good_case_4() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        PutObjectRequest request = new PutObjectRequest("mybucket", "mykey", new File("/path/to/file"));
        
        ObjectMetadata metadata = new ObjectMetadata();
        String metadataKey = "file-owner";
        // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata(metadataKey, "admin");
        request.setMetadata(metadata);
        
        s3Client.putObject(request);
    }

    public void good_case_5() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        ObjectMetadata metadata = new ObjectMetadata();
        // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata("access-level", "restricted");
        metadata.addUserMetadata("department", "finance");
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void good_case_6() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        ObjectMetadata metadata = new ObjectMetadata();
        String key = "document-id";
        String value = "DOC-12345";
        // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata(key, value);
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void good_case_7() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        PutObjectRequest request = new PutObjectRequest("mybucket", "mykey", new File("/path/to/file"));
        
        ObjectMetadata metadata = new ObjectMetadata();
        Map<String, String> metadataMap = new HashMap<>();
        // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadataMap.put("created-by", "system");
        metadataMap.put("created-at", "2023-05-15");
        
        for (Map.Entry<String, String> entry : metadataMap.entrySet()) {
            metadata.addUserMetadata(entry.getKey(), entry.getValue());
        }
        
        request.setMetadata(metadata);
        s3Client.putObject(request);
    }

    public void good_case_8() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        ObjectMetadata metadata = new ObjectMetadata();
        // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata("filename", "report.pdf");
        // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata("filesize", "1024");
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void good_case_9() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        String metadataKeyPrefix = "project";
        String metadataKeySuffix = "id";
        String metadataKey = metadataKeyPrefix + "-" + metadataKeySuffix;
        
        ObjectMetadata metadata = new ObjectMetadata();
        // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata(metadataKey, "PRJ-789");
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void good_case_10() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        PutObjectRequest request = new PutObjectRequest("mybucket", "mykey", new File("/path/to/file"));
        
        ObjectMetadata metadata = new ObjectMetadata();
        for (int i = 0; i < 3; i++) {
            // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
            metadata.addUserMetadata("tag-" + i, "value" + i);
        }
        
        request.setMetadata(metadata);
        s3Client.putObject(request);
    }

    public void good_case_11() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        ObjectMetadata metadata = new ObjectMetadata();
        if (System.currentTimeMillis() % 2 == 0) {
            // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
            metadata.addUserMetadata("process-id", "12345");
        } else {
            // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
            metadata.addUserMetadata("job-id", "67890");
        }
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void good_case_12() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        String[] metadataKeys = {"username", "user-role", "user-department"};
        String[] metadataValues = {"john", "admin", "IT"};
        
        ObjectMetadata metadata = new ObjectMetadata();
        for (int i = 0; i < metadataKeys.length; i++) {
            // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
            metadata.addUserMetadata(metadataKeys[i], metadataValues[i]);
        }
        
        s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
    }

    public void good_case_13() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        PutObjectRequest request = new PutObjectRequest("mybucket", "mykey", new File("/path/to/file"));
        
        ObjectMetadata metadata = new ObjectMetadata();
        // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
        metadata.addUserMetadata("x-custom-header", "custom-value");
        request.setMetadata(metadata);
        
        s3Client.putObject(request);
    }

    public void good_case_14() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        ObjectMetadata metadata = new ObjectMetadata();
        String metadataKey = "security-level";
        String metadataValue = "confidential";
        
        try {
            // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
            metadata.addUserMetadata(metadataKey, metadataValue);
            s3Client.putObject("mybucket", "mykey", new File("/path/to/file"), metadata);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        Map<String, String> userMetadata = new HashMap<>();
        // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
        userMetadata.put("version-number", "1.0");
        // ok: java-checking-s3-object-user-metadata-key-case-sensitivity
        userMetadata.put("revision-history", "Initial version");
        
        ObjectMetadata metadata = new ObjectMetadata();
        for (Map.Entry<String, String> entry : userMetadata.entrySet()) {
            metadata.addUserMetadata(entry.getKey(), entry.getValue());
        }
        
        s3Client.putObject(new PutObjectRequest("mybucket", "mykey", new File("/path/to/file")).withMetadata(metadata));
    }
}
// {/fact}