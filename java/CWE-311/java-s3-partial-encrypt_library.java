import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.IOUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.core.sync.RequestBody;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.apache.commons.crypto.stream.CtrCryptoInputStream;
import org.apache.commons.crypto.stream.CtrCryptoOutputStream;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Properties;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.properties.EncryptableProperties;

// Security Issue: Conditional logic in encryption routines can inadvertently leave sensitive data unencrypted

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    try {
        String data = request.getParameter("data");
        String encryptFlag = request.getParameter("encrypt");
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        ObjectMetadata metadata = new ObjectMetadata();
        
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        
        // ruleid: java-s3-partial-encrypt
        if ("true".equals(encryptFlag)) {
            // Only encrypt if flag is set to true
            SecretKey key = KeyGenerator.getInstance("AES").generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(dataBytes);
            metadata.setSSEAlgorithm(ObjectMetadata.AES_256_SERVER_SIDE_ENCRYPTION);
            s3Client.putObject("my-bucket", "encrypted-data", new String(encryptedData), metadata);
        } else {
            // Data is stored unencrypted
            s3Client.putObject("my-bucket", "raw-data", new String(dataBytes), metadata);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_2(HttpServletRequest request) {
    try {
        String userType = request.getParameter("userType");
        String sensitiveData = request.getParameter("sensitiveData");
        
        // Initialize Google Cloud Storage
        Storage storage = StorageOptions.getDefaultInstance().getService();
        
        // ruleid: java-s3-partial-encrypt
        if ("premium".equals(userType)) {
            // Only premium users get encrypted data
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(sensitiveData.getBytes());
            
            // Store encrypted data
            BlobInfo blobInfo = BlobInfo.newBuilder("secure-bucket", "encrypted-file")
                    .setContentType("application/octet-stream")
                    .build();
            storage.create(blobInfo, encryptedData);
        } else {
            // Regular users get unencrypted data
            BlobInfo blobInfo = BlobInfo.newBuilder("regular-bucket", "plaintext-file")
                    .setContentType("text/plain")
                    .build();
            storage.create(blobInfo, sensitiveData.getBytes());
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3(HttpServletRequest request) {
    try {
        String environment = request.getParameter("environment");
        String configData = request.getParameter("configData");
        
        // AWS KMS client for encryption
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // ruleid: java-s3-partial-encrypt
        if ("production".equals(environment)) {
            // Only encrypt in production
            ByteBuffer plaintext = ByteBuffer.wrap(configData.getBytes());
            EncryptRequest encryptRequest = new EncryptRequest()
                .withKeyId("alias/config-key")
                .withPlaintext(plaintext);
            
            ByteBuffer ciphertext = kmsClient.encrypt(encryptRequest).getCiphertextBlob();
            
            // Save encrypted config
            Files.write(Paths.get("/app/config/secure-config.dat"), ciphertext.array());
        } else {
            // Save unencrypted in dev/test environments
            Files.write(Paths.get("/app/config/config.properties"), configData.getBytes());
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4(HttpServletRequest request) {
    try {
        String dataType = request.getParameter("dataType");
        String content = request.getParameter("content");
        
        // Azure Blob Storage client
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString("DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;EndpointSuffix=core.windows.net")
            .buildClient();
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("data-container");
        
        // ruleid: java-s3-partial-encrypt
        if ("sensitive".equals(dataType)) {
            // Encrypt sensitive data
            SecretKey key = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            
            byte[] encrypted = cipher.doFinal(content.getBytes());
            byte[] encryptedWithIv = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
            System.arraycopy(encrypted, 0, encryptedWithIv, iv.length, encrypted.length);
            
            BlobClient blobClient = containerClient.getBlobClient("sensitive-data.enc");
            blobClient.upload(new ByteArrayInputStream(encryptedWithIv), encryptedWithIv.length);
        } else {
            // Store non-sensitive data without encryption
            BlobClient blobClient = containerClient.getBlobClient("regular-data.txt");
            blobClient.upload(new ByteArrayInputStream(content.getBytes()), content.length());
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request) {
    try {
        String securityLevel = request.getParameter("securityLevel");
        String userData = request.getParameter("userData");
        
        // MinIO client
        MinioClient minioClient = MinioClient.builder()
            .endpoint("https://minio-server:9000")
            .credentials("accessKey", "secretKey")
            .build();
        
        // ruleid: java-s3-partial-encrypt
        if ("high".equals(securityLevel)) {
            // High security - encrypt data
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(userData.getBytes());
            
            // Store encrypted data
            ByteArrayInputStream bais = new ByteArrayInputStream(encryptedData);
            minioClient.putObject(
                PutObjectArgs.builder()
                    .bucket("secure-bucket")
                    .object("encrypted-user-data")
                    .stream(bais, encryptedData.length, -1)
                    .build());
        } else {
            // Lower security - store plaintext
            ByteArrayInputStream bais = new ByteArrayInputStream(userData.getBytes());
            minioClient.putObject(
                PutObjectArgs.builder()
                    .bucket("regular-bucket")
                    .object("user-data")
                    .stream(bais, userData.getBytes().length, -1)
                    .build());
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6(HttpServletRequest request) {
    try {
        String fileType = request.getParameter("fileType");
        String fileContent = request.getParameter("fileContent");
        
        // AWS SDK v2 S3 client
        S3Client s3Client = S3Client.builder().build();
        
        // ruleid: java-s3-partial-encrypt
        if ("confidential".equals(fileType)) {
            // Encrypt confidential files
            SecretKeySpec key = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Note: ECB is not recommended
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(fileContent.getBytes());
            
            // Upload encrypted data
            s3Client.putObject(
                PutObjectRequest.builder()
                    .bucket("confidential-bucket")
                    .key("encrypted-file.dat")
                    .build(),
                RequestBody.fromBytes(encryptedData)
            );
        } else {
            // Store regular files without encryption
            s3Client.putObject(
                PutObjectRequest.builder()
                    .bucket("regular-bucket")
                    .key("plaintext-file.txt")
                    .build(),
                RequestBody.fromBytes(fileContent.getBytes())
            );
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7(HttpServletRequest request) {
    try {
        String dataCategory = request.getParameter("category");
        String content = request.getParameter("content");
        
        // BouncyCastle for encryption
        byte[] key = "0123456789abcdef".getBytes();
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        
        // ruleid: java-s3-partial-encrypt
        if ("financial".equals(dataCategory)) {
            // Encrypt financial data
            KeyParameter keyParam = new KeyParameter(key);
            ParametersWithIV params = new ParametersWithIV(keyParam, iv);
            
            CBCBlockCipher blockCipher = new CBCBlockCipher(new AESEngine());
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher);
            cipher.init(true, params);
            
            byte[] inputBytes = content.getBytes();
            byte[] outputBytes = new byte[cipher.getOutputSize(inputBytes.length)];
            
            int length = cipher.processBytes(inputBytes, 0, inputBytes.length, outputBytes, 0);
            cipher.doFinal(outputBytes, length);
            
            // Write encrypted data to file
            FileOutputStream fos = new FileOutputStream("financial-data.enc");
            fos.write(iv);
            fos.write(outputBytes);
            fos.close();
        } else {
            // Write unencrypted data for non-financial categories
            FileOutputStream fos = new FileOutputStream("regular-data.txt");
            fos.write(content.getBytes());
            fos.close();
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    try {
        String isConfidential = request.getParameter("confidential");
        String documentText = request.getParameter("document");
        
        // Apache Commons Crypto
        Properties properties = new Properties();
        properties.setProperty("commons.crypto.cipher.transformation", "AES/CTR/NoPadding");
        
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(iv);
        
        // ruleid: java-s3-partial-encrypt
        if ("yes".equals(isConfidential)) {
            // Encrypt confidential documents
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            try (CtrCryptoOutputStream cryptoStream = new CtrCryptoOutputStream(
                    properties, outputStream, key, iv)) {
                cryptoStream.write(documentText.getBytes());
                cryptoStream.flush();
            }
            
            // Save encrypted document
            Files.write(Paths.get("confidential-doc.enc"), outputStream.toByteArray());
        } else {
            // Save regular document without encryption
            Files.write(Paths.get("regular-doc.txt"), documentText.getBytes());
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9(HttpServletRequest request) {
    try {
        String dataImportance = request.getParameter("importance");
        String userData = request.getParameter("userData");
        
        // Google Tink for encryption
        AeadConfig.register();
        
        // ruleid: java-s3-partial-encrypt
        if ("critical".equals(dataImportance)) {
            // Encrypt critical data
            KeysetHandle keysetHandle = KeysetHandle.generateNew(
                    AeadKeyTemplates.AES256_GCM);
            Aead aead = keysetHandle.getPrimitive(Aead.class);
            
            byte[] plaintext = userData.getBytes();
            byte[] associatedData = "context".getBytes();
            byte[] ciphertext = aead.encrypt(plaintext, associatedData);
            
            // Save encrypted data
            FileOutputStream out = new FileOutputStream("critical-data.enc");
            out.write(ciphertext);
            out.close();
        } else {
            // Save non-critical data without encryption
            FileOutputStream out = new FileOutputStream("regular-data.txt");
            out.write(userData.getBytes());
            out.close();
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    try {
        String userRole = request.getParameter("role");
        String configData = request.getParameter("config");
        
        // Jasypt for property encryption
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setPassword("masterPassword");
        encryptor.setAlgorithm("PBEWithMD5AndDES");
        
        Properties props = new Properties();
        
        // ruleid: java-s3-partial-encrypt
        if ("admin".equals(userRole)) {
            // Encrypt configuration for admin users
            props.setProperty("database.username", encryptor.encrypt("admin_user"));
            props.setProperty("database.password", encryptor.encrypt("admin_pass"));
            props.setProperty("api.key", encryptor.encrypt("admin_api_key"));
            props.setProperty("custom.config", encryptor.encrypt(configData));
            
            // Save encrypted properties
            FileOutputStream out = new FileOutputStream("admin-config.properties");
            props.store(out, "Admin Configuration");
            out.close();
        } else {
            // Save regular user config without encryption
            props.setProperty("database.username", "regular_user");
            props.setProperty("database.password", "regular_pass");
            props.setProperty("api.key", "regular_api_key");
            props.setProperty("custom.config", configData);
            
            FileOutputStream out = new FileOutputStream("user-config.properties");
            props.store(out, "User Configuration");
            out.close();
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11(@RequestParam String encryptionMode, @RequestParam String message) {
    try {
        // Spring Web controller handling encryption
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // ruleid: java-s3-partial-encrypt
        if ("secure".equals(encryptionMode)) {
            // Encrypt in secure mode
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(message.getBytes());
            byte[] iv = cipher.getIV();
            
            // Save encrypted message
            FileOutputStream fos = new FileOutputStream("secure-message.enc");
            fos.write(iv);
            fos.write(encryptedData);
            fos.close();
        } else {
            // Save plaintext message in standard mode
            FileOutputStream fos = new FileOutputStream("standard-message.txt");
            fos.write(message.getBytes());
            fos.close();
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    try {
        String dataSource = request.getParameter("source");
        String content = request.getParameter("content");
        
        // File channel for writing data
        FileChannel fileChannel = FileChannel.open(
            Paths.get("output-data.bin"),
            StandardOpenOption.CREATE,
            StandardOpenOption.WRITE
        );
        
        // ruleid: java-s3-partial-encrypt
        if ("external".equals(dataSource)) {
            // Encrypt data from external sources
            SecretKey key = KeyGenerator.getInstance("AES").generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            
            byte[] iv = cipher.getIV();
            byte[] encryptedData = cipher.doFinal(content.getBytes());
            
            // Write IV and encrypted data
            ByteBuffer buffer = ByteBuffer.allocate(iv.length + encryptedData.length);
            buffer.put(iv);
            buffer.put(encryptedData);
            buffer.flip();
            fileChannel.write(buffer);
        } else {
            // Write internal data without encryption
            ByteBuffer buffer = ByteBuffer.wrap(content.getBytes());
            fileChannel.write(buffer);
        }
        fileChannel.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13(HttpServletRequest request) {
    try {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet("https://api.example.com/data");
        String apiResponse = IOUtils.toString(httpClient.execute(httpGet).getEntity().getContent());
        
        String processingMode = request.getParameter("mode");
        
        // ruleid: java-s3-partial-encrypt
        if ("secure".equals(processingMode)) {
            // Encrypt API response in secure mode
            SecretKey key = KeyGenerator.getInstance("AES").generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            
            byte[] encryptedData = cipher.doFinal(apiResponse.getBytes());
            String encodedData = Base64.getEncoder().encodeToString(encryptedData);
            
            // Save encrypted response
            FileOutputStream fos = new FileOutputStream("secure-api-response.enc");
            fos.write(encodedData.getBytes());
            fos.close();
        } else {
            // Save plaintext response in standard mode
            FileOutputStream fos = new FileOutputStream("api-response.json");
            fos.write(apiResponse.getBytes());
            fos.close();
        }
        httpClient.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) {
    try {
        String storageType = request.getParameter("storage");
        String sensitiveInfo = request.getParameter("sensitiveInfo");
        
        Map<String, String> dataMap = new HashMap<>();
        dataMap.put("timestamp", String.valueOf(System.currentTimeMillis()));
        dataMap.put("info", sensitiveInfo);
        
        // ruleid: java-s3-partial-encrypt
        if ("secure".equals(storageType)) {
            // Encrypt for secure storage
            SecretKey key = KeyGenerator.getInstance("AES").generateKey();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            
            byte[] encryptedInfo = cipher.doFinal(sensitiveInfo.getBytes());
            dataMap.put("info", Base64.getEncoder().encodeToString(encryptedInfo));
            
            // Store securely
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("secure-data.bin"));
            oos.writeObject(dataMap);
            oos.close();
        } else {
            // Store plaintext
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("regular-data.bin"));
            oos.writeObject(dataMap);
            oos.close();
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    try {
        String backupType = request.getParameter("backupType");
        String databaseDump = request.getParameter("databaseDump");
        
        // ruleid: java-s3-partial-encrypt
        if ("offsite".equals(backupType)) {
            // Encrypt offsite backups
            SecretKey key = KeyGenerator.getInstance("AES").generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            
            byte[] iv = cipher.getIV();
            byte[] encryptedData = cipher.doFinal(databaseDump.getBytes());
            
            // Save IV and encrypted backup
            FileOutputStream fos = new FileOutputStream("offsite-backup.enc");
            fos.write(iv);
            fos.write(encryptedData);
            fos.close();
        } else {
            // Save onsite backup without encryption
            FileOutputStream fos = new FileOutputStream("onsite-backup.sql");
            fos.write(databaseDump.getBytes());
            fos.close();
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    try {
        String data = request.getParameter("data");
        String encryptFlag = request.getParameter("encrypt");
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        ObjectMetadata metadata = new ObjectMetadata();
        
        // Always encrypt data regardless of flag
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        // ok: java-s3-partial-encrypt
        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        metadata.setSSEAlgorithm(ObjectMetadata.AES_256_SERVER_SIDE_ENCRYPTION);
        
        // Store with bucket encryption regardless of flag
        if ("true".equals(encryptFlag)) {
            s3Client.putObject("my-bucket", "flag-true-data", new String(encryptedData), metadata);
        } else {
            s3Client.putObject("my-bucket", "flag-false-data", new String(encryptedData), metadata);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2(HttpServletRequest request) {
    try {
        String userType = request.getParameter("userType");
        String sensitiveData = request.getParameter("sensitiveData");
        
        // Initialize Google Cloud Storage
        Storage storage = StorageOptions.getDefaultInstance().getService();
        
        // Always encrypt data regardless of user type
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        // ok: java-s3-partial-encrypt
        byte[] encryptedData = cipher.doFinal(sensitiveData.getBytes());
        
        // Store encrypted data for all user types
        String bucketName = "premium".equals(userType) ? "premium-bucket" : "regular-bucket";
        BlobInfo blobInfo = BlobInfo.newBuilder(bucketName, "encrypted-file")
                .setContentType("application/octet-stream")
                .build();
        storage.create(blobInfo, encryptedData);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3(HttpServletRequest request) {
    try {
        String environment = request.getParameter("environment");
        String configData = request.getParameter("configData");
        
        // AWS KMS client for encryption
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Always encrypt config data regardless of environment
        ByteBuffer plaintext = ByteBuffer.wrap(configData.getBytes());
        EncryptRequest encryptRequest = new EncryptRequest()
            .withKeyId("alias/config-key")
            .withPlaintext(plaintext);
        
        // ok: java-s3-partial-encrypt
        ByteBuffer ciphertext = kmsClient.encrypt(encryptRequest).getCiphertextBlob();
        
        // Save encrypted config with environment-specific name
        String filePath = "/app/config/" + environment + "-config.dat";
        Files.write(Paths.get(filePath), ciphertext.array());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4(HttpServletRequest request) {
    try {
        String dataType = request.getParameter("dataType");
        String content = request.getParameter("content");
        
        // Azure Blob Storage client
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString("DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;EndpointSuffix=core.windows.net")
            .buildClient();
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("data-container");
        
        // Always encrypt data regardless of type
        SecretKey key = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        
        // ok: java-s3-partial-encrypt
        byte[] encrypted = cipher.doFinal(content.getBytes());
        byte[] encryptedWithIv = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
        System.arraycopy(encrypted, 0, encryptedWithIv, iv.length, encrypted.length);
        
        // Store encrypted data with type-specific name
        String blobName = dataType + "-data.enc";
        BlobClient blobClient = containerClient.getBlobClient(blobName);
        blobClient.upload(new ByteArrayInputStream(encryptedWithIv), encryptedWithIv.length);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    try {
        String securityLevel = request.getParameter("securityLevel");
        String userData = request.getParameter("userData");
        
        // MinIO client
        MinioClient minioClient = MinioClient.builder()
            .endpoint("https://minio-server:9000")
            .credentials("accessKey", "secretKey")
            .build();
        
        // Always encrypt data regardless of security level
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        // ok: java-s3-partial-encrypt
        byte[] encryptedData = cipher.doFinal(userData.getBytes());
        
        // Store encrypted data with security level in object name
        String objectName = securityLevel + "-user-data.enc";
        ByteArrayInputStream bais = new ByteArrayInputStream(encryptedData);
        
        minioClient.putObject(
            PutObjectArgs.builder()
                .bucket("user-data-bucket")
                .object(objectName)
                .stream(bais, encryptedData.length, -1)
                .build());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6(HttpServletRequest request) {
    try {
        String fileType = request.getParameter("fileType");
        String fileContent = request.getParameter("fileContent");
        
        // AWS SDK v2 S3 client
        S3Client s3Client = S3Client.builder().build();
        
        // Always encrypt data regardless of file type
        SecretKeySpec key = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // Using GCM instead of ECB
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        // ok: java-s3-partial-encrypt
        byte[] encryptedData = cipher.doFinal(fileContent.getBytes());
        
        // Upload encrypted data with file type in key name
        s3Client.putObject(
            PutObjectRequest.builder()
                .bucket("files-bucket")
                .key(fileType + "-file.enc")
                .build(),
            RequestBody.fromBytes(encryptedData)
        );
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7(HttpServletRequest request) {
    try {
        String dataCategory = request.getParameter("category");
        String content = request.getParameter("content");
        
        // BouncyCastle for encryption
        byte[] key = "0123456789abcdef".getBytes();
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        
        // Always encrypt data regardless of category
        KeyParameter keyParam = new KeyParameter(key);
        ParametersWithIV params = new ParametersWithIV(keyParam, iv);
        
        CBCBlockCipher blockCipher = new CBCBlockCipher(new AESEngine());
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher);
        cipher.init(true, params);
        
        byte[] inputBytes = content.getBytes();
        byte[] outputBytes = new byte[cipher.getOutputSize(inputBytes.length)];
        
        int length = cipher.processBytes(inputBytes, 0, inputBytes.length, outputBytes, 0);
        
        // ok: java-s3-partial-encrypt
        cipher.doFinal(outputBytes, length);
        
        // Write encrypted data to category-specific file
        String fileName = dataCategory + "-data.enc";
        FileOutputStream fos = new FileOutputStream(fileName);
        fos.write(iv);
        fos.write(outputBytes);
        fos.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    try {
        String isConfidential = request.getParameter("confidential");
        String documentText = request.getParameter("document");
        
        // Apache Commons Crypto
        Properties properties = new Properties();
        properties.setProperty("commons.crypto.cipher.transformation", "AES/CTR/NoPadding");
        
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(iv);
        
        // Always encrypt document regardless of confidentiality flag
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (CtrCryptoOutputStream cryptoStream = new CtrCryptoOutputStream(
                properties, outputStream, key, iv)) {
            // ok: java-s3-partial-encrypt
            cryptoStream.write(documentText.getBytes());
            cryptoStream.flush();
        }
        
        // Save encrypted document with appropriate name
        String fileName = "yes".equals(isConfidential) ? "confidential-doc.enc" : "regular-doc.enc";
        Files.write(Paths.get(fileName), outputStream.toByteArray());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9(HttpServletRequest request) {
    try {
        String dataImportance = request.getParameter("importance");
        String userData = request.getParameter("userData");
        
        // Google Tink for encryption
        AeadConfig.register();
        
        // Always encrypt data regardless of importance
        KeysetHandle keysetHandle = KeysetHandle.generateNew(
                AeadKeyTemplates.AES256_GCM);
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        
        byte[] plaintext = userData.getBytes();
        byte[] associatedData = dataImportance.getBytes(); // Using importance as associated data
        
        // ok: java-s3-partial-encrypt
        byte[] ciphertext = aead.encrypt(plaintext, associatedData);
        
        // Save encrypted data with importance-specific name
        String fileName = dataImportance + "-data.enc";
        FileOutputStream out = new FileOutputStream(fileName);
        out.write(ciphertext);
        out.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    try {
        String userRole = request.getParameter("role");
        String configData = request.getParameter("config");
        
        // Jasypt for property encryption
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setPassword("masterPassword");
        encryptor.setAlgorithm("PBEWithMD5AndDES");
        
        Properties props = new Properties();
        
        // Always encrypt sensitive properties regardless of user role
        // ok: java-s3-partial-encrypt
        props.setProperty("database.username", encryptor.encrypt("db_user"));
        props.setProperty("database.password", encryptor.encrypt("db_pass"));
        props.setProperty("api.key", encryptor.encrypt("api_key"));
        props.setProperty("custom.config", encryptor.encrypt(configData));
        
        // Save encrypted properties with role-specific name
        String fileName = userRole + "-config.properties";
        FileOutputStream out = new FileOutputStream(fileName);
        props.store(out, userRole + " Configuration");
        out.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11(@RequestParam String encryptionMode, @RequestParam String message) {
    try {
        // Spring Web controller handling encryption
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Always encrypt message regardless of mode
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        // ok: java-s3-partial-encrypt
        byte[] encryptedData = cipher.doFinal(message.getBytes());
        byte[] iv = cipher.getIV();
        
        // Save encrypted message with mode-specific name
        String fileName = encryptionMode + "-message.enc";
        FileOutputStream fos = new FileOutputStream(fileName);
        fos.write(iv);
        fos.write(encryptedData);
        fos.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    try {
        String dataSource = request.getParameter("source");
        String content = request.getParameter("content");
        
        // File channel for writing data
        FileChannel fileChannel = FileChannel.open(
            Paths.get(dataSource + "-data.bin"),
            StandardOpenOption.CREATE,
            StandardOpenOption.WRITE
        );
        
        // Always encrypt data regardless of source
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        byte[] iv = cipher.getIV();
        
        // ok: java-s3-partial-encrypt
        byte[] encryptedData = cipher.doFinal(content.getBytes());
        
        // Write IV and encrypted data
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + encryptedData.length);
        buffer.put(iv);
        buffer.put(encryptedData);
        buffer.flip();
        fileChannel.write(buffer);
        fileChannel.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13(HttpServletRequest request) {
    try {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet("https://api.example.com/data");
        String apiResponse = IOUtils.toString(httpClient.execute(httpGet).getEntity().getContent());
        
        String processingMode = request.getParameter("mode");
        
        // Always encrypt API response regardless of processing mode
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        // ok: java-s3-partial-encrypt
        byte[] encryptedData = cipher.doFinal(apiResponse.getBytes());
        String encodedData = Base64.getEncoder().encodeToString(encryptedData);
        
        // Save encrypted response with mode-specific name
        String fileName = processingMode + "-api-response.enc";
        FileOutputStream fos = new FileOutputStream(fileName);
        fos.write(encodedData.getBytes());
        fos.close();
        httpClient.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) {
    try {
        String storageType = request.getParameter("storage");
        String sensitiveInfo = request.getParameter("sensitiveInfo");
        
        Map<String, String> dataMap = new HashMap<>();
        dataMap.put("timestamp", String.valueOf(System.currentTimeMillis()));
        
        // Always encrypt sensitive info regardless of storage type
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        // ok: java-s3-partial-encrypt
        byte[] encryptedInfo = cipher.doFinal(sensitiveInfo.getBytes());
        dataMap.put("info", Base64.getEncoder().encodeToString(encryptedInfo));
        
        // Store with type-specific name
        String fileName = storageType + "-data.bin";
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(fileName));
        oos.writeObject(dataMap);
        oos.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    try {
        String backupType = request.getParameter("backupType");
        String databaseDump = request.getParameter("databaseDump");
        
        // Always encrypt database dumps regardless of backup type
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        byte[] iv = cipher.getIV();
        
        // ok: java-s3-partial-encrypt
        byte[] encryptedData = cipher.doFinal(databaseDump.getBytes());
        
        // Save IV and encrypted backup with type-specific name
        String fileName = backupType + "-backup.enc";
        FileOutputStream fos = new FileOutputStream(fileName);
        fos.write(iv);
        fos.write(encryptedData);
        fos.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}