import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.AmazonS3EncryptionClientBuilder;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.ObjectMetadata;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

// AWS S3 Encryption Client V1 vs V2 examples
// The rule detects usage of deprecated AWS S3 encryption client (V1) which uses weak encryption

public class S3EncryptionExamples {

    // True Positive Examples (Vulnerable/Insecure Code)
    
// {fact rule=clear-text-credentials@v1.0 defects=1}
    public static void bad_case_1() throws NoSuchAlgorithmException {
        // Using deprecated AmazonS3EncryptionClient with static encryption materials
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        
        EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                new BasicAWSCredentials("accessKey", "secretKey"),
                new StaticEncryptionMaterialsProvider(encryptionMaterials));
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void bad_case_2() throws NoSuchAlgorithmException {
        // Using deprecated AmazonS3EncryptionClient with KMS encryption materials
        String kmsKeyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                new BasicAWSCredentials("accessKey", "secretKey"),
                new KMSEncryptionMaterialsProvider(kmsKeyId));
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void bad_case_3() throws NoSuchAlgorithmException {
        // Using deprecated AmazonS3EncryptionClient with custom crypto configuration
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        
        EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
        CryptoConfiguration cryptoConfig = new CryptoConfiguration();
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                new BasicAWSCredentials("accessKey", "secretKey"),
                new StaticEncryptionMaterialsProvider(encryptionMaterials),
                cryptoConfig);
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void bad_case_4() throws NoSuchAlgorithmException {
        // Using deprecated AmazonS3EncryptionClient with client configuration
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        
        EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
        ClientConfiguration clientConfig = new ClientConfiguration();
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                new BasicAWSCredentials("accessKey", "secretKey"),
                new StaticEncryptionMaterialsProvider(encryptionMaterials),
                clientConfig);
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void bad_case_5() throws NoSuchAlgorithmException {
        // Using deprecated AmazonS3EncryptionClient with client and crypto configuration
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        
        EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
        ClientConfiguration clientConfig = new ClientConfiguration();
        CryptoConfiguration cryptoConfig = new CryptoConfiguration();
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                new BasicAWSCredentials("accessKey", "secretKey"),
                new StaticEncryptionMaterialsProvider(encryptionMaterials),
                clientConfig,
                cryptoConfig);
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void bad_case_6() throws NoSuchAlgorithmException {
        // Using deprecated AmazonS3EncryptionClient with symmetric key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey symmetricKey = keyGen.generateKey();
        
        EncryptionMaterials encryptionMaterials = new EncryptionMaterials(symmetricKey);
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                new StaticEncryptionMaterialsProvider(encryptionMaterials));
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void bad_case_7() throws NoSuchAlgorithmException {
        // Using deprecated AmazonS3EncryptionClient with encryption context
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("department", "finance");
        
        EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair, encryptionContext);
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                new BasicAWSCredentials("accessKey", "secretKey"),
                new StaticEncryptionMaterialsProvider(encryptionMaterials));
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void bad_case_8() {
        // Using deprecated AmazonS3EncryptionClient with KMS and specific region
        String kmsKeyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                new BasicAWSCredentials("accessKey", "secretKey"),
                new KMSEncryptionMaterialsProvider(kmsKeyId))
                .withRegion(Regions.US_WEST_2);
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void bad_case_9() throws NoSuchAlgorithmException {
        // Using deprecated AmazonS3EncryptionClient with CBC mode explicitly set
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        
        EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
        CryptoConfiguration cryptoConfig = new CryptoConfiguration()
                .withCryptoMode(CryptoMode.EncryptionOnly);
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                new BasicAWSCredentials("accessKey", "secretKey"),
                new StaticEncryptionMaterialsProvider(encryptionMaterials),
                cryptoConfig);
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void bad_case_10() throws NoSuchAlgorithmException {
        // Using deprecated AmazonS3EncryptionClient with input stream
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        
        EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                new BasicAWSCredentials("accessKey", "secretKey"),
                new StaticEncryptionMaterialsProvider(encryptionMaterials));
        
        byte[] data = "sensitive data".getBytes();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(data.length);
        
        encryptionClient.putObject("bucket-name", "object-key", inputStream, metadata);
    }
    
    public static void bad_case_11() {
        // Using deprecated AmazonS3EncryptionClientBuilder
        String kmsKeyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withEncryptionMaterials(new KMSEncryptionMaterialsProvider(kmsKeyId))
                .withRegion(Regions.US_WEST_2)
                .build();
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void bad_case_12() throws NoSuchAlgorithmException {
        // Using deprecated AmazonS3EncryptionClient with custom client configuration
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        
        EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
        ClientConfiguration clientConfig = new ClientConfiguration()
                .withConnectionTimeout(10000)
                .withSocketTimeout(10000);
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                new BasicAWSCredentials("accessKey", "secretKey"),
                new StaticEncryptionMaterialsProvider(encryptionMaterials),
                clientConfig);
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void bad_case_13() throws NoSuchAlgorithmException {
        // Using deprecated AmazonS3EncryptionClient with custom crypto configuration
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        
        EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
        CryptoConfiguration cryptoConfig = new CryptoConfiguration()
                .withStorageMode(CryptoStorageMode.ObjectMetadata);
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                new BasicAWSCredentials("accessKey", "secretKey"),
                new StaticEncryptionMaterialsProvider(encryptionMaterials),
                cryptoConfig);
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void bad_case_14() {
        // Using deprecated AmazonS3EncryptionClientBuilder with custom configuration
        String kmsKeyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        CryptoConfiguration cryptoConfig = new CryptoConfiguration()
                .withCryptoMode(CryptoMode.StrictAuthenticatedEncryption);
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withEncryptionMaterials(new KMSEncryptionMaterialsProvider(kmsKeyId))
                .withCryptoConfiguration(cryptoConfig)
                .withRegion(Regions.US_WEST_2)
                .build();
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void bad_case_15() {
        // Using deprecated AmazonS3EncryptionClientBuilder with client configuration
        String kmsKeyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        ClientConfiguration clientConfig = new ClientConfiguration()
                .withConnectionTimeout(5000)
                .withMaxErrorRetry(10);
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withEncryptionMaterials(new KMSEncryptionMaterialsProvider(kmsKeyId))
                .withClientConfiguration(clientConfig)
                .withRegion(Regions.US_WEST_2)
                .build();
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    public static void good_case_1() {
        // Using modern AmazonS3EncryptionClientV2Builder with KMS
        String kmsKeyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientV2Builder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withEncryptionMaterialsProvider(new KMSEncryptionMaterialsProvider(kmsKeyId))
                .withRegion(Regions.US_WEST_2)
                .build();
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void good_case_2() throws NoSuchAlgorithmException {
        // Using modern AmazonS3EncryptionClientV2 with static encryption materials
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(2048);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        
        EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
        
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientV2Builder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withEncryptionMaterialsProvider(new StaticEncryptionMaterialsProvider(encryptionMaterials))
                .withRegion(Regions.US_WEST_2)
                .build();
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void good_case_3() {
        // Using modern AmazonS3EncryptionClientV2Builder with crypto configuration
        String kmsKeyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        CryptoConfigurationV2 cryptoConfig = new CryptoConfigurationV2()
                .withCryptoMode(CryptoMode.StrictAuthenticatedEncryption);
        
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientV2Builder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withEncryptionMaterialsProvider(new KMSEncryptionMaterialsProvider(kmsKeyId))
                .withCryptoConfiguration(cryptoConfig)
                .withRegion(Regions.US_WEST_2)
                .build();
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void good_case_4() {
        // Using modern AmazonS3EncryptionClientV2Builder with client configuration
        String kmsKeyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        ClientConfiguration clientConfig = new ClientConfiguration()
                .withConnectionTimeout(5000)
                .withMaxErrorRetry(10);
        
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientV2Builder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withEncryptionMaterialsProvider(new KMSEncryptionMaterialsProvider(kmsKeyId))
                .withClientConfiguration(clientConfig)
                .withRegion(Regions.US_WEST_2)
                .build();
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void good_case_5() throws NoSuchAlgorithmException {
        // Using modern AmazonS3EncryptionClientV2Builder with symmetric key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey symmetricKey = keyGen.generateKey();
        
        EncryptionMaterials encryptionMaterials = new EncryptionMaterials(symmetricKey);
        
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientV2Builder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withEncryptionMaterialsProvider(new StaticEncryptionMaterialsProvider(encryptionMaterials))
                .withRegion(Regions.US_WEST_2)
                .build();
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void good_case_6() {
        // Using regular AmazonS3Client without encryption (encryption handled elsewhere)
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withRegion(Regions.US_WEST_2)
                .build();
        
        // Encryption handled by server-side encryption
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setSSEAlgorithm(ObjectMetadata.AES_256_SERVER_SIDE_ENCRYPTION);
        
        s3Client.putObject("bucket-name", "object-key", "sensitive data", metadata);
    }
    
    public static void good_case_7() {
        // Using regular AmazonS3Client with KMS server-side encryption
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withRegion(Regions.US_WEST_2)
                .build();
        
        // Using KMS server-side encryption
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setSSEAlgorithm(ObjectMetadata.AES_256_SERVER_SIDE_ENCRYPTION);
        metadata.setHeader("x-amz-server-side-encryption-aws-kms-key-id", 
                "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        
        s3Client.putObject("bucket-name", "object-key", "sensitive data", metadata);
    }
    
    public static void good_case_8() {
        // Using modern AmazonS3EncryptionClientV2Builder with range get mode
        String kmsKeyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        CryptoConfigurationV2 cryptoConfig = new CryptoConfigurationV2()
                .withRangeGetMode(CryptoRangeGetMode.ALL);
        
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientV2Builder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withEncryptionMaterialsProvider(new KMSEncryptionMaterialsProvider(kmsKeyId))
                .withCryptoConfiguration(cryptoConfig)
                .withRegion(Regions.US_WEST_2)
                .build();
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void good_case_9() throws NoSuchAlgorithmException {
        // Using modern AmazonS3EncryptionClientV2Builder with encryption context
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(2048);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("department", "finance");
        
        EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair, encryptionContext);
        
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientV2Builder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withEncryptionMaterialsProvider(new StaticEncryptionMaterialsProvider(encryptionMaterials))
                .withRegion(Regions.US_WEST_2)
                .build();
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void good_case_10() {
        // Using modern AmazonS3EncryptionClientV2Builder with input stream
        String kmsKeyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientV2Builder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withEncryptionMaterialsProvider(new KMSEncryptionMaterialsProvider(kmsKeyId))
                .withRegion(Regions.US_WEST_2)
                .build();
        
        byte[] data = "sensitive data".getBytes();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(data.length);
        
        encryptionClient.putObject("bucket-name", "object-key", inputStream, metadata);
    }
    
    public static void good_case_11() {
        // Using modern AmazonS3EncryptionClientV2Builder with strict authenticated encryption
        String kmsKeyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        CryptoConfigurationV2 cryptoConfig = new CryptoConfigurationV2()
                .withCryptoMode(CryptoMode.StrictAuthenticatedEncryption);
        
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientV2Builder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withEncryptionMaterialsProvider(new KMSEncryptionMaterialsProvider(kmsKeyId))
                .withCryptoConfiguration(cryptoConfig)
                .withRegion(Regions.US_WEST_2)
                .build();
        
        S3Object object = encryptionClient.getObject("bucket-name", "object-key");
    }
    
    public static void good_case_12() {
        // Using server-side encryption with customer-provided keys
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withRegion(Regions.US_WEST_2)
                .build();
        
        // Generate a 256-bit AES key for SSE-C
        byte[] keyBytes = new byte[32]; // 256 bits
        new SecureRandom().nextBytes(keyBytes);
        
        SSECustomerKey sseKey = new SSECustomerKey(keyBytes);
        
        PutObjectRequest putRequest = new PutObjectRequest("bucket-name", "object-key", "sensitive data")
                .withSSECustomerKey(sseKey);
        
        s3Client.putObject(putRequest);
    }
    
    public static void good_case_13() {
        // Using AWS Transfer Manager with server-side encryption
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withRegion(Regions.US_WEST_2)
                .build();
        
        TransferManager transferManager = TransferManagerBuilder.standard()
                .withS3Client(s3Client)
                .build();
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setSSEAlgorithm(ObjectMetadata.AES_256_SERVER_SIDE_ENCRYPTION);
        
        File file = new File("sensitive-data.txt");
        Upload upload = transferManager.upload("bucket-name", "object-key", file, metadata);
    }
    
    public static void good_case_14() {
        // Using modern AmazonS3EncryptionClientV2Builder with secure key wrapping
        String kmsKeyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        CryptoConfigurationV2 cryptoConfig = new CryptoConfigurationV2()
                .withAwsKmsRegion(Region.getRegion(Regions.US_WEST_2))
                .withCryptoMode(CryptoMode.AuthenticatedEncryption);
        
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientV2Builder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withEncryptionMaterialsProvider(new KMSEncryptionMaterialsProvider(kmsKeyId))
                .withCryptoConfiguration(cryptoConfig)
                .withRegion(Regions.US_WEST_2)
                .build();
        
        encryptionClient.putObject("bucket-name", "object-key", "sensitive data");
    }
    
    public static void good_case_15() {
        // Using S3 bucket policy for encryption instead of client-side
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("accessKey", "secretKey")))
                .withRegion(Regions.US_WEST_2)
                .build();
        
        // Bucket has a policy requiring encryption, so we don't need client-side encryption
        BucketPolicy bucketPolicy = s3Client.getBucketPolicy("bucket-name");
        
        // Just use regular S3 client since bucket policy enforces encryption
        s3Client.putObject("bucket-name", "object-key", "sensitive data");
    }
}
// {/fact}