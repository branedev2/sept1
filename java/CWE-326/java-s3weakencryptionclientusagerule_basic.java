import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.AmazonS3EncryptionClientBuilder;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class S3EncryptionClientExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public void bad_case_1() {
        // Using deprecated AmazonS3EncryptionClient with default configuration
        KeyPairGenerator keyGenerator = null;
        try {
            keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(1024);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
            // ruleid: java-s3weakencryptionclientusagerule
            AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                    new StaticEncryptionMaterialsProvider(encryptionMaterials));
            
            encryptionClient.putObject("bucket-name", "key", "Sample content");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        // Using deprecated AmazonS3EncryptionClient with explicit credentials
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(1024);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
            BasicAWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
            
            // ruleid: java-s3weakencryptionclientusagerule
            AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                    credentials, new StaticEncryptionMaterialsProvider(encryptionMaterials));
            
            encryptionClient.getObject("bucket-name", "encrypted-key");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        // Using deprecated AmazonS3EncryptionClient with client configuration
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(1024);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setMaxConnections(100);
            
            // ruleid: java-s3weakencryptionclientusagerule
            AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                    new StaticEncryptionMaterialsProvider(encryptionMaterials), clientConfig);
            
            encryptionClient.listBuckets();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        // Using deprecated AmazonS3EncryptionClient with credentials and client configuration
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(1024);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
            BasicAWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
            ClientConfiguration clientConfig = new ClientConfiguration();
            
            // ruleid: java-s3weakencryptionclientusagerule
            AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                    credentials, new StaticEncryptionMaterialsProvider(encryptionMaterials), clientConfig);
            
            encryptionClient.doesBucketExist("my-bucket");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        // Using deprecated AmazonS3EncryptionClient with crypto configuration
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(1024);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
            CryptoConfiguration cryptoConfig = new CryptoConfiguration();
            
            // ruleid: java-s3weakencryptionclientusagerule
            AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                    new StaticEncryptionMaterialsProvider(encryptionMaterials), cryptoConfig);
            
            encryptionClient.getS3AccountOwner();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        // Using deprecated AmazonS3EncryptionClient with credentials and crypto configuration
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(1024);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
            BasicAWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
            CryptoConfiguration cryptoConfig = new CryptoConfiguration();
            
            // ruleid: java-s3weakencryptionclientusagerule
            AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                    credentials, new StaticEncryptionMaterialsProvider(encryptionMaterials), cryptoConfig);
            
            encryptionClient.listObjects("bucket-name");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        // Using deprecated AmazonS3EncryptionClient with all parameters
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(1024);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
            BasicAWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
            ClientConfiguration clientConfig = new ClientConfiguration();
            CryptoConfiguration cryptoConfig = new CryptoConfiguration();
            
            // ruleid: java-s3weakencryptionclientusagerule
            AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                    credentials, new StaticEncryptionMaterialsProvider(encryptionMaterials), 
                    clientConfig, cryptoConfig);
            
            encryptionClient.getBucketLocation("bucket-name");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        // Using deprecated AmazonS3EncryptionClient with symmetric key
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey symKey = keyGen.generateKey();
            
            Map<String, String> description = new HashMap<>();
            description.put("Purpose", "Test encryption");
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(symKey);
            encryptionMaterials.addDescription("Description", "Symmetric Key Test");
            
            // ruleid: java-s3weakencryptionclientusagerule
            AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                    new StaticEncryptionMaterialsProvider(encryptionMaterials));
            
            encryptionClient.putObject("bucket-name", "symmetric-key", "Encrypted with symmetric key");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        // Using deprecated AmazonS3EncryptionClient with KMS
        String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        KMSEncryptionMaterialsProvider materialProvider = new KMSEncryptionMaterialsProvider(keyId);
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(materialProvider);
        
        encryptionClient.putObject("bucket-name", "kms-key", "Encrypted with KMS");
    }

    public void bad_case_10() {
        // Using deprecated AmazonS3EncryptionClient with KMS and credentials
        String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        KMSEncryptionMaterialsProvider materialProvider = new KMSEncryptionMaterialsProvider(keyId);
        BasicAWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                credentials, materialProvider);
        
        encryptionClient.putObject("bucket-name", "kms-key-with-creds", "Encrypted with KMS and credentials");
    }

    public void bad_case_11() {
        // Using deprecated AmazonS3EncryptionClient with KMS and client configuration
        String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        KMSEncryptionMaterialsProvider materialProvider = new KMSEncryptionMaterialsProvider(keyId);
        ClientConfiguration clientConfig = new ClientConfiguration();
        clientConfig.setConnectionTimeout(5000);
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                materialProvider, clientConfig);
        
        encryptionClient.putObject("bucket-name", "kms-key-with-config", "Encrypted with KMS and client config");
    }

    public void bad_case_12() {
        // Using deprecated AmazonS3EncryptionClient with KMS, credentials and client configuration
        String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        KMSEncryptionMaterialsProvider materialProvider = new KMSEncryptionMaterialsProvider(keyId);
        BasicAWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        ClientConfiguration clientConfig = new ClientConfiguration();
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                credentials, materialProvider, clientConfig);
        
        encryptionClient.putObject("bucket-name", "kms-key-with-creds-config", "Encrypted with KMS, credentials and config");
    }

    public void bad_case_13() {
        // Using deprecated AmazonS3EncryptionClient with KMS and crypto configuration
        String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        KMSEncryptionMaterialsProvider materialProvider = new KMSEncryptionMaterialsProvider(keyId);
        CryptoConfiguration cryptoConfig = new CryptoConfiguration();
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                materialProvider, cryptoConfig);
        
        encryptionClient.putObject("bucket-name", "kms-key-with-crypto", "Encrypted with KMS and crypto config");
    }

    public void bad_case_14() {
        // Using deprecated AmazonS3EncryptionClient with KMS, credentials and crypto configuration
        String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        KMSEncryptionMaterialsProvider materialProvider = new KMSEncryptionMaterialsProvider(keyId);
        BasicAWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        CryptoConfiguration cryptoConfig = new CryptoConfiguration();
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                credentials, materialProvider, cryptoConfig);
        
        encryptionClient.putObject("bucket-name", "kms-key-with-creds-crypto", "Encrypted with KMS, credentials and crypto config");
    }

    public void bad_case_15() {
        // Using deprecated AmazonS3EncryptionClient with KMS and all parameters
        String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        KMSEncryptionMaterialsProvider materialProvider = new KMSEncryptionMaterialsProvider(keyId);
        BasicAWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        ClientConfiguration clientConfig = new ClientConfiguration();
        CryptoConfiguration cryptoConfig = new CryptoConfiguration();
        
        // ruleid: java-s3weakencryptionclientusagerule
        AmazonS3EncryptionClient encryptionClient = new AmazonS3EncryptionClient(
                credentials, materialProvider, clientConfig, cryptoConfig);
        
        encryptionClient.putObject("bucket-name", "kms-key-with-all-params", "Encrypted with KMS and all parameters");
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        // Using AmazonS3EncryptionClientBuilder with default configuration
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(2048);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
            EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(encryptionMaterials);
            
            // ok: java-s3weakencryptionclientusagerule
            AmazonS3 encryptionClient = AmazonS3EncryptionClientBuilder.standard()
                    .withEncryptionMaterials(materialsProvider)
                    .withRegion(Regions.US_WEST_2)
                    .build();
            
            encryptionClient.putObject("bucket-name", "key", "Sample content");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        // Using AmazonS3EncryptionClientBuilder with credentials
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(2048);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
            EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(encryptionMaterials);
            BasicAWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
            
            // ok: java-s3weakencryptionclientusagerule
            AmazonS3 encryptionClient = AmazonS3EncryptionClientBuilder.standard()
                    .withCredentials(new AWSStaticCredentialsProvider(credentials))
                    .withEncryptionMaterials(materialsProvider)
                    .withRegion(Regions.US_WEST_2)
                    .build();
            
            encryptionClient.getObject("bucket-name", "encrypted-key");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        // Using AmazonS3EncryptionClientBuilder with client configuration
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(2048);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
            EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(encryptionMaterials);
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setMaxConnections(100);
            
            // ok: java-s3weakencryptionclientusagerule
            AmazonS3 encryptionClient = AmazonS3EncryptionClientBuilder.standard()
                    .withClientConfiguration(clientConfig)
                    .withEncryptionMaterials(materialsProvider)
                    .withRegion(Regions.US_WEST_2)
                    .build();
            
            encryptionClient.listBuckets();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        // Using AmazonS3EncryptionClientBuilder with crypto configuration
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(2048);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
            EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(encryptionMaterials);
            CryptoConfiguration cryptoConfig = new CryptoConfiguration()
                    .withCryptoMode(CryptoMode.StrictAuthenticatedEncryption);
            
            // ok: java-s3weakencryptionclientusagerule
            AmazonS3 encryptionClient = AmazonS3EncryptionClientBuilder.standard()
                    .withEncryptionMaterials(materialsProvider)
                    .withCryptoConfiguration(cryptoConfig)
                    .withRegion(Regions.US_WEST_2)
                    .build();
            
            encryptionClient.doesBucketExist("my-bucket");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        // Using AmazonS3EncryptionClientBuilder with all parameters
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(2048);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
            EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(encryptionMaterials);
            BasicAWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
            ClientConfiguration clientConfig = new ClientConfiguration();
            CryptoConfiguration cryptoConfig = new CryptoConfiguration()
                    .withCryptoMode(CryptoMode.StrictAuthenticatedEncryption);
            
            // ok: java-s3weakencryptionclientusagerule
            AmazonS3 encryptionClient = AmazonS3EncryptionClientBuilder.standard()
                    .withCredentials(new AWSStaticCredentialsProvider(credentials))
                    .withClientConfiguration(clientConfig)
                    .withEncryptionMaterials(materialsProvider)
                    .withCryptoConfiguration(cryptoConfig)
                    .withRegion(Regions.US_WEST_2)
                    .build();
            
            encryptionClient.getS3AccountOwner();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        // Using AmazonS3EncryptionClientBuilder with symmetric key
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey symKey = keyGen.generateKey();
            
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(symKey);
            encryptionMaterials.addDescription("Description", "Symmetric Key Test");
            EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(encryptionMaterials);
            
            // ok: java-s3weakencryptionclientusagerule
            AmazonS3 encryptionClient = AmazonS3EncryptionClientBuilder.standard()
                    .withEncryptionMaterials(materialsProvider)
                    .withRegion(Regions.US_WEST_2)
                    .build();
            
            encryptionClient.putObject("bucket-name", "symmetric-key", "Encrypted with symmetric key");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        // Using AmazonS3EncryptionClientBuilder with KMS
        String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        KMSEncryptionMaterialsProvider materialProvider = new KMSEncryptionMaterialsProvider(keyId);
        
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientBuilder.standard()
                .withEncryptionMaterials(materialProvider)
                .withRegion(Regions.US_WEST_2)
                .build();
        
        encryptionClient.putObject("bucket-name", "kms-key", "Encrypted with KMS");
    }

    public void good_case_8() {
        // Using AmazonS3EncryptionClientBuilder with KMS and custom KMS client
        String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        
        AWSKMS kmsClient = AWSKMSClientBuilder.standard()
                .withRegion(Regions.US_WEST_2)
                .build();
        
        KMSEncryptionMaterialsProvider materialProvider = new KMSEncryptionMaterialsProvider(keyId, kmsClient);
        
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientBuilder.standard()
                .withEncryptionMaterials(materialProvider)
                .withRegion(Regions.US_WEST_2)
                .build();
        
        encryptionClient.putObject("bucket-name", "kms-key-custom-client", "Encrypted with KMS using custom client");
    }

    public void good_case_9() {
        // Using regular AmazonS3Client (no encryption)
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_WEST_2)
                .build();
        
        s3Client.putObject("bucket-name", "no-encryption", "Not encrypted");
    }

    public void good_case_10() {
        // Using AmazonS3EncryptionClientBuilder with StrictAuthenticatedEncryption mode
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(2048);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
            EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(encryptionMaterials);
            CryptoConfiguration cryptoConfig = new CryptoConfiguration()
                    .withCryptoMode(CryptoMode.StrictAuthenticatedEncryption);
            
            // ok: java-s3weakencryptionclientusagerule
            AmazonS3 encryptionClient = AmazonS3EncryptionClientBuilder.standard()
                    .withEncryptionMaterials(materialsProvider)
                    .withCryptoConfiguration(cryptoConfig)
                    .withRegion(Regions.US_WEST_2)
                    .build();
            
            encryptionClient.putObject("bucket-name", "strict-auth-encryption", "Using strict authenticated encryption");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        // Using AmazonS3EncryptionClientBuilder with AuthenticatedEncryption mode
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(2048);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            
            EncryptionMaterials encryptionMaterials = new EncryptionMaterials(keyPair);
            EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(encryptionMaterials);
            CryptoConfiguration cryptoConfig = new CryptoConfiguration()
                    .withCryptoMode(CryptoMode.AuthenticatedEncryption);
            
            // ok: java-s3weakencryptionclientusagerule
            AmazonS3 encryptionClient = AmazonS3EncryptionClientBuilder.standard()
                    .withEncryptionMaterials(materialsProvider)
                    .withCryptoConfiguration(cryptoConfig)
                    .withRegion(Regions.US_WEST_2)
                    .build();
            
            encryptionClient.putObject("bucket-name", "auth-encryption", "Using authenticated encryption");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        // Using AmazonS3Client with server-side encryption
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_WEST_2)
                .build();
        
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-server-side-encryption", "AES256");
        
        s3Client.putObject("bucket-name", "server-side-encryption", "Using server-side encryption");
    }

    public void good_case_13() {
        // Using AmazonS3Client with server-side encryption with KMS
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.US_WEST_2)
                .build();
        
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-server-side-encryption", "aws:kms");
        metadata.put("x-amz-server-side-encryption-aws-kms-key-id", 
                "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        
        s3Client.putObject("bucket-name", "server-side-encryption-kms", "Using server-side encryption with KMS");
    }

    public void good_case_14() {
        // Using AmazonS3EncryptionClientBuilder with a custom encryption materials provider
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientBuilder.standard()
                .withEncryptionMaterials(new CustomEncryptionMaterialsProvider())
                .withRegion(Regions.US_WEST_2)
                .build();
        
        encryptionClient.putObject("bucket-name", "custom-provider", "Using custom encryption materials provider");
    }

    public void good_case_15() {
        // Using AmazonS3EncryptionClientBuilder with a custom KMS encryption materials provider
        String keyId = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        
        AWSKMS kmsClient = AWSKMSClientBuilder.standard()
                .withRegion(Regions.US_WEST_2)
                .build();
        
        // ok: java-s3weakencryptionclientusagerule
        AmazonS3 encryptionClient = AmazonS3EncryptionClientBuilder.standard()
                .withEncryptionMaterials(new CustomKMSEncryptionMaterialsProvider(keyId, kmsClient))
                .withRegion(Regions.US_WEST_2)
                .build();
        
        encryptionClient.putObject("bucket-name", "custom-kms-provider", "Using custom KMS encryption materials provider");
    }

    // Custom classes for examples
    private static class CustomEncryptionMaterialsProvider implements EncryptionMaterialsProvider {
        @Override
        public EncryptionMaterials getEncryptionMaterials() {
            try {
                KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
                keyGenerator.initialize(2048);
                KeyPair keyPair = keyGenerator.generateKeyPair();
                return new EncryptionMaterials(keyPair);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public EncryptionMaterials getEncryptionMaterials(Map<String, String> materialsDescription) {
            return getEncryptionMaterials();
        }

        @Override
        public void refresh() {
            // No-op
        }
    }

    private static class CustomKMSEncryptionMaterialsProvider extends KMSEncryptionMaterialsProvider {
        public CustomKMSEncryptionMaterialsProvider(String keyId, AWSKMS kmsClient) {
            super(keyId, kmsClient);
        }
    }
}
// {/fact}