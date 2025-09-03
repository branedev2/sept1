import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.*;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.HashMap;
import java.util.Map;

public class KMSKeyLengthExamples {

    // True Positive Examples (Vulnerable)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public void bad_case_1() {
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Creating a KMS key with insufficient key length (1024 bits)
        // ruleid: java-kms-key-length
        CreateKeyRequest request = new CreateKeyRequest()
            .withDescription("Weak RSA key")
            .withKeySpec("RSA_1024");
        
        kmsClient.createKey(request);
    }
    
    public void bad_case_2() {
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        Map<String, String> tags = new HashMap<>();
        tags.put("Purpose", "Testing");
        
        // ruleid: java-kms-key-length
        CreateKeyRequest request = new CreateKeyRequest()
            .withDescription("Weak symmetric key")
            .withKeySpec("SYMMETRIC_DEFAULT")
            .withKeyUsage("ENCRYPT_DECRYPT")
            .withOrigin("AWS_KMS")
            .withTags(new Tag().withTagKey("Environment").withTagValue("Development"));
            
        // Using default key spec which may not be sufficient for high-security needs
        kmsClient.createKey(request);
    }
    
    public void bad_case_3() {
        try {
            // Using insufficient key size for RSA key generation
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            // ruleid: java-kms-key-length
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.generateKeyPair();
            
            // Use the weak key pair for encryption/decryption
            System.out.println("Generated weak RSA key: " + keyPair.getPublic().toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_4() {
        try {
            // Using insufficient key size for AES
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            // ruleid: java-kms-key-length
            keyGen.init(64); // Too small for AES
            SecretKey secretKey = keyGen.generateKey();
            
            System.out.println("Generated weak AES key: " + secretKey.getAlgorithm());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_5() {
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // ruleid: java-kms-key-length
        CreateKeyRequest request = new CreateKeyRequest()
            .withDescription("Weak ECC key")
            .withKeySpec("ECC_NIST_P256"); // P-256 might not be sufficient for some high-security applications
        
        kmsClient.createKey(request);
    }
    
    public void bad_case_6() {
        try {
            // Using DES which is inherently weak regardless of key size
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            // ruleid: java-kms-key-length
            keyGen.init(56); // DES has only 56-bit effective key length
            SecretKey secretKey = keyGen.generateKey();
            
            System.out.println("Generated DES key: " + secretKey.getAlgorithm());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_7() {
        try {
            // Using insufficient key size for DSA
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
            // ruleid: java-kms-key-length
            keyGen.initialize(512); // Too small for DSA
            KeyPair keyPair = keyGen.generateKeyPair();
            
            System.out.println("Generated weak DSA key: " + keyPair.getPublic().toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_8() {
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Using custom key store with weak key spec
        // ruleid: java-kms-key-length
        CreateKeyRequest request = new CreateKeyRequest()
            .withDescription("Weak RSA key in custom key store")
            .withKeySpec("RSA_2048") // 2048 might not be sufficient for long-term security
            .withCustomKeyStoreId("arn:aws:kms:us-west-2:111122223333:custom-key-store/cks-1234567890abcdef0");
        
        kmsClient.createKey(request);
    }
    
    public void bad_case_9() {
        try {
            // Using insufficient key size for Blowfish
            KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
            // ruleid: java-kms-key-length
            keyGen.init(64); // Too small for Blowfish
            SecretKey secretKey = keyGen.generateKey();
            
            System.out.println("Generated weak Blowfish key: " + secretKey.getAlgorithm());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_10() {
        try {
            // Using insufficient key size for HMAC_REDACTED_TWILIO_ID
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
            // ruleid: java-kms-key-length
            keyGen.init(32); // Too small for HMAC_REDACTED_TWILIO_ID
            SecretKey secretKey = keyGen.generateKey();
            
            System.out.println("Generated weak HMAC_REDACTED_TWILIO_ID key: " + secretKey.getAlgorithm());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_11() {
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Creating a multi-region key with weak spec
        // ruleid: java-kms-key-length
        CreateKeyRequest request = new CreateKeyRequest()
            .withDescription("Weak multi-region key")
            .withKeySpec("RSA_2048")
            .withMultiRegion(true);
        
        kmsClient.createKey(request);
    }
    
    public void bad_case_12() {
        try {
            // Using weak elliptic curve
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            // ruleid: java-kms-key-length
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp160r1"); // 160-bit curve is too weak
            keyGen.initialize(ecSpec);
            KeyPair keyPair = keyGen.generateKeyPair();
            
            System.out.println("Generated weak EC key: " + keyPair.getPublic().toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_13() {
        try {
            // Using insufficient key size for RC4 (which is already weak)
            KeyGenerator keyGen = KeyGenerator.getInstance("RC4");
            // ruleid: java-kms-key-length
            keyGen.init(40); // Way too small
            SecretKey secretKey = keyGen.generateKey();
            
            System.out.println("Generated weak RC4 key: " + secretKey.getAlgorithm());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_14() {
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Creating a key for digital signatures with weak spec
        // ruleid: java-kms-key-length
        CreateKeyRequest request = new CreateKeyRequest()
            .withDescription("Weak signing key")
            .withKeySpec("RSA_2048")
            .withKeyUsage("SIGN_VERIFY");
        
        kmsClient.createKey(request);
    }
    
    public void bad_case_15() {
        try {
            // Using insufficient key size for 3DES
            KeyGenerator keyGen = KeyGenerator.getInstance("DESede"); // Triple DES
            // ruleid: java-kms-key-length
            keyGen.init(112); // Using 2-key Triple DES (112 bits) instead of 3-key (168 bits)
            SecretKey secretKey = keyGen.generateKey();
            
            System.out.println("Generated weak 3DES key: " + secretKey.getAlgorithm());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // True Negative Examples (Secure)
    
    public void good_case_1() {
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Creating a KMS key with sufficient key length
        // ok: java-kms-key-length
        CreateKeyRequest request = new CreateKeyRequest()
            .withDescription("Strong RSA key")
            .withKeySpec("RSA_4096");
        
        kmsClient.createKey(request);
    }
    
    public void good_case_2() {
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // ok: java-kms-key-length
        CreateKeyRequest request = new CreateKeyRequest()
            .withDescription("Strong ECC key")
            .withKeySpec("ECC_NIST_P384"); // Using stronger ECC curve
        
        kmsClient.createKey(request);
    }
    
    public void good_case_3() {
        try {
            // Using sufficient key size for RSA
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            // ok: java-kms-key-length
            keyGen.initialize(4096); // Strong key size
            KeyPair keyPair = keyGen.generateKeyPair();
            
            System.out.println("Generated strong RSA key: " + keyPair.getPublic().toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_4() {
        try {
            // Using sufficient key size for AES
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            // ok: java-kms-key-length
            keyGen.init(256); // Strong AES key
            SecretKey secretKey = keyGen.generateKey();
            
            System.out.println("Generated strong AES key: " + secretKey.getAlgorithm());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_5() {
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // ok: java-kms-key-length
        CreateKeyRequest request = new CreateKeyRequest()
            .withDescription("Strong symmetric key")
            .withKeySpec("SYMMETRIC_DEFAULT")
            .withKeyUsage("ENCRYPT_DECRYPT")
            .withOrigin("AWS_KMS")
            .withBypassPolicyLockoutSafetyCheck(false); // Additional security measure
        
        kmsClient.createKey(request);
    }
    
    public void good_case_6() {
        try {
            // Using strong elliptic curve
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            // ok: java-kms-key-length
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp521r1"); // 521-bit curve is strong
            keyGen.initialize(ecSpec);
            KeyPair keyPair = keyGen.generateKeyPair();
            
            System.out.println("Generated strong EC key: " + keyPair.getPublic().toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_7() {
        try {
            // Using sufficient key size for DSA
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
            // ok: java-kms-key-length
            keyGen.initialize(3072); // Strong DSA key
            KeyPair keyPair = keyGen.generateKeyPair();
            
            System.out.println("Generated strong DSA key: " + keyPair.getPublic().toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_8() {
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Using custom key store with strong key spec
        // ok: java-kms-key-length
        CreateKeyRequest request = new CreateKeyRequest()
            .withDescription("Strong RSA key in custom key store")
            .withKeySpec("RSA_4096")
            .withCustomKeyStoreId("arn:aws:kms:us-west-2:111122223333:custom-key-store/cks-1234567890abcdef0");
        
        kmsClient.createKey(request);
    }
    
    public void good_case_9() {
        try {
            // Using sufficient key size for Blowfish
            KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
            // ok: java-kms-key-length
            keyGen.init(448); // Maximum key size for Blowfish
            SecretKey secretKey = keyGen.generateKey();
            
            System.out.println("Generated strong Blowfish key: " + secretKey.getAlgorithm());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_10() {
        try {
            // Using sufficient key size for HMAC_REDACTED_TWILIO_ID
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
            // ok: java-kms-key-length
            keyGen.init(256); // Strong HMAC_REDACTED_TWILIO_ID key
            SecretKey secretKey = keyGen.generateKey();
            
            System.out.println("Generated strong HMAC_REDACTED_TWILIO_ID key: " + secretKey.getAlgorithm());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_11() {
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Creating a multi-region key with strong spec
        // ok: java-kms-key-length
        CreateKeyRequest request = new CreateKeyRequest()
            .withDescription("Strong multi-region key")
            .withKeySpec("RSA_4096")
            .withMultiRegion(true);
        
        kmsClient.createKey(request);
    }
    
    public void good_case_12() {
        try {
            // Using secure random with sufficient entropy
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            
            // ok: java-kms-key-length
            keyGen.initialize(4096, secureRandom); // Strong key with good random source
            KeyPair keyPair = keyGen.generateKeyPair();
            
            System.out.println("Generated strong RSA key with secure random: " + keyPair.getPublic().toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_13() {
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Creating a key for digital signatures with strong spec
        // ok: java-kms-key-length
        CreateKeyRequest request = new CreateKeyRequest()
            .withDescription("Strong signing key")
            .withKeySpec("ECC_NIST_P521") // Using the strongest NIST curve
            .withKeyUsage("SIGN_VERIFY");
        
        kmsClient.createKey(request);
    }
    
    public void good_case_14() {
        try {
            // Using sufficient key size for 3DES
            KeyGenerator keyGen = KeyGenerator.getInstance("DESede"); // Triple DES
            // ok: java-kms-key-length
            keyGen.init(168); // Using 3-key Triple DES (168 bits)
            SecretKey secretKey = keyGen.generateKey();
            
            System.out.println("Generated strong 3DES key: " + secretKey.getAlgorithm());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_15() {
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        // Creating a key with policy that enforces strong key specs
        Map<String, String> tags = new HashMap<>();
        tags.put("SecurityLevel", "High");
        
        // ok: java-kms-key-length
        CreateKeyRequest request = new CreateKeyRequest()
            .withDescription("Policy-enforced strong key")
            .withKeySpec("RSA_4096")
            .withPolicy("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"Enable IAM User Permissions\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::111122223333:root\"},\"Action\":\"kms:*\",\"Resource\":\"*\"}]}")
            .withTags(new Tag().withTagKey("SecurityLevel").withTagValue("High"));
        
        kmsClient.createKey(request);
    }
}
// {/fact}