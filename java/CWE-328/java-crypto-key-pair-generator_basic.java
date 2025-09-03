import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Random;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;

public class KeyPairGeneratorExamples {

    // True Positives (Vulnerable Code)

// {fact rule=clear-text-credentials@v1.0 defects=1}
    public void bad_case_1() throws Exception {
        // Using weak key size (512 bits) for RSA
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(512);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted = cipher.doFinal("sensitive data".getBytes());
    }

    public void bad_case_2() throws Exception {
        // Using insecure algorithm (DSA with small key size)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(512);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initSign(keyPair.getPrivate());
    }

    public void bad_case_3() throws Exception {
        // Using weak key size with SecureRandom
        SecureRandom random = new SecureRandom();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(768, random);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void bad_case_4() throws Exception {
        // Using weak EC curve
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp112r1"); // Weak curve
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void bad_case_5() throws Exception {
        // Using weak EC curve with SecureRandom
        SecureRandom random = new SecureRandom();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp112r2"); // Weak curve
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(ecSpec, random);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void bad_case_6() throws Exception {
        // Using weak RSA key with insecure padding mode
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // Vulnerable to padding oracle attacks
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    }

    public void bad_case_7() throws Exception {
        // Using non-standard algorithm with weak key size
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(new RSAKeyGenParameterSpec(512, RSAKeyGenParameterSpec.F4));
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void bad_case_8() throws Exception {
        // Using weak key size with dynamic value (still too small)
        int keySize = 512;
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(keySize);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void bad_case_9() throws Exception {
        // Using weak key size with calculation (still too small)
        int baseBits = 256;
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(baseBits * 2); // 512 bits
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void bad_case_10() throws Exception {
        // Using weak EC curve with dynamic selection
        String curveName = "sect113r1"; // Weak curve
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void bad_case_11() throws Exception {
        // Using weak key with non-standard provider
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(512);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void bad_case_12() throws Exception {
        // Using weak key with custom random number generator
        Random insecureRandom = new Random(); // Not cryptographically secure
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(1024, new SecureRandom(insecureRandom.generateSeed(8)));
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void bad_case_13() throws Exception {
        // Using weak DH parameters
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        DHParameterSpec dhSpec = new DHParameterSpec(
            new BigInteger("prime", 16), 
            new BigInteger("generator", 16),
            512 // Weak key size
        );
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(dhSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void bad_case_14() throws Exception {
        // Using weak key size loaded from configuration
        Properties props = new Properties();
        try (FileInputStream in = new FileInputStream("config.properties")) {
            props.load(in);
        } catch (IOException e) {
            // Default to weak key size if config not found
            props.setProperty("key.size", "512");
        }
        
        int keySize = Integer.parseInt(props.getProperty("key.size"));
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(keySize); // Using potentially weak key size from config
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void bad_case_15() throws Exception {
        // Using weak key with insecure algorithm combination
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Cipher cipher = Cipher.getInstance("RSA/NONE/NoPadding"); // Insecure padding
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    }

    // True Negatives (Secure Code)

    public void good_case_1() throws Exception {
        // Using secure key size for RSA
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    }

    public void good_case_2() throws Exception {
        // Using secure key size for DSA
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(keyPair.getPrivate());
    }

    public void good_case_3() throws Exception {
        // Using secure key size with SecureRandom
        SecureRandom random = new SecureRandom();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(3072, random);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void good_case_4() throws Exception {
        // Using strong EC curve
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1"); // Strong curve
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void good_case_5() throws Exception {
        // Using strong EC curve with SecureRandom
        SecureRandom random = new SecureRandom();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp384r1"); // Strong curve
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(ecSpec, random);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void good_case_6() throws Exception {
        // Using strong RSA key with secure padding mode
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(4096);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    }

    public void good_case_7() throws Exception {
        // Using standard algorithm with strong key size
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void good_case_8() throws Exception {
        // Using strong key size with dynamic value
        int keySize = 2048;
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(keySize);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void good_case_9() throws Exception {
        // Using strong key size with calculation
        int baseBits = 1024;
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(baseBits * 3); // 3072 bits
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void good_case_10() throws Exception {
        // Using strong EC curve with dynamic selection
        String curveName = "secp521r1"; // Strong curve
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void good_case_11() throws Exception {
        // Using strong key with non-standard provider
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void good_case_12() throws Exception {
        // Using strong key with proper SecureRandom
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(2048, secureRandom);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void good_case_13() throws Exception {
        // Using strong DH parameters
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        DHParameterSpec dhSpec = new DHParameterSpec(
            new BigInteger("prime", 16), 
            new BigInteger("generator", 16),
            2048 // Strong key size
        );
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(dhSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void good_case_14() throws Exception {
        // Using strong key size loaded from configuration with minimum check
        Properties props = new Properties();
        try (FileInputStream in = new FileInputStream("config.properties")) {
            props.load(in);
        } catch (IOException e) {
            // Default to strong key size if config not found
            props.setProperty("key.size", "2048");
        }
        
        int keySize = Integer.parseInt(props.getProperty("key.size"));
        // Ensure minimum key size
        keySize = Math.max(keySize, 2048);
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(keySize);
        KeyPair keyPair = keyGen.generateKeyPair();
    }

    public void good_case_15() throws Exception {
        // Using strong key with secure algorithm combination
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(4096);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        
        // Also using the key for digital signatures with a strong algorithm
        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initSign(keyPair.getPrivate());
    }
}
// {/fact}