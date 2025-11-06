import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import javax.servlet.http.*;
import java.io.*;

public class DigitalSignatureExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=clear-text-credentials@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) throws Exception {
        String algorithm = request.getParameter("algorithm");
        
        // Using MD5 for digital signature, which is cryptographically weak
        // ruleid: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("MD5withRSA");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void bad_case_2() throws Exception {
        // Using SHA1 which is no longer considered secure for digital signatures
        // ruleid: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("SHA1withRSA");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void bad_case_3() throws Exception {
        // Using DSA with insufficient key size (512 bits)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        // ruleid: java-secure-algorithms-for-digital-signature
        keyGen.initialize(512);
        KeyPair keyPair = keyGen.generateKeyPair();
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void bad_case_4(HttpServletRequest request) throws Exception {
        // Using user-controlled algorithm which could be manipulated
        String algorithm = request.getParameter("algorithm");
        // ruleid: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance(algorithm);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void bad_case_5() throws Exception {
        // Using RSA with insufficient key size
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ruleid: java-secure-algorithms-for-digital-signature
        keyGen.initialize(512);
        KeyPair keyPair = keyGen.generateKeyPair();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void bad_case_6() throws Exception {
        // Using MD2 hash algorithm which is cryptographically broken
        // ruleid: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("MD2withRSA");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void bad_case_7() throws Exception {
        // Using RIPEMD160 which is not recommended for new applications
        // ruleid: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("RIPEMD160withRSA");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void bad_case_8() throws Exception {
        // Using weak ECDSA curve (prime192v1)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        // ruleid: java-secure-algorithms-for-digital-signature
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void bad_case_9(HttpServletRequest request) throws Exception {
        // Using a hardcoded weak algorithm string
        String weakAlgo = "MD5withRSA";
        // ruleid: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance(weakAlgo);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void bad_case_10() throws Exception {
        // Using DSA with SHA1 (both are weak)
        // ruleid: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("SHA1withDSA");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void bad_case_11() throws Exception {
        // Using RSA with PKCS1Padding which is vulnerable to padding oracle attacks
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ruleid: java-secure-algorithms-for-digital-signature
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted = cipher.doFinal("data to sign".getBytes());
        
        // Using the encrypted data as a signature (not a proper digital signature)
        byte[] signedData = encrypted;
    }

    public void bad_case_12() throws Exception {
        // Using a weak key size for ECDSA
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        // ruleid: java-secure-algorithms-for-digital-signature
        keyGen.initialize(112); // Too small for EC
        KeyPair keyPair = keyGen.generateKeyPair();
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void bad_case_13() throws Exception {
        // Using non-standard or custom signature algorithm
        // ruleid: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("NONEwithRSA");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void bad_case_14() throws Exception {
        // Using MD4 which is cryptographically broken
        try {
            // ruleid: java-secure-algorithms-for-digital-signature
            Signature signature = Signature.getInstance("MD4withRSA");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            signature.initSign(keyPair.getPrivate());
            signature.update("data to sign".getBytes());
            byte[] signedData = signature.sign();
        } catch (NoSuchAlgorithmException e) {
            // MD4 might not be available in all JDK implementations
            System.out.println("MD4 not available");
        }
    }

    public void bad_case_15() throws Exception {
        // Using weak algorithm selected from a map
        Map<String, String> algorithms = new HashMap<>();
        algorithms.put("fast", "MD5withRSA");
        algorithms.put("secure", "SHA256withRSA");
        
        String selectedAlgo = algorithms.get("fast");
        // ruleid: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance(selectedAlgo);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() throws Exception {
        // Using SHA256 with RSA (secure combination)
        // ok: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void good_case_2() throws Exception {
        // Using SHA384 with RSA and sufficient key size
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-secure-algorithms-for-digital-signature
        keyGen.initialize(3072);
        KeyPair keyPair = keyGen.generateKeyPair();
        Signature signature = Signature.getInstance("SHA384withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void good_case_3() throws Exception {
        // Using SHA512 with ECDSA and secure curve
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        // ok: java-secure-algorithms-for-digital-signature
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
        Signature signature = Signature.getInstance("SHA512withECDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void good_case_4() throws Exception {
        // Using SHA256 with DSA and sufficient key size
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        // ok: java-secure-algorithms-for-digital-signature
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void good_case_5(HttpServletRequest request) throws Exception {
        // Validating user input for algorithm selection
        String requestedAlgo = request.getParameter("algorithm");
        String algorithm;
        
        // ok: java-secure-algorithms-for-digital-signature
        if ("SHA256withRSA".equals(requestedAlgo) || "SHA384withRSA".equals(requestedAlgo) || "SHA512withRSA".equals(requestedAlgo)) {
            algorithm = requestedAlgo;
        } else {
            algorithm = "SHA256withRSA"; // Default to secure algorithm
        }
        
        Signature signature = Signature.getInstance(algorithm);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void good_case_6() throws Exception {
        // Using secure algorithm from a configuration
        Properties props = new Properties();
        props.setProperty("signature.algorithm", "SHA256withRSA");
        props.setProperty("key.size", "2048");
        
        // ok: java-secure-algorithms-for-digital-signature
        String algorithm = props.getProperty("signature.algorithm");
        int keySize = Integer.parseInt(props.getProperty("key.size"));
        
        Signature signature = Signature.getInstance(algorithm);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        KeyPair keyPair = keyGen.generateKeyPair();
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void good_case_7() throws Exception {
        // Using SHA3-256 with RSA (modern and secure)
        // ok: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("SHA3-256withRSA");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void good_case_8() throws Exception {
        // Using ECDSA with a strong curve (P-384)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        // ok: java-secure-algorithms-for-digital-signature
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp384r1");
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
        Signature signature = Signature.getInstance("SHA384withECDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void good_case_9() throws Exception {
        // Using secure algorithm with proper key management
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("keystore.p12"), "password".toCharArray());
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("alias", "password".toCharArray());
        
        // ok: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void good_case_10() throws Exception {
        // Using secure algorithm selected from a map
        Map<String, String> algorithms = new HashMap<>();
        algorithms.put("default", "SHA256withRSA");
        algorithms.put("high_security", "SHA512withRSA");
        
        // ok: java-secure-algorithms-for-digital-signature
        String selectedAlgo = algorithms.get("high_security");
        Signature signature = Signature.getInstance(selectedAlgo);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(4096);
        KeyPair keyPair = keyGen.generateKeyPair();
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void good_case_11() throws Exception {
        // Using EdDSA (modern and secure algorithm)
        // ok: java-secure-algorithms-for-digital-signature
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = keyGen.generateKeyPair();
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void good_case_12() throws Exception {
        // Using secure algorithm with proper verification
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ok: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        byte[] data = "data to sign".getBytes();
        signature.update(data);
        byte[] signedData = signature.sign();
        
        // Verify the signature
        signature.initVerify(keyPair.getPublic());
        signature.update(data);
        boolean verified = signature.verify(signedData);
    }

    public void good_case_13() throws Exception {
        // Using secure algorithm with proper exception handling
        try {
            // ok: java-secure-algorithms-for-digital-signature
            Signature signature = Signature.getInstance("SHA512withRSA");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(4096);
            KeyPair keyPair = keyGen.generateKeyPair();
            signature.initSign(keyPair.getPrivate());
            signature.update("data to sign".getBytes());
            byte[] signedData = signature.sign();
        } catch (NoSuchAlgorithmException e) {
            // Fallback to another secure algorithm
            Signature signature = Signature.getInstance("SHA256withRSA");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            signature.initSign(keyPair.getPrivate());
            signature.update("data to sign".getBytes());
            byte[] signedData = signature.sign();
        }
    }

    public void good_case_14() throws Exception {
        // Using secure algorithm with proper key size determination
        int keySize;
        String algorithm = "RSA";
        
        // ok: java-secure-algorithms-for-digital-signature
        if (algorithm.equals("RSA")) {
            keySize = 2048;
        } else if (algorithm.equals("DSA")) {
            keySize = 2048;
        } else {
            keySize = 256; // For EC
        }
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
        keyGen.initialize(keySize);
        KeyPair keyPair = keyGen.generateKeyPair();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update("data to sign".getBytes());
        byte[] signedData = signature.sign();
    }

    public void good_case_15() throws Exception {
        // Using secure algorithm with proper key management and verification
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        
        // ok: java-secure-algorithms-for-digital-signature
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(3072);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Signature signature = Signature.getInstance("SHA512withRSA", "BC");
        signature.initSign(keyPair.getPrivate());
        byte[] data = "data to sign".getBytes();
        signature.update(data);
        byte[] signedData = signature.sign();
    }
}
// {/fact}