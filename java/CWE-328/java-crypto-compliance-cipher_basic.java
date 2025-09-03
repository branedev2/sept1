import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import java.security.spec.KeySpec;

public class CryptoComplianceExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=clear-text-credentials@v1.0 defects=1}
    public void bad_case_1() throws Exception {
        // Using DES which is a weak encryption algorithm
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec("12345678".getBytes(), "DES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_2() throws Exception {
        // Using RC4 which is considered insecure
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("RC4");
        SecretKeySpec keySpec = new SecretKeySpec("0123456789abcdef".getBytes(), "RC4");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_3() throws Exception {
        // Using ECB mode which doesn't provide semantic security
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(new byte[16], "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_4() throws Exception {
        // Using Blowfish with small key size
        byte[] keyBytes = "smallkey".getBytes(); // Only 8 bytes
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "Blowfish");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_5() throws Exception {
        // Using AES with a static IV
        byte[] staticIv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(new byte[16], "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(staticIv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_6() throws Exception {
        // Using Triple DES which is deprecated
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(new byte[24], "DESede");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_7() throws Exception {
        // Using AES with a key that's too short (128 bits when 256 might be required)
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(new byte[16], "AES"); // 128-bit key
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_8() throws Exception {
        // Using RSA without OAEP padding
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        // Assume we have a valid RSA key
        Key publicKey = KeyGenerator.getInstance("RSA").generateKey();
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_9() throws Exception {
        // Using AES in CTR mode without integrity check
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(new byte[16], "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_10() throws Exception {
        // Using a hardcoded key
        byte[] hardcodedKey = "ThisIsAHardcodedKey".getBytes();
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(hardcodedKey, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_11() throws Exception {
        // Using a weak PBE algorithm
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        KeySpec spec = new PBEKeySpec("password".toCharArray(), new byte[8], 1000);
        SecretKey key = factory.generateSecret(spec);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_12() throws Exception {
        // Using a non-random IV
        byte[] iv = "1234567890123456".getBytes(); // Non-random IV
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(new byte[16], "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_13() throws Exception {
        // Using AES-GCM with a reused IV
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmParams = new GCMParameterSpec(128, iv);
        SecretKeySpec keySpec = new SecretKeySpec(new byte[16], "AES");
        
        // First use
        Cipher cipher1 = Cipher.getInstance("AES/GCM/NoPadding");
        cipher1.init(Cipher.ENCRYPT_MODE, keySpec, gcmParams);
        byte[] encrypted1 = cipher1.doFinal("Message 1".getBytes());
        
        // Second use with same IV (very bad practice)
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher2 = Cipher.getInstance("AES/GCM/NoPadding");
        cipher2.init(Cipher.ENCRYPT_MODE, keySpec, gcmParams);
        byte[] encrypted2 = cipher2.doFinal("Message 2".getBytes());
    }

    public void bad_case_14() throws Exception {
        // Using a cipher without specifying mode and padding
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES");  // Defaults to ECB mode in many providers
        SecretKeySpec keySpec = new SecretKeySpec(new byte[16], "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_15() throws Exception {
        // Using RC2 which is a weak algorithm
        // ruleid: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("RC2/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(new byte[8], "RC2");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() throws Exception {
        // Using AES with GCM mode which provides both confidentiality and integrity
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        
        // ok: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(new byte[32], "AES"); // 256-bit key
        GCMParameterSpec gcmParams = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParams);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_2() throws Exception {
        // Using AES with CBC mode and a secure random IV
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        
        // ok: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(new byte[32], "AES"); // 256-bit key
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_3() throws Exception {
        // Using RSA with OAEP padding which is secure against padding oracle attacks
        // ok: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        // Assume we have a valid RSA key
        Key publicKey = KeyGenerator.getInstance("RSA").generateKey();
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_4() throws Exception {
        // Using a secure key generation method
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // 256-bit key
        SecretKey secretKey = keyGen.generateKey();
        
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        
        // ok: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_5() throws Exception {
        // Using a secure PBE algorithm with sufficient iterations
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        int iterations = 10000; // Sufficient iterations
        
        // ok: java-crypto-compliance-cipher
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec("password".toCharArray(), salt, iterations, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmParams = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParams);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_6() throws Exception {
        // Using AES with CTR mode and an HMAC_REDACTED_TWILIO_ID for integrity
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey encKey = keyGen.generateKey();
        
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        
        // ok: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, encKey, ivSpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
        
        // Add HMAC_REDACTED_TWILIO_ID for integrity (simplified)
        KeyGenerator macKeyGen = KeyGenerator.getInstance("HmacSHA256");
        SecretKey macKey = macKeyGen.generateKey();
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(macKey);
        mac.update(iv);
        byte[] macValue = mac.doFinal(encrypted);
    }

    public void good_case_7() throws Exception {
        // Using AES-GCM with a unique IV for each encryption
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        
        // First encryption
        byte[] iv1 = new byte[12];
        new SecureRandom().nextBytes(iv1);
        
        // ok: java-crypto-compliance-cipher
        Cipher cipher1 = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParams1 = new GCMParameterSpec(128, iv1);
        cipher1.init(Cipher.ENCRYPT_MODE, key, gcmParams1);
        byte[] encrypted1 = cipher1.doFinal("Message 1".getBytes());
        
        // Second encryption with different IV
        byte[] iv2 = new byte[12];
        new SecureRandom().nextBytes(iv2);
        
        Cipher cipher2 = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParams2 = new GCMParameterSpec(128, iv2);
        cipher2.init(Cipher.ENCRYPT_MODE, key, gcmParams2);
        byte[] encrypted2 = cipher2.doFinal("Message 2".getBytes());
    }

    public void good_case_8() throws Exception {
        // Using ChaCha20-Poly1305 which is a modern AEAD cipher
        // ok: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        SecretKey key = KeyGenerator.getInstance("ChaCha20").generateKey();
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        IvParameterSpec ivSpec = new IvParameterSpec(nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_9() throws Exception {
        // Using AES-GCM with a 256-bit key and proper parameters
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        
        // ok: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParams = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParams);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_10() throws Exception {
        // Using a key derived from a password with a secure method
        String password = "userPassword";
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        
        // ok: java-crypto-compliance-cipher
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmParams = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParams);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_11() throws Exception {
        // Using RSA with appropriate key size and padding
        // ok: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        // Assume we have a valid RSA key with appropriate size (e.g., 2048 bits)
        Key publicKey = KeyGenerator.getInstance("RSA").generateKey();
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_12() throws Exception {
        // Using AES-CBC with proper key generation and IV handling
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        
        // ok: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key); // Let the cipher generate a secure IV
        byte[] iv = cipher.getIV(); // Store this IV for decryption
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_13() throws Exception {
        // Using authenticated encryption with associated data (AEAD)
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        
        // ok: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParams = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParams);
        
        // Add associated data for additional security
        byte[] associatedData = "Header information".getBytes();
        cipher.updateAAD(associatedData);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_14() throws Exception {
        // Using a secure random number generator for key generation
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, secureRandom);
        SecretKey key = keyGen.generateKey();
        
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        
        // ok: java-crypto-compliance-cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_15() throws Exception {
        // Using a hybrid encryption scheme (RSA for key exchange, AES for data)
        // Generate an AES key for data encryption
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(256);
        SecretKey aesKey = aesKeyGen.generateKey();
        
        // Encrypt data with AES
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        
        // ok: java-crypto-compliance-cipher
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParams = new GCMParameterSpec(128, iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmParams);
        byte[] encryptedData = aesCipher.doFinal("Sensitive data".getBytes());
        
        // Encrypt the AES key with RSA (simplified)
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        // Assume we have a valid RSA key
        Key publicKey = KeyGenerator.getInstance("RSA").generateKey();
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = rsaCipher.doFinal(aesKey.getEncoded());
    }
}
// {/fact}