import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class CryptoComplianceTest {

    // True Positives (Vulnerable Code)

// {fact rule=clear-text-credentials@v1.0 defects=1}
    public void bad_case_1() throws NoSuchAlgorithmException, InvalidKeyException {
        String message = "Message to authenticate";
        String key = "too_short_key";
        
        // Using weak MD5-based MAC_REDACTED_TWILIO_ID
        // ruleid: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacMD5");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacMD5");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    public void bad_case_2() throws NoSuchAlgorithmException, InvalidKeyException {
        String message = "Message to authenticate";
        String key = "weak_static_key_12345";
        
        // Using weak SHA1-based MAC_REDACTED_TWILIO_ID
        // ruleid: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA1");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA1");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    public void bad_case_3() throws NoSuchAlgorithmException, InvalidKeyException {
        String message = "Message to authenticate";
        String key = "static_key_for_mac_algorithm";
        
        // Using MAC_REDACTED_TWILIO_ID with static key and no salt
        // ruleid: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    public void bad_case_4() throws NoSuchAlgorithmException, InvalidKeyException {
        String message = "Message to authenticate";
        
        // Using very short key (8 bytes)
        byte[] keyBytes = new byte[8];
        new SecureRandom().nextBytes(keyBytes);
        
        // ruleid: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    public void bad_case_5() throws NoSuchAlgorithmException, InvalidKeyException {
        String message = "Message to authenticate";
        String key = "insecure_key_comparison";
        
        // Using MAC_REDACTED_TWILIO_ID with insecure comparison (timing attack vulnerability)
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] expectedHmac = mac.doFinal(message.getBytes());
        
        // Simulating received MAC_REDACTED_TWILIO_ID
        byte[] receivedHmac = new byte[expectedHmac.length];
        
        // Insecure comparison (vulnerable to timing attacks)
        boolean isValid = true;
        for (int i = 0; i < expectedHmac.length; i++) {
            // ruleid: java-crypto-compliance
            if (expectedHmac[i] != receivedHmac[i]) {
                isValid = false;
                break;
            }
        }
    }

    public void bad_case_6() throws Exception {
        // Custom MAC_REDACTED_TWILIO_ID implementation using weak hash function
        MessageDigest md = MessageDigest.getInstance("MD5");
        String key = "static_secret_key";
        String message = "Message to authenticate";
        
        // ruleid: java-crypto-compliance
        byte[] result = md.digest((key + message).getBytes());
        String macValue = Base64.getEncoder().encodeToString(result);
    }

    public void bad_case_7() throws Exception {
        // Using MAC_REDACTED_TWILIO_ID with predictable key
        String message = "Message to authenticate";
        String key = "1234567890abcdef"; // Predictable key
        
        // ruleid: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    public void bad_case_8() throws Exception {
        // Using MAC_REDACTED_TWILIO_ID with key derived from weak password
        String userPassword = "simple_password";
        String message = "Message to authenticate";
        
        // Weak key derivation (just using password bytes directly)
        // ruleid: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(userPassword.getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    public void bad_case_9() throws Exception {
        // Using MAC_REDACTED_TWILIO_ID with truncated output (too short)
        String message = "Message to authenticate";
        String key = "some_key_for_mac";
        
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] fullHmac = mac.doFinal(message.getBytes());
        
        // Truncating to only 4 bytes (32 bits) - too short for security
        // ruleid: java-crypto-compliance
        byte[] truncatedHmac = Arrays.copyOf(fullHmac, 4);
    }

    public void bad_case_10() throws Exception {
        // Using MAC_REDACTED_TWILIO_ID with static initialization vector
        String message = "Message to authenticate";
        byte[] iv = new byte[16];
        Arrays.fill(iv, (byte)0); // Static IV filled with zeros
        
        String key = "mac_key_with_static_iv";
        
        // ruleid: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec((key + new String(iv)).getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    public void bad_case_11() throws Exception {
        // Using MAC_REDACTED_TWILIO_ID with key reuse across different contexts
        String key = "reused_key_across_contexts";
        String message1 = "First message";
        String message2 = "Second message in different context";
        
        // ruleid: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmac1 = mac.doFinal(message1.getBytes());
        
        // Reusing the same key in a different context
        mac.reset();
        byte[] hmac2 = mac.doFinal(message2.getBytes());
    }

    public void bad_case_12() throws Exception {
        // Using MAC_REDACTED_TWILIO_ID with insufficient key size for algorithm
        String message = "Message to authenticate";
        byte[] keyBytes = new byte[12]; // 96 bits - insufficient for modern security
        new SecureRandom().nextBytes(keyBytes);
        
        // ruleid: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA384"); // SHA384 needs stronger key
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA384");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    public void bad_case_13() throws Exception {
        // Using MAC_REDACTED_TWILIO_ID with hardcoded key in source code
        String message = "Message to authenticate";
        String hardcodedKey = "c29tZXNlY3JldGtleWZvcm1hY2FsZ29yaXRobQ=="; // Base64 encoded key
        byte[] keyBytes = Base64.getDecoder().decode(hardcodedKey);
        
        // ruleid: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    public void bad_case_14() throws Exception {
        // Custom MAC_REDACTED_TWILIO_ID implementation using simple XOR (very weak)
        String message = "Message to authenticate";
        byte[] key = "simple_xor_key".getBytes();
        byte[] messageBytes = message.getBytes();
        byte[] result = new byte[messageBytes.length];
        
        // ruleid: java-crypto-compliance
        for (int i = 0; i < messageBytes.length; i++) {
            result[i] = (byte) (messageBytes[i] ^ key[i % key.length]);
        }
        // Using this XOR result as a MAC_REDACTED_TWILIO_ID (extremely insecure)
    }

    public void bad_case_15() throws Exception {
        // Using MAC_REDACTED_TWILIO_ID with key derived from system time (predictable)
        String message = "Message to authenticate";
        long currentTime = System.currentTimeMillis();
        String timeBasedKey = "key_" + currentTime;
        
        // ruleid: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(timeBasedKey.getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    // True Negatives (Secure Code)

    public void good_case_1() throws NoSuchAlgorithmException, InvalidKeyException {
        String message = "Message to authenticate";
        
        // Generate a proper key with sufficient length
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        keyGen.init(256); // 256 bits key
        SecretKey secretKey = keyGen.generateKey();
        
        // ok: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    public void good_case_2() throws NoSuchAlgorithmException, InvalidKeyException {
        String message = "Message to authenticate";
        
        // Using a secure random key with sufficient length
        byte[] keyBytes = new byte[32]; // 256 bits
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(keyBytes);
        
        // ok: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    public void good_case_3() throws NoSuchAlgorithmException, InvalidKeyException {
        String message = "Message to authenticate";
        
        // Using a strong algorithm with proper key size
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA512");
        keyGen.init(512); // 512 bits key for SHA-512
        SecretKey secretKey = keyGen.generateKey();
        
        // ok: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(secretKey);
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    public void good_case_4() throws NoSuchAlgorithmException, InvalidKeyException {
        String message = "Message to authenticate";
        
        // Generate a proper key with sufficient length
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        byte[] expectedHmac = mac.doFinal(message.getBytes());
        
        // Simulating received MAC_REDACTED_TWILIO_ID
        byte[] receivedHmac = new byte[expectedHmac.length];
        
        // Secure constant-time comparison to prevent timing attacks
        // ok: java-crypto-compliance
        boolean isValid = MessageDigest.isEqual(expectedHmac, receivedHmac);
    }

    public void good_case_5() throws NoSuchAlgorithmException, InvalidKeyException {
        String message = "Message to authenticate";
        
        // Using environment variable for key (not hardcoded)
        String envKeyBase64 = System.getenv("MAC_REDACTED_TWILIO_ID_KEY");
        if (envKeyBase64 == null || envKeyBase64.isEmpty()) {
            throw new IllegalStateException("MAC_REDACTED_TWILIO_ID key not configured");
        }
        
        byte[] keyBytes = Base64.getDecoder().decode(envKeyBase64);
        
        // ok: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    public void good_case_6() throws Exception {
        // Using a secure key derivation function to derive MAC_REDACTED_TWILIO_ID key from password
        String password = "user_password";
        byte[] salt = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        
        // Simulate PBKDF2 for key derivation (in real code, use actual PBKDF2)
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] saltedPassword = new byte[password.getBytes().length + salt.length];
        System.arraycopy(password.getBytes(), 0, saltedPassword, 0, password.getBytes().length);
        System.arraycopy(salt, 0, saltedPassword, password.getBytes().length, salt.length);
        
        byte[] keyBytes = new byte[32];
        byte[] hash = digest.digest(saltedPassword);
        System.arraycopy(hash, 0, keyBytes, 0, Math.min(hash.length, keyBytes.length));
        
        String message = "Message to authenticate";
        
        // ok: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    public void good_case_7() throws Exception {
        // Using context-specific keys for different operations
        String context1 = "authentication";
        String context2 = "verification";
        String message = "Message to authenticate";
        
        // Generate master key
        byte[] masterKey = new byte[32];
        new SecureRandom().nextBytes(masterKey);
        
        // Derive context-specific keys
        Mac kdf = Mac.getInstance("HmacSHA256");
        SecretKeySpec masterKeySpec = new SecretKeySpec(masterKey, "HmacSHA256");
        kdf.init(masterKeySpec);
        
        byte[] key1 = kdf.doFinal(context1.getBytes());
        byte[] key2 = kdf.doFinal(context2.getBytes());
        
        // Use derived keys for specific contexts
        // ok: java-crypto-compliance
        Mac mac1 = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec1 = new SecretKeySpec(key1, "HmacSHA256");
        mac1.init(keySpec1);
        byte[] hmac1 = mac1.doFinal(message.getBytes());
        
        Mac mac2 = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec2 = new SecretKeySpec(key2, "HmacSHA256");
        mac2.init(keySpec2);
        byte[] hmac2 = mac2.doFinal(message.getBytes());
    }

    public void good_case_8() throws Exception {
        // Using secure key rotation
        String message = "Message to authenticate";
        long keyVersion = 2; // Current key version
        
        // In a real system, keys would be retrieved from a secure key management system
        byte[] currentKey = retrieveKeyForVersion(keyVersion);
        
        // ok: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(currentKey, "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message.getBytes());
        
        // Store both the MAC_REDACTED_TWILIO_ID and the key version used
        String macWithVersion = keyVersion + ":" + Base64.getEncoder().encodeToString(hmac);
    }
    
    private byte[] retrieveKeyForVersion(long version) {
        // Simulate retrieving a key from a secure key management system
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[32];
        random.nextBytes(key);
        return key;
    }

    public void good_case_9() throws Exception {
        // Using MAC_REDACTED_TWILIO_ID with proper authentication tag length
        String message = "Message to authenticate";
        
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        byte[] fullHmac = mac.doFinal(message.getBytes());
        
        // Using full length MAC_REDACTED_TWILIO_ID or truncating to a secure length (still at least 128 bits)
        // ok: java-crypto-compliance
        byte[] truncatedHmac = Arrays.copyOf(fullHmac, 16); // 128 bits, still secure
    }

    public void good_case_10() throws Exception {
        // Using MAC_REDACTED_TWILIO_ID with additional authenticated data
        String message = "Message to authenticate";
        String additionalData = "request_id=12345&timestamp=1609459200";
        
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        // ok: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        mac.update(additionalData.getBytes(StandardCharsets.UTF_8));
        byte[] hmac = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }

    public void good_case_11() throws Exception {
        // Using MAC_REDACTED_TWILIO_ID with secure key storage
        String message = "Message to authenticate";
        
        // Simulate retrieving key from a secure key vault or HSM
        byte[] keyBytes = retrieveKeyFromSecureStorage();
        
        // ok: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmac = mac.doFinal(message.getBytes());
    }
    
    private byte[] retrieveKeyFromSecureStorage() {
        // In a real application, this would connect to a secure key vault or HSM
        // For this example, we'll generate a secure random key
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }

    public void good_case_12() throws Exception {
        // Using MAC_REDACTED_TWILIO_ID with proper algorithm selection based on security requirements
        String message = "Message to authenticate";
        boolean highSecurityRequired = true;
        
        KeyGenerator keyGen;
        Mac mac;
        
        if (highSecurityRequired) {
            keyGen = KeyGenerator.getInstance("HmacSHA512");
            keyGen.init(512);
            SecretKey secretKey = keyGen.generateKey();
            
            // ok: java-crypto-compliance
            mac = Mac.getInstance("HmacSHA512");
            mac.init(secretKey);
        } else {
            keyGen = KeyGenerator.getInstance("HmacSHA256");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            
            mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKey);
        }
        
        byte[] hmac = mac.doFinal(message.getBytes());
    }

    public void good_case_13() throws Exception {
        // Using MAC_REDACTED_TWILIO_ID with nonce to prevent replay attacks
        String message = "Message to authenticate";
        
        // Generate a nonce
        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);
        String nonceBase64 = Base64.getEncoder().encodeToString(nonce);
        
        // Combine message with nonce
        String messageWithNonce = message + "|nonce=" + nonceBase64;
        
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        // ok: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        byte[] hmac = mac.doFinal(messageWithNonce.getBytes());
    }

    public void good_case_14() throws Exception {
        // Using MAC_REDACTED_TWILIO_ID with proper error handling
        String message = "Message to authenticate";
        
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            
            // ok: java-crypto-compliance
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKey);
            byte[] hmac = mac.doFinal(message.getBytes());
            
        } catch (NoSuchAlgorithmException e) {
            // Log the error properly
            System.err.println("MAC_REDACTED_TWILIO_ID algorithm not available: " + e.getMessage());
            // Don't fall back to a weaker algorithm
            throw e;
        } catch (InvalidKeyException e) {
            System.err.println("Invalid key for MAC_REDACTED_TWILIO_ID: " + e.getMessage());
            throw e;
        }
    }

    public void good_case_15() throws Exception {
        // Using MAC_REDACTED_TWILIO_ID with proper key length for the algorithm
        String message = "Message to authenticate";
        
        // Using HMAC_REDACTED_TWILIO_ID-SHA384 with appropriate key length
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA384");
        keyGen.init(384); // Matching key size to hash output size
        SecretKey secretKey = keyGen.generateKey();
        
        // ok: java-crypto-compliance
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(secretKey);
        byte[] hmac = mac.doFinal(message.getBytes());
    }
}
// {/fact}