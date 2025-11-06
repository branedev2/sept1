import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class InsecureIVExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=static-initialization-vector@v1.0 defects=1}
    public void bad_case_1() throws Exception {
        // Using a static byte array as IV
        byte[] keyBytes = "ThisIsASecretKey".getBytes();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        
        // Static IV - predictable and insecure
        byte[] ivBytes = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_2() throws Exception {
        // Using a hardcoded string as IV
        byte[] keyBytes = "ThisIsASecretKey".getBytes();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        
        // Hardcoded string as IV - predictable
        byte[] ivBytes = "ThisIsMyFixedIV!".getBytes();
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_3() throws Exception {
        // Using all zeros as IV
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // All zeros IV - extremely predictable
        byte[] ivBytes = new byte[16]; // Default initialized to all zeros
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_4() throws Exception {
        // Using a constant IV stored in a class field
        final byte[] STATIC_IV = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        IvParameterSpec iv = new IvParameterSpec(STATIC_IV);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_5() throws Exception {
        // Using a predictable pattern for IV
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Predictable pattern (incrementing bytes)
        byte[] ivBytes = new byte[16];
        for (int i = 0; i < ivBytes.length; i++) {
            ivBytes[i] = (byte) i;
        }
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_6() throws Exception {
        // Reusing the same IV for multiple encryptions
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // IV created once and reused
        byte[] ivBytes = "FixedIVForReuse!".getBytes();
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encrypted1 = cipher.doFinal("First message".getBytes());
        
        // Reusing the same IV for a second encryption
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encrypted2 = cipher.doFinal("Second message".getBytes());
    }

    public void bad_case_7() throws Exception {
        // Using system time as IV - predictable
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // System time is predictable and can be guessed
        long currentTime = System.currentTimeMillis();
        byte[] ivBytes = new byte[16];
        for (int i = 0; i < 8; i++) {
            ivBytes[i] = (byte)(currentTime >> (i * 8));
            ivBytes[i + 8] = ivBytes[i]; // Just duplicating to fill 16 bytes
        }
        
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_8() throws Exception {
        // Using a weak pseudo-random number generator for IV
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // java.util.Random is not cryptographically secure
        java.util.Random random = new java.util.Random();
        byte[] ivBytes = new byte[16];
        random.nextBytes(ivBytes);
        
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_9() throws Exception {
        // Using a hardcoded Base64 string as IV
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Hardcoded Base64 string decoded to bytes
        String base64IV = "AAECAwQFBgcICQoLDA0ODw==";
        byte[] ivBytes = Base64.getDecoder().decode(base64IV);
        
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_10() throws Exception {
        // Using a static IV from a configuration file (simulated)
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Simulating reading a static IV from config
        String configIV = getConfigValue("encryption.iv"); // Assume this returns a static value
        byte[] ivBytes = configIV.getBytes();
        
        // Ensure IV is correct length by padding or truncating
        byte[] properIV = new byte[16];
        System.arraycopy(ivBytes, 0, properIV, 0, Math.min(ivBytes.length, 16));
        
        IvParameterSpec iv = new IvParameterSpec(properIV);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_11() throws Exception {
        // Using a counter as IV (predictable sequence)
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Using a simple counter for IV
        static int counter = 0;
        byte[] ivBytes = new byte[16];
        ivBytes[0] = (byte)(counter++);
        
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_12() throws Exception {
        // Using a static IV in a utility method
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        String plaintext = "Sensitive data";
        
        // Static IV embedded in utility method
        byte[] encrypted = encryptWithStaticIV(plaintext, key);
    }
    
    private byte[] encryptWithStaticIV(String data, SecretKey key) throws Exception {
        // Static IV inside utility method
        byte[] ivBytes = "StaticIVInMethod!".getBytes();
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        return cipher.doFinal(data.getBytes());
    }

    public void bad_case_13() throws Exception {
        // Using a static IV for GCM mode (which is even worse than for CBC)
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Static IV for GCM mode
        byte[] ivBytes = "TwelveByteIV!".getBytes(); // GCM typically uses 12 bytes
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_14() throws Exception {
        // Using a static IV with CTR mode
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Static IV/nonce for CTR mode
        byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte)42); // Fill with the same value
        
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void bad_case_15() throws Exception {
        // Using a static IV derived from the key (still predictable)
        byte[] keyBytes = "ThisIsASecretKey".getBytes();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        
        // Deriving IV from key (still predictable if key is compromised)
        byte[] ivBytes = new byte[16];
        System.arraycopy(keyBytes, 0, ivBytes, 0, Math.min(keyBytes.length, 16));
        // XOR with a constant to make it different from the key
        for (int i = 0; i < ivBytes.length; i++) {
            ivBytes[i] ^= 0x3C;
        }
        
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ruleid: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() throws Exception {
        // Using SecureRandom to generate IV
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Secure random IV generation
        SecureRandom secureRandom = new SecureRandom();
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ok: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_2() throws Exception {
        // Using SecureRandom with a seed for IV generation
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Seeded secure random (still secure)
        byte[] seed = "SeedForSecureRandom".getBytes();
        SecureRandom secureRandom = new SecureRandom(seed);
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ok: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_3() throws Exception {
        // Using SecureRandom with getInstance method
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Using a specific algorithm for SecureRandom
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ok: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_4() throws Exception {
        // Using Cipher's built-in IV generation
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Let the Cipher generate the IV
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ok: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        // Get the generated IV for later use (e.g., for decryption)
        byte[] generatedIV = cipher.getIV();
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_5() throws Exception {
        // Using SecureRandom in a utility method
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        String plaintext = "Sensitive data";
        
        // Using a secure utility method
        byte[] encrypted = encryptWithSecureIV(plaintext, key);
    }
    
    private byte[] encryptWithSecureIV(String data, SecretKey key) throws Exception {
        // Secure IV generation inside utility method
        SecureRandom secureRandom = new SecureRandom();
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ok: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        return cipher.doFinal(data.getBytes());
    }

    public void good_case_6() throws Exception {
        // Using SecureRandom for GCM mode
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Secure random IV for GCM (12 bytes is recommended for GCM)
        SecureRandom secureRandom = new SecureRandom();
        byte[] ivBytes = new byte[12];
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // ok: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_7() throws Exception {
        // Using SecureRandom with a different algorithm
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Using a different secure random algorithm
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ok: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_8() throws Exception {
        // Using SecureRandom for CTR mode
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Secure random IV for CTR mode
        SecureRandom secureRandom = new SecureRandom();
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        // ok: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_9() throws Exception {
        // Using SecureRandom and storing IV with ciphertext
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Generate secure IV
        SecureRandom secureRandom = new SecureRandom();
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ok: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] ciphertext = cipher.doFinal("Sensitive data".getBytes());
        
        // Combine IV and ciphertext for storage or transmission
        byte[] combined = new byte[ivBytes.length + ciphertext.length];
        System.arraycopy(ivBytes, 0, combined, 0, ivBytes.length);
        System.arraycopy(ciphertext, 0, combined, ivBytes.length, ciphertext.length);
    }

    public void good_case_10() throws Exception {
        // Using SecureRandom and demonstrating decryption with stored IV
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        String plaintext = "Sensitive data";
        
        // Encryption with secure IV
        SecureRandom secureRandom = new SecureRandom();
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ok: java-crypto-insecure-iv
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ciphertext = encryptCipher.doFinal(plaintext.getBytes());
        
        // Decryption using the same IV
        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = decryptCipher.doFinal(ciphertext);
    }

    public void good_case_11() throws Exception {
        // Using SecureRandom with a factory method pattern
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Factory method to create secure IV
        IvParameterSpec iv = createSecureIV();
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ok: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }
    
    private IvParameterSpec createSecureIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
    }

    public void good_case_12() throws Exception {
        // Using SecureRandom in a more complex encryption workflow
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Generate secure IV
        SecureRandom secureRandom = new SecureRandom();
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        // Encrypt with secure IV
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ok: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        // Process data in chunks (simulating large data)
        byte[] chunk1 = "First chunk of data".getBytes();
        byte[] chunk2 = "Second chunk of data".getBytes();
        
        cipher.update(chunk1);
        byte[] finalEncrypted = cipher.doFinal(chunk2);
    }

    public void good_case_13() throws Exception {
        // Using SecureRandom with different providers
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Using a specific provider for SecureRandom
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ok: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_14() throws Exception {
        // Using SecureRandom with additional entropy
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Add additional entropy to SecureRandom
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(System.nanoTime()); // Additional entropy
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ok: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }

    public void good_case_15() throws Exception {
        // Using SecureRandom with a thread-local instance
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // Thread-local SecureRandom for better performance in multi-threaded environments
        ThreadLocal<SecureRandom> secureRandomThreadLocal = ThreadLocal.withInitial(() -> new SecureRandom());
        SecureRandom secureRandom = secureRandomThreadLocal.get();
        
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ok: java-crypto-insecure-iv
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
    }
    
    // Helper method for bad_case_10
    private String getConfigValue(String key) {
        // Simulated method to get a configuration value
        if ("encryption.iv".equals(key)) {
            return "StaticIVFromConfig";
        }
        return "";
    }
}
// {/fact}