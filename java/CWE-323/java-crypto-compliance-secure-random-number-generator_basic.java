import java.security.SecureRandom;
import java.util.Random;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.math3.random.RandomDataGenerator;
import java.util.concurrent.ThreadLocalRandom;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Base64;

public class SecureRandomExamples {

    // TRUE POSITIVES (Vulnerable Code)

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        
        // Using java.util.Random for generating a token
        // ruleid: java-crypto-compliance-secure-random-number-generator
        Random random = new Random();
        int tokenValue = random.nextInt(1000000);
        
        String token = username + "-" + tokenValue;
        response.getWriter().write("Your secure token is: " + token);
    }
    
    public void bad_case_2() throws Exception {
        byte[] key = new byte[16];
        
        // Using Math.random() for cryptographic key generation
        // ruleid: java-crypto-compliance-secure-random-number-generator
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (Math.random() * 256);
        }
        
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    }
    
    public void bad_case_3(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        // Using Apache Commons RandomUtils for password reset token
        // ruleid: java-crypto-compliance-secure-random-number-generator
        String resetToken = String.valueOf(RandomUtils.nextLong(0, Long.MAX_VALUE));
        
        System.out.println("Password reset token for user " + userId + ": " + resetToken);
    }
    
    public void bad_case_4() throws Exception {
        // Using ThreadLocalRandom for session ID generation
        // ruleid: java-crypto-compliance-secure-random-number-generator
        ThreadLocalRandom random = ThreadLocalRandom.current();
        long sessionId = random.nextLong();
        
        System.out.println("New session created with ID: " + sessionId);
    }
    
    public void bad_case_5() throws Exception {
        // Using Apache Commons Math RandomDataGenerator for IV generation
        // ruleid: java-crypto-compliance-secure-random-number-generator
        RandomDataGenerator generator = new RandomDataGenerator();
        byte[] iv = new byte[16];
        for (int i = 0; i < iv.length; i++) {
            iv[i] = (byte) generator.nextInt(0, 255);
        }
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        System.out.println("IV generated for encryption");
    }
    
    public void bad_case_6(HttpServletRequest request) {
        String username = request.getParameter("username");
        
        // Using Random for generating a verification code
        // ruleid: java-crypto-compliance-secure-random-number-generator
        Random random = new Random(System.currentTimeMillis());
        int verificationCode = 100000 + random.nextInt(900000); // 6-digit code
        
        System.out.println("Verification code for " + username + ": " + verificationCode);
    }
    
    public void bad_case_7() throws Exception {
        // Using Math.random() for salt generation
        // ruleid: java-crypto-compliance-secure-random-number-generator
        byte[] salt = new byte[16];
        for (int i = 0; i < salt.length; i++) {
            salt[i] = (byte) (Math.random() * 256);
        }
        
        System.out.println("Generated salt for password hashing: " + Base64.getEncoder().encodeToString(salt));
    }
    
    public void bad_case_8() {
        // Using Random with fixed seed for encryption key
        // ruleid: java-crypto-compliance-secure-random-number-generator
        Random random = new Random(123456);
        byte[] encryptionKey = new byte[32];
        random.nextBytes(encryptionKey);
        
        System.out.println("Generated encryption key");
    }
    
    public void bad_case_9(HttpServletRequest request) {
        String email = request.getParameter("email");
        
        // Using ThreadLocalRandom for 2FA backup codes
        // ruleid: java-crypto-compliance-secure-random-number-generator
        StringBuilder backupCode = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            backupCode.append(ThreadLocalRandom.current().nextInt(10));
        }
        
        System.out.println("2FA backup code for " + email + ": " + backupCode.toString());
    }
    
    public void bad_case_10() throws Exception {
        // Using Random for nonce generation in authentication
        // ruleid: java-crypto-compliance-secure-random-number-generator
        Random random = new Random();
        byte[] nonce = new byte[16];
        random.nextBytes(nonce);
        
        String nonceBase64 = Base64.getEncoder().encodeToString(nonce);
        System.out.println("Authentication nonce: " + nonceBase64);
    }
    
    public void bad_case_11() {
        // Using Math.random() for CSRF token
        // ruleid: java-crypto-compliance-secure-random-number-generator
        StringBuilder csrfToken = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            csrfToken.append(Integer.toHexString((int) (Math.random() * 16)));
        }
        
        System.out.println("CSRF Token: " + csrfToken.toString());
    }
    
    public void bad_case_12() throws Exception {
        // Using Random for initialization vector in CBC mode
        // ruleid: java-crypto-compliance-secure-random-number-generator
        Random random = new Random();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        System.out.println("IV for CBC mode encryption generated");
    }
    
    public void bad_case_13(HttpServletRequest request) {
        // Using RandomUtils for API key generation
        String userId = request.getParameter("userId");
        
        // ruleid: java-crypto-compliance-secure-random-number-generator
        StringBuilder apiKey = new StringBuilder("api_");
        for (int i = 0; i < 32; i++) {
            apiKey.append(Integer.toHexString(RandomUtils.nextInt(0, 16)));
        }
        
        System.out.println("API key for user " + userId + ": " + apiKey.toString());
    }
    
    public void bad_case_14() {
        // Using Random for password generation
        // ruleid: java-crypto-compliance-secure-random-number-generator
        Random random = new Random();
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        StringBuilder password = new StringBuilder();
        
        for (int i = 0; i < 12; i++) {
            int index = random.nextInt(chars.length());
            password.append(chars.charAt(index));
        }
        
        System.out.println("Generated temporary password: " + password.toString());
    }
    
    public void bad_case_15() throws Exception {
        // Using Math.random() for generating encryption parameters
        // ruleid: java-crypto-compliance-secure-random-number-generator
        int keySize = (int) (Math.random() * 128) + 128; // Random key size between 128 and 256
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize);
        System.out.println("Generated AES key with size: " + keySize);
    }
    
    // TRUE NEGATIVES (Secure Code)
    
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        
        // Using SecureRandom for generating a token
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        int tokenValue = secureRandom.nextInt(1000000);
        
        String token = username + "-" + tokenValue;
        response.getWriter().write("Your secure token is: " + token);
    }
    
    public void good_case_2() throws Exception {
        byte[] key = new byte[16];
        
        // Using SecureRandom for cryptographic key generation
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(key);
        
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    }
    
    public void good_case_3(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        
        // Using SecureRandom for password reset token
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        String resetToken = String.valueOf(secureRandom.nextLong());
        
        System.out.println("Password reset token for user " + userId + ": " + resetToken);
    }
    
    public void good_case_4() throws Exception {
        // Using SecureRandom for session ID generation
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        byte[] sessionIdBytes = new byte[16];
        secureRandom.nextBytes(sessionIdBytes);
        long sessionId = ByteBuffer.wrap(sessionIdBytes).getLong();
        
        System.out.println("New session created with ID: " + sessionId);
    }
    
    public void good_case_5() throws Exception {
        // Using SecureRandom for IV generation
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        System.out.println("IV generated for encryption");
    }
    
    public void good_case_6(HttpServletRequest request) {
        String username = request.getParameter("username");
        
        // Using SecureRandom for generating a verification code
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        int verificationCode = 100000 + secureRandom.nextInt(900000); // 6-digit code
        
        System.out.println("Verification code for " + username + ": " + verificationCode);
    }
    
    public void good_case_7() throws Exception {
        // Using SecureRandom for salt generation
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        
        System.out.println("Generated salt for password hashing: " + Base64.getEncoder().encodeToString(salt));
    }
    
    public void good_case_8() throws NoSuchAlgorithmException {
        // Using SecureRandom with specific algorithm for encryption key
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] encryptionKey = new byte[32];
        secureRandom.nextBytes(encryptionKey);
        
        System.out.println("Generated encryption key");
    }
    
    public void good_case_9(HttpServletRequest request) {
        String email = request.getParameter("email");
        
        // Using SecureRandom for 2FA backup codes
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder backupCode = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            backupCode.append(secureRandom.nextInt(10));
        }
        
        System.out.println("2FA backup code for " + email + ": " + backupCode.toString());
    }
    
    public void good_case_10() throws Exception {
        // Using SecureRandom for nonce generation in authentication
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[16];
        secureRandom.nextBytes(nonce);
        
        String nonceBase64 = Base64.getEncoder().encodeToString(nonce);
        System.out.println("Authentication nonce: " + nonceBase64);
    }
    
    public void good_case_11() {
        // Using SecureRandom for CSRF token
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        
        StringBuilder csrfToken = new StringBuilder();
        for (byte b : randomBytes) {
            csrfToken.append(String.format("%02x", b));
        }
        
        System.out.println("CSRF Token: " + csrfToken.toString());
    }
    
    public void good_case_12() throws Exception {
        // Using SecureRandom for initialization vector in CBC mode
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        System.out.println("IV for CBC mode encryption generated");
    }
    
    public void good_case_13(HttpServletRequest request) {
        // Using SecureRandom for API key generation
        String userId = request.getParameter("userId");
        
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        
        StringBuilder apiKey = new StringBuilder("api_");
        for (byte b : randomBytes) {
            apiKey.append(String.format("%02x", b));
        }
        
        System.out.println("API key for user " + userId + ": " + apiKey.toString());
    }
    
    public void good_case_14() {
        // Using SecureRandom for password generation
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        StringBuilder password = new StringBuilder();
        
        for (int i = 0; i < 12; i++) {
            int index = secureRandom.nextInt(chars.length());
            password.append(chars.charAt(index));
        }
        
        System.out.println("Generated temporary password: " + password.toString());
    }
    
    public void good_case_15() throws Exception {
        // Using SecureRandom for generating encryption parameters
        // ok: java-crypto-compliance-secure-random-number-generator
        SecureRandom secureRandom = new SecureRandom();
        int keySize = 128 + (secureRandom.nextInt(3) * 64); // Either 128, 192, or 256
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize, secureRandom);
        System.out.println("Generated AES key with size: " + keySize);
    }
}
// {/fact}