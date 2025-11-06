import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import javax.xml.bind.DatatypeConverter;
import java.util.Base64;

// Spring Security imports
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

// Apache Shiro imports
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.util.ByteSource;

// JJWT imports
import io.jsonwebtoken.security.Password;
import io.jsonwebtoken.security.Passwords;

// Jasypt imports
import org.jasypt.util.password.StrongPasswordEncryptor;
import org.jasypt.util.password.BasicPasswordEncryptor;

// jBCrypt imports
import org.mindrot.jbcrypt.BCrypt;

// Bouncy Castle imports
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

// Passay imports
import org.passay.PasswordGenerator;

// Dropwizard imports
import io.dropwizard.auth.basic.BasicCredentials;

// Play Framework imports
import play.api.libs.Crypto;

// Jakarta EE Security imports
import jakarta.security.enterprise.identitystore.Pbkdf2PasswordHash;

// Micronaut Security imports
import io.micronaut.security.authentication.Authentication;

// Quarkus Security imports
import io.quarkus.elytron.security.common.BcryptUtil;

// Security Issue: Using MessageDigest for password hashing is insecure because these algorithms are designed for speed and lack salt by default

// True Positive Examples (Vulnerable/Insecure Code)
public class InsecurePasswordHashing {

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public static void bad_case_1() {
        String password = "userPassword";
        try {
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedPassword = md.digest(password.getBytes(StandardCharsets.UTF_8));
            String hashedPasswordHex = DatatypeConverter.printHexBinary(hashedPassword);
            System.out.println("Hashed password: " + hashedPasswordHex);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_2() {
        String password = "userPassword";
        try {
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashedPassword = md.digest(password.getBytes());
            String hashedPasswordBase64 = Base64.getEncoder().encodeToString(hashedPassword);
            System.out.println("Hashed password: " + hashedPasswordBase64);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_3() {
        String password = "userPassword";
        String salt = "randomSalt";
        try {
            // Adding salt manually doesn't make MessageDigest secure for passwords
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(salt.getBytes());
            byte[] hashedPassword = md.digest(password.getBytes());
            String hashedPasswordHex = DatatypeConverter.printHexBinary(hashedPassword);
            System.out.println("Hashed password with salt: " + hashedPasswordHex);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_4() {
        // Apache Shiro with insecure hash
        String password = "userPassword";
        
        // ruleid: java-avoid-message-digest-for-password-hashing
        Md5Hash md5Hash = new Md5Hash(password);
        String hashedPassword = md5Hash.toHex();
        System.out.println("Shiro MD5 hashed password: " + hashedPassword);
    }

    public static void bad_case_5() {
        // Custom implementation with MessageDigest
        String password = "userPassword";
        try {
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hashedPassword = md.digest(password.getBytes());
            String hashedPasswordHex = bytesToHex(hashedPassword);
            System.out.println("SHA-1 hashed password: " + hashedPasswordHex);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_6() {
        // Multiple iterations still using MessageDigest
        String password = "userPassword";
        try {
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = password.getBytes();
            for (int i = 0; i < 1000; i++) {
                hash = md.digest(hash);
            }
            String hashedPassword = Base64.getEncoder().encodeToString(hash);
            System.out.println("Iterated hash: " + hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_7() {
        // Using Jasypt with basic (insecure) password encryptor
        String password = "userPassword";
        
        // ruleid: java-avoid-message-digest-for-password-hashing
        BasicPasswordEncryptor passwordEncryptor = new BasicPasswordEncryptor();
        String encryptedPassword = passwordEncryptor.encryptPassword(password);
        System.out.println("Jasypt basic encrypted password: " + encryptedPassword);
    }

    public static void bad_case_8() {
        // Custom implementation with concatenation
        String password = "userPassword";
        String username = "john.doe";
        try {
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-384");
            String combined = username + ":" + password;
            byte[] hashedPassword = md.digest(combined.getBytes());
            String hashedPasswordHex = DatatypeConverter.printHexBinary(hashedPassword);
            System.out.println("Combined hashed password: " + hashedPasswordHex);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_9() {
        // Using MessageDigest in a custom authentication service
        String password = "userPassword";
        String storedHash = "stored_hash_value";
        try {
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String hashedPassword = bytesToHex(md.digest(password.getBytes()));
            boolean isAuthenticated = hashedPassword.equals(storedHash);
            System.out.println("Authentication result: " + isAuthenticated);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_10() {
        // Using MessageDigest with Base64 encoding
        String password = "userPassword";
        try {
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] hashedBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            String hashedPassword = Base64.getEncoder().encodeToString(hashedBytes);
            System.out.println("Base64 encoded hash: " + hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_11() {
        // Using Apache Shiro with SHA-256 (still not suitable for passwords)
        String password = "userPassword";
        
        // ruleid: java-avoid-message-digest-for-password-hashing
        Sha256Hash sha256Hash = new Sha256Hash(password);
        String hashedPassword = sha256Hash.toBase64();
        System.out.println("Shiro SHA-256 hashed password: " + hashedPassword);
    }

    public static void bad_case_12() {
        // Using MessageDigest in a registration service
        String password = "userPassword";
        try {
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] salt = generateRandomSalt();
            md.update(salt);
            byte[] hashedPassword = md.digest(password.getBytes());
            String storedPassword = Base64.getEncoder().encodeToString(hashedPassword);
            String storedSalt = Base64.getEncoder().encodeToString(salt);
            System.out.println("Stored password: " + storedPassword + ", Salt: " + storedSalt);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_13() {
        // Using MessageDigest with custom key stretching
        String password = "userPassword";
        try {
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = password.getBytes();
            // Key stretching with MessageDigest is still not recommended
            for (int i = 0; i < 10000; i++) {
                hash = md.digest(hash);
            }
            String hashedPassword = Base64.getEncoder().encodeToString(hash);
            System.out.println("Custom stretched hash: " + hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_14() {
        // Using MessageDigest in a token generation service
        String userId = "user123";
        String password = "userPassword";
        try {
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String combined = userId + ":" + password + ":" + System.currentTimeMillis();
            byte[] tokenBytes = md.digest(combined.getBytes());
            String token = Base64.getUrlEncoder().encodeToString(tokenBytes);
            System.out.println("Generated token: " + token);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_15() {
        // Using MessageDigest with a custom salt generation
        String password = "userPassword";
        try {
            String salt = generateCustomSalt();
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt.getBytes());
            byte[] hashedPassword = md.digest(password.getBytes());
            String finalHash = bytesToHex(hashedPassword);
            System.out.println("Hashed password with custom salt: " + finalHash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe/Secure Code)
    public static void good_case_1() {
        // Spring Security BCrypt implementation
        String password = "userPassword";
        
        // ok: java-avoid-message-digest-for-password-hashing
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String hashedPassword = passwordEncoder.encode(password);
        System.out.println("BCrypt hashed password: " + hashedPassword);
    }

    public static void good_case_2() {
        // Spring Security PBKDF2 implementation
        String password = "userPassword";
        
        // ok: java-avoid-message-digest-for-password-hashing
        Pbkdf2PasswordEncoder passwordEncoder = new Pbkdf2PasswordEncoder();
        String hashedPassword = passwordEncoder.encode(password);
        System.out.println("PBKDF2 hashed password: " + hashedPassword);
    }

    public static void good_case_3() {
        // Spring Security Argon2 implementation
        String password = "userPassword";
        
        // ok: java-avoid-message-digest-for-password-hashing
        Argon2PasswordEncoder passwordEncoder = new Argon2PasswordEncoder();
        String hashedPassword = passwordEncoder.encode(password);
        System.out.println("Argon2 hashed password: " + hashedPassword);
    }

    public static void good_case_4() {
        // Spring Security SCrypt implementation
        String password = "userPassword";
        
        // ok: java-avoid-message-digest-for-password-hashing
        SCryptPasswordEncoder passwordEncoder = new SCryptPasswordEncoder();
        String hashedPassword = passwordEncoder.encode(password);
        System.out.println("SCrypt hashed password: " + hashedPassword);
    }

    public static void good_case_5() {
        // jBCrypt implementation
        String password = "userPassword";
        
        // ok: java-avoid-message-digest-for-password-hashing
        String salt = BCrypt.gensalt();
        String hashedPassword = BCrypt.hashpw(password, salt);
        System.out.println("jBCrypt hashed password: " + hashedPassword);
    }

    public static void good_case_6() {
        // Jasypt strong password encryptor
        String password = "userPassword";
        
        // ok: java-avoid-message-digest-for-password-hashing
        StrongPasswordEncryptor passwordEncryptor = new StrongPasswordEncryptor();
        String encryptedPassword = passwordEncryptor.encryptPassword(password);
        System.out.println("Jasypt strong encrypted password: " + encryptedPassword);
    }

    public static void good_case_7() {
        // JJWT secure password hashing
        String password = "userPassword";
        
        // ok: java-avoid-message-digest-for-password-hashing
        Password hashedPassword = Passwords.hash(password.toCharArray());
        System.out.println("JJWT hashed password: " + hashedPassword.toString());
    }

    public static void good_case_8() {
        // Apache Shiro with secure hashing
        String password = "userPassword";
        
        // Generate a random salt
        RandomNumberGenerator rng = new SecureRandomNumberGenerator();
        ByteSource salt = rng.nextBytes();
        
        // ok: java-avoid-message-digest-for-password-hashing
        // Use PBKDF2 with 1000 iterations
        int iterations = 1000;
        Sha256Hash hash = new Sha256Hash(password, salt, iterations);
        String hashedPasswordBase64 = hash.toBase64();
        
        System.out.println("Shiro secure hashed password: " + hashedPasswordBase64);
        System.out.println("Salt: " + salt.toBase64());
    }

    public static void good_case_9() {
        // Bouncy Castle Argon2 implementation
        String password = "userPassword";
        byte[] salt = new byte[16];
        new java.security.SecureRandom().nextBytes(salt);
        
        // ok: java-avoid-message-digest-for-password-hashing
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withParallelism(4)
                .withMemoryAsKB(65536)
                .withIterations(3);
        
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());
        
        byte[] result = new byte[32];
        generator.generateBytes(password.getBytes(StandardCharsets.UTF_8), result, 0, result.length);
        
        String hashedPassword = Base64.getEncoder().encodeToString(result);
        System.out.println("Bouncy Castle Argon2 hashed password: " + hashedPassword);
    }

    public static void good_case_10() {
        // Spring Security DelegatingPasswordEncoder for future-proof hashing
        String password = "userPassword";
        
        // ok: java-avoid-message-digest-for-password-hashing
        PasswordEncoder passwordEncoder = org.springframework.security.crypto.factory.PasswordEncoderFactories.createDelegatingPasswordEncoder();
        String hashedPassword = passwordEncoder.encode(password);
        System.out.println("Spring Security DelegatingPasswordEncoder hashed password: " + hashedPassword);
    }

    public static void good_case_11() {
        // Quarkus BCrypt implementation
        String password = "userPassword";
        
        // ok: java-avoid-message-digest-for-password-hashing
        String hashedPassword = BcryptUtil.bcryptHash(password);
        System.out.println("Quarkus BCrypt hashed password: " + hashedPassword);
    }

    public static void good_case_12() {
        // Jakarta EE Security PBKDF2 implementation
        String password = "userPassword";
        
        // ok: java-avoid-message-digest-for-password-hashing
        Pbkdf2PasswordHash pbkdf2Hash = new Pbkdf2PasswordHash() {
            @Override
            public String generate(char[] chars) {
                // This is a simplified implementation for example purposes
                // In a real application, you would use the actual implementation
                return "pbkdf2:sha256:1000:" + new String(chars).hashCode();
            }

            @Override
            public boolean verify(char[] chars, String s) {
                return generate(chars).equals(s);
            }
        };
        
        String hashedPassword = pbkdf2Hash.generate(password.toCharArray());
        System.out.println("Jakarta EE PBKDF2 hashed password: " + hashedPassword);
    }

    public static void good_case_13() {
        // Custom implementation using Spring Security's recommended approach
        String password = "userPassword";
        
        // ok: java-avoid-message-digest-for-password-hashing
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);
        String hashedPassword = passwordEncoder.encode(password);
        
        // Store the hashed password
        System.out.println("Custom Spring Security implementation: " + hashedPassword);
    }

    public static void good_case_14() {
        // Using Spring Security for password verification
        String password = "userPassword";
        String storedHash = "$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG"; // Example BCrypt hash
        
        // ok: java-avoid-message-digest-for-password-hashing
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        boolean isMatch = passwordEncoder.matches(password, storedHash);
        
        System.out.println("Password verification result: " + isMatch);
    }

    public static void good_case_15() {
        // Using SCrypt with custom parameters
        String password = "userPassword";
        
        // ok: java-avoid-message-digest-for-password-hashing
        SCryptPasswordEncoder passwordEncoder = new SCryptPasswordEncoder(
            16384, // CPU cost
            8,     // Memory cost
            1,     // Parallelization
            32,    // Key length
            16     // Salt length
        );
        
        String hashedPassword = passwordEncoder.encode(password);
        System.out.println("Custom SCrypt hashed password: " + hashedPassword);
    }

    // Helper methods
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] generateRandomSalt() {
        byte[] salt = new byte[16];
        new java.security.SecureRandom().nextBytes(salt);
        return salt;
    }

    private static String generateCustomSalt() {
        return Long.toString(System.currentTimeMillis());
    }

    public static void main(String[] args) {
        // Execute examples
        System.out.println("Running examples...");
    }
}
// {/fact}