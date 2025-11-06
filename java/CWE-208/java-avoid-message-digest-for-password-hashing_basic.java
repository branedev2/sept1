import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.mindrot.jbcrypt.BCrypt;
import java.util.HashMap;
import java.util.Map;

public class PasswordHashingExamples {

    // True Positives (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public String bad_case_1(String password) {
        try {
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public String bad_case_2(String password) {
        try {
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public String bad_case_3(String username, String password) {
        try {
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String saltedPassword = username + password; // Adding a simple salt
            byte[] hashBytes = md.digest(saltedPassword.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public boolean bad_case_4(String password, String storedHash) {
        try {
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            String computedHash = Base64.getEncoder().encodeToString(hashBytes);
            return computedHash.equals(storedHash);
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }

    public String bad_case_5(String password) {
        try {
            // Adding a fixed salt, but still using MessageDigest
            byte[] salt = "fixed_salt_value".getBytes(StandardCharsets.UTF_8);
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public String bad_case_6(String password) {
        try {
            // Multiple rounds of hashing, but still using MessageDigest
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = password.getBytes(StandardCharsets.UTF_8);
            
            // Multiple iterations to slow down attacks
            for (int i = 0; i < 1000; i++) {
                hashBytes = md.digest(hashBytes);
            }
            
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public Map<String, String> bad_case_7(String username, String password) {
        Map<String, String> userRecord = new HashMap<>();
        userRecord.put("username", username);
        
        try {
            // Random salt but still using MessageDigest
            byte[] salt = new byte[16];
            new Random().nextBytes(salt);
            String saltBase64 = Base64.getEncoder().encodeToString(salt);
            
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-384");
            md.update(salt);
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            String hashBase64 = Base64.getEncoder().encodeToString(hashBytes);
            
            userRecord.put("salt", saltBase64);
            userRecord.put("password_hash", hashBase64);
            return userRecord;
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public String bad_case_8(String password) {
        try {
            // Using a combination of hashing algorithms, but still MessageDigest
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] md5Hash = md5.digest(password.getBytes(StandardCharsets.UTF_8));
            
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] finalHash = sha.digest(md5Hash);
            
            return Base64.getEncoder().encodeToString(finalHash);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public String bad_case_9(String password, String pepper) {
        try {
            // Using a pepper (server-side secret) with MessageDigest
            String pepperedPassword = password + pepper;
            
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] hashBytes = md.digest(pepperedPassword.getBytes(StandardCharsets.UTF_8));
            
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public String bad_case_10(String password) {
        StringBuilder hexString = new StringBuilder();
        try {
            // Using MessageDigest with hex encoding
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            
            // Convert to hex
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public String bad_case_11() {
        String password = "user_password";
        try {
            // Using MessageDigest in a utility method
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public String bad_case_12(String password) {
        try {
            // Using MessageDigest with custom encoding
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            
            // Custom base64 encoding without padding
            return Base64.getEncoder().withoutPadding().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public boolean bad_case_13(String username, String password, Map<String, String> userDatabase) {
        try {
            String storedSalt = userDatabase.get(username + ".salt");
            String storedHash = userDatabase.get(username + ".hash");
            
            if (storedSalt == null || storedHash == null) {
                return false;
            }
            
            byte[] salt = Base64.getDecoder().decode(storedSalt);
            
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            String computedHash = Base64.getEncoder().encodeToString(hashBytes);
            
            return computedHash.equals(storedHash);
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }

    public String bad_case_14(String password) {
        try {
            // Using MessageDigest with a different charset
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(password.getBytes("ISO-8859-1"));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (Exception e) {
            return null;
        }
    }

    public String bad_case_15(String password) {
        try {
            // Using MessageDigest with string concatenation
            String salt = "staticSalt123";
            String pepper = "staticPepper456";
            String combined = salt + password + pepper;
            
            // ruleid: java-avoid-message-digest-for-password-hashing
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(combined.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    // True Negatives (Secure Code)

    public String good_case_1(String password) {
        // ok: java-avoid-message-digest-for-password-hashing
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        return encoder.encode(password);
    }

    public boolean good_case_2(String password, String hashedPassword) {
        // ok: java-avoid-message-digest-for-password-hashing
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        return encoder.matches(password, hashedPassword);
    }

    public String good_case_3(String password) {
        // ok: java-avoid-message-digest-for-password-hashing
        Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder();
        return encoder.encode(password);
    }

    public String good_case_4(String password) {
        // ok: java-avoid-message-digest-for-password-hashing
        Argon2PasswordEncoder encoder = new Argon2PasswordEncoder();
        return encoder.encode(password);
    }

    public String good_case_5(String password) {
        // ok: java-avoid-message-digest-for-password-hashing
        SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
        return encoder.encode(password);
    }

    public String good_case_6(String password) {
        // Using PBKDF2 directly with SecretKeyFactory
        try {
            byte[] salt = new byte[16];
            new Random().nextBytes(salt);
            
            // ok: java-avoid-message-digest-for-password-hashing
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return null;
        }
    }

    public String good_case_7(String password) {
        // Using BCrypt directly with jBCrypt library
        // ok: java-avoid-message-digest-for-password-hashing
        String salt = BCrypt.gensalt(12); // Work factor of 12
        return BCrypt.hashpw(password, salt);
    }

    public boolean good_case_8(String password, String hashedPassword) {
        // Verifying with BCrypt directly
        // ok: java-avoid-message-digest-for-password-hashing
        return BCrypt.checkpw(password, hashedPassword);
    }

    public String good_case_9(String password) {
        // Using Spring Security's PasswordEncoder interface with BCrypt
        // ok: java-avoid-message-digest-for-password-hashing
        PasswordEncoder encoder = new BCryptPasswordEncoder(12); // Work factor of 12
        return encoder.encode(password);
    }

    public String good_case_10(String password) {
        // Using PBKDF2 with higher iteration count
        try {
            byte[] salt = new byte[16];
            new Random().nextBytes(salt);
            
            // ok: java-avoid-message-digest-for-password-hashing
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 310000, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            
            // Store both salt and hash
            String saltBase64 = Base64.getEncoder().encodeToString(salt);
            String hashBase64 = Base64.getEncoder().encodeToString(hash);
            
            return saltBase64 + ":" + hashBase64;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return null;
        }
    }

    public Map<String, String> good_case_11(String username, String password) {
        Map<String, String> userRecord = new HashMap<>();
        userRecord.put("username", username);
        
        // Using Argon2 with custom parameters
        // ok: java-avoid-message-digest-for-password-hashing
        Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(32, 64, 1, 15 * 1024, 2);
        String hashedPassword = encoder.encode(password);
        
        userRecord.put("password_hash", hashedPassword);
        return userRecord;
    }

    public String good_case_12(String password) {
        // Using SCrypt with custom parameters
        // ok: java-avoid-message-digest-for-password-hashing
        SCryptPasswordEncoder encoder = new SCryptPasswordEncoder(
            16384, // CPU cost
            8,     // Memory cost
            1,     // Parallelization
            32,    // Key length
            64     // Salt length
        );
        return encoder.encode(password);
    }

    public boolean good_case_13(String password, String hashedPassword) {
        // Using Pbkdf2PasswordEncoder with custom parameters
        // ok: java-avoid-message-digest-for-password-hashing
        Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder(
            "secret", // Secret key
            8,        // Salt length
            185000,   // Iterations
            256       // Hash width
        );
        return encoder.matches(password, hashedPassword);
    }

    public String good_case_14(String password) {
        // Using MessageDigest for non-password hashing purposes
        try {
            // This is OK because we're not hashing a password
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest("This is not a password".getBytes(StandardCharsets.UTF_8));
            
            // ok: java-avoid-message-digest-for-password-hashing
            // For password hashing, we use a proper password hashing algorithm
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
            return encoder.encode(password);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public String good_case_15(String password) {
        // Using a delegating password encoder that can handle multiple formats
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("bcrypt", new BCryptPasswordEncoder());
        encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
        encoders.put("argon2", new Argon2PasswordEncoder());
        encoders.put("scrypt", new SCryptPasswordEncoder());
        
        // ok: java-avoid-message-digest-for-password-hashing
        // DelegatingPasswordEncoder allows for upgrading encoding strategies
        PasswordEncoder passwordEncoder = new org.springframework.security.crypto.password.DelegatingPasswordEncoder("bcrypt", encoders);
        return passwordEncoder.encode(password);
    }
}
// {/fact}