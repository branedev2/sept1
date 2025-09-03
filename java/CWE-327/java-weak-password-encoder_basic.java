import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.authentication.encoding.Md5PasswordEncoder;
import org.springframework.security.authentication.encoding.ShaPasswordEncoder;
import org.springframework.security.authentication.encoding.LdapShaPasswordEncoder;
import org.springframework.security.authentication.encoding.PlaintextPasswordEncoder;

public class WeakPasswordEncoderExamples {

    // TRUE POSITIVES (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public void bad_case_1() {
        // Using NoOpPasswordEncoder which doesn't actually encode passwords
        // ruleid: java-weak-password-encoder
        PasswordEncoder encoder = NoOpPasswordEncoder.getInstance();
        String encodedPassword = encoder.encode("password123");
        
        boolean matches = encoder.matches("password123", encodedPassword);
        System.out.println("Password matches: " + matches);
    }

    public void bad_case_2() {
        // Using deprecated MD5 password encoder
        // ruleid: java-weak-password-encoder
        org.springframework.security.authentication.encoding.Md5PasswordEncoder encoder = 
            new org.springframework.security.authentication.encoding.Md5PasswordEncoder();
        String encodedPassword = encoder.encodePassword("password123", null);
        
        boolean matches = encoder.isPasswordValid(encodedPassword, "password123", null);
        System.out.println("Password matches: " + matches);
    }

    public void bad_case_3() {
        try {
            // Using weak MD5 algorithm directly
            // ruleid: java-weak-password-encoder
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest("password123".getBytes());
            String encodedPassword = Base64.getEncoder().encodeToString(digest);
            
            System.out.println("Encoded password: " + encodedPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            // Using weak SHA-1 algorithm directly
            // ruleid: java-weak-password-encoder
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest("password123".getBytes());
            String encodedPassword = Base64.getEncoder().encodeToString(digest);
            
            System.out.println("Encoded password: " + encodedPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        // Using deprecated ShaPasswordEncoder with SHA-1
        // ruleid: java-weak-password-encoder
        org.springframework.security.authentication.encoding.ShaPasswordEncoder encoder = 
            new org.springframework.security.authentication.encoding.ShaPasswordEncoder();
        String encodedPassword = encoder.encodePassword("password123", null);
        
        boolean matches = encoder.isPasswordValid(encodedPassword, "password123", null);
        System.out.println("Password matches: " + matches);
    }

    public void bad_case_6() {
        // Using deprecated StandardPasswordEncoder (uses SHA-256)
        // ruleid: java-weak-password-encoder
        StandardPasswordEncoder encoder = new StandardPasswordEncoder();
        String encodedPassword = encoder.encode("password123");
        
        boolean matches = encoder.matches("password123", encodedPassword);
        System.out.println("Password matches: " + matches);
    }

    public void bad_case_7() {
        // Using deprecated LdapShaPasswordEncoder
        // ruleid: java-weak-password-encoder
        org.springframework.security.authentication.encoding.LdapShaPasswordEncoder encoder = 
            new org.springframework.security.authentication.encoding.LdapShaPasswordEncoder();
        String encodedPassword = encoder.encodePassword("password123", null);
        
        boolean matches = encoder.isPasswordValid(encodedPassword, "password123", null);
        System.out.println("Password matches: " + matches);
    }

    public void bad_case_8() {
        // Using deprecated PlaintextPasswordEncoder
        // ruleid: java-weak-password-encoder
        org.springframework.security.authentication.encoding.PlaintextPasswordEncoder encoder = 
            new org.springframework.security.authentication.encoding.PlaintextPasswordEncoder();
        String encodedPassword = encoder.encodePassword("password123", null);
        
        boolean matches = encoder.isPasswordValid(encodedPassword, "password123", null);
        System.out.println("Password matches: " + matches);
    }

    public void bad_case_9() {
        try {
            // Using weak DES encryption for passwords
            // ruleid: java-weak-password-encoder
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            SecretKey key = keyGen.generateKey();
            
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedPassword = cipher.doFinal("password123".getBytes());
            
            System.out.println("Encrypted password: " + Base64.getEncoder().encodeToString(encryptedPassword));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            // Using weak RC2 encryption for passwords
            // ruleid: java-weak-password-encoder
            Cipher cipher = Cipher.getInstance("RC2/ECB/PKCS5Padding");
            KeyGenerator keyGen = KeyGenerator.getInstance("RC2");
            SecretKey key = keyGen.generateKey();
            
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedPassword = cipher.doFinal("password123".getBytes());
            
            System.out.println("Encrypted password: " + Base64.getEncoder().encodeToString(encryptedPassword));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            // Using weak Blowfish encryption for passwords
            // ruleid: java-weak-password-encoder
            Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
            KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
            SecretKey key = keyGen.generateKey();
            
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedPassword = cipher.doFinal("password123".getBytes());
            
            System.out.println("Encrypted password: " + Base64.getEncoder().encodeToString(encryptedPassword));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            // Using weak SHA-1 with PBKDF2
            // ruleid: java-weak-password-encoder
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            PBEKeySpec spec = new PBEKeySpec("password123".toCharArray(), salt, 1000, 128);
            SecretKey key = factory.generateSecret(spec);
            byte[] encodedPassword = key.getEncoded();
            
            System.out.println("Encoded password: " + Base64.getEncoder().encodeToString(encodedPassword));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        // Using weak PBKDF2 with too few iterations
        try {
            // ruleid: java-weak-password-encoder
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            // Only 100 iterations is too few for security
            PBEKeySpec spec = new PBEKeySpec("password123".toCharArray(), salt, 100, 256);
            SecretKey key = factory.generateSecret(spec);
            byte[] encodedPassword = key.getEncoded();
            
            System.out.println("Encoded password: " + Base64.getEncoder().encodeToString(encodedPassword));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        // Using Spring's Encryptors.standard() with a weak password
        // ruleid: java-weak-password-encoder
        String password = "weakpass";
        String salt = "abc123";
        TextEncryptor encryptor = Encryptors.standard(password, salt);
        
        String encryptedText = encryptor.encrypt("sensitive data");
        System.out.println("Encrypted: " + encryptedText);
    }

    public void bad_case_15() {
        // Using BCrypt with too low work factor
        // ruleid: java-weak-password-encoder
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4); // Work factor too low
        String encodedPassword = encoder.encode("password123");
        
        boolean matches = encoder.matches("password123", encodedPassword);
        System.out.println("Password matches: " + matches);
    }

    // TRUE NEGATIVES (Secure Code)

    public void good_case_1() {
        // Using BCrypt with appropriate work factor
        // ok: java-weak-password-encoder
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
        String encodedPassword = encoder.encode("password123");
        
        boolean matches = encoder.matches("password123", encodedPassword);
        System.out.println("Password matches: " + matches);
    }

    public void good_case_2() {
        // Using Argon2 password encoder with appropriate parameters
        // ok: java-weak-password-encoder
        Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(16, 32, 1, 65536, 10);
        String encodedPassword = encoder.encode("password123");
        
        boolean matches = encoder.matches("password123", encodedPassword);
        System.out.println("Password matches: " + matches);
    }

    public void good_case_3() {
        // Using SCrypt password encoder with appropriate parameters
        // ok: java-weak-password-encoder
        SCryptPasswordEncoder encoder = new SCryptPasswordEncoder(16384, 8, 1, 32, 64);
        String encodedPassword = encoder.encode("password123");
        
        boolean matches = encoder.matches("password123", encodedPassword);
        System.out.println("Password matches: " + matches);
    }

    public void good_case_4() {
        // Using PBKDF2 with appropriate iterations and SHA-256
        try {
            // ok: java-weak-password-encoder
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            // 310000 iterations is recommended by OWASP as of 2021
            PBEKeySpec spec = new PBEKeySpec("password123".toCharArray(), salt, 310000, 256);
            SecretKey key = factory.generateSecret(spec);
            byte[] encodedPassword = key.getEncoded();
            
            System.out.println("Encoded password: " + Base64.getEncoder().encodeToString(encodedPassword));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        // Using Spring's Pbkdf2PasswordEncoder with appropriate parameters
        // ok: java-weak-password-encoder
        Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder("", 16, 310000, 256);
        String encodedPassword = encoder.encode("password123");
        
        boolean matches = encoder.matches("password123", encodedPassword);
        System.out.println("Password matches: " + matches);
    }

    public void good_case_6() {
        try {
            // Using SHA-256 with salt and multiple iterations
            // ok: java-weak-password-encoder
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            // Add salt to the password
            md.update(salt);
            
            // Perform multiple iterations (10000+)
            byte[] digest = md.digest("password123".getBytes());
            for (int i = 0; i < 10000; i++) {
                md.reset();
                digest = md.digest(digest);
            }
            
            String encodedPassword = Base64.getEncoder().encodeToString(digest);
            System.out.println("Encoded password: " + encodedPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            // Using AES encryption with appropriate key size and mode
            // ok: java-weak-password-encoder
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // 256-bit key
            SecretKey key = keyGen.generateKey();
            
            // Using CBC mode with IV
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] encryptedPassword = cipher.doFinal("password123".getBytes());
            
            System.out.println("Encrypted password: " + Base64.getEncoder().encodeToString(encryptedPassword));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        // Using Spring's Encryptors.stronger() with appropriate password and salt
        // ok: java-weak-password-encoder
        String password = "strongPassword123!@#";
        byte[] saltBytes = new byte[16];
        new SecureRandom().nextBytes(saltBytes);
        String salt = new String(Hex.encode(saltBytes));
        
        TextEncryptor encryptor = Encryptors.stronger(password, salt);
        String encryptedText = encryptor.encrypt("sensitive data");
        System.out.println("Encrypted: " + encryptedText);
    }

    public void good_case_9() {
        try {
            // Using PBKDF2 with SHA-512
            // ok: java-weak-password-encoder
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            PBEKeySpec spec = new PBEKeySpec("password123".toCharArray(), salt, 210000, 512);
            SecretKey key = factory.generateSecret(spec);
            byte[] encodedPassword = key.getEncoded();
            
            System.out.println("Encoded password: " + Base64.getEncoder().encodeToString(encodedPassword));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        // Using BCrypt with random salt generation
        // ok: java-weak-password-encoder
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(13, new SecureRandom());
        String encodedPassword = encoder.encode("password123");
        
        boolean matches = encoder.matches("password123", encodedPassword);
        System.out.println("Password matches: " + matches);
    }

    public void good_case_11() {
        try {
            // Using AES-GCM for authenticated encryption
            // ok: java-weak-password-encoder
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey key = keyGen.generateKey();
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = new byte[12]; // 96 bits IV for GCM
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] encryptedPassword = cipher.doFinal("password123".getBytes());
            
            System.out.println("Encrypted password: " + Base64.getEncoder().encodeToString(encryptedPassword));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        // Using Argon2 with custom parameters for memory-hard function
        // ok: java-weak-password-encoder
        int saltLength = 16;
        int hashLength = 32;
        int parallelism = 4;
        int memory = 131072; // 128MB
        int iterations = 10;
        
        Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(saltLength, hashLength, parallelism, memory, iterations);
        String encodedPassword = encoder.encode("password123");
        
        boolean matches = encoder.matches("password123", encodedPassword);
        System.out.println("Password matches: " + matches);
    }

    public void good_case_13() {
        // Using SCrypt with custom parameters
        // ok: java-weak-password-encoder
        int cpuCost = 32768;
        int memoryCost = 8;
        int parallelization = 2;
        int keyLength = 32;
        int saltLength = 64;
        
        SCryptPasswordEncoder encoder = new SCryptPasswordEncoder(cpuCost, memoryCost, parallelization, keyLength, saltLength);
        String encodedPassword = encoder.encode("password123");
        
        boolean matches = encoder.matches("password123", encodedPassword);
        System.out.println("Password matches: " + matches);
    }

    public void good_case_14() {
        try {
            // Using PBKDF2 with high iteration count and appropriate key length
            // ok: java-weak-password-encoder
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] salt = new byte[32]; // 256-bit salt
            new SecureRandom().nextBytes(salt);
            
            // 600,000 iterations for extra security
            PBEKeySpec spec = new PBEKeySpec("password123".toCharArray(), salt, 600000, 256);
            SecretKey key = factory.generateSecret(spec);
            byte[] encodedPassword = key.getEncoded();
            
            System.out.println("Encoded password: " + Base64.getEncoder().encodeToString(encodedPassword));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        // Using a custom password encoder that combines multiple secure algorithms
        // ok: java-weak-password-encoder
        PasswordEncoder encoder = new PasswordEncoder() {
            private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);
            private final Pbkdf2PasswordEncoder pbkdf2 = new Pbkdf2PasswordEncoder("", 16, 310000, 256);
            
            @Override
            public String encode(CharSequence rawPassword) {
                // First encode with BCrypt
                String bcryptResult = bcrypt.encode(rawPassword);
                // Then encode the result with PBKDF2
                return pbkdf2.encode(bcryptResult);
            }
            
            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                // First check if the raw password, when encoded with PBKDF2, matches the encoded password
                String bcryptResult = bcrypt.encode(rawPassword);
                return pbkdf2.matches(bcryptResult, encodedPassword);
            }
        };
        
        String encodedPassword = encoder.encode("password123");
        System.out.println("Encoded password: " + encodedPassword);
    }
}
// {/fact}