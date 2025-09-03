import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class PBKDF2SecurityExamples {

    // True Positives (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public void bad_case_1() {
        try {
            // Creating instance but not using it
            // ruleid: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            
            // Password is processed insecurely without using the factory
            String password = "password123";
            byte[] hashedPassword = password.getBytes();
            System.out.println("Password processed insecurely");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            String password = "userPassword";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            // Creating instance but not using it
            // ruleid: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            
            // Using a different approach instead
            System.out.println("Password: " + password + " will be processed differently");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try {
            // Creating multiple instances but not using them
            // ruleid: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            // ruleid: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            
            // Using string concatenation instead of proper key derivation
            String password = "secret";
            String salt = "staticSalt";
            String combined = password + salt;
            System.out.println("Combined: " + combined);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        String algorithm = "PBKDF2WithHmacSHA512";
        try {
            // Creating instance in a variable but never using the variable
            // ruleid: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
            
            // Using a different approach
            String password = "myPassword";
            System.out.println("Password length: " + password.length());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try {
            // Creating instance but not using it for key generation
            // ruleid: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            
            // Using a simple hash instead
            String password = "password123";
            int hashCode = password.hashCode();
            System.out.println("Hash code: " + hashCode);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            String password = "userPassword";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            // Creating instance in a conditional block but not using it
            if (password.length() > 8) {
                // ruleid: java-hash-algo-compliance-check-for-pbkdf2
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            }
            
            // Using Base64 encoding instead of proper key derivation
            String encoded = Base64.getEncoder().encodeToString(password.getBytes());
            System.out.println("Encoded: " + encoded);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            // Creating instance in a loop but not using it
            for (int i = 0; i < 3; i++) {
                // ruleid: java-hash-algo-compliance-check-for-pbkdf2
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                System.out.println("Iteration: " + i);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            String password = "password123";
            byte[] salt = "salt12345678".getBytes();
            
            // Creating instance but overwriting the reference before using it
            // ruleid: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            factory = null; // Overwriting the reference
            
            // Using string manipulation instead
            String result = password + new String(salt);
            System.out.println("Result: " + result);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        try {
            // Creating instance but only using it for toString()
            // ruleid: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            System.out.println("Factory: " + factory.toString());
            
            // Not using it for actual key generation
            String password = "mySecretPassword";
            System.out.println("Password: " + password);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            // Creating instance but passing it to a method that doesn't use it for key generation
            // ruleid: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            printAlgorithm(factory);
            
            // Using a simple approach instead
            String password = "password";
            System.out.println("Password characters: " + password.toCharArray().length);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    
    private void printAlgorithm(SecretKeyFactory factory) {
        System.out.println("Algorithm: " + factory.getAlgorithm());
    }

    public void bad_case_11() {
        try {
            String password = "userPassword";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            // Creating instance but not using it due to early return
            // ruleid: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            
            if (password.length() < 10) {
                System.out.println("Password too short");
                return; // Early return
            }
            
            // Code below is never reached for short passwords
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKey key = factory.generateSecret(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            // Creating instance but not using it due to exception handling
            // ruleid: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            
            try {
                // Intentionally causing an exception
                int result = 10 / 0;
                
                // Code below is never reached
                String password = "myPassword";
                byte[] salt = new byte[16];
                new SecureRandom().nextBytes(salt);
                PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
                SecretKey key = factory.generateSecret(spec);
            } catch (ArithmeticException e) {
                System.out.println("Exception occurred: " + e.getMessage());
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            String algorithm = getAlgorithm();
            
            // Creating instance dynamically but not using it
            // ruleid: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
            
            // Using a different approach
            String password = "securePassword";
            System.out.println("Password length: " + password.length());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    
    private String getAlgorithm() {
        return "PBKDF2WithHmacSHA1";
    }

    public void bad_case_14() {
        try {
            // Creating instance in a switch statement but not using it
            String mode = "secure";
            switch (mode) {
                case "secure":
                    // ruleid: java-hash-algo-compliance-check-for-pbkdf2
                    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                    break;
                case "fast":
                    // ruleid: java-hash-algo-compliance-check-for-pbkdf2
                    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                    break;
            }
            
            // Using string manipulation instead
            String password = "myPassword";
            String salt = "staticSalt";
            String combined = password + salt;
            System.out.println("Combined: " + combined);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            // Creating multiple instances with different algorithms but not using them
            String[] algorithms = {"PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA256", "PBKDF2WithHmacSHA512"};
            
            for (String algorithm : algorithms) {
                // ruleid: java-hash-algo-compliance-check-for-pbkdf2
                SecretKeyFactory.getInstance(algorithm);
                System.out.println("Created factory for: " + algorithm);
            }
            
            // Using a simple approach instead
            String password = "password123";
            System.out.println("Password: " + password);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    // True Negatives (Secure Code)

    public void good_case_1() {
        try {
            // Creating instance and properly using it
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            
            String password = "password123";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKey key = factory.generateSecret(spec);
            byte[] hashedPassword = key.getEncoded();
            
            System.out.println("Password hashed securely");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            String password = "userPassword";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            // Creating instance and using it with stronger algorithm
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
            SecretKey key = factory.generateSecret(spec);
            byte[] hashedPassword = key.getEncoded();
            
            System.out.println("Password hashed with SHA-256");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        try {
            // Creating instance and using it in a helper method
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            
            String password = "secret";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            byte[] hashedPassword = deriveKey(factory, password, salt);
            System.out.println("Password hashed with helper method");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private byte[] deriveKey(SecretKeyFactory factory, String password, byte[] salt) 
            throws InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 120000, 512);
        SecretKey key = factory.generateSecret(spec);
        return key.getEncoded();
    }

    public void good_case_4() {
        try {
            String algorithm = "PBKDF2WithHmacSHA1";
            
            // Creating instance and using it with dynamic algorithm
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
            
            String password = "myPassword";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKey key = factory.generateSecret(spec);
            byte[] hashedPassword = key.getEncoded();
            
            System.out.println("Password hashed with dynamic algorithm");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            // Creating instance and using it in a conditional block
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            
            String password = "password123";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            if (password.length() >= 8) {
                PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
                SecretKey key = factory.generateSecret(spec);
                byte[] hashedPassword = key.getEncoded();
                System.out.println("Password hashed in conditional block");
            } else {
                System.out.println("Password too short");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            String password = "userPassword";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            // Creating instance and using it in a loop for multiple iterations
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            
            for (int i = 0; i < 3; i++) {
                PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536 * (i + 1), 128);
                SecretKey key = factory.generateSecret(spec);
                byte[] hashedPassword = key.getEncoded();
                System.out.println("Iteration " + i + " hash: " + Base64.getEncoder().encodeToString(hashedPassword));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            // Creating instance and using it with try-with-resources
            String password = "securePassword";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            
            try {
                PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
                SecretKey key = factory.generateSecret(spec);
                byte[] hashedPassword = key.getEncoded();
                System.out.println("Password hashed with try-with-resources");
            } finally {
                Arrays.fill(password.toCharArray(), '0'); // Clear password from memory
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try {
            // Creating instance and using it with error handling
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            
            String password = "myPassword";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            try {
                PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 120000, 512);
                SecretKey key = factory.generateSecret(spec);
                byte[] hashedPassword = key.getEncoded();
                System.out.println("Password hashed with error handling");
            } catch (InvalidKeySpecException e) {
                System.out.println("Invalid key specification: " + e.getMessage());
            }
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Algorithm not available: " + e.getMessage());
        }
    }

    public void good_case_9() {
        try {
            // Creating multiple instances and using them for different purposes
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory1 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            
            String password = "password123";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            // Using first factory for authentication
            PBEKeySpec spec1 = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKey key1 = factory1.generateSecret(spec1);
            byte[] authKey = key1.getEncoded();
            
            // Using second factory for encryption
            PBEKeySpec spec2 = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
            SecretKey key2 = factory2.generateSecret(spec2);
            byte[] encryptionKey = key2.getEncoded();
            
            System.out.println("Multiple keys generated for different purposes");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            String password = "userPassword";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            // Creating instance and using it with a switch statement
            String strength = "high";
            SecretKeyFactory factory;
            int iterations;
            int keyLength;
            
            switch (strength) {
                case "low":
                    // ok: java-hash-algo-compliance-check-for-pbkdf2
                    factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                    iterations = 10000;
                    keyLength = 128;
                    break;
                case "medium":
                    // ok: java-hash-algo-compliance-check-for-pbkdf2
                    factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                    iterations = 65536;
                    keyLength = 256;
                    break;
                case "high":
                default:
                    // ok: java-hash-algo-compliance-check-for-pbkdf2
                    factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
                    iterations = 120000;
                    keyLength = 512;
                    break;
            }
            
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
            SecretKey key = factory.generateSecret(spec);
            byte[] hashedPassword = key.getEncoded();
            
            System.out.println("Password hashed with " + strength + " security level");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            // Creating instance and using it with dynamic parameters
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            
            String password = "mySecurePassword";
            byte[] salt = generateRandomSalt();
            int iterations = calculateIterations();
            int keyLength = 256;
            
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
            SecretKey key = factory.generateSecret(spec);
            byte[] hashedPassword = key.getEncoded();
            
            System.out.println("Password hashed with dynamic parameters");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private byte[] generateRandomSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }
    
    private int calculateIterations() {
        // Calculate iterations based on system performance
        return 100000;
    }

    public void good_case_12() {
        try {
            // Creating instance and using it with a custom wrapper
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            
            PasswordHasher hasher = new PasswordHasher(factory);
            String password = "securePassword";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            byte[] hashedPassword = hasher.hashPassword(password, salt);
            System.out.println("Password hashed with custom wrapper");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static class PasswordHasher {
        private final SecretKeyFactory factory;
        
        public PasswordHasher(SecretKeyFactory factory) {
            this.factory = factory;
        }
        
        public byte[] hashPassword(String password, byte[] salt) throws InvalidKeySpecException {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 120000, 512);
            SecretKey key = factory.generateSecret(spec);
            return key.getEncoded();
        }
    }

    public void good_case_13() {
        try {
            // Creating instance and using it with a lambda expression
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            
            String password = "password123";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            PasswordProcessor processor = (pwd, s) -> {
                try {
                    PBEKeySpec spec = new PBEKeySpec(pwd.toCharArray(), s, 65536, 128);
                    SecretKey key = factory.generateSecret(spec);
                    return key.getEncoded();
                } catch (InvalidKeySpecException e) {
                    throw new RuntimeException(e);
                }
            };
            
            byte[] hashedPassword = processor.process(password, salt);
            System.out.println("Password hashed with lambda expression");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private interface PasswordProcessor {
        byte[] process(String password, byte[] salt);
    }

    public void good_case_14() {
        try {
            // Creating instance and using it with different key lengths
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            
            String password = "myPassword";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            int[] keyLengths = {128, 256, 512};
            for (int keyLength : keyLengths) {
                PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, keyLength);
                SecretKey key = factory.generateSecret(spec);
                byte[] hashedPassword = key.getEncoded();
                System.out.println("Password hashed with key length: " + keyLength);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        try {
            // Creating instance and using it to verify a password
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            
            String password = "userPassword";
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            // First, hash the password
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 120000, 512);
            SecretKey key = factory.generateSecret(spec);
            byte[] storedHash = key.getEncoded();
            
            // Later, verify the password
            String inputPassword = "userPassword"; // In a real scenario, this would be user input
            PBEKeySpec verifySpec = new PBEKeySpec(inputPassword.toCharArray(), salt, 120000, 512);
            SecretKey verifyKey = factory.generateSecret(verifySpec);
            byte[] verifyHash = verifyKey.getEncoded();
            
            boolean passwordMatches = Arrays.equals(storedHash, verifyHash);
            System.out.println("Password verification result: " + passwordMatches);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}