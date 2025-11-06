import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;
import java.io.Console;
import java.util.Scanner;
import javax.swing.JPasswordField;
import javax.swing.JOptionPane;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;

public class PBEKeySpecExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = new byte[16];
        int iterationCount = 1000;
        int keyLength = 256;
        
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        KeySpec keySpec = new PBEKeySpec("hardcoded_password".toCharArray(), salt, iterationCount, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
    }

    public void bad_case_2() throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = new byte[16];
        int iterationCount = 2000;
        int keyLength = 128;
        
        String password = "my_secret_password_123";
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey key = keyFactory.generateSecret(pbeKeySpec);
    }

    public void bad_case_3() throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = getSalt();
        int iterations = 10000;
        int keyLength = 256;
        
        final char[] PASSWORD = {'P', 'a', 's', 's', 'w', 'o', 'r', 'd', '1', '2', '3'};
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec spec = new PBEKeySpec(PASSWORD, salt, iterations, keyLength);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = skf.generateSecret(spec).getEncoded();
    }

    public void bad_case_4() throws Exception {
        byte[] salt = "SaltySalt".getBytes();
        int iterations = 1024;
        int keySize = 256;
        
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec spec = new PBEKeySpec("SuperSecretKey!".toCharArray(), salt, iterations, keySize);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
    }

    public void bad_case_5() throws Exception {
        String password = "hardcoded_master_key";
        byte[] salt = generateRandomSalt();
        
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKeySpec key = new SecretKeySpec(keyFac.generateSecret(pbeKeySpec).getEncoded(), "AES");
        
        encryptData(key, "sensitive data");
    }

    public void bad_case_6() throws Exception {
        byte[] salt = "fixed_salt_value".getBytes();
        int iterations = 5000;
        
        char[] hardcodedPass = {'s', 'e', 'c', 'r', 'e', 't', 'P', 'a', 's', 's', '1', '2', '3'};
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec pbeSpec = new PBEKeySpec(hardcodedPass, salt, iterations, 128);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] keyBytes = keyFactory.generateSecret(pbeSpec).getEncoded();
        
        storeEncryptedData(keyBytes, "data to encrypt");
    }

    public void bad_case_7() throws Exception {
        final String ENCRYPTION_PASSWORD = "EncryptionKey2023!";
        byte[] salt = getSaltFromConfig();
        
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec = new PBEKeySpec(ENCRYPTION_PASSWORD.toCharArray(), salt, 15000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(keySpec).getEncoded();
        
        encryptDatabaseCredentials(keyBytes);
    }

    public void bad_case_8() throws Exception {
        String constantPassword = "ApplicationWidePassword";
        byte[] salt = generateSalt();
        int iterations = 20000;
        
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        KeySpec spec = new PBEKeySpec(constantPassword.toCharArray(), salt, iterations, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = f.generateSecret(spec).getEncoded();
        
        encryptUserData(key, "user data");
    }

    public void bad_case_9() throws Exception {
        // Hardcoded password in a different form
        StringBuilder passwordBuilder = new StringBuilder();
        passwordBuilder.append("hard");
        passwordBuilder.append("coded");
        passwordBuilder.append("_password");
        String password = passwordBuilder.toString();
        
        byte[] salt = "SaltValue".getBytes();
        
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        
        encryptFile(key, "sensitive.txt");
    }

    public void bad_case_10() throws Exception {
        // Hardcoded password as a constant
        final String CRYPTO_PASSWORD = "CryptoPassword123!";
        byte[] salt = getSaltFromDatabase();
        
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec pbeKeySpec = new PBEKeySpec(CRYPTO_PASSWORD.toCharArray(), salt, 10000, 256);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = keyFactory.generateSecret(pbeKeySpec);
        
        encryptApiCredentials(key);
    }

    public void bad_case_11() throws Exception {
        // Password in a configuration class
        EncryptionConfig config = new EncryptionConfig();
        String password = config.getDefaultPassword(); // Returns hardcoded "DefaultEncryptionPassword"
        byte[] salt = config.getDefaultSalt();
        
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        
        encryptBackupData(key);
    }

    public void bad_case_12() throws Exception {
        // Multiple hardcoded passwords in the same method
        byte[] salt1 = generateSalt();
        byte[] salt2 = generateSalt();
        
        // First hardcoded password
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec1 = new PBEKeySpec("password1".toCharArray(), salt1, 10000, 256);
        SecretKeyFactory factory1 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key1 = factory1.generateSecret(keySpec1);
        
        // Second hardcoded password
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec2 = new PBEKeySpec("password2".toCharArray(), salt2, 10000, 256);
        SecretKeyFactory factory2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key2 = factory2.generateSecret(keySpec2);
        
        encryptTwoFactorData(key1, key2);
    }

    public void bad_case_13() throws Exception {
        // Hardcoded password with string concatenation
        String part1 = "Secret";
        String part2 = "Password";
        String password = part1 + part2 + "2023";
        
        byte[] salt = getSaltForUser("admin");
        
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        
        encryptAdminCredentials(key);
    }

    public void bad_case_14() throws Exception {
        // Hardcoded password in a method that looks like it's getting from a secure source
        String password = getPasswordFromSecureSource(); // Actually returns hardcoded value
        byte[] salt = generateRandomBytes(16);
        
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        
        encryptPaymentInfo(key);
    }

    public void bad_case_15() throws Exception {
        // Hardcoded password in a different character encoding
        String password = new String(new byte[]{112, 97, 115, 115, 119, 111, 114, 100, 49, 50, 51}); // "password123"
        byte[] salt = getSaltFromConfig();
        
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        
        encryptSensitiveDocuments(key);
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() throws Exception {
        byte[] salt = new byte[16];
        int iterationCount = 1000;
        int keyLength = 256;
        
        Console console = System.console();
        char[] password = console.readPassword("Enter password: ");
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        KeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
    }

    public void good_case_2() throws Exception {
        byte[] salt = new byte[16];
        int iterationCount = 2000;
        int keyLength = 128;
        
        // Reading password from environment variable
        String envPassword = System.getenv("APP_ENCRYPTION_PASSWORD");
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec pbeKeySpec = new PBEKeySpec(envPassword.toCharArray(), salt, iterationCount, keyLength);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey key = keyFactory.generateSecret(pbeKeySpec);
    }

    public void good_case_3() throws Exception {
        byte[] salt = getSalt();
        int iterations = 10000;
        int keyLength = 256;
        
        // Reading password from properties file
        Properties props = new Properties();
        props.load(new FileInputStream("config.properties"));
        String password = props.getProperty("encryption.password");
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = skf.generateSecret(spec).getEncoded();
    }

    public void good_case_4() throws Exception {
        byte[] salt = "SaltySalt".getBytes();
        int iterations = 1024;
        int keySize = 256;
        
        // Reading password from user input
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter encryption password: ");
        String password = scanner.nextLine();
        scanner.close();
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keySize);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    public void good_case_5() throws Exception {
        // Using a password dialog
        JPasswordField passwordField = new JPasswordField();
        int option = JOptionPane.showConfirmDialog(null, passwordField, "Enter Password", JOptionPane.OK_CANCEL_OPTION);
        char[] password = passwordField.getPassword();
        
        byte[] salt = generateRandomSalt();
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 10000, 256);
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKeySpec key = new SecretKeySpec(keyFac.generateSecret(pbeKeySpec).getEncoded(), "AES");
        
        encryptData(key, "sensitive data");
    }

    public void good_case_6() throws Exception {
        byte[] salt = "fixed_salt_value".getBytes();
        int iterations = 5000;
        
        // Reading password from a secure vault service
        char[] password = getPasswordFromVault("encryption-key");
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, iterations, 128);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] keyBytes = keyFactory.generateSecret(pbeSpec).getEncoded();
        
        storeEncryptedData(keyBytes, "data to encrypt");
    }

    public void good_case_7() throws Exception {
        // Reading password from a configuration file
        Configuration config = new PropertiesConfiguration("app-config.properties");
        String password = config.getString("encryption.password");
        
        byte[] salt = getSaltFromConfig();
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 15000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(keySpec).getEncoded();
        
        encryptDatabaseCredentials(keyBytes);
    }

    public void good_case_8() throws Exception {
        // Reading password from a secure file
        String password = new String(Files.readAllBytes(Paths.get("/secure/path/password.txt")));
        byte[] salt = generateSalt();
        int iterations = 20000;
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = f.generateSecret(spec).getEncoded();
        
        encryptUserData(key, "user data");
    }

    public void good_case_9() throws Exception {
        // Using a password callback
        PasswordCallback callback = new PasswordCallback();
        char[] password = callback.getPassword();
        
        byte[] salt = "SaltValue".getBytes();
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, 10000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        
        encryptFile(key, "sensitive.txt");
    }

    public void good_case_10() throws Exception {
        // Reading password from command line arguments
        String[] args = getCommandLineArgs();
        String password = args[0]; // Assuming first argument is the password
        
        byte[] salt = getSaltFromDatabase();
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = keyFactory.generateSecret(pbeKeySpec);
        
        encryptApiCredentials(key);
    }

    public void good_case_11() throws Exception {
        // Reading password from a secure API
        String password = getPasswordFromSecureApi("encryption-key-id");
        byte[] salt = generateRandomSalt();
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        
        encryptBackupData(key);
    }

    public void good_case_12() throws Exception {
        // Using a key management service
        KeyManagementService kms = new KeyManagementService();
        char[] password = kms.retrievePassword("encryption-key");
        
        byte[] salt = generateSalt();
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, 10000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        
        encryptTwoFactorData(key, null);
    }

    public void good_case_13() throws Exception {
        // Reading password from a secure database
        DatabasePasswordProvider provider = new DatabasePasswordProvider();
        String password = provider.getPassword("admin-encryption-key");
        
        byte[] salt = getSaltForUser("admin");
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        
        encryptAdminCredentials(key);
    }

    public void good_case_14() throws Exception {
        // Reading password from a hardware security module
        HardwareSecurityModule hsm = new HardwareSecurityModule();
        char[] password = hsm.getSecurePassword("payment-encryption-key");
        
        byte[] salt = generateRandomBytes(16);
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, 10000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        
        encryptPaymentInfo(key);
    }

    public void good_case_15() throws Exception {
        // Reading password from a secure configuration service
        ConfigurationService configService = new ConfigurationService();
        String password = configService.getSecureConfig("document-encryption-password");
        
        byte[] salt = getSaltFromConfig();
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        
        encryptSensitiveDocuments(key);
    }

    // Helper methods to make the examples work
    private byte[] getSalt() {
        return new byte[16]; // Just a placeholder
    }
    
    private byte[] generateRandomSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }
    
    private void encryptData(SecretKeySpec key, String data) {
        // Encryption implementation
    }
    
    private void storeEncryptedData(byte[] key, String data) {
        // Store encrypted data implementation
    }
    
    private byte[] getSaltFromConfig() {
        return new byte[16]; // Just a placeholder
    }
    
    private void encryptDatabaseCredentials(byte[] keyBytes) {
        // Encrypt database credentials implementation
    }
    
    private void encryptUserData(byte[] key, String userData) {
        // Encrypt user data implementation
    }
    
    private void encryptFile(SecretKey key, String filename) {
        // Encrypt file implementation
    }
    
    private byte[] getSaltFromDatabase() {
        return new byte[16]; // Just a placeholder
    }
    
    private void encryptApiCredentials(SecretKey key) {
        // Encrypt API credentials implementation
    }
    
    private void encryptBackupData(SecretKey key) {
        // Encrypt backup data implementation
    }
    
    private void encryptTwoFactorData(SecretKey key1, SecretKey key2) {
        // Encrypt two-factor data implementation
    }
    
    private byte[] getSaltForUser(String username) {
        return new byte[16]; // Just a placeholder
    }
    
    private void encryptAdminCredentials(SecretKey key) {
        // Encrypt admin credentials implementation
    }
    
    private byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
    
    private void encryptPaymentInfo(SecretKey key) {
        // Encrypt payment info implementation
    }
    
    private void encryptSensitiveDocuments(SecretKey key) {
        // Encrypt sensitive documents implementation
    }
    
    private String getPasswordFromSecureSource() {
        return "hardcoded_password"; // This is the issue - returns hardcoded value
    }
    
    private byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }
    
    private char[] getPasswordFromVault(String keyId) {
        // Implementation to get password from a secure vault
        return "secure_password".toCharArray(); // Simplified for example
    }
    
    private String[] getCommandLineArgs() {
        return new String[]{"command_line_password"}; // Simplified for example
    }
    
    private String getPasswordFromSecureApi(String keyId) {
        // Implementation to get password from a secure API
        return "api_retrieved_password"; // Simplified for example
    }
    
    // Mock classes for examples
    private class EncryptionConfig {
        public String getDefaultPassword() {
            return "DefaultEncryptionPassword"; // Hardcoded password
        }
        
        public byte[] getDefaultSalt() {
            return new byte[16];
        }
    }
    
    private class PasswordCallback {
        public char[] getPassword() {
            // Implementation to get password from a callback
            return "callback_password".toCharArray(); // Simplified for example
        }
    }
    
    private class KeyManagementService {
        public char[] retrievePassword(String keyId) {
            // Implementation to retrieve password from a key management service
            return "kms_password".toCharArray(); // Simplified for example
        }
    }
    
    private class DatabasePasswordProvider {
        public String getPassword(String keyId) {
            // Implementation to get password from a database
            return "db_password"; // Simplified for example
        }
    }
    
    private class HardwareSecurityModule {
        public char[] getSecurePassword(String keyId) {
            // Implementation to get password from a hardware security module
            return "hsm_password".toCharArray(); // Simplified for example
        }
    }
    
    private class ConfigurationService {
        public String getSecureConfig(String configKey) {
            // Implementation to get configuration from a secure service
            return "config_password"; // Simplified for example
        }
    }
}
// {/fact}