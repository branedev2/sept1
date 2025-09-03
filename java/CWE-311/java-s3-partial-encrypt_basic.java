import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.Properties;

public class PartialEncryptionExamples {

    // True Positives (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        try {
            String data = request.getParameter("data");
            String type = request.getParameter("type");
            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            
            // Conditional encryption based on type parameter
            if ("sensitive".equals(type)) {
                SecretKey key = generateKey();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                IvParameterSpec iv = generateIv();
                cipher.init(Cipher.ENCRYPT_MODE, key, iv);
                byte[] encryptedData = cipher.doFinal(dataBytes);
                storeData(encryptedData);
            } else {
                // ruleid: java-s3-partial-encrypt
                storeData(dataBytes); // Storing unencrypted data
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2(HttpServletRequest request) {
        try {
            String userId = request.getParameter("userId");
            String password = request.getParameter("password");
            boolean isPremiumUser = "premium".equals(request.getParameter("userType"));
            
            // Only encrypt passwords for premium users
            if (isPremiumUser) {
                SecretKey key = generateKey();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encryptedPassword = cipher.doFinal(password.getBytes());
                saveUserCredentials(userId, encryptedPassword);
            } else {
                // ruleid: java-s3-partial-encrypt
                saveUserCredentials(userId, password.getBytes()); // Storing unencrypted password
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3(HttpServletRequest request) {
        try {
            String creditCardNumber = request.getParameter("ccNumber");
            boolean isTestEnvironment = "test".equals(System.getProperty("env"));
            
            byte[] dataToStore;
            if (!isTestEnvironment) {
                SecretKey key = generateKey();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                dataToStore = cipher.doFinal(creditCardNumber.getBytes());
            } else {
                // ruleid: java-s3-partial-encrypt
                dataToStore = creditCardNumber.getBytes(); // Storing unencrypted in test environment
            }
            storeData(dataToStore);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4(HttpServletRequest request) {
        try {
            String data = request.getParameter("data");
            int dataLength = data.length();
            
            // Only encrypt data if it's longer than 10 characters
            if (dataLength > 10) {
                SecretKey key = generateKey();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encryptedData = cipher.doFinal(data.getBytes());
                storeData(encryptedData);
            } else {
                // ruleid: java-s3-partial-encrypt
                storeData(data.getBytes()); // Storing short data unencrypted
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5(HttpServletRequest request) {
        try {
            String apiKey = request.getParameter("apiKey");
            boolean isInternalRequest = request.getHeader("X-Internal") != null;
            
            // Only encrypt API keys for external requests
            if (!isInternalRequest) {
                SecretKey key = generateKey();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encryptedKey = cipher.doFinal(apiKey.getBytes());
                saveApiKey(encryptedKey);
            } else {
                // ruleid: java-s3-partial-encrypt
                saveApiKey(apiKey.getBytes()); // Storing internal API keys unencrypted
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6(HttpServletRequest request) {
        try {
            String personalData = request.getParameter("personalData");
            String country = request.getParameter("country");
            
            // Only encrypt for certain countries
            if ("US".equals(country) || "EU".equals(country)) {
                SecretKey key = generateKey();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encryptedData = cipher.doFinal(personalData.getBytes());
                storePersonalData(encryptedData);
            } else {
                // ruleid: java-s3-partial-encrypt
                storePersonalData(personalData.getBytes()); // Storing unencrypted for other countries
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7(HttpServletRequest request) {
        try {
            String userData = request.getParameter("userData");
            int userId = Integer.parseInt(request.getParameter("userId"));
            
            // Only encrypt for even user IDs
            if (userId % 2 == 0) {
                SecretKey key = generateKey();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encryptedData = cipher.doFinal(userData.getBytes());
                saveUserData(userId, encryptedData);
            } else {
                // ruleid: java-s3-partial-encrypt
                saveUserData(userId, userData.getBytes()); // Storing unencrypted for odd user IDs
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8(HttpServletRequest request) {
        try {
            String message = request.getParameter("message");
            boolean isEncrypted = Boolean.parseBoolean(request.getParameter("encrypt"));
            
            if (isEncrypted) {
                SecretKey key = generateKey();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encryptedMessage = cipher.doFinal(message.getBytes());
                sendMessage(encryptedMessage);
            } else {
                // ruleid: java-s3-partial-encrypt
                sendMessage(message.getBytes()); // Sending unencrypted message
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9(HttpServletRequest request) {
        try {
            String fileContent = request.getParameter("content");
            String fileName = request.getParameter("fileName");
            
            // Only encrypt files with .sensitive extension
            if (fileName.endsWith(".sensitive")) {
                SecretKey key = generateKey();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encryptedContent = cipher.doFinal(fileContent.getBytes());
                writeToFile(fileName, encryptedContent);
            } else {
                // ruleid: java-s3-partial-encrypt
                writeToFile(fileName, fileContent.getBytes()); // Writing unencrypted content
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10(HttpServletRequest request) {
        try {
            String configData = request.getParameter("configData");
            boolean isProduction = "production".equals(System.getProperty("environment"));
            
            // Only encrypt in production
            if (isProduction) {
                SecretKey key = generateKey();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encryptedConfig = cipher.doFinal(configData.getBytes());
                saveConfiguration(encryptedConfig);
            } else {
                // ruleid: java-s3-partial-encrypt
                saveConfiguration(configData.getBytes()); // Saving unencrypted in non-production
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11(HttpServletRequest request) {
        try {
            Map<String, String> userData = new HashMap<>();
            userData.put("name", request.getParameter("name"));
            userData.put("email", request.getParameter("email"));
            userData.put("ssn", request.getParameter("ssn"));
            
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            
            // Only encrypt SSN, leaving other fields unencrypted
            byte[] encryptedSsn = cipher.doFinal(userData.get("ssn").getBytes());
            userData.put("ssn", Base64.getEncoder().encodeToString(encryptedSsn));
            
            // ruleid: java-s3-partial-encrypt
            storeUserProfile(userData); // Other sensitive fields remain unencrypted
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12(HttpServletRequest request) {
        try {
            String healthData = request.getParameter("healthData");
            int dataCategory = Integer.parseInt(request.getParameter("category"));
            
            // Only encrypt categories 1-3
            if (dataCategory >= 1 && dataCategory <= 3) {
                SecretKey key = generateKey();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encryptedData = cipher.doFinal(healthData.getBytes());
                storeHealthData(dataCategory, encryptedData);
            } else {
                // ruleid: java-s3-partial-encrypt
                storeHealthData(dataCategory, healthData.getBytes()); // Storing unencrypted health data
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) {
        try {
            String token = request.getParameter("token");
            boolean rememberMe = Boolean.parseBoolean(request.getParameter("rememberMe"));
            
            // Only encrypt token for remember-me cookies
            if (rememberMe) {
                SecretKey key = generateKey();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encryptedToken = cipher.doFinal(token.getBytes());
                response.addCookie(createCookie("auth_token", Base64.getEncoder().encodeToString(encryptedToken)));
            } else {
                // ruleid: java-s3-partial-encrypt
                response.addCookie(createCookie("auth_token", token)); // Setting unencrypted token in cookie
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14(HttpServletRequest request) {
        try {
            Properties dbConfig = new Properties();
            dbConfig.setProperty("db.url", request.getParameter("dbUrl"));
            dbConfig.setProperty("db.user", request.getParameter("dbUser"));
            dbConfig.setProperty("db.password", request.getParameter("dbPassword"));
            
            boolean isLocalDb = request.getParameter("dbUrl").contains("localhost");
            
            // Only encrypt password for non-local databases
            if (!isLocalDb) {
                SecretKey key = generateKey();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encryptedPassword = cipher.doFinal(dbConfig.getProperty("db.password").getBytes());
                dbConfig.setProperty("db.password", Base64.getEncoder().encodeToString(encryptedPassword));
            }
            
            // ruleid: java-s3-partial-encrypt
            saveDbConfig(dbConfig); // Password might be unencrypted for local DBs
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15(HttpServletRequest request) {
        try {
            String backupData = request.getParameter("backupData");
            String backupType = request.getParameter("backupType");
            
            // Only encrypt full backups
            if ("full".equals(backupType)) {
                SecretKey key = generateKey();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encryptedBackup = cipher.doFinal(backupData.getBytes());
                createBackup(backupType, encryptedBackup);
            } else {
                // ruleid: java-s3-partial-encrypt
                createBackup(backupType, backupData.getBytes()); // Creating unencrypted partial backups
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negatives (Secure Code)

    public void good_case_1(HttpServletRequest request) {
        try {
            String data = request.getParameter("data");
            String type = request.getParameter("type");
            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            
            // Always encrypt data regardless of type
            // ok: java-s3-partial-encrypt
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = generateIv();
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encryptedData = cipher.doFinal(dataBytes);
            storeData(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2(HttpServletRequest request) {
        try {
            String userId = request.getParameter("userId");
            String password = request.getParameter("password");
            boolean isPremiumUser = "premium".equals(request.getParameter("userType"));
            
            // Encrypt all passwords regardless of user type
            // ok: java-s3-partial-encrypt
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedPassword = cipher.doFinal(password.getBytes());
            saveUserCredentials(userId, encryptedPassword);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3(HttpServletRequest request) {
        try {
            String creditCardNumber = request.getParameter("ccNumber");
            boolean isTestEnvironment = "test".equals(System.getProperty("env"));
            
            // Encrypt credit card numbers in all environments
            // ok: java-s3-partial-encrypt
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedCcNumber = cipher.doFinal(creditCardNumber.getBytes());
            storeData(encryptedCcNumber);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4(HttpServletRequest request) {
        try {
            String data = request.getParameter("data");
            int dataLength = data.length();
            
            // Encrypt all data regardless of length
            // ok: java-s3-partial-encrypt
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            storeData(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5(HttpServletRequest request) {
        try {
            String apiKey = request.getParameter("apiKey");
            boolean isInternalRequest = request.getHeader("X-Internal") != null;
            
            // Encrypt all API keys regardless of request source
            // ok: java-s3-partial-encrypt
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedKey = cipher.doFinal(apiKey.getBytes());
            saveApiKey(encryptedKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6(HttpServletRequest request) {
        try {
            String personalData = request.getParameter("personalData");
            String country = request.getParameter("country");
            
            // Encrypt personal data for all countries
            // ok: java-s3-partial-encrypt
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(personalData.getBytes());
            storePersonalData(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7(HttpServletRequest request) {
        try {
            String userData = request.getParameter("userData");
            int userId = Integer.parseInt(request.getParameter("userId"));
            
            // Encrypt for all user IDs
            // ok: java-s3-partial-encrypt
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(userData.getBytes());
            saveUserData(userId, encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8(HttpServletRequest request) {
        try {
            String message = request.getParameter("message");
            boolean isEncrypted = Boolean.parseBoolean(request.getParameter("encrypt"));
            
            // Always encrypt messages regardless of parameter
            // ok: java-s3-partial-encrypt
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedMessage = cipher.doFinal(message.getBytes());
            sendMessage(encryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9(HttpServletRequest request) {
        try {
            String fileContent = request.getParameter("content");
            String fileName = request.getParameter("fileName");
            
            // Encrypt all file content regardless of extension
            // ok: java-s3-partial-encrypt
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedContent = cipher.doFinal(fileContent.getBytes());
            writeToFile(fileName, encryptedContent);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10(HttpServletRequest request) {
        try {
            String configData = request.getParameter("configData");
            boolean isProduction = "production".equals(System.getProperty("environment"));
            
            // Encrypt configuration in all environments
            // ok: java-s3-partial-encrypt
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedConfig = cipher.doFinal(configData.getBytes());
            saveConfiguration(encryptedConfig);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11(HttpServletRequest request) {
        try {
            Map<String, String> userData = new HashMap<>();
            userData.put("name", request.getParameter("name"));
            userData.put("email", request.getParameter("email"));
            userData.put("ssn", request.getParameter("ssn"));
            
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            
            // Encrypt all sensitive fields
            // ok: java-s3-partial-encrypt
            Map<String, String> encryptedData = new HashMap<>();
            for (Map.Entry<String, String> entry : userData.entrySet()) {
                byte[] encryptedValue = cipher.doFinal(entry.getValue().getBytes());
                encryptedData.put(entry.getKey(), Base64.getEncoder().encodeToString(encryptedValue));
            }
            storeUserProfile(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12(HttpServletRequest request) {
        try {
            String healthData = request.getParameter("healthData");
            int dataCategory = Integer.parseInt(request.getParameter("category"));
            
            // Encrypt all health data regardless of category
            // ok: java-s3-partial-encrypt
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(healthData.getBytes());
            storeHealthData(dataCategory, encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) {
        try {
            String token = request.getParameter("token");
            boolean rememberMe = Boolean.parseBoolean(request.getParameter("rememberMe"));
            
            // Always encrypt tokens for cookies
            // ok: java-s3-partial-encrypt
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedToken = cipher.doFinal(token.getBytes());
            response.addCookie(createCookie("auth_token", Base64.getEncoder().encodeToString(encryptedToken)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14(HttpServletRequest request) {
        try {
            Properties dbConfig = new Properties();
            dbConfig.setProperty("db.url", request.getParameter("dbUrl"));
            dbConfig.setProperty("db.user", request.getParameter("dbUser"));
            dbConfig.setProperty("db.password", request.getParameter("dbPassword"));
            
            boolean isLocalDb = request.getParameter("dbUrl").contains("localhost");
            
            // Encrypt all database passwords regardless of location
            // ok: java-s3-partial-encrypt
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedPassword = cipher.doFinal(dbConfig.getProperty("db.password").getBytes());
            dbConfig.setProperty("db.password", Base64.getEncoder().encodeToString(encryptedPassword));
            saveDbConfig(dbConfig);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15(HttpServletRequest request) {
        try {
            String backupData = request.getParameter("backupData");
            String backupType = request.getParameter("backupType");
            
            // Encrypt all backups regardless of type
            // ok: java-s3-partial-encrypt
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBackup = cipher.doFinal(backupData.getBytes());
            createBackup(backupType, encryptedBackup);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Helper methods
    private SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    private IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private void storeData(byte[] data) {
        // Implementation to store data
    }

    private void saveUserCredentials(String userId, byte[] encryptedPassword) {
        // Implementation to save user credentials
    }

    private void saveApiKey(byte[] apiKey) {
        // Implementation to save API key
    }

    private void storePersonalData(byte[] data) {
        // Implementation to store personal data
    }

    private void saveUserData(int userId, byte[] data) {
        // Implementation to save user data
    }

    private void sendMessage(byte[] message) {
        // Implementation to send message
    }

    private void writeToFile(String fileName, byte[] content) {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(content);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void saveConfiguration(byte[] config) {
        // Implementation to save configuration
    }

    private void storeUserProfile(Map<String, String> userData) {
        // Implementation to store user profile
    }

    private void storeHealthData(int category, byte[] data) {
        // Implementation to store health data
    }

    private javax.servlet.http.Cookie createCookie(String name, String value) {
        return new javax.servlet.http.Cookie(name, value);
    }

    private void saveDbConfig(Properties config) {
        // Implementation to save database configuration
    }

    private void createBackup(String type, byte[] data) {
        // Implementation to create backup
    }
}
// {/fact}