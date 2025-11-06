import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.Date;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class MandatoryMethodsTest {

    // True Positives (Vulnerable Code)

// {fact rule=client-constructor-deprecated-rule@v1.0 defects=1}
    public static void bad_case_1() {
        class UserCredentials {
            private String username;
            private String password;
            
            // Missing constructor to initialize fields
            
            public void authenticate() {
                // ruleid: java-mandatory-methods
                if (username == null || password == null) {
                    throw new NullPointerException("Credentials not initialized");
                }
                // Authentication logic
            }
        }
        
        UserCredentials credentials = new UserCredentials();
        credentials.authenticate(); // Will throw exception due to uninitialized fields
    }

    public static void bad_case_2() {
        class DatabaseConnection {
            private String connectionUrl;
            private String username;
            private String password;
            
            // Constructor doesn't initialize all required fields
            public DatabaseConnection(String url) {
                this.connectionUrl = url;
            }
            
            public void connect() throws SQLException {
                // ruleid: java-mandatory-methods
                Connection conn = DriverManager.getConnection(connectionUrl, username, password);
                // Will fail due to null username and password
            }
        }
        
        DatabaseConnection db = new DatabaseConnection("jdbc:mysql://localhost:3306/mydb");
        try {
            db.connect();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_3() {
        class SecurityConfig {
            private KeyStore trustStore;
            
            // Missing initialization method for trustStore
            
            public SSLContext createSSLContext() throws Exception {
                // ruleid: java-mandatory-methods
                SSLContext sslContext = SSLContext.getInstance("TLS");
                // Will fail because trustStore is null
                KeyStore.TrustManagerFactory tmf = KeyStore.TrustManagerFactory.getInstance(KeyStore.TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(trustStore);
                sslContext.init(null, tmf.getTrustManagers(), null);
                return sslContext;
            }
        }
        
        SecurityConfig config = new SecurityConfig();
        try {
            config.createSSLContext();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_4() {
        class CryptoService {
            private Cipher cipher;
            
            public CryptoService() {
                // Constructor doesn't initialize cipher
            }
            
            public byte[] encrypt(byte[] data) throws Exception {
                // ruleid: java-mandatory-methods
                return cipher.doFinal(data); // NullPointerException
            }
        }
        
        CryptoService service = new CryptoService();
        try {
            service.encrypt("sensitive data".getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_5() {
        class ConfigurationManager {
            private Map<String, String> settings;
            
            // No initialization of settings map
            
            public String getSetting(String key) {
                // ruleid: java-mandatory-methods
                return settings.get(key); // NullPointerException
            }
        }
        
        ConfigurationManager manager = new ConfigurationManager();
        manager.getSetting("important-setting");
    }

    public static void bad_case_6() {
        class UserSession {
            private String sessionId;
            private Date expiryTime;
            
            // Constructor doesn't set expiry time
            public UserSession(String id) {
                this.sessionId = id;
            }
            
            public boolean isValid() {
                // ruleid: java-mandatory-methods
                return new Date().before(expiryTime); // NullPointerException
            }
        }
        
        UserSession session = new UserSession("abc123");
        session.isValid();
    }

    public static void bad_case_7() {
        class Logger {
            private File logFile;
            
            // Missing initialization of logFile
            
            public void log(String message) {
                try {
                    // ruleid: java-mandatory-methods
                    java.io.FileWriter writer = new java.io.FileWriter(logFile, true);
                    writer.write(message + "\n");
                    writer.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        
        Logger logger = new Logger();
        logger.log("This will fail");
    }

    public static void bad_case_8() {
        class EmailSender {
            private String smtpServer;
            private int port;
            
            // Constructor doesn't initialize fields
            public EmailSender() {
                // Empty constructor
            }
            
            public void sendEmail(String to, String subject, String body) {
                // ruleid: java-mandatory-methods
                System.out.println("Sending email via " + smtpServer + ":" + port);
                // Will print "Sending email via null:0"
            }
        }
        
        EmailSender sender = new EmailSender();
        sender.sendEmail("user@example.com", "Test", "Hello");
    }

    public static void bad_case_9() {
        class ApiClient {
            private String apiKey;
            private String baseUrl;
            
            // Missing initialization for apiKey
            public ApiClient(String url) {
                this.baseUrl = url;
            }
            
            public void makeAuthenticatedRequest(String endpoint) {
                // ruleid: java-mandatory-methods
                String url = baseUrl + endpoint + "?key=" + apiKey;
                System.out.println("Making request to: " + url);
                // Will include "key=null" in URL
            }
        }
        
        ApiClient client = new ApiClient("https://api.example.com");
        client.makeAuthenticatedRequest("/data");
    }

    public static void bad_case_10() {
        class CacheManager {
            private Map<String, Object> cache;
            
            // No initialization of cache map
            
            public void put(String key, Object value) {
                // ruleid: java-mandatory-methods
                cache.put(key, value); // NullPointerException
            }
        }
        
        CacheManager manager = new CacheManager();
        manager.put("key", "value");
    }

    public static void bad_case_11() {
        class FileProcessor {
            private List<File> filesToProcess;
            
            // Missing initialization of list
            
            public void processFiles() {
                // ruleid: java-mandatory-methods
                for (File file : filesToProcess) { // NullPointerException
                    System.out.println("Processing: " + file.getName());
                }
            }
        }
        
        FileProcessor processor = new FileProcessor();
        processor.processFiles();
    }

    public static void bad_case_12() {
        class TrustManagerImpl implements X509TrustManager {
            private X509Certificate[] acceptedIssuers;
            
            // Missing initialization of acceptedIssuers
            
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                // No implementation needed for example
            }
            
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                // No implementation needed for example
            }
            
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                // ruleid: java-mandatory-methods
                return acceptedIssuers; // Will return null
            }
        }
        
        TrustManagerImpl trustManager = new TrustManagerImpl();
        trustManager.getAcceptedIssuers();
    }

    public static void bad_case_13() {
        class RequestHandler {
            private String[] allowedMethods;
            
            // Missing initialization of allowedMethods
            
            public boolean isMethodAllowed(String method) {
                // ruleid: java-mandatory-methods
                for (String allowed : allowedMethods) { // NullPointerException
                    if (allowed.equals(method)) {
                        return true;
                    }
                }
                return false;
            }
        }
        
        RequestHandler handler = new RequestHandler();
        handler.isMethodAllowed("GET");
    }

    public static void bad_case_14() {
        class SecureRandom {
            private byte[] seed;
            
            // Missing initialization of seed
            
            public byte[] generateRandomBytes(int length) {
                // ruleid: java-mandatory-methods
                byte[] result = new byte[length];
                for (int i = 0; i < length; i++) {
                    result[i] = seed[i % seed.length]; // NullPointerException
                }
                return result;
            }
        }
        
        SecureRandom random = new SecureRandom();
        random.generateRandomBytes(16);
    }

    public static void bad_case_15() {
        class AuthenticationService {
            private String[] validTokens;
            
            // Missing initialization of validTokens
            
            public boolean validateToken(String token) {
                // ruleid: java-mandatory-methods
                for (String validToken : validTokens) { // NullPointerException
                    if (validToken.equals(token)) {
                        return true;
                    }
                }
                return false;
            }
        }
        
        AuthenticationService service = new AuthenticationService();
        service.validateToken("abc123");
    }

    // True Negatives (Secure Code)

    public static void good_case_1() {
        class UserCredentials {
            private String username;
            private String password;
            
            // Constructor properly initializes all fields
            public UserCredentials(String username, String password) {
                this.username = username;
                this.password = password;
            }
            
            public void authenticate() {
                // ok: java-mandatory-methods
                if (username != null && password != null) {
                    // Authentication logic
                    System.out.println("Authenticating user: " + username);
                }
            }
        }
        
        UserCredentials credentials = new UserCredentials("user", "pass");
        credentials.authenticate();
    }

    public static void good_case_2() {
        class DatabaseConnection {
            private String connectionUrl;
            private String username;
            private String password;
            
            // Constructor initializes all required fields
            public DatabaseConnection(String url, String username, String password) {
                this.connectionUrl = url;
                this.username = username;
                this.password = password;
            }
            
            public void connect() throws SQLException {
                // ok: java-mandatory-methods
                Connection conn = DriverManager.getConnection(connectionUrl, username, password);
                System.out.println("Connected successfully");
            }
        }
        
        DatabaseConnection db = new DatabaseConnection("jdbc:mysql://localhost:3306/mydb", "user", "pass");
        try {
            db.connect();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_3() {
        class SecurityConfig {
            private KeyStore trustStore;
            
            // Proper initialization method
            public SecurityConfig() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
                trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                trustStore.load(null, null); // Initialize empty keystore
            }
            
            public SSLContext createSSLContext() throws Exception {
                SSLContext sslContext = SSLContext.getInstance("TLS");
                // ok: java-mandatory-methods
                KeyStore.TrustManagerFactory tmf = KeyStore.TrustManagerFactory.getInstance(KeyStore.TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(trustStore);
                sslContext.init(null, tmf.getTrustManagers(), null);
                return sslContext;
            }
        }
        
        try {
            SecurityConfig config = new SecurityConfig();
            config.createSSLContext();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_4() {
        class CryptoService {
            private Cipher cipher;
            
            public CryptoService() throws Exception {
                // Constructor initializes cipher
                this.cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                SecretKey key = KeyGenerator.getInstance("AES").generateKey();
                cipher.init(Cipher.ENCRYPT_MODE, key);
            }
            
            public byte[] encrypt(byte[] data) throws Exception {
                // ok: java-mandatory-methods
                return cipher.doFinal(data);
            }
        }
        
        try {
            CryptoService service = new CryptoService();
            service.encrypt("sensitive data".getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_5() {
        class ConfigurationManager {
            private Map<String, String> settings;
            
            // Initialize settings map in constructor
            public ConfigurationManager() {
                this.settings = new HashMap<>();
                settings.put("default-setting", "default-value");
            }
            
            public String getSetting(String key) {
                // ok: java-mandatory-methods
                return settings.get(key);
            }
        }
        
        ConfigurationManager manager = new ConfigurationManager();
        manager.getSetting("default-setting");
    }

    public static void good_case_6() {
        class UserSession {
            private String sessionId;
            private Date expiryTime;
            
            // Constructor sets all fields
            public UserSession(String id) {
                this.sessionId = id;
                // Set expiry to 30 minutes from now
                this.expiryTime = new Date(System.currentTimeMillis() + 30 * 60 * 1000);
            }
            
            public boolean isValid() {
                // ok: java-mandatory-methods
                return new Date().before(expiryTime);
            }
        }
        
        UserSession session = new UserSession("abc123");
        session.isValid();
    }

    public static void good_case_7() {
        class Logger {
            private File logFile;
            
            // Initialize logFile in constructor
            public Logger(String logFilePath) {
                this.logFile = new File(logFilePath);
            }
            
            public void log(String message) {
                try {
                    // ok: java-mandatory-methods
                    java.io.FileWriter writer = new java.io.FileWriter(logFile, true);
                    writer.write(message + "\n");
                    writer.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        
        Logger logger = new Logger("application.log");
        // This would work if the file exists or can be created
    }

    public static void good_case_8() {
        class EmailSender {
            private String smtpServer;
            private int port;
            
            // Constructor initializes all fields
            public EmailSender(String smtpServer, int port) {
                this.smtpServer = smtpServer;
                this.port = port;
            }
            
            public void sendEmail(String to, String subject, String body) {
                // ok: java-mandatory-methods
                System.out.println("Sending email via " + smtpServer + ":" + port);
                // Will print correct server and port
            }
        }
        
        EmailSender sender = new EmailSender("smtp.example.com", 587);
        sender.sendEmail("user@example.com", "Test", "Hello");
    }

    public static void good_case_9() {
        class ApiClient {
            private String apiKey;
            private String baseUrl;
            
            // Constructor initializes all fields
            public ApiClient(String url, String apiKey) {
                this.baseUrl = url;
                this.apiKey = apiKey;
            }
            
            public void makeAuthenticatedRequest(String endpoint) {
                // ok: java-mandatory-methods
                String url = baseUrl + endpoint + "?key=" + apiKey;
                System.out.println("Making request to: " + url);
                // Will include proper API key in URL
            }
        }
        
        ApiClient client = new ApiClient("https://api.example.com", "my-api-key");
        client.makeAuthenticatedRequest("/data");
    }

    public static void good_case_10() {
        class CacheManager {
            private Map<String, Object> cache;
            
            // Initialize cache in constructor
            public CacheManager() {
                this.cache = new HashMap<>();
            }
            
            public void put(String key, Object value) {
                // ok: java-mandatory-methods
                cache.put(key, value);
            }
        }
        
        CacheManager manager = new CacheManager();
        manager.put("key", "value");
    }

    public static void good_case_11() {
        class FileProcessor {
            private List<File> filesToProcess;
            
            // Initialize list in constructor
            public FileProcessor() {
                this.filesToProcess = new ArrayList<>();
            }
            
            public void addFile(File file) {
                filesToProcess.add(file);
            }
            
            public void processFiles() {
                // ok: java-mandatory-methods
                for (File file : filesToProcess) {
                    System.out.println("Processing: " + file.getName());
                }
            }
        }
        
        FileProcessor processor = new FileProcessor();
        processor.addFile(new File("example.txt"));
        processor.processFiles();
    }

    public static void good_case_12() {
        class TrustManagerImpl implements X509TrustManager {
            private X509Certificate[] acceptedIssuers;
            
            // Initialize in constructor
            public TrustManagerImpl() {
                this.acceptedIssuers = new X509Certificate[0]; // Empty array instead of null
            }
            
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                // No implementation needed for example
            }
            
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                // No implementation needed for example
            }
            
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                // ok: java-mandatory-methods
                return acceptedIssuers;
            }
        }
        
        TrustManagerImpl trustManager = new TrustManagerImpl();
        trustManager.getAcceptedIssuers();
    }

    public static void good_case_13() {
        class RequestHandler {
            private String[] allowedMethods;
            
            // Initialize array in constructor
            public RequestHandler() {
                this.allowedMethods = new String[]{"GET", "POST", "PUT", "DELETE"};
            }
            
            public boolean isMethodAllowed(String method) {
                // ok: java-mandatory-methods
                for (String allowed : allowedMethods) {
                    if (allowed.equals(method)) {
                        return true;
                    }
                }
                return false;
            }
        }
        
        RequestHandler handler = new RequestHandler();
        handler.isMethodAllowed("GET");
    }

    public static void good_case_14() {
        class SecureRandomGenerator {
            private byte[] seed;
            
            // Initialize seed in constructor
            public SecureRandomGenerator() {
                SecureRandom random = new SecureRandom();
                this.seed = new byte[16];
                random.nextBytes(this.seed);
            }
            
            public byte[] generateRandomBytes(int length) {
                // ok: java-mandatory-methods
                byte[] result = new byte[length];
                for (int i = 0; i < length; i++) {
                    result[i] = seed[i % seed.length];
                }
                return result;
            }
        }
        
        SecureRandomGenerator random = new SecureRandomGenerator();
        random.generateRandomBytes(16);
    }

    public static void good_case_15() {
        class AuthenticationService {
            private String[] validTokens;
            
            // Initialize array in constructor
            public AuthenticationService() {
                this.validTokens = new String[]{"token1", "token2", "token3"};
            }
            
            public boolean validateToken(String token) {
                // ok: java-mandatory-methods
                for (String validToken : validTokens) {
                    if (validToken.equals(token)) {
                        return true;
                    }
                }
                return false;
            }
        }
        
        AuthenticationService service = new AuthenticationService();
        service.validateToken("token1");
    }
}
// {/fact}