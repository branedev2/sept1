import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.Message;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import java.nio.file.Files;
import java.nio.file.Paths;

public class HardcodedSecretsInComments {

    // True Positive Examples (Vulnerable Code)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        try {
            // ruleid: java-hardcoded-secrets-in-comments
            // Database password: P@ssw0rd123
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = "admin";
            String password = getPasswordFromSecureStore();
            Connection conn = DriverManager.getConnection(url, username, password);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            String url = "jdbc:postgresql://localhost:5432/mydb";
            // ruleid: java-hardcoded-secrets-in-comments
            /* 
             * Connection details:
             * username: postgres
             * password: SuperSecretP@ss!
             */
            Connection conn = DriverManager.getConnection(
                url, 
                System.getenv("DB_USER"), 
                System.getenv("DB_PASSWORD")
            );
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        // ruleid: java-hardcoded-secrets-in-comments
        // API key for production: sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY
        String apiEndpoint = "https://api.example.com/v1/data";
        String apiKey = System.getenv("API_KEY");
        
        try {
            java.net.URL url = new java.net.URL(apiEndpoint);
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            conn.setRequestMethod("GET");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            // ruleid: java-hardcoded-secrets-in-comments
            // AWS credentials - accessKey: AKIAIOSFODNN7EXAMPLE, secretKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
            AWSCredentials credentials = new BasicAWSCredentials(
                System.getenv("AWS_AC_REDACTED_TWILIO_ID_KEY"),
                System.getenv("AWS_SECRET_KEY")
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        // ruleid: java-hardcoded-secrets-in-comments
        /* Encryption key: 1234567890abcdef */
        String plaintext = "Sensitive data";
        String encryptionKey = loadKeyFromSecureStorage();
        
        try {
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            // Encryption logic would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");
            
            // ruleid: java-hardcoded-secrets-in-comments
            // SMTP password: emailP@ssw0rd!
            Session session = Session.getInstance(props, new javax.mail.Authenticator() {
                protected javax.mail.PasswordAuthentication getPasswordAuthentication() {
                    return new javax.mail.PasswordAuthentication(
                        System.getenv("EMAIL_USER"), 
                        System.getenv("EMAIL_PASSWORD")
                    );
                }
            });
            
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("from@example.com"));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("to@example.com"));
            message.setSubject("Test Subject");
            message.setText("Test Body");
            
            Transport.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        // ruleid: java-hardcoded-secrets-in-comments
        // SSH private key passphrase: ssh-secret-passphrase-123
        try {
            JSch jsch = new JSch();
            String privateKeyPath = "/path/to/private/key";
            String passphrase = getPassphraseFromSecureStore();
            jsch.addIdentity(privateKeyPath, passphrase);
            com.jcraft.jsch.Session session = jsch.getSession("username", "hostname", 22);
            session.connect();
        } catch (JSchException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            // ruleid: java-hardcoded-secrets-in-comments
            /* OAuth client secret: oauth-client-secret-123456789 */
            String authUrl = "https://oauth.example.com/token";
            String clientId = "my-client-id";
            String clientSecret = System.getenv("OAUTH_CLIENT_SECRET");
            
            // OAuth authentication logic would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        // ruleid: java-hardcoded-secrets-in-comments
        // MongoDB connection string: mongodb+srv://admin:mongodb-password-123@cluster0.example.mongodb.net/
        try {
            String connectionString = System.getenv("MONGODB_URI");
            // MongoDB connection logic would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            // ruleid: java-hardcoded-secrets-in-comments
            // JWT signing key: jwt-signing-key-very-secret-do-not-share
            String jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
            String signingKey = loadSigningKeyFromSecureStorage();
            
            // JWT verification logic would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        // ruleid: java-hardcoded-secrets-in-comments
        /* 
         * Firebase config:
         * apiKey: "AIzaSyDOCAbC123dEf456GhI789jKl012-MnO"
         * authDomain: "myapp.firebaseapp.com"
         * databaseURL: "https://myapp.firebaseio.com"
         */
        try {
            // Firebase initialization logic would go here using environment variables
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            // ruleid: java-hardcoded-secrets-in-comments
            // Stripe test API key: sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY
            String apiKey = System.getenv("STRIPE_API_KEY");
            
            // Stripe API call logic would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        // ruleid: java-hardcoded-secrets-in-comments
        // Encryption salt: 8a7b6c5d4e3f2g1h
        try {
            String password = "userPassword";
            String salt = getSaltFromSecureStorage();
            
            TextEncryptor encryptor = Encryptors.text(password, salt);
            String encrypted = encryptor.encrypt("sensitive data");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            // ruleid: java-hardcoded-secrets-in-comments
            /* Redis password: redis-password-123 */
            String redisHost = "localhost";
            int redisPort = 6379;
            String redisPassword = System.getenv("REDIS_PASSWORD");
            
            // Redis connection logic would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        // ruleid: java-hardcoded-secrets-in-comments
        // FTP credentials: username=ftpuser, password=ftp-P@ssw0rd!
        try {
            String ftpHost = "ftp.example.com";
            String ftpUser = System.getenv("FTP_USER");
            String ftpPassword = System.getenv("FTP_PASSWORD");
            
            // FTP connection logic would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        try {
            // ok: java-hardcoded-secrets-in-comments
            // Database connection using environment variables for security
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = System.getenv("DB_USER");
            String password = System.getenv("DB_PASSWORD");
            Connection conn = DriverManager.getConnection(url, username, password);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            // ok: java-hardcoded-secrets-in-comments
            /* 
             * Using a properties file to store connection details
             * See config/database.properties for structure
             */
            Properties props = new Properties();
            props.load(new FileInputStream("config/database.properties"));
            
            Connection conn = DriverManager.getConnection(
                props.getProperty("db.url"),
                props.getProperty("db.user"),
                props.getProperty("db.password")
            );
        } catch (SQLException | IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        // ok: java-hardcoded-secrets-in-comments
        // API authentication using environment variables
        String apiEndpoint = "https://api.example.com/v1/data";
        String apiKey = System.getenv("API_KEY");
        
        try {
            java.net.URL url = new java.net.URL(apiEndpoint);
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            conn.setRequestMethod("GET");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        try {
            // ok: java-hardcoded-secrets-in-comments
            // AWS credentials loaded from environment variables
            AWSCredentials credentials = new BasicAWSCredentials(
                System.getenv("AWS_AC_REDACTED_TWILIO_ID_KEY"),
                System.getenv("AWS_SECRET_KEY")
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        // ok: java-hardcoded-secrets-in-comments
        // Encryption using keys from secure storage
        String plaintext = "Sensitive data";
        String encryptionKey = loadKeyFromSecureStorage();
        
        try {
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            // Encryption logic would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            // ok: java-hardcoded-secrets-in-comments
            // Email configuration with credentials from environment variables
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");
            
            Session session = Session.getInstance(props, new javax.mail.Authenticator() {
                protected javax.mail.PasswordAuthentication getPasswordAuthentication() {
                    return new javax.mail.PasswordAuthentication(
                        System.getenv("EMAIL_USER"), 
                        System.getenv("EMAIL_PASSWORD")
                    );
                }
            });
            
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("from@example.com"));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("to@example.com"));
            message.setSubject("Test Subject");
            message.setText("Test Body");
            
            Transport.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        // ok: java-hardcoded-secrets-in-comments
        // SSH connection using key from secure storage
        try {
            JSch jsch = new JSch();
            String privateKeyPath = "/path/to/private/key";
            String passphrase = getPassphraseFromSecureStore();
            jsch.addIdentity(privateKeyPath, passphrase);
            com.jcraft.jsch.Session session = jsch.getSession("username", "hostname", 22);
            session.connect();
        } catch (JSchException e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try {
            // ok: java-hardcoded-secrets-in-comments
            // OAuth authentication with client secret from environment
            String authUrl = "https://oauth.example.com/token";
            String clientId = "my-client-id";
            String clientSecret = System.getenv("OAUTH_CLIENT_SECRET");
            
            // OAuth authentication logic would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        // ok: java-hardcoded-secrets-in-comments
        // MongoDB connection using URI from environment variable
        try {
            String connectionString = System.getenv("MONGODB_URI");
            // MongoDB connection logic would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            // ok: java-hardcoded-secrets-in-comments
            // JWT verification with signing key from secure storage
            String jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
            String signingKey = loadSigningKeyFromSecureStorage();
            
            // JWT verification logic would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        // ok: java-hardcoded-secrets-in-comments
        // Firebase initialization with config from environment variables
        try {
            // Firebase initialization logic would go here using environment variables
            String apiKey = System.getenv("FIREBASE_API_KEY");
            String authDomain = System.getenv("FIREBASE_AUTH_DOMAIN");
            String databaseUrl = System.getenv("FIREBASE_DATABASE_URL");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try {
            // ok: java-hardcoded-secrets-in-comments
            // Stripe API integration with key from environment variable
            String apiKey = System.getenv("STRIPE_API_KEY");
            
            // Stripe API call logic would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        // ok: java-hardcoded-secrets-in-comments
        // Secure encryption using salt from secure storage
        try {
            String password = "userPassword";
            String salt = getSaltFromSecureStorage();
            
            TextEncryptor encryptor = Encryptors.text(password, salt);
            String encrypted = encryptor.encrypt("sensitive data");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try {
            // ok: java-hardcoded-secrets-in-comments
            // Redis connection with password from environment variable
            String redisHost = "localhost";
            int redisPort = 6379;
            String redisPassword = System.getenv("REDIS_PASSWORD");
            
            // Redis connection logic would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        // ok: java-hardcoded-secrets-in-comments
        // FTP connection using credentials from environment variables
        try {
            String ftpHost = "ftp.example.com";
            String ftpUser = System.getenv("FTP_USER");
            String ftpPassword = System.getenv("FTP_PASSWORD");
            
            // FTP connection logic would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Helper methods (implementations not shown for brevity)
    private String getPasswordFromSecureStore() {
        // Implementation to retrieve password from a secure credential store
        return "securely-retrieved-password";
    }
    
    private String loadKeyFromSecureStorage() {
        // Implementation to load encryption key from secure storage
        return "securely-loaded-key";
    }
    
    private String getPassphraseFromSecureStore() {
        // Implementation to retrieve SSH key passphrase from secure storage
        return "securely-retrieved-passphrase";
    }
    
    private String loadSigningKeyFromSecureStorage() {
        // Implementation to load JWT signing key from secure storage
        return "securely-loaded-signing-key";
    }
    
    private String getSaltFromSecureStorage() {
        // Implementation to retrieve encryption salt from secure storage
        return "securely-retrieved-salt";
    }
}
// {/fact}