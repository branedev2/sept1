import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.auth.AuthScope;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.Message;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session as JschSession;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Base64;
import java.util.Map;
import java.util.HashMap;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;

public class HardcodedSecretsExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = "admin";
            String password = "P@ssw0rd123!";
            
            Connection connection = DriverManager.getConnection(url, username, password);
            System.out.println("Database connected successfully");
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String apiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
            
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + apiKey);
            
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://api.stripe.com/v1/customers");
            request.addHeader("Authorization", "Bearer " + apiKey);
            httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String accessKey = "AKIAIOSFODNN7EXAMPLE";
            String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
            
            BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKey, secretKey);
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                                .withRegion("us-west-2")
                                .build();
            
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String mongoUri = "mongodb+srv://adminuser:SuperSecretP@ssw0rd@cluster0.mongodb.net/test";
            
            MongoClient mongoClient = new MongoClient(new MongoClientURI(mongoUri));
            System.out.println("MongoDB connected successfully");
            mongoClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String smtpUsername = "user@example.com";
            String smtpPassword = "myEmailP@ssword!123";
            
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");
            props.put("mail.smtp.starttls.enable", "true");
            
            Session session = Session.getInstance(props);
            Transport transport = session.getTransport("smtp");
            transport.connect(props.getProperty("mail.smtp.host"), smtpUsername, smtpPassword);
            
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(smtpUsername));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("recipient@example.com"));
            message.setSubject("Test Email");
            message.setText("This is a test email.");
            
            Transport.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String sshHost = "example.com";
            String sshUser = "admin";
            String sshPassword = "sshSecretP@ss123!";
            
            JSch jsch = new JSch();
            JschSession session = jsch.getSession(sshUser, sshHost, 22);
            session.setPassword(sshPassword);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            System.out.println("SSH connection established");
            session.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String tenantId = "8b6a7c3d-1234-5678-9abc-def012345678";
            String clientId = "1a2b3c4d-5e6f-7g8h-9i0j-1k2l3m4n5o6p";
            String clientSecret = "Q~abcdefghijklmnopqrstuvwxyz123456789ABCDEF";
            
            ClientSecretCredential credential = new ClientSecretCredentialBuilder()
                .tenantId(tenantId)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();
                
            // Use the credential to authenticate with Azure services
            System.out.println("Azure credential created successfully");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String encryptionKey = "1234567890abcdef";
            String textToEncrypt = "Sensitive information";
            
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(textToEncrypt.getBytes());
            
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            System.out.println("Encrypted text: " + encryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String apiEndpoint = "https://api.example.com/data";
            String username = "apiuser";
            String password = "ApiP@ssw0rd!";
            
            CredentialsProvider provider = new BasicCredentialsProvider();
            UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(username, password);
            provider.setCredentials(AuthScope.ANY, credentials);
            
            CloseableHttpClient client = HttpClients.custom()
                .setDefaultCredentialsProvider(provider)
                .build();
                
            HttpGet request = new HttpGet(apiEndpoint);
            client.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String jwtSecret = "mySuperSecretJwtSigningKey12345!@#$%";
            
            Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
            String jwt = Jwts.builder()
                .setSubject("user123")
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
                
            System.out.println("Generated JWT: " + jwt);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String redisPassword = "Redis@123Password!";
            
            // Connect to Redis with authentication
            String redisUrl = "redis://:" + redisPassword + "@localhost:6379/0";
            System.out.println("Connecting to Redis with URL: " + redisUrl);
            
            // Simulating Redis connection with the password
            System.out.println("Redis connection established with authentication");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String oauthClientId = "my-client-id-12345";
            String oauthClientSecret = "oauth2-client-secret-very-secure-token";
            
            // Using OAuth client credentials to get access token
            String tokenEndpoint = "https://auth.example.com/oauth/token";
            String authHeader = "Basic " + Base64.getEncoder().encodeToString(
                (oauthClientId + ":" + oauthClientSecret).getBytes(StandardCharsets.UTF_8));
            
            HttpGet request = new HttpGet(tokenEndpoint);
            request.setHeader("Authorization", authHeader);
            
            CloseableHttpClient httpClient = HttpClients.createDefault();
            httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String privateKeyContent = "-----BEGIN PRIVATE KEY-----\n" +
                "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n" +
                "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n" +
                "NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n" +
                "-----END PRIVATE KEY-----";
            
            // Using the private key for signing
            System.out.println("Using private key with length: " + privateKeyContent.length());
            
            // Simulating signing operation with the private key
            String signature = "simulated-signature-using-private-key";
            System.out.println("Generated signature: " + signature);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String elasticsearchUsername = "elastic";
            String elasticsearchPassword = "changeme123!";
            
            // Connect to Elasticsearch with basic authentication
            String elasticsearchUrl = "https://localhost:9200";
            String authHeader = "Basic " + Base64.getEncoder().encodeToString(
                (elasticsearchUsername + ":" + elasticsearchPassword).getBytes(StandardCharsets.UTF_8));
            
            HttpGet request = new HttpGet(elasticsearchUrl);
            request.setHeader("Authorization", authHeader);
            
            CloseableHttpClient httpClient = HttpClients.createDefault();
            httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String ftpUsername = "ftpuser";
            String ftpPassword = "Ftp@P@ssw0rd!";
            
            // Connect to FTP server with credentials
            String ftpHost = "ftp.example.com";
            int ftpPort = 21;
            
            System.out.println("Connecting to FTP server: " + ftpHost + ":" + ftpPort);
            System.out.println("Using credentials - Username: " + ftpUsername + ", Password: " + ftpPassword);
            
            // Simulating FTP connection
            System.out.println("FTP connection established successfully");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = System.getenv("DB_USERNAME");
            String password = System.getenv("DB_PASSWORD");
            
            Connection connection = DriverManager.getConnection(url, username, password);
            System.out.println("Database connected successfully");
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String apiKey = System.getenv("STRIPE_API_KEY");
            
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://api.stripe.com/v1/customers");
            request.addHeader("Authorization", "Bearer " + apiKey);
            httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String accessKey = System.getenv("AWS_AC_REDACTED_TWILIO_ID_KEY");
            String secretKey = System.getenv("AWS_SECRET_KEY");
            
            BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKey, secretKey);
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                                .withRegion("us-west-2")
                                .build();
            
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String username = System.getenv("MONGO_USERNAME");
            String password = System.getenv("MONGO_PASSWORD");
            String host = System.getenv("MONGO_HOST");
            
            String mongoUri = String.format("mongodb+srv://%s:%s@%s/test", username, password, host);
            
            MongoClient mongoClient = new MongoClient(new MongoClientURI(mongoUri));
            System.out.println("MongoDB connected successfully");
            mongoClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String smtpUsername = System.getenv("SMTP_USERNAME");
            String smtpPassword = System.getenv("SMTP_PASSWORD");
            
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");
            props.put("mail.smtp.starttls.enable", "true");
            
            Session session = Session.getInstance(props);
            Transport transport = session.getTransport("smtp");
            transport.connect(props.getProperty("mail.smtp.host"), smtpUsername, smtpPassword);
            
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(smtpUsername));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("recipient@example.com"));
            message.setSubject("Test Email");
            message.setText("This is a test email.");
            
            Transport.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String sshHost = System.getenv("SSH_HOST");
            String sshUser = System.getenv("SSH_USER");
            String sshPassword = System.getenv("SSH_PASSWORD");
            
            JSch jsch = new JSch();
            JschSession session = jsch.getSession(sshUser, sshHost, 22);
            session.setPassword(sshPassword);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            System.out.println("SSH connection established");
            session.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String tenantId = System.getenv("AZURE_TENANT_ID");
            String clientId = System.getenv("AZURE_CLIENT_ID");
            String clientSecret = System.getenv("AZURE_CLIENT_SECRET");
            
            ClientSecretCredential credential = new ClientSecretCredentialBuilder()
                .tenantId(tenantId)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();
                
            // Use the credential to authenticate with Azure services
            System.out.println("Azure credential created successfully");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String encryptionKey = System.getenv("ENCRYPTION_KEY");
            String textToEncrypt = "Sensitive information";
            
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(textToEncrypt.getBytes());
            
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            System.out.println("Encrypted text: " + encryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String apiEndpoint = "https://api.example.com/data";
            String username = System.getenv("API_USERNAME");
            String password = System.getenv("API_PASSWORD");
            
            CredentialsProvider provider = new BasicCredentialsProvider();
            UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(username, password);
            provider.setCredentials(AuthScope.ANY, credentials);
            
            CloseableHttpClient client = HttpClients.custom()
                .setDefaultCredentialsProvider(provider)
                .build();
                
            HttpGet request = new HttpGet(apiEndpoint);
            client.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String jwtSecret = System.getenv("JWT_SECRET_KEY");
            
            Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
            String jwt = Jwts.builder()
                .setSubject("user123")
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
                
            System.out.println("Generated JWT: " + jwt);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            Properties props = new Properties();
            FileInputStream fis = new FileInputStream("config.properties");
            props.load(fis);
            fis.close();
            
            String dbUrl = props.getProperty("db.url");
            String dbUser = props.getProperty("db.user");
            String dbPassword = props.getProperty("db.password");
            
            Connection connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword);
            System.out.println("Database connected successfully using properties file");
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            // Reading credentials from a secure vault or service
            String redisPassword = getSecretFromVault("redis-password");
            
            // Connect to Redis with authentication
            String redisUrl = "redis://:" + redisPassword + "@localhost:6379/0";
            System.out.println("Connecting to Redis with secure password from vault");
            
            // Simulating Redis connection with the password
            System.out.println("Redis connection established with authentication");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String getSecretFromVault(String secretName) {
        // This would be implemented to retrieve secrets from a secure vault
        // For example, HashiCorp Vault, AWS Secrets Manager, etc.
        System.out.println("Retrieving secret: " + secretName + " from secure vault");
        return System.getenv(secretName.toUpperCase().replace("-", "_"));
    }

    public void good_case_13() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            // Reading private key from a file that's properly secured with file permissions
            byte[] keyBytes = Files.readAllBytes(Paths.get("/secure/path/to/private.key"));
            String privateKeyContent = new String(keyBytes, StandardCharsets.UTF_8);
            
            // Using the private key for signing
            System.out.println("Using private key loaded from secure file");
            
            // Simulating signing operation with the private key
            String signature = "simulated-signature-using-private-key";
            System.out.println("Generated signature: " + signature);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            // Using a secure credential provider
            Map<String, String> secretsMap = getCredentialsFromSecureStore();
            
            String elasticsearchUsername = secretsMap.get("es_username");
            String elasticsearchPassword = secretsMap.get("es_password");
            
            // Connect to Elasticsearch with basic authentication
            String elasticsearchUrl = "https://localhost:9200";
            String authHeader = "Basic " + Base64.getEncoder().encodeToString(
                (elasticsearchUsername + ":" + elasticsearchPassword).getBytes(StandardCharsets.UTF_8));
            
            HttpGet request = new HttpGet(elasticsearchUrl);
            request.setHeader("Authorization", authHeader);
            
            CloseableHttpClient httpClient = HttpClients.createDefault();
            httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Map<String, String> getCredentialsFromSecureStore() {
        // This would be implemented to retrieve credentials from a secure credential store
        Map<String, String> credentials = new HashMap<>();
        credentials.put("es_username", System.getenv("ES_USERNAME"));
        credentials.put("es_password", System.getenv("ES_PASSWORD"));
        return credentials;
    }

    public void good_case_15() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            // Using system properties that are set at runtime
            String ftpUsername = System.getProperty("ftp.username", System.getenv("FTP_USERNAME"));
            String ftpPassword = System.getProperty("ftp.password", System.getenv("FTP_PASSWORD"));
            
            // Connect to FTP server with credentials
            String ftpHost = System.getProperty("ftp.host", "ftp.example.com");
            int ftpPort = Integer.parseInt(System.getProperty("ftp.port", "21"));
            
            System.out.println("Connecting to FTP server: " + ftpHost + ":" + ftpPort);
            System.out.println("Using credentials from system properties or environment variables");
            
            // Simulating FTP connection
            System.out.println("FTP connection established successfully");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}