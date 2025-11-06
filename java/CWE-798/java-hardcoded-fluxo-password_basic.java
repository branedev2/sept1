import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3Client;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.io.File;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session as JschSession;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;
import io.github.cdimascio.dotenv.Dotenv;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;

public class HardcodedCredentialsExamples {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        try {
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = "admin";
            // ruleid: java-hardcoded-fluxo-password
            String password = "s3cr3tP@ssw0rd";
            Connection connection = DriverManager.getConnection(url, username, password);
            System.out.println("Database connected successfully");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_2() {
        try {
            // ruleid: java-hardcoded-fluxo-password
            AWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
            AmazonS3Client s3Client = new AmazonS3Client(credentials);
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_3() {
        try {
            // ruleid: java-hardcoded-fluxo-password
            String mongoUri = "mongodb://dbuser:dbpassword123@mongodb0.example.com:27017/admin";
            MongoClient mongoClient = new MongoClient(new MongoClientURI(mongoUri));
            System.out.println("MongoDB connected successfully");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_4() {
        try {
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");
            
            Session session = Session.getInstance(props, new javax.mail.Authenticator() {
                protected javax.mail.PasswordAuthentication getPasswordAuthentication() {
                    // ruleid: java-hardcoded-fluxo-password
                    return new javax.mail.PasswordAuthentication("company@gmail.com", "emailP@ssw0rd!");
                }
            });
            
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress("from@example.com"));
            message.setRecipients(MimeMessage.RecipientType.TO, InternetAddress.parse("to@example.com"));
            message.setSubject("Test Subject");
            message.setText("Test Email Body");
            
            Transport.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_5() {
        try {
            JSch jsch = new JSch();
            JschSession session = jsch.getSession("sshuser", "remote-server.com", 22);
            // ruleid: java-hardcoded-fluxo-password
            session.setPassword("sshP@ssw0rd123");
            session.connect();
            System.out.println("SSH connection established");
        } catch (JSchException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_6() {
        try {
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                .url("https://api.example.com/data")
                .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ")
                // ruleid: java-hardcoded-fluxo-password
                .header("X-API-Key", "api_key_12345abcdef")
                .build();
            
            Response response = client.newCall(request).execute();
            System.out.println(response.body().string());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_7() {
        try {
            // ruleid: java-hardcoded-fluxo-password
            String encryptionKey = "ThisIsAHardcodedEncryptionKey123!";
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            
            String dataToEncrypt = "Sensitive information";
            byte[] encryptedData = cipher.doFinal(dataToEncrypt.getBytes());
            System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encryptedData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_8() {
        try {
            // ruleid: java-hardcoded-fluxo-password
            TextEncryptor encryptor = Encryptors.text("encryptionPassword", "5c0744940b5c369b");
            String encryptedText = encryptor.encrypt("sensitive data");
            System.out.println("Encrypted: " + encryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_9() {
        try {
            String filePath = "/secure/protected-file.txt";
            // ruleid: java-hardcoded-fluxo-password
            String filePassword = "file-access-password-123";
            
            // Simulating a password-protected file access
            if (authenticateFileAccess(filePath, filePassword)) {
                String content = new String(Files.readAllBytes(Paths.get(filePath)));
                System.out.println("File content: " + content);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    private boolean authenticateFileAccess(String path, String password) {
        // Simulated authentication
        return password != null && !password.isEmpty();
    }
    
    public void bad_case_10() {
        try {
            Properties connectionProps = new Properties();
            connectionProps.put("user", "oracle_user");
            // ruleid: java-hardcoded-fluxo-password
            connectionProps.put("password", "0r@cl3P@ssw0rd");
            
            Connection conn = DriverManager.getConnection(
                "jdbc:oracle:thin:@localhost:1521:orcl", 
                connectionProps);
            System.out.println("Oracle DB connected");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_11() {
        try {
            // ruleid: java-hardcoded-fluxo-password
            String redisPassword = "Redis-Server-Pass-2023";
            
            // Simulating Redis connection with password
            JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost", 6379, 2000, redisPassword);
            try (Jedis jedis = pool.getResource()) {
                jedis.set("test", "value");
                String value = jedis.get("test");
                System.out.println("Retrieved value: " + value);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_12() {
        try {
            // Simulating FTP connection
            FTPClient ftpClient = new FTPClient();
            ftpClient.connect("ftp.example.com");
            // ruleid: java-hardcoded-fluxo-password
            boolean success = ftpClient.login("ftpuser", "ftpP@ssw0rd");
            
            if (success) {
                System.out.println("FTP login successful");
                ftpClient.logout();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_13() {
        try {
            // Simulating LDAP authentication
            Hashtable<String, Object> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://ldap.example.com:389");
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, "cn=Directory Manager");
            // ruleid: java-hardcoded-fluxo-password
            env.put(Context.SECURITY_CREDENTIALS, "ldap@dmin123");
            
            DirContext ctx = new InitialDirContext(env);
            System.out.println("LDAP connection successful");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_14() {
        try {
            // Simulating Elasticsearch client
            // ruleid: java-hardcoded-fluxo-password
            final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            credentialsProvider.setCredentials(AuthScope.ANY,
                    new UsernamePasswordCredentials("elastic", "elastic_password_2023"));
            
            RestClient restClient = RestClient.builder(new HttpHost("localhost", 9200))
                    .setHttpClientConfigCallback(httpClientBuilder -> httpClientBuilder
                            .setDefaultCredentialsProvider(credentialsProvider))
                    .build();
            
            System.out.println("Elasticsearch client created");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_15() {
        try {
            // Simulating Kafka connection with SASL
            Properties props = new Properties();
            props.put("bootstrap.servers", "kafka:9092");
            props.put("security.protocol", "SASL_PLAINTEXT");
            props.put("sasl.mechanism", "PLAIN");
            // ruleid: java-hardcoded-fluxo-password
            props.put("sasl.jaas.config", 
                "org.apache.kafka.common.security.plain.PlainLoginModule required " +
                "username=\"kafka_user\" " +
                "password=\"kafka_secret_123\";");
            
            KafkaProducer<String, String> producer = new KafkaProducer<>(props);
            System.out.println("Kafka producer created");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // True Negative Examples (Secure Code)
    
    public void good_case_1() {
        try {
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = System.getenv("DB_USERNAME");
            // ok: java-hardcoded-fluxo-password
            String password = System.getenv("DB_PASSWORD");
            Connection connection = DriverManager.getConnection(url, username, password);
            System.out.println("Database connected successfully");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_2() {
        try {
            // ok: java-hardcoded-fluxo-password
            String accessKey = System.getenv("AWS_AC_REDACTED_TWILIO_ID_KEY_ID");
            String secretKey = System.getenv("AWS_SECRET_AC_REDACTED_TWILIO_ID_KEY");
            AWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);
            AmazonS3Client s3Client = new AmazonS3Client(credentials);
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_3() {
        try {
            String username = System.getenv("MONGO_USERNAME");
            // ok: java-hardcoded-fluxo-password
            String password = System.getenv("MONGO_PASSWORD");
            String mongoUri = String.format("mongodb://%s:%s@mongodb0.example.com:27017/admin", 
                                           username, password);
            MongoClient mongoClient = new MongoClient(new MongoClientURI(mongoUri));
            System.out.println("MongoDB connected successfully");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_4() {
        try {
            final String username = System.getenv("EMAIL_USERNAME");
            // ok: java-hardcoded-fluxo-password
            final String password = System.getenv("EMAIL_PASSWORD");
            
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");
            
            Session session = Session.getInstance(props, new javax.mail.Authenticator() {
                protected javax.mail.PasswordAuthentication getPasswordAuthentication() {
                    return new javax.mail.PasswordAuthentication(username, password);
                }
            });
            
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress("from@example.com"));
            message.setRecipients(MimeMessage.RecipientType.TO, InternetAddress.parse("to@example.com"));
            message.setSubject("Test Subject");
            message.setText("Test Email Body");
            
            Transport.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_5() {
        try {
            JSch jsch = new JSch();
            JschSession session = jsch.getSession("sshuser", "remote-server.com", 22);
            // ok: java-hardcoded-fluxo-password
            session.setPassword(System.getenv("SSH_PASSWORD"));
            session.connect();
            System.out.println("SSH connection established");
        } catch (JSchException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_6() {
        try {
            // ok: java-hardcoded-fluxo-password
            String apiKey = System.getenv("API_KEY");
            
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                .url("https://api.example.com/data")
                .header("Authorization", "Bearer " + apiKey)
                .build();
            
            Response response = client.newCall(request).execute();
            System.out.println(response.body().string());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_7() {
        try {
            // ok: java-hardcoded-fluxo-password
            String encryptionKey = System.getenv("ENCRYPTION_KEY");
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            
            String dataToEncrypt = "Sensitive information";
            byte[] encryptedData = cipher.doFinal(dataToEncrypt.getBytes());
            System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encryptedData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_8() {
        try {
            // Using a vault to retrieve secrets
            VaultTemplate vaultTemplate = new VaultTemplate();
            // ok: java-hardcoded-fluxo-password
            VaultResponse response = vaultTemplate.read("secret/encryption-keys");
            String password = (String) response.getData().get("password");
            String salt = (String) response.getData().get("salt");
            
            TextEncryptor encryptor = Encryptors.text(password, salt);
            String encryptedText = encryptor.encrypt("sensitive data");
            System.out.println("Encrypted: " + encryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_9() {
        try {
            String filePath = "/secure/protected-file.txt";
            // ok: java-hardcoded-fluxo-password
            String filePassword = loadPasswordFromSecureStorage("file-access");
            
            // Simulating a password-protected file access
            if (authenticateFileAccess(filePath, filePassword)) {
                String content = new String(Files.readAllBytes(Paths.get(filePath)));
                System.out.println("File content: " + content);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    private String loadPasswordFromSecureStorage(String key) {
        // Simulated secure password retrieval
        return System.getenv(key.toUpperCase() + "_PASSWORD");
    }
    
    public void good_case_10() {
        try {
            Properties connectionProps = new Properties();
            connectionProps.put("user", System.getenv("ORAC_REDACTED_TWILIO_ID_USER"));
            // ok: java-hardcoded-fluxo-password
            connectionProps.put("password", System.getenv("ORAC_REDACTED_TWILIO_ID_PASSWORD"));
            
            Connection conn = DriverManager.getConnection(
                "jdbc:oracle:thin:@localhost:1521:orcl", 
                connectionProps);
            System.out.println("Oracle DB connected");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_11() {
        try {
            // Loading configuration from properties file
            Properties properties = new Properties();
            FileInputStream fis = new FileInputStream("config.properties");
            properties.load(fis);
            
            // ok: java-hardcoded-fluxo-password
            String redisPassword = properties.getProperty("redis.password");
            
            // Simulating Redis connection with password
            JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost", 6379, 2000, redisPassword);
            try (Jedis jedis = pool.getResource()) {
                jedis.set("test", "value");
                String value = jedis.get("test");
                System.out.println("Retrieved value: " + value);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_12() {
        try {
            // Using dotenv to load environment variables from .env file
            Dotenv dotenv = Dotenv.load();
            
            // Simulating FTP connection
            FTPClient ftpClient = new FTPClient();
            ftpClient.connect("ftp.example.com");
            // ok: java-hardcoded-fluxo-password
            boolean success = ftpClient.login(dotenv.get("FTP_USER"), dotenv.get("FTP_PASSWORD"));
            
            if (success) {
                System.out.println("FTP login successful");
                ftpClient.logout();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_13() {
        try {
            // Using Apache Commons Configuration to load properties
            Configuration config = new PropertiesConfiguration("ldap.properties");
            
            // Simulating LDAP authentication
            Hashtable<String, Object> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, config.getString("ldap.url"));
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, config.getString("ldap.principal"));
            // ok: java-hardcoded-fluxo-password
            env.put(Context.SECURITY_CREDENTIALS, config.getString("ldap.credentials"));
            
            DirContext ctx = new InitialDirContext(env);
            System.out.println("LDAP connection successful");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_14() {
        try {
            // Using a credential provider that loads from a secure source
            // ok: java-hardcoded-fluxo-password
            final CredentialsProvider credentialsProvider = new SystemPropertyCredentialsProvider();
            
            RestClient restClient = RestClient.builder(new HttpHost("localhost", 9200))
                    .setHttpClientConfigCallback(httpClientBuilder -> httpClientBuilder
                            .setDefaultCredentialsProvider(credentialsProvider))
                    .build();
            
            System.out.println("Elasticsearch client created");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_15() {
        try {
            // Loading Kafka credentials from environment variables
            String username = System.getenv("KAFKA_USERNAME");
            // ok: java-hardcoded-fluxo-password
            String password = System.getenv("KAFKA_PASSWORD");
            
            Properties props = new Properties();
            props.put("bootstrap.servers", "kafka:9092");
            props.put("security.protocol", "SASL_PLAINTEXT");
            props.put("sasl.mechanism", "PLAIN");
            props.put("sasl.jaas.config", 
                "org.apache.kafka.common.security.plain.PlainLoginModule required " +
                "username=\"" + username + "\" " +
                "password=\"" + password + "\";");
            
            KafkaProducer<String, String> producer = new KafkaProducer<>(props);
            System.out.println("Kafka producer created");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Helper classes for simulation purposes
    private static class JedisPool {
        public JedisPool(Object config, String host, int port, int timeout, String password) {}
        public Jedis getResource() { return new Jedis(); }
    }
    
    private static class Jedis implements AutoCloseable {
        public void set(String key, String value) {}
        public String get(String key) { return "value"; }
        public void close() {}
    }
    
    private static class JedisPoolConfig {}
    
    private static class FTPClient {
        public void connect(String host) {}
        public boolean login(String user, String password) { return true; }
        public void logout() {}
    }
    
    private static class SystemPropertyCredentialsProvider implements CredentialsProvider {
        public void setCredentials(AuthScope scope, Credentials credentials) {}
        public Credentials getCredentials(AuthScope scope) { 
            return new UsernamePasswordCredentials(System.getProperty("es.username"), 
                                                 System.getProperty("es.password")); 
        }
        public void clear() {}
    }
    
    private static class AuthScope {
        public static final AuthScope ANY = new AuthScope();
    }
    
    private static class Credentials {}
    
    private static class UsernamePasswordCredentials extends Credentials {
        public UsernamePasswordCredentials(String username, String password) {}
    }
    
    private static class KafkaProducer<K, V> {
        public KafkaProducer(Properties props) {}
    }
    
    private interface Context {
        String INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID = "java.naming.factory.initial";
        String PROVIDER_URL = "java.naming.provider.url";
        String SECURITY_AUTHENTICATION = "java.naming.security.authentication";
        String SECURITY_PRINCIPAL = "java.naming.security.principal";
        String SECURITY_CREDENTIALS = "java.naming.security.credentials";
    }
    
    private interface DirContext {}
    
    private static class InitialDirContext implements DirContext {
        public InitialDirContext(Hashtable<String, Object> env) {}
    }
}
// {/fact}