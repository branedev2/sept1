import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import javax.mail.Authenticator;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.mongodb.MongoClient;
import org.mongodb.MongoCredential;
import org.mongodb.ServerAddress;
import java.util.Arrays;

public class HardcodedSecretsTest {

    // True Positives (Vulnerable Code)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        try {
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = "admin";
            // ruleid: java-hardcodedsecrets
            String password = "P@ssw0rd123";
            Connection conn = DriverManager.getConnection(url, username, password);
            System.out.println("Database connection established");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // ruleid: java-hardcodedsecrets
            BasicAWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                    .withCredentials(new AWSStaticCredentialsProvider(credentials))
                    .withRegion("us-west-2")
                    .build();
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try {
            JSch jsch = new JSch();
            Session session = jsch.getSession("root", "192.168.1.1", 22);
            // ruleid: java-hardcodedsecrets
            session.setPassword("supersecretpassword");
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
        } catch (JSchException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            // ruleid: java-hardcodedsecrets
            String apiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url("https://api.stripe.com/v1/charges")
                    .addHeader("Authorization", "Bearer " + apiKey)
                    .build();
            Response response = client.newCall(request).execute();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try {
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");
            
            // ruleid: java-hardcodedsecrets
            Session session = Session.getInstance(props, new Authenticator() {
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication("user@gmail.com", "gmailP@ssw0rd!");
                }
            });
            
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress("from@example.com"));
            message.setRecipients(MimeMessage.RecipientType.TO, InternetAddress.parse("to@example.com"));
            message.setSubject("Test Email");
            message.setText("This is a test email");
            Transport.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            // ruleid: java-hardcodedsecrets
            String encryptionKey = "0123456789abcdef";
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        // MongoDB connection with hardcoded credentials
        // ruleid: java-hardcodedsecrets
        MongoCredential credential = MongoCredential.createCredential(
                "mongoAdmin", 
                "admin", 
                "sup3rS3cr3tP@ssw0rd".toCharArray());
        
        MongoClient mongoClient = new MongoClient(
                new ServerAddress("localhost", 27017), 
                Arrays.asList(credential));
        
        System.out.println("Connected to MongoDB");
    }

    public void bad_case_8() {
        try {
            Properties props = new Properties();
            props.setProperty("user", "postgres");
            // ruleid: java-hardcodedsecrets
            props.setProperty("password", "postgresP@ssw0rd");
            Connection conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/mydb", props);
            System.out.println("PostgreSQL connection established");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        try {
            // ruleid: java-hardcodedsecrets
            String oauthToken = "ya29.a0AfH6SMBx-CIZfKLHY2jvYL6vYZGHOHKhWnWMDjgOcSJOkH_sJ2ZwlvJkJYeqMW9C7IgdUz-9tJF67K";
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url("https://www.googleapis.com/drive/v3/files")
                    .addHeader("Authorization", "Bearer " + oauthToken)
                    .build();
            Response response = client.newCall(request).execute();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            // ruleid: java-hardcodedsecrets
            String ftpPassword = "ftpP@ssw0rd123";
            org.apache.commons.net.ftp.FTPClient ftpClient = new org.apache.commons.net.ftp.FTPClient();
            ftpClient.connect("ftp.example.com");
            ftpClient.login("ftpuser", ftpPassword);
            ftpClient.enterLocalPassiveMode();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            // ruleid: java-hardcodedsecrets
            String jwtSecret = "jwt_super_secret_key_for_signing_tokens_do_not_share";
            io.jsonwebtoken.Jwts.builder()
                .setSubject("user123")
                .signWith(io.jsonwebtoken.SignatureAlgorithm.HS256, jwtSecret.getBytes())
                .compact();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            // ruleid: java-hardcodedsecrets
            String redisPassword = "redis_secure_password_123";
            redis.clients.jedis.Jedis jedis = new redis.clients.jedis.Jedis("localhost");
            jedis.auth(redisPassword);
            jedis.set("key", "value");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            // ruleid: java-hardcodedsecrets
            String azureKey = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey123456789;EndpointSuffix=core.windows.net";
            com.azure.storage.blob.BlobServiceClient blobServiceClient = 
                new com.azure.storage.blob.BlobServiceClientBuilder()
                    .connectionString(azureKey)
                    .buildClient();
            blobServiceClient.listBlobContainers();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            // ruleid: java-hardcodedsecrets
            String githubToken = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                .url("https://api.github.com/user/repos")
                .addHeader("Authorization", "token " + githubToken)
                .build();
            Response response = client.newCall(request).execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            // ruleid: java-hardcodedsecrets
            String elasticPassword = "elastic_password_123!";
            org.elasticsearch.client.RestHighLevelClient client = new org.elasticsearch.client.RestHighLevelClient(
                org.elasticsearch.client.RestClient.builder(
                    new org.apache.http.HttpHost("localhost", 9200, "http")
                ).setHttpClientConfigCallback(httpClientBuilder -> 
                    httpClientBuilder.setDefaultCredentialsProvider(
                        new org.apache.http.impl.client.BasicCredentialsProvider() {{
                            setCredentials(
                                org.apache.http.auth.AuthScope.ANY,
                                new org.apache.http.auth.UsernamePasswordCredentials("elastic", elasticPassword)
                            );
                        }}
                    )
                )
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negatives (Secure Code)

    public void good_case_1() {
        try {
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = System.getenv("DB_USERNAME");
            // ok: java-hardcodedsecrets
            String password = System.getenv("DB_PASSWORD");
            Connection conn = DriverManager.getConnection(url, username, password);
            System.out.println("Database connection established");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            // ok: java-hardcodedsecrets
            String accessKey = System.getProperty("aws.accessKeyId");
            String secretKey = System.getProperty("aws.secretKey");
            BasicAWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                    .withCredentials(new AWSStaticCredentialsProvider(credentials))
                    .withRegion("us-west-2")
                    .build();
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        try {
            JSch jsch = new JSch();
            Session session = jsch.getSession("root", "192.168.1.1", 22);
            // ok: java-hardcodedsecrets
            session.setPassword(getPasswordFromSecureStore());
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
        } catch (JSchException e) {
            e.printStackTrace();
        }
    }

    private String getPasswordFromSecureStore() {
        // This would retrieve the password from a secure credential store
        return System.getenv("SSH_PASSWORD");
    }

    public void good_case_4() {
        try {
            // ok: java-hardcodedsecrets
            String apiKey = loadApiKeyFromVault("stripe");
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url("https://api.stripe.com/v1/charges")
                    .addHeader("Authorization", "Bearer " + apiKey)
                    .build();
            Response response = client.newCall(request).execute();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String loadApiKeyFromVault(String service) {
        // This would retrieve the API key from a secure vault like HashiCorp Vault
        return System.getenv(service.toUpperCase() + "_API_KEY");
    }

    public void good_case_5() {
        try {
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");
            
            final String username = System.getenv("EMAIL_USERNAME");
            final String password = System.getenv("EMAIL_PASSWORD");
            
            // ok: java-hardcodedsecrets
            Session session = Session.getInstance(props, new Authenticator() {
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(username, password);
                }
            });
            
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress("from@example.com"));
            message.setRecipients(MimeMessage.RecipientType.TO, InternetAddress.parse("to@example.com"));
            message.setSubject("Test Email");
            message.setText("This is a test email");
            Transport.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            // ok: java-hardcodedsecrets
            String encryptionKey = loadEncryptionKeyFromSecureStorage();
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal("Sensitive data".getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String loadEncryptionKeyFromSecureStorage() {
        // This would retrieve the encryption key from a secure storage
        return System.getenv("ENCRYPTION_KEY");
    }

    public void good_case_7() {
        // MongoDB connection with credentials from environment variables
        // ok: java-hardcodedsecrets
        String username = System.getenv("MONGO_USERNAME");
        String password = System.getenv("MONGO_PASSWORD");
        String database = System.getenv("MONGO_DATABASE");
        
        MongoCredential credential = MongoCredential.createCredential(
                username, 
                database, 
                password.toCharArray());
        
        MongoClient mongoClient = new MongoClient(
                new ServerAddress("localhost", 27017), 
                Arrays.asList(credential));
        
        System.out.println("Connected to MongoDB");
    }

    public void good_case_8() {
        try {
            Properties props = new Properties();
            props.setProperty("user", System.getenv("POSTGRES_USER"));
            // ok: java-hardcodedsecrets
            props.setProperty("password", System.getenv("POSTGRES_PASSWORD"));
            Connection conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/mydb", props);
            System.out.println("PostgreSQL connection established");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            // ok: java-hardcodedsecrets
            String oauthToken = retrieveTokenFromSecureStorage("google");
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url("https://www.googleapis.com/drive/v3/files")
                    .addHeader("Authorization", "Bearer " + oauthToken)
                    .build();
            Response response = client.newCall(request).execute();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String retrieveTokenFromSecureStorage(String service) {
        // This would retrieve the token from a secure token store
        return System.getenv(service.toUpperCase() + "_OAUTH_TOKEN");
    }

    public void good_case_10() {
        try {
            // ok: java-hardcodedsecrets
            String ftpPassword = getCredentialFromStore("ftp.password");
            org.apache.commons.net.ftp.FTPClient ftpClient = new org.apache.commons.net.ftp.FTPClient();
            ftpClient.connect("ftp.example.com");
            ftpClient.login("ftpuser", ftpPassword);
            ftpClient.enterLocalPassiveMode();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String getCredentialFromStore(String key) {
        // This would retrieve credentials from a secure credential store
        return System.getenv(key.toUpperCase().replace(".", "_"));
    }

    public void good_case_11() {
        try {
            // ok: java-hardcodedsecrets
            String jwtSecret = loadSecretFromKeyStore("jwt");
            io.jsonwebtoken.Jwts.builder()
                .setSubject("user123")
                .signWith(io.jsonwebtoken.SignatureAlgorithm.HS256, jwtSecret.getBytes())
                .compact();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String loadSecretFromKeyStore(String alias) {
        // This would load a secret from a secure key store
        return System.getenv(alias.toUpperCase() + "_SECRET");
    }

    public void good_case_12() {
        try {
            // ok: java-hardcodedsecrets
            String redisPassword = System.getProperty("redis.password");
            redis.clients.jedis.Jedis jedis = new redis.clients.jedis.Jedis("localhost");
            jedis.auth(redisPassword);
            jedis.set("key", "value");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            // ok: java-hardcodedsecrets
            String azureKey = loadConnectionStringFromSecureConfig("azure.storage");
            com.azure.storage.blob.BlobServiceClient blobServiceClient = 
                new com.azure.storage.blob.BlobServiceClientBuilder()
                    .connectionString(azureKey)
                    .buildClient();
            blobServiceClient.listBlobContainers();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String loadConnectionStringFromSecureConfig(String configKey) {
        // This would load a connection string from a secure configuration source
        return System.getenv(configKey.toUpperCase().replace(".", "_"));
    }

    public void good_case_14() {
        try {
            // ok: java-hardcodedsecrets
            String githubToken = getSecretFromEnvironment("GITHUB_TOKEN");
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                .url("https://api.github.com/user/repos")
                .addHeader("Authorization", "token " + githubToken)
                .build();
            Response response = client.newCall(request).execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String getSecretFromEnvironment(String key) {
        // Get secret from environment variable
        return System.getenv(key);
    }

    public void good_case_15() {
        try {
            // ok: java-hardcodedsecrets
            String elasticPassword = loadPasswordFromConfigFile("elastic.properties");
            org.elasticsearch.client.RestHighLevelClient client = new org.elasticsearch.client.RestHighLevelClient(
                org.elasticsearch.client.RestClient.builder(
                    new org.apache.http.HttpHost("localhost", 9200, "http")
                ).setHttpClientConfigCallback(httpClientBuilder -> 
                    httpClientBuilder.setDefaultCredentialsProvider(
                        new org.apache.http.impl.client.BasicCredentialsProvider() {{
                            setCredentials(
                                org.apache.http.auth.AuthScope.ANY,
                                new org.apache.http.auth.UsernamePasswordCredentials("elastic", elasticPassword)
                            );
                        }}
                    )
                )
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String loadPasswordFromConfigFile(String configFile) {
        // This would load a password from a secure configuration file
        Properties props = new Properties();
        try {
            props.load(new FileInputStream(new File(configFile)));
            return props.getProperty("password");
        } catch (IOException e) {
            return System.getenv("ELASTIC_PASSWORD");
        }
    }
}
// {/fact}