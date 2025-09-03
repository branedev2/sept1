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
import org.apache.http.HttpResponse;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.nio.file.Files;
import java.nio.file.Paths;

public class HardcodedCredentialsExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = "admin";
            String password = "SuperSecretP@ssw0rd123";
            
            Connection connection = DriverManager.getConnection(url, username, password);
            System.out.println("Database connected!");
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String apiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
            String url = "https://api.stripe.com/v1/charges";
            
            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet request = new HttpGet(url);
            request.addHeader("Authorization", "Bearer " + apiKey);
            HttpResponse response = client.execute(request);
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        // ruleid: java-hardcoded-secrets-basic-ide
        String accessKey = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        
        BasicAWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .withRegion("us-west-2")
                .build();
        
        s3Client.listBuckets();
    }

    public void bad_case_4() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String encryptionKey = "1234567890abcdef";
            String dataToEncrypt = "Sensitive information";
            
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(dataToEncrypt.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String mongoUri = "mongodb://admin:mongodb123@localhost:27017/admin";
            MongoClientURI uri = new MongoClientURI(mongoUri);
            MongoClient mongoClient = new MongoClient(uri);
            System.out.println("MongoDB connected!");
            mongoClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String tenantId = "11111111-1111-1111-1111-111111111111";
            String clientId = "22222222-2222-2222-2222-222222222222";
            String clientSecret = "Q~secretAzureKeyValue8dKasdjfhkaKJHDSF";
            
            ClientSecretCredential credential = new ClientSecretCredentialBuilder()
                .tenantId(tenantId)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");
            
            String username = "myemail@gmail.com";
            String password = "gmailAppPassword123!";
            
            Session session = Session.getInstance(props);
            Transport transport = session.getTransport("smtp");
            transport.connect(username, password);
            transport.close();
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            JSch jsch = new JSch();
            String host = "example.com";
            String user = "sshuser";
            String password = "ssh-password-123!";
            
            com.jcraft.jsch.Session session = jsch.getSession(user, host, 22);
            session.setPassword(password);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            session.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String oauthToken = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
            String url = "https://api.github.com/user/repos";
            
            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet request = new HttpGet(url);
            request.addHeader("Authorization", "token " + oauthToken);
            HttpResponse response = client.execute(request);
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String url = "jdbc:postgresql://localhost:5432/mydb";
            String username = "postgres";
            String password = "postgres_admin_pwd!";
            
            Connection connection = DriverManager.getConnection(url, username, password);
            System.out.println("PostgreSQL connected!");
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String apiEndpoint = "https://api.twilio.com/2010-04-01/Accounts";
            String accountSid = "AC_REDACTED_TWILIO_ID";
            String authToken = "ef01234567890abcd";
            
            String auth = accountSid + ":" + authToken;
            String encodedAuth = java.util.Base64.getEncoder().encodeToString(auth.getBytes());
            
            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet request = new HttpGet(apiEndpoint);
            request.addHeader("Authorization", "Basic " + encodedAuth);
            HttpResponse response = client.execute(request);
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String jwtSecret = "jwt_super_secret_key_for_signing_tokens_123456789";
            String subject = "user123";
            
            String token = io.jsonwebtoken.Jwts.builder()
                .setSubject(subject)
                .signWith(io.jsonwebtoken.SignatureAlgorithm.HS256, jwtSecret.getBytes())
                .compact();
            
            System.out.println("Generated JWT: " + token);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String privateKeyContent = "-----BEGIN PRIVATE KEY-----\n" +
                "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n" +
                "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n" +
                "NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n" +
                "-----END PRIVATE KEY-----";
            
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
            java.security.spec.PKCS8EncodedKeySpec keySpecPKCS8 = new java.security.spec.PKCS8EncodedKeySpec(
                    java.util.Base64.getDecoder().decode(privateKeyContent.replace("-----BEGIN PRIVATE KEY-----", "")
                            .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "")));
            java.security.PrivateKey privateKey = kf.generatePrivate(keySpecPKCS8);
            
            System.out.println("Private key loaded: " + privateKey.getAlgorithm());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String url = "sftp://example.com";
            String username = "ftpuser";
            String password = "ftp_p@ssw0rd!";
            
            org.apache.commons.vfs2.FileSystemOptions opts = new org.apache.commons.vfs2.FileSystemOptions();
            org.apache.commons.vfs2.provider.sftp.SftpFileSystemConfigBuilder.getInstance().setUserDirIsRoot(opts, true);
            org.apache.commons.vfs2.provider.sftp.SftpFileSystemConfigBuilder.getInstance().setPassword(opts, password);
            
            org.apache.commons.vfs2.FileSystemManager fsManager = org.apache.commons.vfs2.VFS.getManager();
            org.apache.commons.vfs2.FileObject remoteFile = fsManager.resolveFile(
                    url + "/" + username, opts);
            
            System.out.println("Connected to SFTP server");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String redisHost = "localhost";
            int redisPort = 6379;
            String redisPassword = "redis_secure_password_123";
            
            redis.clients.jedis.Jedis jedis = new redis.clients.jedis.Jedis(redisHost, redisPort);
            jedis.auth(redisPassword);
            System.out.println("Connected to Redis");
            jedis.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        try {
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = System.getenv("DB_USERNAME");
            String password = System.getenv("DB_PASSWORD");
            
            // ok: java-hardcoded-secrets-basic-ide
            Connection connection = DriverManager.getConnection(url, username, password);
            System.out.println("Database connected!");
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            // Load API key from environment variable
            String apiKey = System.getenv("STRIPE_API_KEY");
            String url = "https://api.stripe.com/v1/charges";
            
            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet request = new HttpGet(url);
            // ok: java-hardcoded-secrets-basic-ide
            request.addHeader("Authorization", "Bearer " + apiKey);
            HttpResponse response = client.execute(request);
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        // Load AWS credentials from environment variables
        String accessKey = System.getenv("AWS_AC_REDACTED_TWILIO_ID_KEY");
        String secretKey = System.getenv("AWS_SECRET_KEY");
        
        // ok: java-hardcoded-secrets-basic-ide
        BasicAWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .withRegion("us-west-2")
                .build();
        
        s3Client.listBuckets();
    }

    public void good_case_4() {
        try {
            // Load encryption key from environment variable
            String encryptionKey = System.getenv("ENCRYPTION_KEY");
            String dataToEncrypt = "Sensitive information";
            
            // ok: java-hardcoded-secrets-basic-ide
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(dataToEncrypt.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            // Load MongoDB URI from environment variable
            String mongoUri = System.getenv("MONGODB_URI");
            
            // ok: java-hardcoded-secrets-basic-ide
            MongoClientURI uri = new MongoClientURI(mongoUri);
            MongoClient mongoClient = new MongoClient(uri);
            System.out.println("MongoDB connected!");
            mongoClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            // Load Azure credentials from environment variables
            String tenantId = System.getenv("AZURE_TENANT_ID");
            String clientId = System.getenv("AZURE_CLIENT_ID");
            String clientSecret = System.getenv("AZURE_CLIENT_SECRET");
            
            // ok: java-hardcoded-secrets-basic-ide
            ClientSecretCredential credential = new ClientSecretCredentialBuilder()
                .tenantId(tenantId)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");
            
            // Load email credentials from environment variables
            String username = System.getenv("EMAIL_USERNAME");
            String password = System.getenv("EMAIL_PASSWORD");
            
            Session session = Session.getInstance(props);
            Transport transport = session.getTransport("smtp");
            // ok: java-hardcoded-secrets-basic-ide
            transport.connect(username, password);
            transport.close();
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try {
            JSch jsch = new JSch();
            String host = "example.com";
            String user = System.getenv("SSH_USER");
            String password = System.getenv("SSH_PASSWORD");
            
            com.jcraft.jsch.Session session = jsch.getSession(user, host, 22);
            // ok: java-hardcoded-secrets-basic-ide
            session.setPassword(password);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            session.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            // Load GitHub token from environment variable
            String oauthToken = System.getenv("GITHUB_TOKEN");
            String url = "https://api.github.com/user/repos";
            
            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet request = new HttpGet(url);
            // ok: java-hardcoded-secrets-basic-ide
            request.addHeader("Authorization", "token " + oauthToken);
            HttpResponse response = client.execute(request);
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            // Load database credentials from properties file
            Properties props = new Properties();
            props.load(new FileInputStream("config.properties"));
            
            String url = props.getProperty("db.url");
            String username = props.getProperty("db.username");
            String password = props.getProperty("db.password");
            
            // ok: java-hardcoded-secrets-basic-ide
            Connection connection = DriverManager.getConnection(url, username, password);
            System.out.println("PostgreSQL connected!");
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            String apiEndpoint = "https://api.twilio.com/2010-04-01/Accounts";
            
            // Load Twilio credentials from environment variables
            String accountSid = System.getenv("TWILIO_AC_REDACTED_TWILIO_ID_SID");
            String authToken = System.getenv("TWILIO_AUTH_TOKEN");
            
            String auth = accountSid + ":" + authToken;
            String encodedAuth = java.util.Base64.getEncoder().encodeToString(auth.getBytes());
            
            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet request = new HttpGet(apiEndpoint);
            // ok: java-hardcoded-secrets-basic-ide
            request.addHeader("Authorization", "Basic " + encodedAuth);
            HttpResponse response = client.execute(request);
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try {
            // Load JWT secret from environment variable
            String jwtSecret = System.getenv("JWT_SECRET");
            String subject = "user123";
            
            // ok: java-hardcoded-secrets-basic-ide
            String token = io.jsonwebtoken.Jwts.builder()
                .setSubject(subject)
                .signWith(io.jsonwebtoken.SignatureAlgorithm.HS256, jwtSecret.getBytes())
                .compact();
            
            System.out.println("Generated JWT: " + token);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            // Load private key from file
            byte[] keyBytes = Files.readAllBytes(Paths.get("private_key.pem"));
            String privateKeyContent = new String(keyBytes);
            
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
            java.security.spec.PKCS8EncodedKeySpec keySpecPKCS8 = new java.security.spec.PKCS8EncodedKeySpec(
                    java.util.Base64.getDecoder().decode(privateKeyContent.replace("-----BEGIN PRIVATE KEY-----", "")
                            .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "")));
            // ok: java-hardcoded-secrets-basic-ide
            java.security.PrivateKey privateKey = kf.generatePrivate(keySpecPKCS8);
            
            System.out.println("Private key loaded: " + privateKey.getAlgorithm());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try {
            String url = "sftp://example.com";
            String username = System.getenv("FTP_USER");
            String password = System.getenv("FTP_PASSWORD");
            
            org.apache.commons.vfs2.FileSystemOptions opts = new org.apache.commons.vfs2.FileSystemOptions();
            org.apache.commons.vfs2.provider.sftp.SftpFileSystemConfigBuilder.getInstance().setUserDirIsRoot(opts, true);
            // ok: java-hardcoded-secrets-basic-ide
            org.apache.commons.vfs2.provider.sftp.SftpFileSystemConfigBuilder.getInstance().setPassword(opts, password);
            
            org.apache.commons.vfs2.FileSystemManager fsManager = org.apache.commons.vfs2.VFS.getManager();
            org.apache.commons.vfs2.FileObject remoteFile = fsManager.resolveFile(
                    url + "/" + username, opts);
            
            System.out.println("Connected to SFTP server");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        try {
            String redisHost = "localhost";
            int redisPort = 6379;
            // Load Redis password from environment variable
            String redisPassword = System.getenv("REDIS_PASSWORD");
            
            redis.clients.jedis.Jedis jedis = new redis.clients.jedis.Jedis(redisHost, redisPort);
            // ok: java-hardcoded-secrets-basic-ide
            jedis.auth(redisPassword);
            System.out.println("Connected to Redis");
            jedis.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}