import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.Message;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session as JSchSession;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;
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
            String password = "Password123!";
            
            Connection connection = DriverManager.getConnection(url, username, password);
            System.out.println("Database connected successfully");
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String apiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
            
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("Authorization", "Bearer " + apiKey);
            
            HttpEntity<String> request = new HttpEntity<>("{\"amount\": 1000, \"currency\": \"usd\"}", headers);
            restTemplate.postForObject("https://api.stripe.com/v1/charges", request, String.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        // ruleid: java-hardcoded-secrets-basic-ide
        BasicAWSCredentials awsCredentials = new BasicAWSCredentials(
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCredentials))
                .withRegion("us-west-2")
                .build();
        
        s3Client.listBuckets();
    }

    public void bad_case_4() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String connectionString = "mongodb://admin:mongodb123@localhost:27017/admin";
            MongoClientURI uri = new MongoClientURI(connectionString);
            MongoClient mongoClient = new MongoClient(uri);
            
            System.out.println("Connected to MongoDB");
            mongoClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String storageConnectionString = "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY==;EndpointSuffix=core.windows.net";
            
            BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                    .connectionString(storageConnectionString)
                    .buildClient();
            
            blobServiceClient.listBlobContainers();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");
            
            Session session = Session.getInstance(props, new javax.mail.Authenticator() {
                protected javax.mail.PasswordAuthentication getPasswordAuthentication() {
                    return new javax.mail.PasswordAuthentication("user@gmail.com", "gmailP@ssw0rd");
                }
            });
            
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("from@gmail.com"));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("to@gmail.com"));
            message.setSubject("Test Email");
            message.setText("This is a test email.");
            
            Transport.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            JSch jsch = new JSch();
            JSchSession session = jsch.getSession("root", "192.168.1.1", 22);
            session.setPassword("r00tP@ssw0rd!");
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            System.out.println("Connected to SSH server");
            session.disconnect();
        } catch (JSchException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String key = "ThisIsA32ByteKeyForAES1234567890"; // 32 bytes for AES-256
            String dataToEncrypt = "Sensitive data";
            
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            
            byte[] encryptedData = cipher.doFinal(dataToEncrypt.getBytes());
            String encryptedText = Base64.getEncoder().encodeToString(encryptedData);
            System.out.println("Encrypted: " + encryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        // ruleid: java-hardcoded-secrets-basic-ide
        String githubToken = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";
        
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "token " + githubToken);
        headers.set("Accept", "application/vnd.github.v3+json");
        
        HttpEntity<String> request = new HttpEntity<>(headers);
        restTemplate.exchange("https://api.github.com/user/repos", org.springframework.http.HttpMethod.GET, request, String.class);
    }

    public void bad_case_10() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String url = "jdbc:postgresql://localhost:5432/mydb";
            String user = "postgres";
            String password = "P0stgr3SQL!";
            
            Properties props = new Properties();
            props.setProperty("user", user);
            props.setProperty("password", password);
            
            Connection conn = DriverManager.getConnection(url, props);
            System.out.println("Connected to PostgreSQL database");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String twilioAccountSid = "AC_REDACTED_TWILIO_ID";
            String twilioAuthToken = "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p";
            
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            String auth = twilioAccountSid + ":" + twilioAuthToken;
            String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
            headers.set("Authorization", "Basic " + encodedAuth);
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            HttpEntity<String> request = new HttpEntity<>("Body=Hello&To=%2B15551234567&From=%2B15557654321", headers);
            restTemplate.postForObject("https://api.twilio.com/2010-04-01/Accounts/" + twilioAccountSid + "/Messages.json", 
                    request, String.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String slackWebhookUrl = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";
            
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            String jsonPayload = "{\"text\":\"Hello from Java application!\"}";
            HttpEntity<String> request = new HttpEntity<>(jsonPayload, headers);
            
            restTemplate.postForObject(slackWebhookUrl, request, String.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String jwtSecret = "verySecretKeyThatShouldBeAtLeast32Chars";
            
            // Simulating JWT token creation
            String header = Base64.getEncoder().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
            String payload = Base64.getEncoder().encodeToString("{\"sub\":\"1234567890\",\"name\":\"John Doe\"}".getBytes());
            
            SecretKeySpec secretKey = new SecretKeySpec(jwtSecret.getBytes(), "HmacSHA256");
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(secretKey);
            
            String signature = Base64.getEncoder().encodeToString(
                    mac.doFinal((header + "." + payload).getBytes()));
            
            String jwtToken = header + "." + payload + "." + signature;
            System.out.println("JWT Token: " + jwtToken);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String ftpUsername = "ftpuser";
            String ftpPassword = "ftpP@ssw0rd!";
            
            org.apache.commons.net.ftp.FTPClient ftpClient = new org.apache.commons.net.ftp.FTPClient();
            ftpClient.connect("ftp.example.com");
            boolean loggedIn = ftpClient.login(ftpUsername, ftpPassword);
            
            if (loggedIn) {
                System.out.println("FTP login successful");
                ftpClient.logout();
            }
            ftpClient.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String redisHost = "localhost";
            int redisPort = 6379;
            String redisPassword = "r3d1sP@ssw0rd";
            
            redis.clients.jedis.Jedis jedis = new redis.clients.jedis.Jedis(redisHost, redisPort);
            jedis.auth(redisPassword);
            
            jedis.set("key", "value");
            System.out.println("Value from Redis: " + jedis.get("key"));
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
            System.out.println("Database connected successfully");
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            // Load API key from environment variable
            String apiKey = System.getenv("STRIPE_API_KEY");
            
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            // ok: java-hardcoded-secrets-basic-ide
            headers.set("Authorization", "Bearer " + apiKey);
            
            HttpEntity<String> request = new HttpEntity<>("{\"amount\": 1000, \"currency\": \"usd\"}", headers);
            restTemplate.postForObject("https://api.stripe.com/v1/charges", request, String.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        String accessKey = System.getenv("AWS_AC_REDACTED_TWILIO_ID_KEY_ID");
        String secretKey = System.getenv("AWS_SECRET_AC_REDACTED_TWILIO_ID_KEY");
        
        // ok: java-hardcoded-secrets-basic-ide
        BasicAWSCredentials awsCredentials = new BasicAWSCredentials(accessKey, secretKey);
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCredentials))
                .withRegion("us-west-2")
                .build();
        
        s3Client.listBuckets();
    }

    public void good_case_4() {
        try {
            String username = System.getenv("MONGO_USERNAME");
            String password = System.getenv("MONGO_PASSWORD");
            String host = System.getenv("MONGO_HOST");
            
            // ok: java-hardcoded-secrets-basic-ide
            String connectionString = String.format("mongodb://%s:%s@%s:27017/admin", username, password, host);
            
            MongoClientURI uri = new MongoClientURI(connectionString);
            MongoClient mongoClient = new MongoClient(uri);
            
            System.out.println("Connected to MongoDB");
            mongoClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            // ok: java-hardcoded-secrets-basic-ide
            String storageConnectionString = System.getenv("AZURE_STORAGE_CONNECTION_STRING");
            
            BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                    .connectionString(storageConnectionString)
                    .buildClient();
            
            blobServiceClient.listBlobContainers();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            final String username = System.getenv("SMTP_USERNAME");
            final String password = System.getenv("SMTP_PASSWORD");
            
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");
            
            // ok: java-hardcoded-secrets-basic-ide
            Session session = Session.getInstance(props, new javax.mail.Authenticator() {
                protected javax.mail.PasswordAuthentication getPasswordAuthentication() {
                    return new javax.mail.PasswordAuthentication(username, password);
                }
            });
            
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("from@gmail.com"));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("to@gmail.com"));
            message.setSubject("Test Email");
            message.setText("This is a test email.");
            
            Transport.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            String sshUser = System.getenv("SSH_USERNAME");
            String sshPassword = System.getenv("SSH_PASSWORD");
            String sshHost = System.getenv("SSH_HOST");
            
            JSch jsch = new JSch();
            JSchSession session = jsch.getSession(sshUser, sshHost, 22);
            
            // ok: java-hardcoded-secrets-basic-ide
            session.setPassword(sshPassword);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            
            System.out.println("Connected to SSH server");
            session.disconnect();
        } catch (JSchException e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try {
            // ok: java-hardcoded-secrets-basic-ide
            String key = System.getenv("ENCRYPTION_KEY");
            String dataToEncrypt = "Sensitive data";
            
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            
            byte[] encryptedData = cipher.doFinal(dataToEncrypt.getBytes());
            String encryptedText = Base64.getEncoder().encodeToString(encryptedData);
            System.out.println("Encrypted: " + encryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        // Load GitHub token from environment variable
        String githubToken = System.getenv("GITHUB_TOKEN");
        
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        
        // ok: java-hardcoded-secrets-basic-ide
        headers.set("Authorization", "token " + githubToken);
        headers.set("Accept", "application/vnd.github.v3+json");
        
        HttpEntity<String> request = new HttpEntity<>(headers);
        restTemplate.exchange("https://api.github.com/user/repos", org.springframework.http.HttpMethod.GET, request, String.class);
    }

    public void good_case_10() {
        try {
            String url = "jdbc:postgresql://localhost:5432/mydb";
            
            // Load credentials from properties file
            Properties configProps = new Properties();
            configProps.load(new FileInputStream("config.properties"));
            
            String user = configProps.getProperty("db.user");
            String password = configProps.getProperty("db.password");
            
            Properties connProps = new Properties();
            connProps.setProperty("user", user);
            
            // ok: java-hardcoded-secrets-basic-ide
            connProps.setProperty("password", password);
            
            Connection conn = DriverManager.getConnection(url, connProps);
            System.out.println("Connected to PostgreSQL database");
            conn.close();
        } catch (SQLException | IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            // Load Twilio credentials from environment variables
            String twilioAccountSid = System.getenv("TWILIO_AC_REDACTED_TWILIO_ID_SID");
            String twilioAuthToken = System.getenv("TWILIO_AUTH_TOKEN");
            
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            
            // ok: java-hardcoded-secrets-basic-ide
            String auth = twilioAccountSid + ":" + twilioAuthToken;
            String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
            headers.set("Authorization", "Basic " + encodedAuth);
            
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            HttpEntity<String> request = new HttpEntity<>("Body=Hello&To=%2B15551234567&From=%2B15557654321", headers);
            restTemplate.postForObject("https://api.twilio.com/2010-04-01/Accounts/" + twilioAccountSid + "/Messages.json", 
                    request, String.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try {
            // ok: java-hardcoded-secrets-basic-ide
            String slackWebhookUrl = System.getenv("SLAC_REDACTED_TWILIO_ID_WEBHOOK_URL");
            
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            String jsonPayload = "{\"text\":\"Hello from Java application!\"}";
            HttpEntity<String> request = new HttpEntity<>(jsonPayload, headers);
            
            restTemplate.postForObject(slackWebhookUrl, request, String.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            // ok: java-hardcoded-secrets-basic-ide
            String jwtSecret = new String(Files.readAllBytes(Paths.get("/secure/path/jwt_secret.key")));
            
            // Simulating JWT token creation
            String header = Base64.getEncoder().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
            String payload = Base64.getEncoder().encodeToString("{\"sub\":\"1234567890\",\"name\":\"John Doe\"}".getBytes());
            
            SecretKeySpec secretKey = new SecretKeySpec(jwtSecret.getBytes(), "HmacSHA256");
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(secretKey);
            
            String signature = Base64.getEncoder().encodeToString(
                    mac.doFinal((header + "." + payload).getBytes()));
            
            String jwtToken = header + "." + payload + "." + signature;
            System.out.println("JWT Token: " + jwtToken);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try {
            // Load FTP credentials from environment variables
            String ftpUsername = System.getenv("FTP_USERNAME");
            String ftpPassword = System.getenv("FTP_PASSWORD");
            String ftpHost = System.getenv("FTP_HOST");
            
            org.apache.commons.net.ftp.FTPClient ftpClient = new org.apache.commons.net.ftp.FTPClient();
            ftpClient.connect(ftpHost);
            
            // ok: java-hardcoded-secrets-basic-ide
            boolean loggedIn = ftpClient.login(ftpUsername, ftpPassword);
            
            if (loggedIn) {
                System.out.println("FTP login successful");
                ftpClient.logout();
            }
            ftpClient.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        try {
            // Load Redis credentials from environment variables
            String redisHost = System.getenv("REDIS_HOST");
            int redisPort = Integer.parseInt(System.getenv("REDIS_PORT"));
            String redisPassword = System.getenv("REDIS_PASSWORD");
            
            redis.clients.jedis.Jedis jedis = new redis.clients.jedis.Jedis(redisHost, redisPort);
            
            // ok: java-hardcoded-secrets-basic-ide
            jedis.auth(redisPassword);
            
            jedis.set("key", "value");
            System.out.println("Value from Redis: " + jedis.get("key"));
            jedis.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}