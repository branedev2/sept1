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
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.sendgrid.SendGrid;
import com.sendgrid.Request;
import com.sendgrid.Response;
import com.sendgrid.Method;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.nio.file.Files;
import java.nio.file.Paths;

public class HardcodedSecretsExamples {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = "admin";
            String password = "Password123!";
            
            Connection conn = DriverManager.getConnection(url, username, password);
            System.out.println("Database connection established");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_2() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String apiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
            
            SendGrid sendGrid = new SendGrid(apiKey);
            Request request = new Request();
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody("{\"personalizations\":[{\"to\":[{\"email\":\"test@example.com\"}]}],\"from\":{\"email\":\"test@example.com\"},\"subject\":\"Test Email\",\"content\":[{\"type\":\"text/plain\",\"value\":\"Hello World\"}]}");
            Response response = sendGrid.api(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_3() {
        // ruleid: java-hardcoded-secrets-library-ide
        String accessKey = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        
        BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKey, secretKey);
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                            .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                            .withRegion("us-west-2")
                            .build();
        
        s3Client.listBuckets();
    }
    
    public void bad_case_4() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String connectionString = "mongodb+srv://dbadmin:SuperSecretP@ssw0rd@cluster0.mongodb.net/test";
            
            MongoClient mongoClient = new MongoClient(new MongoClientURI(connectionString));
            System.out.println("MongoDB connection established");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_5() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String connectionString = "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY==;EndpointSuffix=core.windows.net";
            
            BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                                                .connectionString(connectionString)
                                                .buildClient();
            System.out.println("Azure Blob storage connection established");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_6() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String smtpUsername = "AKIAXXX7XXXEXAMPLE";
            String smtpPassword = "BNp9N8aZYEXAMPLEKEY/EXAMPLEKEY/EXAMPLEKEY";
            
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.host", "email-smtp.us-west-2.amazonaws.com");
            props.put("mail.smtp.port", "587");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.user", smtpUsername);
            props.put("mail.smtp.password", smtpPassword);
            
            // Email sending code would go here
            System.out.println("SMTP connection configured");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_7() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String encryptionKey = "1234567890abcdef";
            String dataToEncrypt = "Sensitive information";
            
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(dataToEncrypt.getBytes());
            
            System.out.println("Data encrypted");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_8() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String sshHost = "example.com";
            String sshUsername = "admin";
            String sshPassword = "SuperSecretP@ssword123";
            
            JSch jsch = new JSch();
            Session session = jsch.getSession(sshUsername, sshHost, 22);
            session.setPassword(sshPassword);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            
            System.out.println("SSH connection established");
            session.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_9() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String authToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
            
            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://api.example.com/data");
            request.addHeader("Authorization", "Bearer " + authToken);
            
            client.execute(request);
            System.out.println("API request sent with authentication");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_10() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String ftpUsername = "ftpuser";
            String ftpPassword = "ftpP@ssw0rd!";
            
            // FTP connection code using Apache Commons Net
            org.apache.commons.net.ftp.FTPClient ftpClient = new org.apache.commons.net.ftp.FTPClient();
            ftpClient.connect("ftp.example.com");
            boolean loggedIn = ftpClient.login(ftpUsername, ftpPassword);
            
            if (loggedIn) {
                System.out.println("FTP connection established");
                ftpClient.disconnect();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_11() {
        // ruleid: java-hardcoded-secrets-library-ide
        String redisPassword = "R3d!$P@ssw0rd";
        
        // Redis connection using Jedis
        redis.clients.jedis.Jedis jedis = new redis.clients.jedis.Jedis("localhost");
        jedis.auth(redisPassword);
        System.out.println("Redis connection established");
        jedis.close();
    }
    
    public void bad_case_12() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String privateKeyContent = "-----BEGIN RSA PRIVATE KEY-----\n" +
                                      "MIIEpAIBAAKCAQEAxzYuc1RV+rcbAHmlJv6GcA...\n" +
                                      "-----END RSA PRIVATE KEY-----";
            
            // Using the private key for SSH connection
            JSch jsch = new JSch();
            jsch.addIdentity("key", privateKeyContent.getBytes(), null, null);
            Session session = jsch.getSession("user", "example.com", 22);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            
            System.out.println("SSH connection established with private key");
            session.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_13() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String oauthClientId = "client_id_123456";
            String oauthClientSecret = "client_secret_abcdef123456";
            
            // OAuth token request
            String tokenUrl = "https://oauth.example.com/token";
            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet request = new HttpGet(tokenUrl + 
                                         "?client_id=" + oauthClientId + 
                                         "&client_secret=" + oauthClientSecret + 
                                         "&grant_type=client_credentials");
            
            client.execute(request);
            System.out.println("OAuth token requested");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_14() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String elasticSearchUsername = "elastic";
            String elasticSearchPassword = "changeme123";
            
            // Elasticsearch connection
            org.elasticsearch.client.RestHighLevelClient client = new org.elasticsearch.client.RestHighLevelClient(
                org.elasticsearch.client.RestClient.builder(
                    new org.apache.http.HttpHost("localhost", 9200, "http")
                ).setHttpClientConfigCallback(httpClientBuilder -> {
                    httpClientBuilder.setDefaultCredentialsProvider(
                        new org.apache.http.impl.client.BasicCredentialsProvider() {{
                            setCredentials(
                                org.apache.http.auth.AuthScope.ANY,
                                new org.apache.http.auth.UsernamePasswordCredentials(
                                    elasticSearchUsername, elasticSearchPassword
                                )
                            );
                        }}
                    );
                    return httpClientBuilder;
                })
            );
            
            System.out.println("Elasticsearch connection established");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_15() {
        try {
            // ruleid: java-hardcoded-secrets-library-ide
            String rabbitMqUsername = "guest";
            String rabbitMqPassword = "guest123";
            
            // RabbitMQ connection
            com.rabbitmq.client.ConnectionFactory factory = new com.rabbitmq.client.ConnectionFactory();
            factory.setHost("localhost");
            factory.setUsername(rabbitMqUsername);
            factory.setPassword(rabbitMqPassword);
            com.rabbitmq.client.Connection connection = factory.newConnection();
            
            System.out.println("RabbitMQ connection established");
            connection.close();
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
            
            Connection conn = DriverManager.getConnection(url, username, password);
            System.out.println("Database connection established");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_2() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String apiKey = System.getenv("SENDGRID_API_KEY");
            
            SendGrid sendGrid = new SendGrid(apiKey);
            Request request = new Request();
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody("{\"personalizations\":[{\"to\":[{\"email\":\"test@example.com\"}]}],\"from\":{\"email\":\"test@example.com\"},\"subject\":\"Test Email\",\"content\":[{\"type\":\"text/plain\",\"value\":\"Hello World\"}]}");
            Response response = sendGrid.api(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_3() {
        // ok: java-hardcoded-secrets-library-ide
        String accessKey = System.getenv("AWS_AC_REDACTED_TWILIO_ID_KEY");
        String secretKey = System.getenv("AWS_SECRET_KEY");
        
        BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKey, secretKey);
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                            .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                            .withRegion("us-west-2")
                            .build();
        
        s3Client.listBuckets();
    }
    
    public void good_case_4() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String username = System.getenv("MONGO_USERNAME");
            String password = System.getenv("MONGO_PASSWORD");
            String host = System.getenv("MONGO_HOST");
            String connectionString = "mongodb+srv://" + username + ":" + password + "@" + host + "/test";
            
            MongoClient mongoClient = new MongoClient(new MongoClientURI(connectionString));
            System.out.println("MongoDB connection established");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_5() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String accountName = System.getenv("AZURE_STORAGE_AC_REDACTED_TWILIO_ID");
            String accountKey = System.getenv("AZURE_STORAGE_KEY");
            String connectionString = "DefaultEndpointsProtocol=https;AccountName=" + accountName + ";AccountKey=" + accountKey + ";EndpointSuffix=core.windows.net";
            
            BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                                                .connectionString(connectionString)
                                                .buildClient();
            System.out.println("Azure Blob storage connection established");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_6() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String smtpUsername = System.getenv("SMTP_USERNAME");
            String smtpPassword = System.getenv("SMTP_PASSWORD");
            
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.host", "email-smtp.us-west-2.amazonaws.com");
            props.put("mail.smtp.port", "587");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.user", smtpUsername);
            props.put("mail.smtp.password", smtpPassword);
            
            // Email sending code would go here
            System.out.println("SMTP connection configured");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_7() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String encryptionKey = System.getenv("ENCRYPTION_KEY");
            String dataToEncrypt = "Sensitive information";
            
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(dataToEncrypt.getBytes());
            
            System.out.println("Data encrypted");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_8() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String sshHost = "example.com";
            String sshUsername = System.getenv("SSH_USERNAME");
            String sshPassword = System.getenv("SSH_PASSWORD");
            
            JSch jsch = new JSch();
            Session session = jsch.getSession(sshUsername, sshHost, 22);
            session.setPassword(sshPassword);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            
            System.out.println("SSH connection established");
            session.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_9() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String authToken = System.getenv("API_AUTH_TOKEN");
            
            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://api.example.com/data");
            request.addHeader("Authorization", "Bearer " + authToken);
            
            client.execute(request);
            System.out.println("API request sent with authentication");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_10() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            Properties props = new Properties();
            props.load(new FileInputStream("config.properties"));
            
            String ftpUsername = props.getProperty("ftp.username");
            String ftpPassword = props.getProperty("ftp.password");
            
            // FTP connection code using Apache Commons Net
            org.apache.commons.net.ftp.FTPClient ftpClient = new org.apache.commons.net.ftp.FTPClient();
            ftpClient.connect("ftp.example.com");
            boolean loggedIn = ftpClient.login(ftpUsername, ftpPassword);
            
            if (loggedIn) {
                System.out.println("FTP connection established");
                ftpClient.disconnect();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_11() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String redisPassword = Files.readString(Paths.get("/run/secrets/redis_password")).trim();
            
            // Redis connection using Jedis
            redis.clients.jedis.Jedis jedis = new redis.clients.jedis.Jedis("localhost");
            jedis.auth(redisPassword);
            System.out.println("Redis connection established");
            jedis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_12() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String privateKeyPath = System.getenv("SSH_PRIVATE_KEY_PATH");
            
            // Using the private key for SSH connection
            JSch jsch = new JSch();
            jsch.addIdentity(privateKeyPath);
            Session session = jsch.getSession("user", "example.com", 22);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            
            System.out.println("SSH connection established with private key");
            session.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_13() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String oauthClientId = System.getenv("OAUTH_CLIENT_ID");
            String oauthClientSecret = System.getenv("OAUTH_CLIENT_SECRET");
            
            // OAuth token request
            String tokenUrl = "https://oauth.example.com/token";
            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet request = new HttpGet(tokenUrl + 
                                         "?client_id=" + oauthClientId + 
                                         "&client_secret=" + oauthClientSecret + 
                                         "&grant_type=client_credentials");
            
            client.execute(request);
            System.out.println("OAuth token requested");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_14() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            String elasticSearchUsername = System.getenv("ES_USERNAME");
            String elasticSearchPassword = System.getenv("ES_PASSWORD");
            
            // Elasticsearch connection
            org.elasticsearch.client.RestHighLevelClient client = new org.elasticsearch.client.RestHighLevelClient(
                org.elasticsearch.client.RestClient.builder(
                    new org.apache.http.HttpHost("localhost", 9200, "http")
                ).setHttpClientConfigCallback(httpClientBuilder -> {
                    httpClientBuilder.setDefaultCredentialsProvider(
                        new org.apache.http.impl.client.BasicCredentialsProvider() {{
                            setCredentials(
                                org.apache.http.auth.AuthScope.ANY,
                                new org.apache.http.auth.UsernamePasswordCredentials(
                                    elasticSearchUsername, elasticSearchPassword
                                )
                            );
                        }}
                    );
                    return httpClientBuilder;
                })
            );
            
            System.out.println("Elasticsearch connection established");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_15() {
        try {
            // ok: java-hardcoded-secrets-library-ide
            // Using a secrets manager service
            com.amazonaws.services.secretsmanager.AWSSecretsManager secretsManager = 
                com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder.standard()
                    .withRegion("us-west-2")
                    .build();
            
            com.amazonaws.services.secretsmanager.model.GetSecretValueRequest getSecretValueRequest = 
                new com.amazonaws.services.secretsmanager.model.GetSecretValueRequest()
                    .withSecretId("rabbitmq/credentials");
            
            com.amazonaws.services.secretsmanager.model.GetSecretValueResult getSecretValueResult = 
                secretsManager.getSecretValue(getSecretValueRequest);
            
            String secret = getSecretValueResult.getSecretString();
            // Parse JSON secret to get username and password
            // For simplicity, assuming secret is in format: {"username":"value","password":"value"}
            String rabbitMqUsername = secret.split("\"username\":\"")[1].split("\"")[0];
            String rabbitMqPassword = secret.split("\"password\":\"")[1].split("\"")[0];
            
            // RabbitMQ connection
            com.rabbitmq.client.ConnectionFactory factory = new com.rabbitmq.client.ConnectionFactory();
            factory.setHost("localhost");
            factory.setUsername(rabbitMqUsername);
            factory.setPassword(rabbitMqPassword);
            com.rabbitmq.client.Connection connection = factory.newConnection();
            
            System.out.println("RabbitMQ connection established");
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}