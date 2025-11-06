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
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.DriveScopes;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.sendgrid.SendGrid;
import com.sendgrid.Request;
import com.sendgrid.Response;
import com.sendgrid.Method;
import com.stripe.Stripe;
import com.stripe.model.Customer;
import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.settings.Settings;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import redis.clients.jedis.Jedis;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import okhttp3.OkHttpClient;
import okhttp3.Request.Builder;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import com.rabbitmq.client.ConnectionFactory;
import org.apache.commons.net.ftp.FTPClient;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.social.twitter.api.impl.TwitterTemplate;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.apis.TwitterApi;
import org.apache.commons.mail.SimpleEmail;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
import java.net.URI;

// Security Issue: Hardcoded credentials in source code

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    // JDBC connection with hardcoded credentials
    try {
        // ruleid: java-hardcoded-secrets-library-ide
        Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb", "admin", "Password123!");
        // Use connection...
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_2() {
    // AWS SDK with hardcoded credentials
    // ruleid: java-hardcoded-secrets-library-ide
    BasicAWSCredentials awsCreds = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                          .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                          .withRegion("us-west-2")
                          .build();
}

public void bad_case_3() {
    // MongoDB connection with hardcoded credentials
    // ruleid: java-hardcoded-secrets-library-ide
    MongoClientURI uri = new MongoClientURI("mongodb://dbuser:dbpassword@localhost:27017/database");
    MongoClient mongoClient = new MongoClient(uri);
    // Use MongoDB client...
}

public void bad_case_4() {
    // SendGrid API with hardcoded key
    // ruleid: java-hardcoded-secrets-library-ide
    SendGrid sendGrid = new SendGrid("SG.REDAC_REDACTED_TWILIO_ID_SENDGRID_KEY.1234567890abcdefghijklmnopqrstuvwxyz");
    try {
        Request request = new Request();
        request.setMethod(Method.POST);
        request.setEndpoint("mail/send");
        // Set request body...
        Response response = sendGrid.api(request);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    // Stripe API with hardcoded key
    // ruleid: java-hardcoded-secrets-library-ide
    Stripe.apiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
    try {
        Customer customer = Customer.create(null);
        // Use customer...
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    // Twilio API with hardcoded credentials
    // ruleid: java-hardcoded-secrets-library-ide
    Twilio.init("AC_REDACTED_TWILIO_ID", "a1234567890abcdef1234567890abcde");
    Message message = Message.creator(
            new com.twilio.type.PhoneNumber("+15558675309"),
            new com.twilio.type.PhoneNumber("+15551234567"),
            "Hello from Twilio!")
        .create();
}

public void bad_case_7() {
    // JWT signing with hardcoded secret
    // ruleid: java-hardcoded-secrets-library-ide
    String jwtToken = Jwts.builder()
        .setSubject("user123")
        .signWith(SignatureAlgorithm.HS256, "mysupersecretkey12345678901234567890")
        .compact();
}

public void bad_case_8() {
    // Azure Blob Storage with hardcoded connection string
    // ruleid: java-hardcoded-secrets-library-ide
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
        .connectionString("DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;EndpointSuffix=core.windows.net")
        .buildClient();
}

public void bad_case_9() {
    // Google Drive API with hardcoded client secrets
    try {
        HttpTransport httpTransport = null; // Initialize properly in real code
        JsonFactory jsonFactory = null; // Initialize properly in real code
        
        // ruleid: java-hardcoded-secrets-library-ide
        GoogleCredential credential = new GoogleCredential.Builder()
            .setTransport(httpTransport)
            .setJsonFactory(jsonFactory)
            .setClientSecrets("client_id_value", "client_secret_value")
            .build();
            
        Drive service = new Drive.Builder(httpTransport, jsonFactory, credential)
            .setApplicationName("MyApp")
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10() {
    // Redis connection with hardcoded password
    // ruleid: java-hardcoded-secrets-library-ide
    Jedis jedis = new Jedis("localhost", 6379);
    jedis.auth("myRedisPassword123");
    // Use jedis...
    jedis.close();
}

public void bad_case_11() {
    // Elasticsearch client with hardcoded credentials
    // ruleid: java-hardcoded-secrets-library-ide
    RestHighLevelClient client = new RestHighLevelClient(
        RestClient.builder(
            new HttpHost("localhost", 9200, "http"))
            .setHttpClientConfigCallback(httpClientBuilder -> 
                httpClientBuilder.setDefaultCredentialsProvider(provider -> {
                    provider.setCredentials(
                        AuthScope.ANY,
                        new UsernamePasswordCredentials("elastic", "changeme")
                    );
                    return httpClientBuilder;
                })
            )
    );
}

public void bad_case_12() {
    // Spring Security encryption with hardcoded password and salt
    // ruleid: java-hardcoded-secrets-library-ide
    TextEncryptor encryptor = Encryptors.text("password", "5c0744940b5c369b");
    String encryptedText = encryptor.encrypt("sensitive data");
}

public void bad_case_13() {
    // FTP client with hardcoded credentials
    FTPClient ftpClient = new FTPClient();
    try {
        ftpClient.connect("ftp.example.com");
        // ruleid: java-hardcoded-secrets-library-ide
        boolean success = ftpClient.login("ftpuser", "ftppassword");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_14() {
    // SSH connection with hardcoded credentials using JSch
    try {
        JSch jsch = new JSch();
        Session session = jsch.getSession("sshuser", "ssh.example.com", 22);
        // ruleid: java-hardcoded-secrets-library-ide
        session.setPassword("sshpassword");
        session.setConfig("StrictHostKeyChecking", "no");
        session.connect();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15() {
    // Twitter API with hardcoded credentials
    // ruleid: java-hardcoded-secrets-library-ide
    TwitterTemplate twitter = new TwitterTemplate("consumerKey", "consumerSecret", "accessToken", "accessTokenSecret");
    // Use twitter client...
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    // JDBC connection with credentials from environment variables
    try {
        String dbUser = System.getenv("DB_USER");
        String dbPassword = System.getenv("DB_PASSWORD");
        // ok: java-hardcoded-secrets-library-ide
        Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb", dbUser, dbPassword);
        // Use connection...
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    // AWS SDK with credentials from environment variables
    String accessKey = System.getenv("AWS_AC_REDACTED_TWILIO_ID_KEY");
    String secretKey = System.getenv("AWS_SECRET_KEY");
    // ok: java-hardcoded-secrets-library-ide
    BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKey, secretKey);
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                          .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                          .withRegion("us-west-2")
                          .build();
}

public void good_case_3() {
    // MongoDB connection with credentials from properties file
    try {
        Properties props = new Properties();
        props.load(new FileInputStream("config.properties"));
        String username = props.getProperty("mongodb.user");
        String password = props.getProperty("mongodb.password");
        // ok: java-hardcoded-secrets-library-ide
        MongoClientURI uri = new MongoClientURI("mongodb://" + username + ":" + password + "@localhost:27017/database");
        MongoClient mongoClient = new MongoClient(uri);
        // Use MongoDB client...
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_4() {
    // SendGrid API with key from environment variable
    String apiKey = System.getenv("SENDGRID_API_KEY");
    // ok: java-hardcoded-secrets-library-ide
    SendGrid sendGrid = new SendGrid(apiKey);
    try {
        Request request = new Request();
        request.setMethod(Method.POST);
        request.setEndpoint("mail/send");
        // Set request body...
        Response response = sendGrid.api(request);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    // Stripe API with key from environment variable
    String apiKey = System.getenv("STRIPE_API_KEY");
    // ok: java-hardcoded-secrets-library-ide
    Stripe.apiKey = apiKey;
    try {
        Customer customer = Customer.create(null);
        // Use customer...
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6() {
    // Twilio API with credentials from environment variables
    String accountSid = System.getenv("TWILIO_AC_REDACTED_TWILIO_ID_SID");
    String authToken = System.getenv("TWILIO_AUTH_TOKEN");
    // ok: java-hardcoded-secrets-library-ide
    Twilio.init(accountSid, authToken);
    Message message = Message.creator(
            new com.twilio.type.PhoneNumber("+15558675309"),
            new com.twilio.type.PhoneNumber("+15551234567"),
            "Hello from Twilio!")
        .create();
}

public void good_case_7() {
    // JWT signing with secret from environment variable
    String jwtSecret = System.getenv("JWT_SECRET_KEY");
    // ok: java-hardcoded-secrets-library-ide
    String jwtToken = Jwts.builder()
        .setSubject("user123")
        .signWith(SignatureAlgorithm.HS256, jwtSecret)
        .compact();
}

public void good_case_8() {
    // Azure Blob Storage with connection string from environment variable
    String connectionString = System.getenv("AZURE_STORAGE_CONNECTION_STRING");
    // ok: java-hardcoded-secrets-library-ide
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
        .connectionString(connectionString)
        .buildClient();
}

public void good_case_9() {
    // Google Drive API with client secrets from environment variables
    try {
        HttpTransport httpTransport = null; // Initialize properly in real code
        JsonFactory jsonFactory = null; // Initialize properly in real code
        
        String clientId = System.getenv("GOOGLE_CLIENT_ID");
        String clientSecret = System.getenv("GOOGLE_CLIENT_SECRET");
        
        // ok: java-hardcoded-secrets-library-ide
        GoogleCredential credential = new GoogleCredential.Builder()
            .setTransport(httpTransport)
            .setJsonFactory(jsonFactory)
            .setClientSecrets(clientId, clientSecret)
            .build();
            
        Drive service = new Drive.Builder(httpTransport, jsonFactory, credential)
            .setApplicationName("MyApp")
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10() {
    // Redis connection with password from environment variable
    String redisPassword = System.getenv("REDIS_PASSWORD");
    Jedis jedis = new Jedis("localhost", 6379);
    // ok: java-hardcoded-secrets-library-ide
    jedis.auth(redisPassword);
    // Use jedis...
    jedis.close();
}

public void good_case_11() {
    // Elasticsearch client with credentials from environment variables
    String username = System.getenv("ES_USERNAME");
    String password = System.getenv("ES_PASSWORD");
    
    // ok: java-hardcoded-secrets-library-ide
    RestHighLevelClient client = new RestHighLevelClient(
        RestClient.builder(
            new HttpHost("localhost", 9200, "http"))
            .setHttpClientConfigCallback(httpClientBuilder -> 
                httpClientBuilder.setDefaultCredentialsProvider(provider -> {
                    provider.setCredentials(
                        AuthScope.ANY,
                        new UsernamePasswordCredentials(username, password)
                    );
                    return httpClientBuilder;
                })
            )
    );
}

public void good_case_12() {
    // Spring Security encryption with password and salt from environment variables
    String password = System.getenv("ENCRYPTION_PASSWORD");
    String salt = System.getenv("ENCRYPTION_SALT");
    // ok: java-hardcoded-secrets-library-ide
    TextEncryptor encryptor = Encryptors.text(password, salt);
    String encryptedText = encryptor.encrypt("sensitive data");
}

public void good_case_13() {
    // FTP client with credentials from environment variables
    FTPClient ftpClient = new FTPClient();
    try {
        ftpClient.connect("ftp.example.com");
        String username = System.getenv("FTP_USERNAME");
        String password = System.getenv("FTP_PASSWORD");
        // ok: java-hardcoded-secrets-library-ide
        boolean success = ftpClient.login(username, password);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_14() {
    // SSH connection with credentials from environment variables using JSch
    try {
        JSch jsch = new JSch();
        Session session = jsch.getSession("sshuser", "ssh.example.com", 22);
        String password = System.getenv("SSH_PASSWORD");
        // ok: java-hardcoded-secrets-library-ide
        session.setPassword(password);
        session.setConfig("StrictHostKeyChecking", "no");
        session.connect();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15() {
    // Twitter API with credentials from environment variables
    String consumerKey = System.getenv("TWITTER_CONSUMER_KEY");
    String consumerSecret = System.getenv("TWITTER_CONSUMER_SECRET");
    String accessToken = System.getenv("TWITTER_AC_REDACTED_TWILIO_ID_TOKEN");
    String accessTokenSecret = System.getenv("TWITTER_AC_REDACTED_TWILIO_ID_TOKEN_SECRET");
    
    // ok: java-hardcoded-secrets-library-ide
    TwitterTemplate twitter = new TwitterTemplate(consumerKey, consumerSecret, accessToken, accessTokenSecret);
    // Use twitter client...
}