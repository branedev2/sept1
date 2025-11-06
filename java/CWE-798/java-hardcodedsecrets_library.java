import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.auth.AuthScope;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3Client;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.rabbitmq.client.ConnectionFactory;
import redis.clients.jedis.Jedis;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.KafkaProducer;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Credentials;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.apache.http.HttpHost;
import com.twilio.Twilio;
import com.sendgrid.SendGrid;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import java.io.File;
import java.io.FileOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;

// Security Issue: Hardcoded credentials in Java code

// True Positive Examples (Vulnerable/Insecure Code)

public class HardcodedCredentialsExamples {

    // True Positive Examples (Vulnerable/Insecure Code)
    
// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        // JDBC Database Connection with hardcoded credentials
        try {
            // ruleid: java-hardcodedsecrets
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb", "admin", "password123");
            
            // Use connection
            System.out.println("Database connected");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_2() {
        // Apache HttpClient with hardcoded basic auth
        CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        
        // ruleid: java-hardcodedsecrets
        credentialsProvider.setCredentials(
            new AuthScope("api.example.com", 443),
            new UsernamePasswordCredentials("apiuser", "secret_api_key")
        );
        
        HttpClient client = HttpClients.custom()
            .setDefaultCredentialsProvider(credentialsProvider)
            .build();
    }
    
    public void bad_case_3() {
        // AWS SDK with hardcoded credentials
        // ruleid: java-hardcodedsecrets
        AWSCredentials credentials = new BasicAWSCredentials(
            "AKIAIOSFODNN7EXAMPLE", 
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        
        AmazonS3Client s3Client = new AmazonS3Client(credentials);
        s3Client.listBuckets();
    }
    
    public void bad_case_4() {
        // MongoDB connection with hardcoded credentials in URI
        try {
            // ruleid: java-hardcodedsecrets
            MongoClientURI uri = new MongoClientURI(
                "mongodb://dbuser:dbpassword@mongodb.example.com:27017/database"
            );
            
            MongoClient mongoClient = new MongoClient(uri);
            System.out.println("MongoDB connected");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_5() {
        // RabbitMQ connection with hardcoded credentials
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("rabbitmq.example.com");
        
        // ruleid: java-hardcodedsecrets
        factory.setUsername("rabbit_user");
        // ruleid: java-hardcodedsecrets
        factory.setPassword("carrot123");
        
        try {
            com.rabbitmq.client.Connection connection = factory.newConnection();
            System.out.println("RabbitMQ connected");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_6() {
        // Redis connection with hardcoded credentials
        // ruleid: java-hardcodedsecrets
        Jedis jedis = new Jedis("redis.example.com", 6379);
        jedis.auth("redis_secret_password");
        
        System.out.println("Redis connected");
        jedis.close();
    }
    
    public void bad_case_7() {
        // Azure client credentials hardcoded
        // ruleid: java-hardcodedsecrets
        ClientSecretCredential clientSecretCredential = new ClientSecretCredentialBuilder()
            .tenantId("11111111-1111-1111-1111-111111111111")
            .clientId("22222222-2222-2222-2222-222222222222")
            .clientSecret("supersecretclientvalue")
            .build();
    }
    
    public void bad_case_8() {
        // Google API client with hardcoded credentials
        try {
            // ruleid: java-hardcodedsecrets
            GoogleCredential credential = new GoogleCredential.Builder()
                .setClientSecrets("client_id_value", "client_secret_value")
                .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_9() {
        // Kafka producer with hardcoded credentials
        Properties props = new Properties();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "kafka.example.com:9092");
        
        // ruleid: java-hardcodedsecrets
        props.put("sasl.jaas.config", 
            "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"kafka_user\" password=\"kafka_password\";");
        
        KafkaProducer<String, String> producer = new KafkaProducer<>(props);
    }
    
    public void bad_case_10() {
        // SSH connection with JSch and hardcoded credentials
        try {
            JSch jsch = new JSch();
            Session session = jsch.getSession("sshuser", "ssh.example.com", 22);
            
            // ruleid: java-hardcodedsecrets
            session.setPassword("ssh_password");
            
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_11() {
        // JWT token generation with hardcoded secret
        // ruleid: java-hardcodedsecrets
        String jwtSecret = "jwt_super_secret_key_do_not_share";
        
        String token = Jwts.builder()
            .setSubject("user123")
            .signWith(SignatureAlgorithm.HS512, jwtSecret)
            .compact();
    }
    
    public void bad_case_12() {
        // OkHttp client with hardcoded basic auth
        OkHttpClient client = new OkHttpClient();
        
        // ruleid: java-hardcodedsecrets
        String credentials = Credentials.basic("okhttp_user", "okhttp_password");
        
        Request request = new Request.Builder()
            .url("https://api.example.org/data")
            .header("Authorization", credentials)
            .build();
    }
    
    public void bad_case_13() {
        // Elasticsearch client with hardcoded credentials
        RestClientBuilder builder = RestClient.builder(
            new HttpHost("elasticsearch.example.com", 9200, "https"));
        
        // ruleid: java-hardcodedsecrets
        final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY,
            new UsernamePasswordCredentials("elastic", "changeme"));
        
        builder.setHttpClientConfigCallback(httpClientBuilder -> 
            httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider));
    }
    
    public void bad_case_14() {
        // Twilio API with hardcoded credentials
        // ruleid: java-hardcodedsecrets
        Twilio.init("AC_REDACTED_TWILIO_ID", "auth_token_here");
    }
    
    public void bad_case_15() {
        // SendGrid API with hardcoded key
        // ruleid: java-hardcodedsecrets
        SendGrid sendGrid = new SendGrid("SG.REDAC_REDACTED_TWILIO_ID_SENDGRID_KEY");
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    public void good_case_1() {
        // JDBC connection with credentials from properties file
        try {
            Properties props = new Properties();
            props.load(new FileInputStream("database.properties"));
            
            // ok: java-hardcodedsecrets
            Connection conn = DriverManager.getConnection(
                props.getProperty("db.url"),
                props.getProperty("db.user"),
                props.getProperty("db.password")
            );
            
            System.out.println("Database connected");
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_2() {
        // Apache HttpClient with credentials from environment variables
        CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        
        // ok: java-hardcodedsecrets
        credentialsProvider.setCredentials(
            new AuthScope("api.example.com", 443),
            new UsernamePasswordCredentials(
                System.getenv("API_USERNAME"),
                System.getenv("API_PASSWORD")
            )
        );
        
        HttpClient client = HttpClients.custom()
            .setDefaultCredentialsProvider(credentialsProvider)
            .build();
    }
    
    public void good_case_3() {
        // AWS SDK using default credential provider chain
        // ok: java-hardcodedsecrets
        AmazonS3Client s3Client = new AmazonS3Client();
        s3Client.listBuckets();
    }
    
    public void good_case_4() {
        // MongoDB connection with credentials from system properties
        try {
            String username = System.getProperty("mongodb.user");
            String password = System.getProperty("mongodb.password");
            String host = System.getProperty("mongodb.host", "localhost");
            
            // ok: java-hardcodedsecrets
            MongoClientURI uri = new MongoClientURI(
                "mongodb://" + username + ":" + password + "@" + host + ":27017/database"
            );
            
            MongoClient mongoClient = new MongoClient(uri);
            System.out.println("MongoDB connected");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_5() {
        // RabbitMQ connection with credentials from configuration
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("rabbitmq.example.com");
        
        try {
            Properties props = new Properties();
            props.load(new FileInputStream("rabbitmq.properties"));
            
            // ok: java-hardcodedsecrets
            factory.setUsername(props.getProperty("rabbitmq.user"));
            // ok: java-hardcodedsecrets
            factory.setPassword(props.getProperty("rabbitmq.password"));
            
            com.rabbitmq.client.Connection connection = factory.newConnection();
            System.out.println("RabbitMQ connected");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_6() {
        // Redis connection with credentials from environment
        // ok: java-hardcodedsecrets
        Jedis jedis = new Jedis("redis.example.com", 6379);
        jedis.auth(System.getenv("REDIS_PASSWORD"));
        
        System.out.println("Redis connected");
        jedis.close();
    }
    
    public void good_case_7() {
        // Azure client credentials from environment variables
        // ok: java-hardcodedsecrets
        ClientSecretCredential clientSecretCredential = new ClientSecretCredentialBuilder()
            .tenantId(System.getenv("AZURE_TENANT_ID"))
            .clientId(System.getenv("AZURE_CLIENT_ID"))
            .clientSecret(System.getenv("AZURE_CLIENT_SECRET"))
            .build();
    }
    
    public void good_case_8() {
        // Google API client with credentials from file
        try {
            // ok: java-hardcodedsecrets
            GoogleCredential credential = GoogleCredential
                .fromStream(new FileInputStream("google-credentials.json"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_9() {
        // Kafka producer with credentials from properties file
        try {
            Properties configProps = new Properties();
            configProps.load(new FileInputStream("kafka.properties"));
            
            Properties props = new Properties();
            props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "kafka.example.com:9092");
            
            // ok: java-hardcodedsecrets
            props.put("sasl.jaas.config", 
                "org.apache.kafka.common.security.plain.PlainLoginModule required " +
                "username=\"" + configProps.getProperty("kafka.username") + "\" " +
                "password=\"" + configProps.getProperty("kafka.password") + "\";");
            
            KafkaProducer<String, String> producer = new KafkaProducer<>(props);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_10() {
        // SSH connection with JSch and credentials from user input
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter SSH password: ");
            String password = scanner.nextLine();
            
            JSch jsch = new JSch();
            Session session = jsch.getSession("sshuser", "ssh.example.com", 22);
            
            // ok: java-hardcodedsecrets
            session.setPassword(password);
            
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            scanner.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_11() {
        // JWT token generation with secret from environment
        // ok: java-hardcodedsecrets
        String jwtSecret = System.getenv("JWT_SECRET");
        
        String token = Jwts.builder()
            .setSubject("user123")
            .signWith(SignatureAlgorithm.HS512, jwtSecret)
            .compact();
    }
    
    public void good_case_12() {
        // OkHttp client with credentials from configuration
        try {
            Properties props = new Properties();
            props.load(new FileInputStream("api.properties"));
            
            OkHttpClient client = new OkHttpClient();
            
            // ok: java-hardcodedsecrets
            String credentials = Credentials.basic(
                props.getProperty("api.username"),
                props.getProperty("api.password")
            );
            
            Request request = new Request.Builder()
                .url("https://api.example.org/data")
                .header("Authorization", credentials)
                .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_13() {
        // Elasticsearch client with credentials from environment variables
        RestClientBuilder builder = RestClient.builder(
            new HttpHost("elasticsearch.example.com", 9200, "https"));
        
        // ok: java-hardcodedsecrets
        final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY,
            new UsernamePasswordCredentials(
                System.getenv("ES_USERNAME"),
                System.getenv("ES_PASSWORD")
            ));
        
        builder.setHttpClientConfigCallback(httpClientBuilder -> 
            httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider));
    }
    
    public void good_case_14() {
        // Twilio API with credentials from properties
        try {
            Properties props = new Properties();
            props.load(new FileInputStream("twilio.properties"));
            
            // ok: java-hardcodedsecrets
            Twilio.init(
                props.getProperty("twilio.account.sid"),
                props.getProperty("twilio.auth.token")
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_15() {
        // SendGrid API with key from environment variable
        // ok: java-hardcodedsecrets
        SendGrid sendGrid = new SendGrid(System.getenv("SENDGRID_API_KEY"));
    }
}
// {/fact}