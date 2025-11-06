import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3Client;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.sendgrid.SendGrid;
import com.twilio.Twilio;
import com.stripe.Stripe;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.apache.http.HttpHost;
import redis.clients.jedis.Jedis;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.rabbitmq.client.ConnectionFactory;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import com.slack.api.Slack;
import com.slack.api.methods.MethodsClient;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import java.util.HashMap;
import java.util.Map;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretVersionName;
import io.github.cdimascio.dotenv.Dotenv;

// Security Issue: Hardcoded credentials in source code (CWE-798)

// True Positive Examples (Vulnerable/Insecure Code)

public class HardcodedSecretsTest {

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        // JDBC Database Connection with hardcoded credentials
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = "admin";
            // ruleid: java-hardcoded-secrets-basic-ide
            String password = "p@ssw0rd123";
            
            Connection connection = DriverManager.getConnection(url, username, password);
            // Use connection...
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        // AWS SDK with hardcoded credentials
        // ruleid: java-hardcoded-secrets-basic-ide
        String awsAccessKey = "AKIAIOSFODNN7EXAMPLE";
        // ruleid: java-hardcoded-secrets-basic-ide
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        
        AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        AmazonS3Client s3Client = new AmazonS3Client(credentials);
        // Use S3 client...
    }

    public void bad_case_3() {
        // Azure Storage SDK with hardcoded connection string
        // ruleid: java-hardcoded-secrets-basic-ide
        String connectionString = "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY==;EndpointSuffix=core.windows.net";
        
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                .connectionString(connectionString)
                .buildClient();
        // Use blob service client...
    }

    public void bad_case_4() {
        // SendGrid Email API with hardcoded API key
        // ruleid: java-hardcoded-secrets-basic-ide
        String apiKey = "SG.REDAC_REDACTED_TWILIO_ID_SENDGRID_KEY.KwNlLGgxN9YvUHzOh7InBrZy5nZIEGjgEVK4jBgHYrI";
        
        SendGrid sendGrid = new SendGrid(apiKey);
        // Use SendGrid...
    }

    public void bad_case_5() {
        // Twilio API with hardcoded credentials
        // ruleid: java-hardcoded-secrets-basic-ide
        String accountSid = "AC_REDACTED_TWILIO_ID";
        // ruleid: java-hardcoded-secrets-basic-ide
        String authToken = "01234567890abcdef01234567890abcdef";
        
        Twilio.init(accountSid, authToken);
        // Use Twilio...
    }

    public void bad_case_6() {
        // Stripe Payment API with hardcoded key
        // ruleid: java-hardcoded-secrets-basic-ide
        String apiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
        
        Stripe.apiKey = apiKey;
        // Use Stripe...
    }

    public void bad_case_7() {
        // Elasticsearch REST client with hardcoded credentials
        RestClientBuilder builder = RestClient.builder(new HttpHost("localhost", 9200, "http"));
        
        // ruleid: java-hardcoded-secrets-basic-ide
        String username = "elastic";
        // ruleid: java-hardcoded-secrets-basic-ide
        String password = "changeme";
        
        // Add basic authentication
        builder.setHttpClientConfigCallback(httpClientBuilder -> 
            httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider -> {
                credentialsProvider.setCredentials(
                    AuthScope.ANY,
                    new UsernamePasswordCredentials(username, password)
                );
                return httpClientBuilder;
            })
        );
        // Use Elasticsearch client...
    }

    public void bad_case_8() {
        // Redis connection with hardcoded password
        // ruleid: java-hardcoded-secrets-basic-ide
        String password = "Redis2019!";
        
        Jedis jedis = new Jedis("localhost");
        jedis.auth(password);
        // Use Redis...
    }

    public void bad_case_9() {
        // MongoDB connection with hardcoded credentials in connection string
        // ruleid: java-hardcoded-secrets-basic-ide
        String connectionString = "mongodb://admin:MongoDB2019!@localhost:27017/admin";
        
        MongoClient mongoClient = new MongoClient(new MongoClientURI(connectionString));
        // Use MongoDB...
    }

    public void bad_case_10() {
        // RabbitMQ connection with hardcoded credentials
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost");
        // ruleid: java-hardcoded-secrets-basic-ide
        factory.setUsername("guest");
        // ruleid: java-hardcoded-secrets-basic-ide
        factory.setPassword("guest123");
        
        try {
            com.rabbitmq.client.Connection connection = factory.newConnection();
            // Use RabbitMQ...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        // Kafka producer with hardcoded SASL credentials
        Properties props = new Properties();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
        props.put("security.protocol", "SASL_PLAINTEXT");
        props.put("sasl.mechanism", "PLAIN");
        // ruleid: java-hardcoded-secrets-basic-ide
        props.put("sasl.jaas.config", 
                 "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"kafkauser\" password=\"kafkapass123\";");
        
        KafkaProducer<String, String> producer = new KafkaProducer<>(props);
        // Use Kafka producer...
    }

    public void bad_case_12() {
        // Slack API with hardcoded token
        // ruleid: java-hardcoded-secrets-basic-ide
        String token = "xoxb-REDACTED_SLACK_TOKENabcdef1234567890abcdef";
        
        Slack slack = Slack.getInstance();
        MethodsClient methods = slack.methods(token);
        // Use Slack methods...
    }

    public void bad_case_13() {
        // Spring Security encryption with hardcoded password and salt
        // ruleid: java-hardcoded-secrets-basic-ide
        String password = "encryptionPassword";
        // ruleid: java-hardcoded-secrets-basic-ide
        String salt = "deadbeefdeadbeef";
        
        TextEncryptor encryptor = Encryptors.text(password, salt);
        String encrypted = encryptor.encrypt("sensitive data");
        // Use encrypted data...
    }

    public void bad_case_14() {
        // JWT token generation with hardcoded secret key
        // ruleid: java-hardcoded-secrets-basic-ide
        String secretKey = "mysupersecretkeythatissupersecretandnobodyshouldknow";
        
        String jwtToken = Jwts.builder()
                .setSubject("user123")
                .signWith(SignatureAlgorithm.HS256, secretKey.getBytes())
                .compact();
        // Use JWT token...
    }

    public void bad_case_15() {
        // Google API client with hardcoded API key
        try {
            // ruleid: java-hardcoded-secrets-basic-ide
            String apiKey = "AIzaSyDI0Y5XXXXXXXXXXXXXXXXXXXX-XXXXXXXX";
            
            GoogleCredential credential = new GoogleCredential().setAccessToken(apiKey);
            // Use Google API...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe/Secure Code)

    public void good_case_1() {
        // JDBC Database Connection with credentials from properties file
        try {
            Properties props = new Properties();
            props.load(new FileInputStream("config.properties"));
            
            String url = "jdbc:mysql://localhost:3306/mydb";
            // ok: java-hardcoded-secrets-basic-ide
            String username = props.getProperty("db.username");
            // ok: java-hardcoded-secrets-basic-ide
            String password = props.getProperty("db.password");
            
            Connection connection = DriverManager.getConnection(url, username, password);
            // Use connection...
        } catch (SQLException | IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        // AWS SDK with credentials from environment variables
        // ok: java-hardcoded-secrets-basic-ide
        String awsAccessKey = System.getenv("AWS_AC_REDACTED_TWILIO_ID_KEY_ID");
        // ok: java-hardcoded-secrets-basic-ide
        String awsSecretKey = System.getenv("AWS_SECRET_AC_REDACTED_TWILIO_ID_KEY");
        
        AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        AmazonS3Client s3Client = new AmazonS3Client(credentials);
        // Use S3 client...
    }

    public void good_case_3() {
        // Azure Storage SDK with connection string from environment variable
        // ok: java-hardcoded-secrets-basic-ide
        String connectionString = System.getenv("AZURE_STORAGE_CONNECTION_STRING");
        
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                .connectionString(connectionString)
                .buildClient();
        // Use blob service client...
    }

    public void good_case_4() {
        // SendGrid Email API with API key from environment variable
        // ok: java-hardcoded-secrets-basic-ide
        String apiKey = System.getenv("SENDGRID_API_KEY");
        
        SendGrid sendGrid = new SendGrid(apiKey);
        // Use SendGrid...
    }

    public void good_case_5() {
        // Twilio API with credentials from environment variables
        // ok: java-hardcoded-secrets-basic-ide
        String accountSid = System.getenv("TWILIO_AC_REDACTED_TWILIO_ID_SID");
        // ok: java-hardcoded-secrets-basic-ide
        String authToken = System.getenv("TWILIO_AUTH_TOKEN");
        
        Twilio.init(accountSid, authToken);
        // Use Twilio...
    }

    public void good_case_6() {
        // Stripe Payment API with key from environment variable
        // ok: java-hardcoded-secrets-basic-ide
        String apiKey = System.getenv("STRIPE_API_KEY");
        
        Stripe.apiKey = apiKey;
        // Use Stripe...
    }

    public void good_case_7() {
        // Elasticsearch REST client with credentials from environment variables
        RestClientBuilder builder = RestClient.builder(new HttpHost("localhost", 9200, "http"));
        
        // ok: java-hardcoded-secrets-basic-ide
        String username = System.getenv("ES_USERNAME");
        // ok: java-hardcoded-secrets-basic-ide
        String password = System.getenv("ES_PASSWORD");
        
        // Add basic authentication
        builder.setHttpClientConfigCallback(httpClientBuilder -> 
            httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider -> {
                credentialsProvider.setCredentials(
                    AuthScope.ANY,
                    new UsernamePasswordCredentials(username, password)
                );
                return httpClientBuilder;
            })
        );
        // Use Elasticsearch client...
    }

    public void good_case_8() {
        // Redis connection with password from environment variable
        // ok: java-hardcoded-secrets-basic-ide
        String password = System.getenv("REDIS_PASSWORD");
        
        Jedis jedis = new Jedis("localhost");
        jedis.auth(password);
        // Use Redis...
    }

    public void good_case_9() {
        // MongoDB connection with credentials from environment variables
        // ok: java-hardcoded-secrets-basic-ide
        String username = System.getenv("MONGO_USERNAME");
        // ok: java-hardcoded-secrets-basic-ide
        String password = System.getenv("MONGO_PASSWORD");
        String host = System.getenv("MONGO_HOST");
        
        String connectionString = String.format("mongodb://%s:%s@%s:27017/admin", username, password, host);
        MongoClient mongoClient = new MongoClient(new MongoClientURI(connectionString));
        // Use MongoDB...
    }

    public void good_case_10() {
        // RabbitMQ connection with credentials from environment variables
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost");
        // ok: java-hardcoded-secrets-basic-ide
        factory.setUsername(System.getenv("RABBITMQ_USERNAME"));
        // ok: java-hardcoded-secrets-basic-ide
        factory.setPassword(System.getenv("RABBITMQ_PASSWORD"));
        
        try {
            com.rabbitmq.client.Connection connection = factory.newConnection();
            // Use RabbitMQ...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        // Kafka producer with SASL credentials from environment variables
        Properties props = new Properties();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
        props.put("security.protocol", "SASL_PLAINTEXT");
        props.put("sasl.mechanism", "PLAIN");
        
        // ok: java-hardcoded-secrets-basic-ide
        String username = System.getenv("KAFKA_USERNAME");
        // ok: java-hardcoded-secrets-basic-ide
        String password = System.getenv("KAFKA_PASSWORD");
        props.put("sasl.jaas.config", 
                 String.format("org.apache.kafka.common.security.plain.PlainLoginModule required username=\"%s\" password=\"%s\";", 
                              username, password));
        
        KafkaProducer<String, String> producer = new KafkaProducer<>(props);
        // Use Kafka producer...
    }

    public void good_case_12() {
        // Slack API with token from environment variable
        // ok: java-hardcoded-secrets-basic-ide
        String token = System.getenv("SLAC_REDACTED_TWILIO_ID_API_TOKEN");
        
        Slack slack = Slack.getInstance();
        MethodsClient methods = slack.methods(token);
        // Use Slack methods...
    }

    public void good_case_13() {
        // Spring Security encryption with password and salt from environment variables
        // ok: java-hardcoded-secrets-basic-ide
        String password = System.getenv("ENCRYPTION_PASSWORD");
        // ok: java-hardcoded-secrets-basic-ide
        String salt = System.getenv("ENCRYPTION_SALT");
        
        TextEncryptor encryptor = Encryptors.text(password, salt);
        String encrypted = encryptor.encrypt("sensitive data");
        // Use encrypted data...
    }

    public void good_case_14() {
        // JWT token generation with secret key from AWS Secrets Manager
        try {
            SecretsManagerClient secretsClient = SecretsManagerClient.create();
            GetSecretValueRequest getSecretValueRequest = GetSecretValueRequest.builder()
                .secretId("jwt/secret-key")
                .build();
            
            GetSecretValueResponse getSecretValueResponse = secretsClient.getSecretValue(getSecretValueRequest);
            // ok: java-hardcoded-secrets-basic-ide
            String secretKey = getSecretValueResponse.secretString();
            
            String jwtToken = Jwts.builder()
                    .setSubject("user123")
                    .signWith(SignatureAlgorithm.HS256, secretKey.getBytes())
                    .compact();
            // Use JWT token...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        // Google API client with API key from dotenv file
        try {
            Dotenv dotenv = Dotenv.load();
            // ok: java-hardcoded-secrets-basic-ide
            String apiKey = dotenv.get("GOOGLE_API_KEY");
            
            GoogleCredential credential = new GoogleCredential().setAccessToken(apiKey);
            // Use Google API...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}