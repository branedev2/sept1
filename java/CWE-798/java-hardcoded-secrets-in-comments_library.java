import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Properties;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import redis.clients.jedis.Jedis;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.twilio.Twilio;
import com.stripe.Stripe;
import com.sendgrid.SendGrid;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import com.rabbitmq.client.ConnectionFactory;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.core.DockerClientBuilder;
import org.apache.kafka.clients.producer.KafkaProducer;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.util.Config;

// Security Issue: Hardcoded secrets in comments in Java source files

// True Positive Examples (Vulnerable/Insecure Code)
public class HardcodedSecretsInComments {

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        // ruleid: java-hardcoded-secrets-in-comments
        // Database connection with password: p@ssw0rd123
        String url = "jdbc:mysql://localhost:3306/mydb";
        String username = "admin";
        String password = System.getenv("DB_PASSWORD");
        Connection connection = DriverManager.getConnection(url, username, password);
    }

    public void bad_case_2() {
        // AWS S3 client setup
        // ruleid: java-hardcoded-secrets-in-comments
        // AWS Secret Key: AKIAIOSFODNN7EXAMPLE123
        String accessKey = System.getProperty("aws.access.key");
        String secretKey = System.getProperty("aws.secret.key");
        AWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);
    }

    public void bad_case_3() {
        // Spring JDBC configuration
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("com.mysql.jdbc.Driver");
        dataSource.setUrl("jdbc:mysql://localhost:3306/testdb");
        dataSource.setUsername("root");
        // ruleid: java-hardcoded-secrets-in-comments
        /* 
         * Using password: spring_secure_pwd!2023
         */
        dataSource.setPassword(getPasswordFromVault());
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    }

    public void bad_case_4() {
        // MongoDB connection setup
        // ruleid: java-hardcoded-secrets-in-comments
        // Connection string with auth: mongodb://admin:mongo123@localhost:27017/admin
        String connectionString = "mongodb://localhost:27017/admin";
        MongoClient mongoClient = new MongoClient(new MongoClientURI(connectionString));
    }

    public void bad_case_5() {
        // Redis client configuration
        Jedis jedis = new Jedis("localhost");
        // ruleid: java-hardcoded-secrets-in-comments
        // Auth with password: redis_pwd_2023!
        jedis.auth(fetchRedisPassword());
    }

    public void bad_case_6() {
        // OkHttp client with API key
        OkHttpClient client = new OkHttpClient();
        // ruleid: java-hardcoded-secrets-in-comments
        // API Key for service: 9a8b7c6d5e4f3g2h1i
        Request request = new Request.Builder()
                .url("https://api.example.com/data")
                .addHeader("Authorization", "Bearer " + System.getenv("API_KEY"))
                .build();
    }

    public void bad_case_7() {
        // Google API client setup
        // ruleid: java-hardcoded-secrets-in-comments
        /* Google API client secret: gcp_secret_key_XYZ987654321 */
        GoogleCredential credential = GoogleCredential.getApplicationDefault()
                .createScoped(Arrays.asList("https://www.googleapis.com/auth/cloud-platform"));
    }

    public void bad_case_8() {
        // Apache HttpClient with basic auth
        CloseableHttpClient httpClient = HttpClients.createDefault();
        // ruleid: java-hardcoded-secrets-in-comments
        // Basic auth credentials: username=admin, password=http_client_pwd!
        String encodedAuth = Base64.getEncoder().encodeToString(
                (System.getenv("USERNAME") + ":" + System.getenv("PASSWORD")).getBytes());
    }

    public void bad_case_9() {
        // Azure client credential
        // ruleid: java-hardcoded-secrets-in-comments
        // Client secret for Azure AD: azure_client_secret_12345
        ClientSecretCredential clientSecretCredential = new ClientSecretCredentialBuilder()
                .clientId(System.getenv("AZURE_CLIENT_ID"))
                .clientSecret(System.getenv("AZURE_CLIENT_SECRET"))
                .tenantId(System.getenv("AZURE_TENANT_ID"))
                .build();
    }

    public void bad_case_10() {
        // Twilio client setup
        // ruleid: java-hardcoded-secrets-in-comments
        // Twilio Auth Token: 9876543210abcdefghijklmnop
        Twilio.init(System.getenv("TWILIO_AC_REDACTED_TWILIO_ID_SID"), System.getenv("TWILIO_AUTH_TOKEN"));
    }

    public void bad_case_11() {
        // Stripe API integration
        // ruleid: java-hardcoded-secrets-in-comments
        /* 
         * Stripe Secret Key: sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY
         */
        Stripe.apiKey = System.getenv("STRIPE_API_KEY");
    }

    public void bad_case_12() {
        // SendGrid email service
        // ruleid: java-hardcoded-secrets-in-comments
        // SendGrid API Key: SG.REDAC_REDACTED_TWILIO_ID_SENDGRID_KEY
        SendGrid sendGrid = new SendGrid(System.getenv("SENDGRID_API_KEY"));
    }

    public void bad_case_13() {
        // Elasticsearch client configuration
        // ruleid: java-hardcoded-secrets-in-comments
        // Elastic search credentials: elastic:elastic_password_2023
        RestHighLevelClient client = new RestHighLevelClient(
                RestClient.builder(new HttpHost("localhost", 9200, "http")));
    }

    public void bad_case_14() {
        // RabbitMQ connection setup
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost");
        // ruleid: java-hardcoded-secrets-in-comments
        /* RabbitMQ password: rabbit_mq_secure_password! */
        factory.setUsername(System.getenv("RABBITMQ_USER"));
        factory.setPassword(System.getenv("RABBITMQ_PASSWORD"));
    }

    public void bad_case_15() {
        // HikariCP database connection pool
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:postgresql://localhost:5432/mydb");
        config.setUsername("postgres");
        // ruleid: java-hardcoded-secrets-in-comments
        // HikariCP using password: hikari_db_password_2023!
        config.setPassword(System.getenv("DB_PASSWORD"));
        HikariDataSource dataSource = new HikariDataSource(config);
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1() {
        // ok: java-hardcoded-secrets-in-comments
        // Database connection with credentials from environment variables
        String url = "jdbc:mysql://localhost:3306/mydb";
        String username = System.getenv("DB_USERNAME");
        String password = System.getenv("DB_PASSWORD");
        Connection connection = DriverManager.getConnection(url, username, password);
    }

    public void good_case_2() {
        // ok: java-hardcoded-secrets-in-comments
        // AWS S3 client setup with credentials from environment
        String accessKey = System.getProperty("aws.access.key");
        String secretKey = System.getProperty("aws.secret.key");
        AwsBasicCredentials credentials = AwsBasicCredentials.create(accessKey, secretKey);
        S3Client s3Client = S3Client.builder()
                .region(Region.US_WEST_2)
                .credentialsProvider(() -> credentials)
                .build();
    }

    public void good_case_3() {
        // ok: java-hardcoded-secrets-in-comments
        // Spring JDBC configuration with secure password handling
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("com.mysql.jdbc.Driver");
        dataSource.setUrl("jdbc:mysql://localhost:3306/testdb");
        dataSource.setUsername(System.getenv("DB_USER"));
        dataSource.setPassword(getPasswordFromVault());
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    }

    public void good_case_4() {
        // ok: java-hardcoded-secrets-in-comments
        // MongoDB connection setup with secure credentials
        String connectionString = "mongodb://localhost:27017/admin";
        // Using credentials from secure store
        connectionString = connectionString.replace("localhost", 
                System.getenv("MONGO_HOST") + ":" + System.getenv("MONGO_PORT"));
        MongoClient mongoClient = new MongoClient(new MongoClientURI(connectionString));
    }

    public void good_case_5() {
        // ok: java-hardcoded-secrets-in-comments
        // Redis client configuration with secure auth
        Jedis jedis = new Jedis("localhost");
        // Authenticate using password from secure source
        jedis.auth(fetchRedisPassword());
    }

    public void good_case_6() {
        // ok: java-hardcoded-secrets-in-comments
        // OkHttp client with securely stored API key
        OkHttpClient client = new OkHttpClient();
        // Using API key from environment variable
        Request request = new Request.Builder()
                .url("https://api.example.com/data")
                .addHeader("Authorization", "Bearer " + System.getenv("API_KEY"))
                .build();
    }

    public void good_case_7() {
        // ok: java-hardcoded-secrets-in-comments
        // Google API client setup with secure credential handling
        // Using application default credentials
        GoogleCredential credential = GoogleCredential.getApplicationDefault()
                .createScoped(Arrays.asList("https://www.googleapis.com/auth/cloud-platform"));
    }

    public void good_case_8() {
        // ok: java-hardcoded-secrets-in-comments
        // Apache HttpClient with securely stored auth credentials
        CloseableHttpClient httpClient = HttpClients.createDefault();
        // Using environment variables for authentication
        String encodedAuth = Base64.getEncoder().encodeToString(
                (System.getenv("USERNAME") + ":" + System.getenv("PASSWORD")).getBytes());
    }

    public void good_case_9() {
        // ok: java-hardcoded-secrets-in-comments
        // Azure client credential with secure secret management
        // Using environment variables for Azure authentication
        ClientSecretCredential clientSecretCredential = new ClientSecretCredentialBuilder()
                .clientId(System.getenv("AZURE_CLIENT_ID"))
                .clientSecret(System.getenv("AZURE_CLIENT_SECRET"))
                .tenantId(System.getenv("AZURE_TENANT_ID"))
                .build();
    }

    public void good_case_10() {
        // ok: java-hardcoded-secrets-in-comments
        // Twilio client setup with secure token handling
        // Initializing with environment variables
        Twilio.init(System.getenv("TWILIO_AC_REDACTED_TWILIO_ID_SID"), System.getenv("TWILIO_AUTH_TOKEN"));
    }

    public void good_case_11() {
        // ok: java-hardcoded-secrets-in-comments
        // Stripe API integration with secure key management
        // Setting API key from environment variable
        Stripe.apiKey = System.getenv("STRIPE_API_KEY");
    }

    public void good_case_12() {
        // ok: java-hardcoded-secrets-in-comments
        // SendGrid email service with secure API key handling
        // Using environment variable for API key
        SendGrid sendGrid = new SendGrid(System.getenv("SENDGRID_API_KEY"));
    }

    public void good_case_13() {
        // ok: java-hardcoded-secrets-in-comments
        // Elasticsearch client with secure authentication
        // Using environment variables for credentials
        RestHighLevelClient client = new RestHighLevelClient(
                RestClient.builder(new HttpHost(System.getenv("ES_HOST"), 
                        Integer.parseInt(System.getenv("ES_PORT")), "http")));
    }

    public void good_case_14() {
        // ok: java-hardcoded-secrets-in-comments
        // RabbitMQ connection with secure credential handling
        // Using environment variables for authentication
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost(System.getenv("RABBITMQ_HOST"));
        factory.setUsername(System.getenv("RABBITMQ_USER"));
        factory.setPassword(System.getenv("RABBITMQ_PASSWORD"));
    }

    public void good_case_15() {
        // ok: java-hardcoded-secrets-in-comments
        // JWT token creation with secure signing
        // Using environment variable for secret key
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(Algorithm.HMAC_REDACTED_TWILIO_ID(System.getenv("JWT_SECRET")));
    }

    // Helper methods
    private String getPasswordFromVault() {
        // Implementation to retrieve password from secure vault
        return "securePassword";
    }

    private String fetchRedisPassword() {
        // Implementation to fetch Redis password from secure source
        return "redisPassword";
    }
}
// {/fact}