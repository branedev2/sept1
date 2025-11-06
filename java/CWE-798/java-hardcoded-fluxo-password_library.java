import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3Client;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.auth.AuthScope;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import redis.clients.jedis.Jedis;
import com.rabbitmq.client.ConnectionFactory;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import com.twilio.Twilio;
import com.sendgrid.SendGrid;
import com.stripe.Stripe;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Credentials;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPReply;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;

// Security Issue: Hardcoded credentials in source code (CWE-798)

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    // JDBC Database Connection with hardcoded credentials
    try {
        // ruleid: java-hardcoded-fluxo-password
        String password = "db_password_123";
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/mydb", "admin", password);
        // Use connection...
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_2() {
    // Spring JDBC Template with hardcoded credentials
    DriverManagerDataSource dataSource = new DriverManagerDataSource();
    dataSource.setDriverClassName("com.mysql.jdbc.Driver");
    dataSource.setUrl("jdbc:mysql://localhost:3306/mydb");
    dataSource.setUsername("admin");
    // ruleid: java-hardcoded-fluxo-password
    dataSource.setPassword("spring_secure_pwd!");
    
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    // Use jdbcTemplate...
}

public void bad_case_3() {
    // AWS S3 Client with hardcoded credentials
    // ruleid: java-hardcoded-fluxo-password
    String awsSecretKey = "aws/Secret/Key+12345";
    AWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", awsSecretKey);
    AmazonS3Client s3Client = new AmazonS3Client(credentials);
    // Use S3 client...
}

public void bad_case_4() {
    // Apache HTTP Client with hardcoded credentials
    DefaultHttpClient httpClient = new DefaultHttpClient();
    // ruleid: java-hardcoded-fluxo-password
    String password = "http_basic_auth_pwd";
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("user", password);
    httpClient.getCredentialsProvider().setCredentials(
        new AuthScope("example.com", 443),
        credentials);
    
    HttpGet request = new HttpGet("https://example.com/api/data");
    // Execute request...
}

public void bad_case_5() {
    // JSch SSH/SFTP connection with hardcoded credentials
    try {
        JSch jsch = new JSch();
        Session session = jsch.getSession("sftpuser", "sftp.example.com", 22);
        // ruleid: java-hardcoded-fluxo-password
        session.setPassword("sftp_secret_123");
        session.setConfig("StrictHostKeyChecking", "no");
        session.connect();
        
        Channel channel = session.openChannel("sftp");
        channel.connect();
        ChannelSftp sftpChannel = (ChannelSftp) channel;
        // Use SFTP channel...
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    // MongoDB connection with hardcoded credentials
    // ruleid: java-hardcoded-fluxo-password
    String mongoPassword = "mongo_db_pwd_456";
    MongoClientURI uri = new MongoClientURI(
        "mongodb://dbuser:" + mongoPassword + "@mongodb.example.com:27017/database");
    MongoClient mongoClient = new MongoClient(uri);
    // Use MongoDB client...
}

public void bad_case_7() {
    // Redis connection with hardcoded credentials
    Jedis jedis = new Jedis("redis.example.com", 6379);
    // ruleid: java-hardcoded-fluxo-password
    jedis.auth("redis_secret_key_789");
    // Use Redis client...
}

public void bad_case_8() {
    // RabbitMQ connection with hardcoded credentials
    ConnectionFactory factory = new ConnectionFactory();
    factory.setHost("rabbitmq.example.com");
    factory.setUsername("rabbit_user");
    // ruleid: java-hardcoded-fluxo-password
    factory.setPassword("carrot_123!");
    // Create connection...
}

public void bad_case_9() {
    // Elasticsearch client with hardcoded credentials
    try {
        Settings settings = Settings.builder()
            .put("cluster.name", "elasticsearch")
            .put("client.transport.sniff", true)
            .put("xpack.security.user", "elastic:elastic_password_123")  // ruleid: java-hardcoded-fluxo-password
            .build();
        
        TransportClient client = new TransportClient(settings)
            .addTransportAddress(new TransportAddress(InetAddress.getByName("elasticsearch.example.com"), 9300));
        // Use Elasticsearch client...
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10() {
    // Azure Blob Storage with hardcoded credentials
    // ruleid: java-hardcoded-fluxo-password
    String azureKey = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=azure_storage_key_123==;EndpointSuffix=core.windows.net";
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
        .connectionString(azureKey)
        .buildClient();
    // Use Azure Blob Storage client...
}

public void bad_case_11() {
    // Google API Client with hardcoded credentials
    try {
        // ruleid: java-hardcoded-fluxo-password
        String clientSecret = "google_oauth_secret_xyz";
        GoogleCredential credential = new GoogleCredential.Builder()
            .setClientSecrets("client_id", clientSecret)
            .build();
        // Use Google API client...
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12() {
    // Kafka Producer with hardcoded credentials
    Properties props = new Properties();
    props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "kafka.example.com:9092");
    props.put("security.protocol", "SASL_SSL");
    props.put("sasl.mechanism", "PLAIN");
    // ruleid: java-hardcoded-fluxo-password
    props.put("sasl.jaas.config", "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"kafka_user\" password=\"kafka_secret_456\";");
    
    KafkaProducer<String, String> producer = new KafkaProducer<>(props);
    // Use Kafka producer...
}

public void bad_case_13() {
    // Twilio API with hardcoded credentials
    // ruleid: java-hardcoded-fluxo-password
    String authToken = "twilio_auth_token_789";
    Twilio.init("TWILIO_AC_REDACTED_TWILIO_ID_SID", authToken);
    // Use Twilio client...
}

public void bad_case_14() {
    // SendGrid API with hardcoded credentials
    // ruleid: java-hardcoded-fluxo-password
    String apiKey = "SG.REDAC_REDACTED_TWILIO_ID_SENDGRID_KEY";
    SendGrid sendGrid = new SendGrid(apiKey);
    // Use SendGrid client...
}

public void bad_case_15() {
    // Stripe API with hardcoded credentials
    // ruleid: java-hardcoded-fluxo-password
    Stripe.apiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
    // Use Stripe client...
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    // JDBC Database Connection with credentials from properties file
    try {
        Properties props = new Properties();
        props.load(new FileInputStream("config.properties"));
        
        // ok: java-hardcoded-fluxo-password
        String password = props.getProperty("db.password");
        Connection conn = DriverManager.getConnection(
            props.getProperty("db.url"), 
            props.getProperty("db.user"), 
            password);
        // Use connection...
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    // Spring JDBC Template with environment variables
    DriverManagerDataSource dataSource = new DriverManagerDataSource();
    dataSource.setDriverClassName("com.mysql.jdbc.Driver");
    dataSource.setUrl("jdbc:mysql://localhost:3306/mydb");
    dataSource.setUsername(System.getenv("DB_USERNAME"));
    // ok: java-hardcoded-fluxo-password
    dataSource.setPassword(System.getenv("DB_PASSWORD"));
    
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    // Use jdbcTemplate...
}

public void good_case_3() {
    // AWS S3 Client with credentials from environment variables
    // ok: java-hardcoded-fluxo-password
    String awsSecretKey = System.getenv("AWS_SECRET_AC_REDACTED_TWILIO_ID_KEY");
    AWSCredentials credentials = new BasicAWSCredentials(
        System.getenv("AWS_AC_REDACTED_TWILIO_ID_KEY_ID"), 
        awsSecretKey);
    AmazonS3Client s3Client = new AmazonS3Client(credentials);
    // Use S3 client...
}

public void good_case_4() {
    // Apache HTTP Client with credentials from configuration file
    try {
        Configuration config = new PropertiesConfiguration("app.properties");
        DefaultHttpClient httpClient = new DefaultHttpClient();
        
        // ok: java-hardcoded-fluxo-password
        String password = config.getString("http.auth.password");
        UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(
            config.getString("http.auth.username"), 
            password);
        httpClient.getCredentialsProvider().setCredentials(
            new AuthScope("example.com", 443),
            credentials);
        
        HttpGet request = new HttpGet("https://example.com/api/data");
        // Execute request...
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    // JSch SSH/SFTP connection with credentials from secure storage
    try {
        JSch jsch = new JSch();
        Session session = jsch.getSession("sftpuser", "sftp.example.com", 22);
        
        // Read password from secure storage
        // ok: java-hardcoded-fluxo-password
        String password = new String(Files.readAllBytes(Paths.get("/secure/path/sftp_credentials.txt")));
        session.setPassword(password);
        session.setConfig("StrictHostKeyChecking", "no");
        session.connect();
        
        Channel channel = session.openChannel("sftp");
        channel.connect();
        ChannelSftp sftpChannel = (ChannelSftp) channel;
        // Use SFTP channel...
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6() {
    // MongoDB connection with credentials from environment variables
    // ok: java-hardcoded-fluxo-password
    String mongoPassword = System.getenv("MONGO_PASSWORD");
    MongoClientURI uri = new MongoClientURI(
        "mongodb://dbuser:" + mongoPassword + "@mongodb.example.com:27017/database");
    MongoClient mongoClient = new MongoClient(uri);
    // Use MongoDB client...
}

public void good_case_7() {
    // Redis connection with credentials from properties file
    try {
        Properties props = new Properties();
        props.load(new FileInputStream("redis.properties"));
        
        Jedis jedis = new Jedis("redis.example.com", 6379);
        // ok: java-hardcoded-fluxo-password
        jedis.auth(props.getProperty("redis.password"));
        // Use Redis client...
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    // RabbitMQ connection with credentials from system properties
    ConnectionFactory factory = new ConnectionFactory();
    factory.setHost("rabbitmq.example.com");
    factory.setUsername(System.getProperty("rabbitmq.username"));
    // ok: java-hardcoded-fluxo-password
    factory.setPassword(System.getProperty("rabbitmq.password"));
    // Create connection...
}

public void good_case_9() {
    // Elasticsearch client with credentials from environment variables
    try {
        // ok: java-hardcoded-fluxo-password
        String elasticPassword = System.getenv("ELASTIC_PASSWORD");
        Settings settings = Settings.builder()
            .put("cluster.name", "elasticsearch")
            .put("client.transport.sniff", true)
            .put("xpack.security.user", "elastic:" + elasticPassword)
            .build();
        
        TransportClient client = new TransportClient(settings)
            .addTransportAddress(new TransportAddress(InetAddress.getByName("elasticsearch.example.com"), 9300));
        // Use Elasticsearch client...
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10() {
    // Azure Blob Storage with credentials from configuration
    try {
        Properties props = new Properties();
        props.load(new FileInputStream("azure.properties"));
        
        // ok: java-hardcoded-fluxo-password
        String connectionString = props.getProperty("azure.storage.connection-string");
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString(connectionString)
            .buildClient();
        // Use Azure Blob Storage client...
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    // Google API Client with credentials from file
    try {
        // ok: java-hardcoded-fluxo-password
        GoogleCredential credential = GoogleCredential.fromStream(
            new FileInputStream("/secure/path/google_credentials.json"));
        // Use Google API client...
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12() {
    // Kafka Producer with credentials from environment variables
    Properties props = new Properties();
    props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "kafka.example.com:9092");
    props.put("security.protocol", "SASL_SSL");
    props.put("sasl.mechanism", "PLAIN");
    
    // ok: java-hardcoded-fluxo-password
    String kafkaPassword = System.getenv("KAFKA_PASSWORD");
    props.put("sasl.jaas.config", 
        "org.apache.kafka.common.security.plain.PlainLoginModule required " +
        "username=\"" + System.getenv("KAFKA_USERNAME") + "\" " +
        "password=\"" + kafkaPassword + "\";");
    
    KafkaProducer<String, String> producer = new KafkaProducer<>(props);
    // Use Kafka producer...
}

public void good_case_13() {
    // Twilio API with credentials from system properties
    // ok: java-hardcoded-fluxo-password
    String authToken = System.getProperty("twilio.auth.token");
    Twilio.init(System.getProperty("twilio.account.sid"), authToken);
    // Use Twilio client...
}

public void good_case_14() {
    // SendGrid API with credentials from environment variables
    // ok: java-hardcoded-fluxo-password
    String apiKey = System.getenv("SENDGRID_API_KEY");
    SendGrid sendGrid = new SendGrid(apiKey);
    // Use SendGrid client...
}

public void good_case_15() {
    // Stripe API with credentials from Spring Vault
    try {
        VaultEndpoint vaultEndpoint = new VaultEndpoint();
        vaultEndpoint.setHost("vault.example.com");
        vaultEndpoint.setPort(8200);
        
        VaultTemplate vaultTemplate = new VaultTemplate(
            vaultEndpoint, 
            new TokenAuthentication(System.getenv("VAULT_TOKEN"))
        );
        
        VaultResponse response = vaultTemplate.read("secret/stripe");
        // ok: java-hardcoded-fluxo-password
        Stripe.apiKey = (String) response.getData().get("api_key");
        // Use Stripe client...
    } catch (Exception e) {
        e.printStackTrace();
    }
}