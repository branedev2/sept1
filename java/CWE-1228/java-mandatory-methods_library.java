import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.HttpURLConnection;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;

import org.apache.commons.io.FileUtils;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;

import redis.clients.jedis.Jedis;

import com.mongodb.MongoClient;
import com.mongodb.client.MongoDatabase;

import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.indices.CreateIndexRequest;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.ConnectionFactory;

// Security Issue: Improper object initialization can lead to insecure object states and enable various attacks

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // Spring JDBC Template missing required initialization
    DriverManagerDataSource dataSource = new DriverManagerDataSource();
    // ruleid: java-mandatory-methods
    JdbcTemplate jdbcTemplate = new JdbcTemplate();
    // Missing dataSource initialization: jdbcTemplate.setDataSource(dataSource);
    
    String query = "SELECT * FROM users WHERE username = ?";
    String username = request.getParameter("username");
    jdbcTemplate.queryForList(query, username); // Potential issues due to improper initialization
}

public void bad_case_2(HttpServletRequest request) {
    // AWS S3 Client missing region specification
    String accessKey = request.getHeader("X-Access-Key");
    String secretKey = request.getHeader("X-Secret-Key");
    BasicAWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);
    
    // ruleid: java-mandatory-methods
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
            .withCredentials(new AWSStaticCredentialsProvider(credentials))
            .build();
    // Missing region specification: .withRegion(Regions.US_EAST_1)
    
    s3Client.getObject("bucket-name", "object-key");
}

public void bad_case_3(HttpServletRequest request) {
    // Gson builder without proper type adapters for sensitive data
    // ruleid: java-mandatory-methods
    Gson gson = new Gson(); // Using default constructor without proper configuration
    
    String jsonInput = request.getParameter("userdata");
    UserCredentials credentials = gson.fromJson(jsonInput, UserCredentials.class);
    // Sensitive data may not be properly handled
}

public void bad_case_4(HttpServletRequest request) {
    // OkHttp client without proper timeout configuration
    // ruleid: java-mandatory-methods
    OkHttpClient client = new OkHttpClient(); // Default constructor without timeouts
    
    String url = request.getParameter("url");
    Request okRequest = new Request.Builder()
            .url(url)
            .build();
    
    try {
        Response response = client.newCall(okRequest).execute();
        // Client could hang indefinitely on slow connections
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request) {
    // Hibernate without proper configuration
    // ruleid: java-mandatory-methods
    SessionFactory sessionFactory = new Configuration().buildSessionFactory();
    // Missing configuration setup and validation
    
    Session session = sessionFactory.openSession();
    String hql = "FROM User WHERE username = '" + request.getParameter("username") + "'";
    session.createQuery(hql).list(); // Potential SQL injection
}

public void bad_case_6(HttpServletRequest request) {
    // HikariCP connection pool without proper configuration
    // ruleid: java-mandatory-methods
    HikariDataSource dataSource = new HikariDataSource();
    // Missing essential configurations like connection timeout, max pool size
    
    try {
        Connection conn = dataSource.getConnection();
        String query = "SELECT * FROM users WHERE id = " + request.getParameter("id");
        conn.createStatement().executeQuery(query);
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_7(HttpServletRequest request) {
    // Kafka Producer without proper configuration
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    
    // ruleid: java-mandatory-methods
    KafkaProducer<String, String> producer = new KafkaProducer<>(props);
    // Missing essential configurations like acks, retries, batch.size
    
    String topic = request.getParameter("topic");
    String message = request.getParameter("message");
    producer.send(new ProducerRecord<>(topic, message));
}

public void bad_case_8(HttpServletRequest request) {
    // Redis Jedis client without proper pool configuration
    // ruleid: java-mandatory-methods
    Jedis jedis = new Jedis("localhost");
    // Missing timeout settings and connection pool configuration
    
    String key = request.getParameter("key");
    jedis.get(key);
}

public void bad_case_9(HttpServletRequest request) {
    // MongoDB client without proper connection settings
    // ruleid: java-mandatory-methods
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    // Missing connection options like maxPoolSize, connectTimeout
    
    String dbName = request.getParameter("db");
    MongoDatabase database = mongoClient.getDatabase(dbName);
}

public void bad_case_10(HttpServletRequest request) {
    // ElasticSearch client without proper configuration
    // ruleid: java-mandatory-methods
    RestHighLevelClient client = new RestHighLevelClient(
            RestClient.builder(new HttpHost("localhost", 9200, "http")));
    // Missing connection timeout, socket timeout, etc.
    
    try {
        CreateIndexRequest createIndexRequest = new CreateIndexRequest(request.getParameter("index"));
        client.indices().create(createIndexRequest);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_11(HttpServletRequest request) {
    // RabbitMQ client without proper connection settings
    ConnectionFactory factory = new ConnectionFactory();
    factory.setHost("localhost");
    
    // ruleid: java-mandatory-methods
    try {
        com.rabbitmq.client.Connection connection = factory.newConnection();
        // Missing connection timeout, heartbeat, etc.
        
        Channel channel = connection.createChannel();
        String queueName = request.getParameter("queue");
        channel.queueDeclare(queueName, false, false, false, null);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    // Apache Commons Exec without proper configuration
    // ruleid: java-mandatory-methods
    DefaultExecutor executor = new DefaultExecutor();
    // Missing working directory, execution timeout, etc.
    
    try {
        String command = "echo " + request.getParameter("input");
        CommandLine cmdLine = CommandLine.parse(command);
        executor.execute(cmdLine);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_13(HttpServletRequest request) {
    // Retrofit client without proper configuration
    // ruleid: java-mandatory-methods
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .build();
    // Missing converter factory, call adapter factory, etc.
    
    ApiService service = retrofit.create(ApiService.class);
    // API calls may fail due to missing converters
}

public void bad_case_14(HttpServletRequest request) {
    // JDBC Connection without proper configuration
    // ruleid: java-mandatory-methods
    try {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        // Missing username, password, connection properties
        
        String query = "SELECT * FROM users WHERE name = ?";
        PreparedStatement stmt = conn.prepareStatement(query);
        stmt.setString(1, request.getParameter("name"));
        stmt.executeQuery();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    // Apache HTTP Client without proper configuration
    // ruleid: java-mandatory-methods
    HttpClient client = HttpClients.createDefault();
    // Missing connection timeout, socket timeout, etc.
    
    try {
        HttpGet httpGet = new HttpGet(request.getParameter("url"));
        client.execute(httpGet);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // Spring JDBC Template with proper initialization
    DriverManagerDataSource dataSource = new DriverManagerDataSource();
    dataSource.setDriverClassName("com.mysql.jdbc.Driver");
    dataSource.setUrl("jdbc:mysql://localhost:3306/mydb");
    dataSource.setUsername("user");
    dataSource.setPassword("password");
    
    // ok: java-mandatory-methods
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    
    String query = "SELECT * FROM users WHERE username = ?";
    String username = request.getParameter("username");
    jdbcTemplate.queryForList(query, username);
}

public void good_case_2(HttpServletRequest request) {
    // AWS S3 Client with proper region specification
    String accessKey = request.getHeader("X-Access-Key");
    String secretKey = request.getHeader("X-Secret-Key");
    BasicAWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);
    
    // ok: java-mandatory-methods
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
            .withRegion("us-east-1")
            .withCredentials(new AWSStaticCredentialsProvider(credentials))
            .build();
    
    s3Client.getObject("bucket-name", "object-key");
}

public void good_case_3(HttpServletRequest request) {
    // Gson builder with proper type adapters for sensitive data
    // ok: java-mandatory-methods
    Gson gson = new GsonBuilder()
            .registerTypeAdapter(UserCredentials.class, new UserCredentialsTypeAdapter())
            .disableHtmlEscaping()
            .create();
    
    String jsonInput = request.getParameter("userdata");
    UserCredentials credentials = gson.fromJson(jsonInput, UserCredentials.class);
}

public void good_case_4(HttpServletRequest request) {
    // OkHttp client with proper timeout configuration
    // ok: java-mandatory-methods
    OkHttpClient client = new OkHttpClient.Builder()
            .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
            .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
            .writeTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
            .build();
    
    String url = request.getParameter("url");
    Request okRequest = new Request.Builder()
            .url(url)
            .build();
    
    try {
        Response response = client.newCall(okRequest).execute();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    // Hibernate with proper configuration
    // ok: java-mandatory-methods
    SessionFactory sessionFactory = new Configuration()
            .configure("hibernate.cfg.xml")
            .addAnnotatedClass(User.class)
            .buildSessionFactory();
    
    Session session = sessionFactory.openSession();
    String username = request.getParameter("username");
    session.createQuery("FROM User WHERE username = :username")
           .setParameter("username", username)
           .list();
}

public void good_case_6(HttpServletRequest request) {
    // HikariCP connection pool with proper configuration
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
    config.setUsername("user");
    config.setPassword("password");
    config.setMaximumPoolSize(10);
    config.setConnectionTimeout(30000);
    
    // ok: java-mandatory-methods
    HikariDataSource dataSource = new HikariDataSource(config);
    
    try {
        Connection conn = dataSource.getConnection();
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        stmt.setString(1, request.getParameter("id"));
        stmt.executeQuery();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_7(HttpServletRequest request) {
    // Kafka Producer with proper configuration
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    props.put("acks", "all");
    props.put("retries", 3);
    props.put("batch.size", 16384);
    props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    
    // ok: java-mandatory-methods
    KafkaProducer<String, String> producer = new KafkaProducer<>(props);
    
    String topic = request.getParameter("topic");
    String message = request.getParameter("message");
    producer.send(new ProducerRecord<>(topic, message));
}

public void good_case_8(HttpServletRequest request) {
    // Redis Jedis client with proper pool configuration
    redis.clients.jedis.JedisPoolConfig poolConfig = new redis.clients.jedis.JedisPoolConfig();
    poolConfig.setMaxTotal(128);
    poolConfig.setMaxIdle(128);
    poolConfig.setMinIdle(16);
    poolConfig.setTestOnBorrow(true);
    poolConfig.setTestOnReturn(true);
    
    redis.clients.jedis.JedisPool jedisPool = new redis.clients.jedis.JedisPool(poolConfig, "localhost", 6379, 2000);
    
    // ok: java-mandatory-methods
    try (Jedis jedis = jedisPool.getResource()) {
        String key = request.getParameter("key");
        jedis.get(key);
    }
}

public void good_case_9(HttpServletRequest request) {
    // MongoDB client with proper connection settings
    com.mongodb.MongoClientOptions options = com.mongodb.MongoClientOptions.builder()
            .connectTimeout(10000)
            .socketTimeout(60000)
            .maxConnectionIdleTime(600000)
            .maxConnectionLifeTime(3600000)
            .connectionsPerHost(100)
            .build();
    
    // ok: java-mandatory-methods
    MongoClient mongoClient = new MongoClient(new com.mongodb.ServerAddress("localhost", 27017), options);
    
    String dbName = request.getParameter("db");
    MongoDatabase database = mongoClient.getDatabase(dbName);
}

public void good_case_10(HttpServletRequest request) {
    // ElasticSearch client with proper configuration
    // ok: java-mandatory-methods
    RestHighLevelClient client = new RestHighLevelClient(
            RestClient.builder(new HttpHost("localhost", 9200, "http"))
                    .setRequestConfigCallback(requestConfigBuilder -> 
                        requestConfigBuilder
                            .setConnectTimeout(5000)
                            .setSocketTimeout(60000))
                    .setMaxRetryTimeoutMillis(60000));
    
    try {
        CreateIndexRequest createIndexRequest = new CreateIndexRequest(request.getParameter("index"));
        client.indices().create(createIndexRequest);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_11(HttpServletRequest request) {
    // RabbitMQ client with proper connection settings
    ConnectionFactory factory = new ConnectionFactory();
    factory.setHost("localhost");
    factory.setPort(5672);
    factory.setUsername("guest");
    factory.setPassword("guest");
    factory.setConnectionTimeout(30000);
    factory.setRequestedHeartbeat(60);
    
    // ok: java-mandatory-methods
    try {
        com.rabbitmq.client.Connection connection = factory.newConnection();
        Channel channel = connection.createChannel();
        String queueName = request.getParameter("queue");
        channel.queueDeclare(queueName, false, false, false, null);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    // Apache Commons Exec with proper configuration
    // ok: java-mandatory-methods
    DefaultExecutor executor = new DefaultExecutor();
    executor.setWorkingDirectory(new File("/tmp"));
    executor.setExitValue(0);
    
    // Set timeout of 60 seconds
    org.apache.commons.exec.ExecuteWatchdog watchdog = new org.apache.commons.exec.ExecuteWatchdog(60000);
    executor.setWatchdog(watchdog);
    
    try {
        String input = request.getParameter("input");
        CommandLine cmdLine = CommandLine.parse("echo");
        cmdLine.addArgument(input, false);
        executor.execute(cmdLine);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_13(HttpServletRequest request) {
    // Retrofit client with proper configuration
    // ok: java-mandatory-methods
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .client(new OkHttpClient.Builder()
                    .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
                    .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
                    .build())
            .build();
    
    ApiService service = retrofit.create(ApiService.class);
}

public void good_case_14(HttpServletRequest request) {
    // JDBC Connection with proper configuration
    Properties props = new Properties();
    props.setProperty("user", "username");
    props.setProperty("password", "password");
    props.setProperty("connectTimeout", "30000");
    props.setProperty("socketTimeout", "30000");
    
    // ok: java-mandatory-methods
    try {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", props);
        
        String query = "SELECT * FROM users WHERE name = ?";
        PreparedStatement stmt = conn.prepareStatement(query);
        stmt.setString(1, request.getParameter("name"));
        stmt.executeQuery();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    // Apache HTTP Client with proper configuration
    org.apache.http.client.config.RequestConfig requestConfig = org.apache.http.client.config.RequestConfig.custom()
            .setConnectTimeout(5000)
            .setSocketTimeout(30000)
            .setConnectionRequestTimeout(5000)
            .build();
    
    // ok: java-mandatory-methods
    HttpClient client = HttpClients.custom()
            .setDefaultRequestConfig(requestConfig)
            .setMaxConnTotal(100)
            .setMaxConnPerRoute(20)
            .build();
    
    try {
        HttpGet httpGet = new HttpGet(request.getParameter("url"));
        client.execute(httpGet);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

// Helper class for examples
class UserCredentials {
    private String username;
    private String password;
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}

// Helper class for examples
class UserCredentialsTypeAdapter extends com.google.gson.TypeAdapter<UserCredentials> {
    @Override
    public void write(com.google.gson.stream.JsonWriter out, UserCredentials value) throws IOException {
        // Implementation for secure serialization
    }
    
    @Override
    public UserCredentials read(com.google.gson.stream.JsonReader in) throws IOException {
        // Implementation for secure deserialization
        return new UserCredentials();
    }
}

// Helper interface for examples
interface ApiService {
    // API service methods
}

class User {
    private int id;
    private String username;
    
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
}