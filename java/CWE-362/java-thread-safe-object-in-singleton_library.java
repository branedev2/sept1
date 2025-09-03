import java.util.*;
import java.util.concurrent.*;
import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.springframework.web.*;
import org.apache.http.client.*;
import org.apache.http.impl.client.*;
import org.apache.http.client.methods.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.auth.*;
import com.google.gson.*;
import okhttp3.*;
import retrofit2.*;
import retrofit2.converter.gson.*;
import org.apache.commons.exec.*;
import java.sql.*;
import redis.clients.jedis.*;
import com.mongodb.*;
import org.hibernate.*;
import javax.jms.*;
import org.apache.kafka.clients.producer.*;
import org.apache.kafka.clients.consumer.*;
import com.rabbitmq.client.*;
import org.quartz.*;
import org.quartz.impl.*;
import com.azure.storage.blob.*;
import com.google.cloud.storage.*;
import software.amazon.awssdk.services.dynamodb.*;
import io.vertx.core.*;
import io.vertx.ext.web.*;
import play.mvc.*;
import spark.*;
import io.javalin.*;
import com.zaxxer.hikari.*;

// Security Issue: Thread-unsafe objects in singleton classes can lead to race conditions and data corruption

// True Positive Examples (Vulnerable/Insecure Code)

// Example 1: Spring Controller as Singleton with non-thread-safe SimpleDateFormat
@Controller
public class bad_case_1 {
    // ruleid: java-thread-safe-object-in-singleton
    private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    
    @GetMapping("/format-date")
    public String formatDate(@RequestParam String date) {
        try {
            return dateFormat.format(dateFormat.parse(date));
        } catch (Exception e) {
            return "Error parsing date";
        }
    }
}

// Example 2: Singleton with non-thread-safe StringBuilder
public class bad_case_2 {
    private static bad_case_2 instance;
    // ruleid: java-thread-safe-object-in-singleton
    private StringBuilder messageBuilder = new StringBuilder();
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_2() {}
    
    public static synchronized bad_case_2 getInstance() {
        if (instance == null) {
            instance = new bad_case_2();
        }
        return instance;
    }
    
    public String processRequest(HttpServletRequest request) {
        String message = request.getParameter("message");
        messageBuilder.append(message);
        return messageBuilder.toString();
    }
}
// {/fact}

// Example 3: OkHttp client singleton with non-thread-safe state
public class bad_case_3 {
    private static bad_case_3 instance;
    private OkHttpClient client = new OkHttpClient();
    // ruleid: java-thread-safe-object-in-singleton
    private String lastResponse;
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_3() {}
    
    public static bad_case_3 getInstance() {
        if (instance == null) {
            instance = new bad_case_3();
        }
        return instance;
    }
    
    public String fetchData(String url) throws IOException {
        Request request = new Request.Builder().url(url).build();
        try (Response response = client.newCall(request).execute()) {
            lastResponse = response.body().string();
            return lastResponse;
        }
    }
    
    public String getLastResponse() {
        return lastResponse;
    }
}
// {/fact}

// Example 4: AWS S3 Client singleton with non-thread-safe ArrayList
public class bad_case_4 {
    private static bad_case_4 instance;
    private AmazonS3 s3Client;
    // ruleid: java-thread-safe-object-in-singleton
    private List<String> uploadedFiles = new ArrayList<>();
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_4() {
        s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
    }
    
    public static bad_case_4 getInstance() {
        if (instance == null) {
            instance = new bad_case_4();
        }
        return instance;
    }
    
    public void uploadFile(String bucketName, String key, InputStream data) {
        s3Client.putObject(bucketName, key, data, null);
        uploadedFiles.add(key);
    }
    
    public List<String> getUploadedFiles() {
        return uploadedFiles;
    }
}
// {/fact}

// Example 5: Retrofit API Client singleton with non-thread-safe HashMap
public class bad_case_5 {
    private static bad_case_5 instance;
    private Retrofit retrofit;
    // ruleid: java-thread-safe-object-in-singleton
    private Map<String, Object> apiResponses = new HashMap<>();
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_5() {
        retrofit = new Retrofit.Builder()
                .baseUrl("https://api.example.com/")
                .addConverterFactory(GsonConverterFactory.create())
                .build();
    }
    
    public static bad_case_5 getInstance() {
        if (instance == null) {
            instance = new bad_case_5();
        }
        return instance;
    }
    
    public void cacheApiResponse(String endpoint, Object response) {
        apiResponses.put(endpoint, response);
    }
    
    public Object getCachedResponse(String endpoint) {
        return apiResponses.get(endpoint);
    }
}
// {/fact}

// Example 6: Apache Commons Exec singleton with non-thread-safe state
public class bad_case_6 {
    private static bad_case_6 instance;
    // ruleid: java-thread-safe-object-in-singleton
    private CommandLine commandLine;
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_6() {}
    
    public static bad_case_6 getInstance() {
        if (instance == null) {
            instance = new bad_case_6();
        }
        return instance;
    }
    
    public String executeCommand(String command) throws IOException {
        commandLine = CommandLine.parse(command);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        DefaultExecutor executor = new DefaultExecutor();
        PumpStreamHandler streamHandler = new PumpStreamHandler(outputStream);
        executor.setStreamHandler(streamHandler);
        executor.execute(commandLine);
        return outputStream.toString();
    }
}
// {/fact}

// Example 7: JDBC Connection singleton with non-thread-safe state
public class bad_case_7 {
    private static bad_case_7 instance;
    private Connection connection;
    // ruleid: java-thread-safe-object-in-singleton
    private Statement statement;
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_7() {
        try {
            connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            statement = connection.createStatement();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    public static bad_case_7 getInstance() {
        if (instance == null) {
            instance = new bad_case_7();
        }
        return instance;
    }
    
    public ResultSet executeQuery(String query) throws SQLException {
        return statement.executeQuery(query);
    }
}
// {/fact}

// Example 8: Redis client singleton with non-thread-safe state
public class bad_case_8 {
    private static bad_case_8 instance;
    private Jedis jedis;
    // ruleid: java-thread-safe-object-in-singleton
    private String lastKey;
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_8() {
        jedis = new Jedis("localhost");
    }
    
    public static bad_case_8 getInstance() {
        if (instance == null) {
            instance = new bad_case_8();
        }
        return instance;
    }
    
    public String getValue(String key) {
        lastKey = key;
        return jedis.get(key);
    }
    
    public String getLastKey() {
        return lastKey;
    }
}
// {/fact}

// Example 9: MongoDB client singleton with non-thread-safe state
public class bad_case_9 {
    private static bad_case_9 instance;
    private MongoClient mongoClient;
    // ruleid: java-thread-safe-object-in-singleton
    private Document lastDocument;
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_9() {
        mongoClient = new MongoClient("localhost", 27017);
    }
    
    public static bad_case_9 getInstance() {
        if (instance == null) {
            instance = new bad_case_9();
        }
        return instance;
    }
    
    public void saveDocument(String collection, Document document) {
        mongoClient.getDatabase("mydb").getCollection(collection).insertOne(document);
        lastDocument = document;
    }
    
    public Document getLastDocument() {
        return lastDocument;
    }
}
// {/fact}

// Example 10: Hibernate session factory singleton with non-thread-safe state
public class bad_case_10 {
    private static bad_case_10 instance;
    private SessionFactory sessionFactory;
    // ruleid: java-thread-safe-object-in-singleton
    private Session currentSession;
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_10() {
        // Initialize sessionFactory
    }
    
    public static bad_case_10 getInstance() {
        if (instance == null) {
            instance = new bad_case_10();
        }
        return instance;
    }
    
    public void beginTransaction() {
        currentSession = sessionFactory.openSession();
        currentSession.beginTransaction();
    }
    
    public Session getCurrentSession() {
        return currentSession;
    }
}
// {/fact}

// Example 11: JMS singleton with non-thread-safe state
public class bad_case_11 {
    private static bad_case_11 instance;
    private Connection connection;
    // ruleid: java-thread-safe-object-in-singleton
    private Session session;
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_11() {
        try {
            // Initialize connection
            session = connection.createSession(false, Session.AUTO_AC_REDACTED_TWILIO_ID);
        } catch (JMSException e) {
            e.printStackTrace();
        }
    }
    
    public static bad_case_11 getInstance() {
        if (instance == null) {
            instance = new bad_case_11();
        }
        return instance;
    }
    
    public void sendMessage(String queueName, String messageText) throws JMSException {
        Queue queue = session.createQueue(queueName);
        MessageProducer producer = session.createProducer(queue);
        TextMessage message = session.createTextMessage(messageText);
        producer.send(message);
    }
}
// {/fact}

// Example 12: Kafka producer singleton with non-thread-safe state
public class bad_case_12 {
    private static bad_case_12 instance;
    private KafkaProducer<String, String> producer;
    // ruleid: java-thread-safe-object-in-singleton
    private String lastTopic;
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_12() {
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        producer = new KafkaProducer<>(props);
    }
    
    public static bad_case_12 getInstance() {
        if (instance == null) {
            instance = new bad_case_12();
        }
        return instance;
    }
    
    public void sendMessage(String topic, String message) {
        lastTopic = topic;
        producer.send(new ProducerRecord<>(topic, message));
    }
    
    public String getLastTopic() {
        return lastTopic;
    }
}
// {/fact}

// Example 13: RabbitMQ client singleton with non-thread-safe state
public class bad_case_13 {
    private static bad_case_13 instance;
    private Connection connection;
    private Channel channel;
    // ruleid: java-thread-safe-object-in-singleton
    private String lastQueue;
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_13() {
        try {
            ConnectionFactory factory = new ConnectionFactory();
            factory.setHost("localhost");
            connection = factory.newConnection();
            channel = connection.createChannel();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static bad_case_13 getInstance() {
        if (instance == null) {
            instance = new bad_case_13();
        }
        return instance;
    }
    
    public void sendMessage(String queue, String message) throws Exception {
        lastQueue = queue;
        channel.queueDeclare(queue, false, false, false, null);
        channel.basicPublish("", queue, null, message.getBytes());
    }
    
    public String getLastQueue() {
        return lastQueue;
    }
}
// {/fact}

// Example 14: Quartz scheduler singleton with non-thread-safe state
public class bad_case_14 {
    private static bad_case_14 instance;
    private Scheduler scheduler;
    // ruleid: java-thread-safe-object-in-singleton
    private JobDetail lastJob;
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_14() {
        try {
            scheduler = StdSchedulerFactory.getDefaultScheduler();
            scheduler.start();
        } catch (SchedulerException e) {
            e.printStackTrace();
        }
    }
    
    public static bad_case_14 getInstance() {
        if (instance == null) {
            instance = new bad_case_14();
        }
        return instance;
    }
    
    public void scheduleJob(JobDetail job, Trigger trigger) throws SchedulerException {
        lastJob = job;
        scheduler.scheduleJob(job, trigger);
    }
    
    public JobDetail getLastJob() {
        return lastJob;
    }
}
// {/fact}

// Example 15: Azure Blob Storage singleton with non-thread-safe state
public class bad_case_15 {
    private static bad_case_15 instance;
    private BlobServiceClient blobServiceClient;
    // ruleid: java-thread-safe-object-in-singleton
    private List<String> uploadedBlobs = new ArrayList<>();
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_15() {
        blobServiceClient = new BlobServiceClientBuilder()
                .connectionString("connection-string")
                .buildClient();
    }
    
    public static bad_case_15 getInstance() {
        if (instance == null) {
            instance = new bad_case_15();
        }
        return instance;
    }
    
    public void uploadBlob(String containerName, String blobName, InputStream data) {
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient(containerName);
        BlobClient blobClient = containerClient.getBlobClient(blobName);
        blobClient.upload(data, true);
        uploadedBlobs.add(blobName);
    }
    
    public List<String> getUploadedBlobs() {
        return uploadedBlobs;
    }
}
// {/fact}

// True Negative Examples (Safe/Secure Code)

// Example 1: Spring Controller as Singleton with thread-safe SimpleDateFormat
@Controller
public class good_case_1 {
    // ok: java-thread-safe-object-in-singleton
    private final ThreadLocal<SimpleDateFormat> dateFormat = 
        ThreadLocal.withInitial(() -> new SimpleDateFormat("yyyy-MM-dd"));
    
    @GetMapping("/format-date")
    public String formatDate(@RequestParam String date) {
        try {
            SimpleDateFormat formatter = dateFormat.get();
            return formatter.format(formatter.parse(date));
        } catch (Exception e) {
            return "Error parsing date";
        }
    }
}

// Example 2: Singleton with thread-safe StringBuilder usage
public class good_case_2 {
    private static good_case_2 instance;
    
// {fact rule=thread-safety-violation@v1.0 defects=0}
    private good_case_2() {}
    
    public static synchronized good_case_2 getInstance() {
        if (instance == null) {
            instance = new good_case_2();
        }
        return instance;
    }
    
    public String processRequest(HttpServletRequest request) {
        String message = request.getParameter("message");
        // ok: java-thread-safe-object-in-singleton
        StringBuilder messageBuilder = new StringBuilder();
        messageBuilder.append(message);
        return messageBuilder.toString();
    }
}
// {/fact}

// Example 3: OkHttp client singleton with thread-safe state
public class good_case_3 {
    private static good_case_3 instance;
    private final OkHttpClient client = new OkHttpClient();
    
// {fact rule=thread-safety-violation@v1.0 defects=0}
    private good_case_3() {}
    
    public static good_case_3 getInstance() {
        if (instance == null) {
            instance = new good_case_3();
        }
        return instance;
    }
    
    public String fetchData(String url) throws IOException {
        Request request = new Request.Builder().url(url).build();
        try (Response response = client.newCall(request).execute()) {
            // ok: java-thread-safe-object-in-singleton
            return response.body().string();
        }
    }
}
// {/fact}

// Example 4: AWS S3 Client singleton with thread-safe collection
public class good_case_4 {
    private static good_case_4 instance;
    private final AmazonS3 s3Client;
    // ok: java-thread-safe-object-in-singleton
    private final ConcurrentLinkedQueue<String> uploadedFiles = new ConcurrentLinkedQueue<>();
    
// {fact rule=thread-safety-violation@v1.0 defects=0}
    private good_case_4() {
        s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .build();
    }
    
    public static good_case_4 getInstance() {
        if (instance == null) {
            instance = new good_case_4();
        }
        return instance;
    }
    
    public void uploadFile(String bucketName, String key, InputStream data) {
        s3Client.putObject(bucketName, key, data, null);
        uploadedFiles.add(key);
    }
    
    public List<String> getUploadedFiles() {
        return new ArrayList<>(uploadedFiles);
    }
}
// {/fact}

// Example 5: Retrofit API Client singleton with thread-safe map
public class good_case_5 {
    private static good_case_5 instance;
    private final Retrofit retrofit;
    // ok: java-thread-safe-object-in-singleton
    private final ConcurrentHashMap<String, Object> apiResponses = new ConcurrentHashMap<>();
    
// {fact rule=thread-safety-violation@v1.0 defects=0}
    private good_case_5() {
        retrofit = new Retrofit.Builder()
                .baseUrl("https://api.example.com/")
                .addConverterFactory(GsonConverterFactory.create())
                .build();
    }
    
    public static good_case_5 getInstance() {
        if (instance == null) {
            instance = new good_case_5();
        }
        return instance;
    }
    
    public void cacheApiResponse(String endpoint, Object response) {
        apiResponses.put(endpoint, response);
    }
    
    public Object getCachedResponse(String endpoint) {
        return apiResponses.get(endpoint);
    }
}
// {/fact}

// Example 6: Apache Commons Exec singleton with thread-safe approach
public class good_case_6 {
    private static good_case_6 instance;
    
// {fact rule=thread-safety-violation@v1.0 defects=0}
    private good_case_6() {}
    
    public static good_case_6 getInstance() {
        if (instance == null) {
            instance = new good_case_6();
        }
        return instance;
    }
    
    public String executeCommand(String command) throws IOException {
        // ok: java-thread-safe-object-in-singleton
        CommandLine commandLine = CommandLine.parse(command);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        DefaultExecutor executor = new DefaultExecutor();
        PumpStreamHandler streamHandler = new PumpStreamHandler(outputStream);
        executor.setStreamHandler(streamHandler);
        executor.execute(commandLine);
        return outputStream.toString();
    }
}
// {/fact}

// Example 7: JDBC Connection singleton with thread-safe approach
public class good_case_7 {
    private static good_case_7 instance;
    private final DataSource dataSource;
    
// {fact rule=thread-safety-violation@v1.0 defects=0}
    private good_case_7() {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
        config.setUsername("user");
        config.setPassword("password");
        dataSource = new HikariDataSource(config);
    }
    
    public static good_case_7 getInstance() {
        if (instance == null) {
            instance = new good_case_7();
        }
        return instance;
    }
    
    public ResultSet executeQuery(String query) throws SQLException {
        // ok: java-thread-safe-object-in-singleton
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {
            return statement.executeQuery(query);
        }
    }
}
// {/fact}

// Example 8: Redis client singleton with thread-safe approach
public class good_case_8 {
    private static good_case_8 instance;
    private final JedisPool jedisPool;
    
// {fact rule=thread-safety-violation@v1.0 defects=0}
    private good_case_8() {
        jedisPool = new JedisPool("localhost", 6379);
    }
    
    public static good_case_8 getInstance() {
        if (instance == null) {
            instance = new good_case_8();
        }
        return instance;
    }
    
    public String getValue(String key) {
        // ok: java-thread-safe-object-in-singleton
        try (Jedis jedis = jedisPool.getResource()) {
            return jedis.get(key);
        }
    }
}
// {/fact}

// Example 9: MongoDB client singleton with thread-safe approach
public class good_case_9 {
    private static good_case_9 instance;
    private final MongoClient mongoClient;
    
// {fact rule=thread-safety-violation@v1.0 defects=0}
    private good_case_9() {
        mongoClient = new MongoClient("localhost", 27017);
    }
    
    public static good_case_9 getInstance() {
        if (instance == null) {
            instance = new good_case_9();
        }
        return instance;
    }
    
    public void saveDocument(String collection, Document document) {
        // ok: java-thread-safe-object-in-singleton
        mongoClient.getDatabase("mydb").getCollection(collection).insertOne(document);
    }
}
// {/fact}

// Example 10: Hibernate session factory singleton with thread-safe approach
public class good_case_10 {
    private static good_case_10 instance;
    private final SessionFactory sessionFactory;
    
// {fact rule=thread-safety-violation@v1.0 defects=0}
    private good_case_10() {
        // Initialize sessionFactory
        sessionFactory = null; // Placeholder
    }
    
    public static good_case_10 getInstance() {
        if (instance == null) {
            instance = new good_case_10();
        }
        return instance;
    }
    
    public Session getSession() {
        // ok: java-thread-safe-object-in-singleton
        return sessionFactory.openSession();
    }
    
    public void executeInTransaction(Consumer<Session> operation) {
        try (Session session = sessionFactory.openSession()) {
            session.beginTransaction();
            try {
                operation.accept(session);
                session.getTransaction().commit();
            } catch (Exception e) {
                session.getTransaction().rollback();
                throw e;
            }
        }
    }
}
// {/fact}

// Example 11: JMS singleton with thread-safe approach
public class good_case_11 {
    private static good_case_11 instance;
    private final ConnectionFactory connectionFactory;
    
// {fact rule=thread-safety-violation@v1.0 defects=0}
    private good_case_11() {
        // Initialize connectionFactory
        connectionFactory = null; // Placeholder
    }
    
    public static good_case_11 getInstance() {
        if (instance == null) {
            instance = new good_case_11();
        }
        return instance;
    }
    
    public void sendMessage(String queueName, String messageText) throws JMSException {
        // ok: java-thread-safe-object-in-singleton
        try (Connection connection = connectionFactory.createConnection();
             Session session = connection.createSession(false, Session.AUTO_AC_REDACTED_TWILIO_ID)) {
            Queue queue = session.createQueue(queueName);
            MessageProducer producer = session.createProducer(queue);
            TextMessage message = session.createTextMessage(messageText);
            producer.send(message);
        }
    }
}
// {/fact}

// Example 12: Kafka producer singleton with thread-safe approach
public class good_case_12 {
    private static good_case_12 instance;
    private final KafkaProducer<String, String> producer;
    
// {fact rule=thread-safety-violation@v1.0 defects=0}
    private good_case_12() {
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        producer = new KafkaProducer<>(props);
    }
    
    public static good_case_12 getInstance() {
        if (instance == null) {
            instance = new good_case_12();
        }
        return instance;
    }
    
    public void sendMessage(String topic, String message) {
        // ok: java-thread-safe-object-in-singleton
        producer.send(new ProducerRecord<>(topic, message));
    }
}
// {/fact}

// Example 13: RabbitMQ client singleton with thread-safe approach
public class good_case_13 {
    private static good_case_13 instance;
    private final ConnectionFactory factory;
    
// {fact rule=thread-safety-violation@v1.0 defects=0}
    private good_case_13() {
        factory = new ConnectionFactory();
        factory.setHost("localhost");
    }
    
    public static good_case_13 getInstance() {
        if (instance == null) {
            instance = new good_case_13();
        }
        return instance;
    }
    
    public void sendMessage(String queue, String message) throws Exception {
        // ok: java-thread-safe-object-in-singleton
        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(queue, false, false, false, null);
            channel.basicPublish("", queue, null, message.getBytes());
        }
    }
}
// {/fact}

// Example 14: Quartz scheduler singleton with thread-safe approach
public class good_case_14 {
    private static good_case_14 instance;
    private final Scheduler scheduler;
    
// {fact rule=thread-safety-violation@v1.0 defects=0}
    private good_case_14() {
        try {
            scheduler = StdSchedulerFactory.getDefaultScheduler();
            scheduler.start();
        } catch (SchedulerException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static good_case_14 getInstance() {
        if (instance == null) {
            instance = new good_case_14();
        }
        return instance;
    }
    
    public void scheduleJob(JobDetail job, Trigger trigger) throws SchedulerException {
        // ok: java-thread-safe-object-in-singleton
        scheduler.scheduleJob(job, trigger);
    }
}
// {/fact}

// Example 15: Azure Blob Storage singleton with thread-safe collection
public class good_case_15 {
    private static good_case_15 instance;
    private final BlobServiceClient blobServiceClient;
    // ok: java-thread-safe-object-in-singleton
    private final CopyOnWriteArrayList<String> uploadedBlobs = new CopyOnWriteArrayList<>();
    
// {fact rule=thread-safety-violation@v1.0 defects=0}
    private good_case_15() {
        blobServiceClient = new BlobServiceClientBuilder()
                .connectionString("connection-string")
                .buildClient();
    }
    
    public static good_case_15 getInstance() {
        if (instance == null) {
            instance = new good_case_15();
        }
        return instance;
    }
    
    public void uploadBlob(String containerName, String blobName, InputStream data) {
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient(containerName);
        BlobClient blobClient = containerClient.getBlobClient(blobName);
        blobClient.upload(data, true);
        uploadedBlobs.add(blobName);
    }
    
    public List<String> getUploadedBlobs() {
        return new ArrayList<>(uploadedBlobs);
    }
}
// {/fact}