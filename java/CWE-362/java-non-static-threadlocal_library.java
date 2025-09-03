import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.client.methods.HttpGet;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.io.FileUtils;
import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import javax.jms.Queue;
import javax.jms.QueueConnectionFactory;
import org.apache.activemq.ActiveMQConnectionFactory;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.quartz.Job;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import redis.clients.jedis.Jedis;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.ConnectionFactory;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

// Security Issue: ThreadLocal fields without the static modifier can lead to memory leaks

// True Positive Examples (Vulnerable/Insecure Code)

class bad_case_1 {
    // Spring Web MVC controller with non-static ThreadLocal
    @RestController
    public class UserController {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<String> userContext = new ThreadLocal<>();
        
        @GetMapping("/user")
        public String getUser(HttpServletRequest request) {
            String userId = request.getParameter("id");
            userContext.set(userId);
            // Process user data
            String result = processUserData();
            userContext.remove(); // Even with proper cleanup, non-static is problematic
            return result;
        }
        
        private String processUserData() {
            return "Processed: " + userContext.get();
        }
    }
}

class bad_case_2 {
    // Apache HttpClient with non-static ThreadLocal for connection tracking
    public class HttpClientWrapper {
        private HttpClient httpClient = HttpClients.createDefault();
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<HttpGet> requestContext = new ThreadLocal<>();
        
        public String fetchData(String url) {
            HttpGet request = new HttpGet(url);
            requestContext.set(request);
            try {
                // Execute request using the ThreadLocal context
                return httpClient.execute(request).toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            } finally {
                requestContext.remove();
            }
        }
    }
}

class bad_case_3 {
    // AWS SDK with non-static ThreadLocal for credentials
    public class S3FileUploader {
        private AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<String> sessionToken = new ThreadLocal<>();
        
        public void uploadFile(String bucketName, String key, File file) {
            sessionToken.set(generateSessionToken());
            try {
                s3Client.putObject(bucketName, key, file);
                System.out.println("Using token: " + sessionToken.get());
            } finally {
                sessionToken.remove();
            }
        }
        
        private String generateSessionToken() {
            return "token-" + System.currentTimeMillis();
        }
    }
}

class bad_case_4 {
    // Jackson ObjectMapper with non-static ThreadLocal
    public class JsonProcessor {
        private ObjectMapper mapper = new ObjectMapper();
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<Object> currentObject = new ThreadLocal<>();
        
        public String serializeObject(Object obj) {
            currentObject.set(obj);
            try {
                return mapper.writeValueAsString(currentObject.get());
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            } finally {
                currentObject.remove();
            }
        }
    }
}

class bad_case_5 {
    // Hibernate with non-static ThreadLocal for session tracking
    public class HibernateDao {
        private SessionFactory sessionFactory;
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<Session> sessionContext = new ThreadLocal<>();
        
        public void saveEntity(Object entity) {
            Session session = sessionFactory.openSession();
            sessionContext.set(session);
            try {
                session.beginTransaction();
                session.save(entity);
                session.getTransaction().commit();
            } finally {
                sessionContext.get().close();
                sessionContext.remove();
            }
        }
    }
}

class bad_case_6 {
    // Log4j with non-static ThreadLocal for context
    public class LoggingService {
        private Logger logger = LogManager.getLogger(LoggingService.class);
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<String> loggingContext = new ThreadLocal<>();
        
        public void logOperation(String operation, String details) {
            loggingContext.set("Operation: " + operation);
            try {
                logger.info("{} - Details: {}", loggingContext.get(), details);
            } finally {
                loggingContext.remove();
            }
        }
    }
}

class bad_case_7 {
    // Retrofit API client with non-static ThreadLocal
    public class ApiClient {
        private Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://api.example.com/")
                .addConverterFactory(GsonConverterFactory.create())
                .build();
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<String> apiToken = new ThreadLocal<>();
        
        public void executeApiCall(String token, String endpoint) {
            apiToken.set(token);
            try {
                // Use apiToken.get() for authentication in API calls
                System.out.println("Calling " + endpoint + " with token: " + apiToken.get());
            } finally {
                apiToken.remove();
            }
        }
    }
}

class bad_case_8 {
    // OkHttp client with non-static ThreadLocal
    public class HttpService {
        private OkHttpClient client = new OkHttpClient();
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<Request> currentRequest = new ThreadLocal<>();
        
        public String makeRequest(String url) {
            Request request = new Request.Builder().url(url).build();
            currentRequest.set(request);
            try {
                return client.newCall(currentRequest.get()).execute().body().string();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            } finally {
                currentRequest.remove();
            }
        }
    }
}

class bad_case_9 {
    // Apache Commons Exec with non-static ThreadLocal
    public class CommandExecutor {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<CommandLine> commandContext = new ThreadLocal<>();
        
        public int executeCommand(String command) {
            CommandLine cmdLine = CommandLine.parse(command);
            commandContext.set(cmdLine);
            try {
                DefaultExecutor executor = new DefaultExecutor();
                return executor.execute(commandContext.get());
            } catch (Exception e) {
                return -1;
            } finally {
                commandContext.remove();
            }
        }
    }
}

class bad_case_10 {
    // JDBC with non-static ThreadLocal for connection management
    public class DatabaseService {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<Connection> connectionContext = new ThreadLocal<>();
        
        public void executeQuery(String sql, String param) {
            try {
                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "pass");
                connectionContext.set(conn);
                PreparedStatement stmt = connectionContext.get().prepareStatement(sql);
                stmt.setString(1, param);
                stmt.executeQuery();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    if (connectionContext.get() != null) {
                        connectionContext.get().close();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                connectionContext.remove();
            }
        }
    }
}

class bad_case_11 {
    // ActiveMQ JMS with non-static ThreadLocal
    public class MessageService {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<javax.jms.Session> jmsSession = new ThreadLocal<>();
        
        public void sendMessage(String message) {
            try {
                QueueConnectionFactory factory = new ActiveMQConnectionFactory("tcp://localhost:61616");
                javax.jms.Connection connection = factory.createConnection();
                javax.jms.Session session = connection.createSession(false, javax.jms.Session.AUTO_AC_REDACTED_TWILIO_ID);
                jmsSession.set(session);
                
                Queue queue = jmsSession.get().createQueue("testQueue");
                javax.jms.MessageProducer producer = jmsSession.get().createProducer(queue);
                javax.jms.TextMessage textMessage = jmsSession.get().createTextMessage(message);
                producer.send(textMessage);
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                jmsSession.remove();
            }
        }
    }
}

class bad_case_12 {
    // Quartz Scheduler with non-static ThreadLocal
    public class ScheduledJob implements Job {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<JobExecutionContext> jobContext = new ThreadLocal<>();
        
        @Override
        public void execute(JobExecutionContext context) throws JobExecutionException {
            jobContext.set(context);
            try {
                // Use job context from ThreadLocal
                System.out.println("Executing job: " + jobContext.get().getJobDetail().getKey());
            } finally {
                jobContext.remove();
            }
        }
    }
}

class bad_case_13 {
    // Google Cloud Storage with non-static ThreadLocal
    public class CloudStorageService {
        private Storage storage = StorageOptions.getDefaultInstance().getService();
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<String> bucketContext = new ThreadLocal<>();
        
        public void uploadFile(String bucketName, String fileName, byte[] content) {
            bucketContext.set(bucketName);
            try {
                storage.create(
                    com.google.cloud.storage.BlobInfo.newBuilder(bucketContext.get(), fileName).build(),
                    content
                );
            } finally {
                bucketContext.remove();
            }
        }
    }
}

class bad_case_14 {
    // Kafka Producer with non-static ThreadLocal
    public class KafkaMessageSender {
        private KafkaProducer<String, String> producer;
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<String> topicContext = new ThreadLocal<>();
        
        public void sendMessage(String topic, String key, String value) {
            topicContext.set(topic);
            try {
                producer.send(new ProducerRecord<>(topicContext.get(), key, value));
            } finally {
                topicContext.remove();
            }
        }
    }
}

class bad_case_15 {
    // Redis Jedis client with non-static ThreadLocal
    public class RedisService {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<Jedis> jedisContext = new ThreadLocal<>();
        
        public String getValue(String key) {
            Jedis jedis = new Jedis("localhost");
            jedisContext.set(jedis);
            try {
                return jedisContext.get().get(key);
            } finally {
                jedisContext.get().close();
                jedisContext.remove();
            }
        }
    }
}

// True Negative Examples (Safe/Secure Code)

class good_case_1 {
    // Spring Web MVC controller with static ThreadLocal
    @RestController
    public class UserController {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<String> userContext = new ThreadLocal<>();
        
        @GetMapping("/user")
        public String getUser(HttpServletRequest request) {
            String userId = request.getParameter("id");
            userContext.set(userId);
            // Process user data
            String result = processUserData();
            userContext.remove();
            return result;
        }
        
        private String processUserData() {
            return "Processed: " + userContext.get();
        }
    }
}

class good_case_2 {
    // Apache HttpClient with static ThreadLocal for connection tracking
    public class HttpClientWrapper {
        private HttpClient httpClient = HttpClients.createDefault();
        // ok: java-non-static-threadlocal
        private static ThreadLocal<HttpGet> requestContext = new ThreadLocal<>();
        
        public String fetchData(String url) {
            HttpGet request = new HttpGet(url);
            requestContext.set(request);
            try {
                // Execute request using the ThreadLocal context
                return httpClient.execute(request).toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            } finally {
                requestContext.remove();
            }
        }
    }
}

class good_case_3 {
    // AWS SDK with static ThreadLocal for credentials
    public class S3FileUploader {
        private AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        // ok: java-non-static-threadlocal
        private static ThreadLocal<String> sessionToken = new ThreadLocal<>();
        
        public void uploadFile(String bucketName, String key, File file) {
            sessionToken.set(generateSessionToken());
            try {
                s3Client.putObject(bucketName, key, file);
                System.out.println("Using token: " + sessionToken.get());
            } finally {
                sessionToken.remove();
            }
        }
        
        private String generateSessionToken() {
            return "token-" + System.currentTimeMillis();
        }
    }
}

class good_case_4 {
    // Jackson ObjectMapper with static ThreadLocal
    public class JsonProcessor {
        private ObjectMapper mapper = new ObjectMapper();
        // ok: java-non-static-threadlocal
        private static ThreadLocal<Object> currentObject = new ThreadLocal<>();
        
        public String serializeObject(Object obj) {
            currentObject.set(obj);
            try {
                return mapper.writeValueAsString(currentObject.get());
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            } finally {
                currentObject.remove();
            }
        }
    }
}

class good_case_5 {
    // Hibernate with static ThreadLocal for session tracking
    public class HibernateDao {
        private SessionFactory sessionFactory;
        // ok: java-non-static-threadlocal
        private static ThreadLocal<Session> sessionContext = new ThreadLocal<>();
        
        public void saveEntity(Object entity) {
            Session session = sessionFactory.openSession();
            sessionContext.set(session);
            try {
                session.beginTransaction();
                session.save(entity);
                session.getTransaction().commit();
            } finally {
                sessionContext.get().close();
                sessionContext.remove();
            }
        }
    }
}

class good_case_6 {
    // Log4j with static ThreadLocal for context
    public class LoggingService {
        private Logger logger = LogManager.getLogger(LoggingService.class);
        // ok: java-non-static-threadlocal
        private static ThreadLocal<String> loggingContext = new ThreadLocal<>();
        
        public void logOperation(String operation, String details) {
            loggingContext.set("Operation: " + operation);
            try {
                logger.info("{} - Details: {}", loggingContext.get(), details);
            } finally {
                loggingContext.remove();
            }
        }
    }
}

class good_case_7 {
    // Retrofit API client with static ThreadLocal
    public class ApiClient {
        private Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://api.example.com/")
                .addConverterFactory(GsonConverterFactory.create())
                .build();
        // ok: java-non-static-threadlocal
        private static ThreadLocal<String> apiToken = new ThreadLocal<>();
        
        public void executeApiCall(String token, String endpoint) {
            apiToken.set(token);
            try {
                // Use apiToken.get() for authentication in API calls
                System.out.println("Calling " + endpoint + " with token: " + apiToken.get());
            } finally {
                apiToken.remove();
            }
        }
    }
}

class good_case_8 {
    // OkHttp client with static ThreadLocal
    public class HttpService {
        private OkHttpClient client = new OkHttpClient();
        // ok: java-non-static-threadlocal
        private static ThreadLocal<Request> currentRequest = new ThreadLocal<>();
        
        public String makeRequest(String url) {
            Request request = new Request.Builder().url(url).build();
            currentRequest.set(request);
            try {
                return client.newCall(currentRequest.get()).execute().body().string();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            } finally {
                currentRequest.remove();
            }
        }
    }
}

class good_case_9 {
    // Apache Commons Exec with static ThreadLocal
    public class CommandExecutor {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<CommandLine> commandContext = new ThreadLocal<>();
        
        public int executeCommand(String command) {
            CommandLine cmdLine = CommandLine.parse(command);
            commandContext.set(cmdLine);
            try {
                DefaultExecutor executor = new DefaultExecutor();
                return executor.execute(commandContext.get());
            } catch (Exception e) {
                return -1;
            } finally {
                commandContext.remove();
            }
        }
    }
}

class good_case_10 {
    // JDBC with static ThreadLocal for connection management
    public class DatabaseService {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<Connection> connectionContext = new ThreadLocal<>();
        
        public void executeQuery(String sql, String param) {
            try {
                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "pass");
                connectionContext.set(conn);
                PreparedStatement stmt = connectionContext.get().prepareStatement(sql);
                stmt.setString(1, param);
                stmt.executeQuery();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    if (connectionContext.get() != null) {
                        connectionContext.get().close();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                connectionContext.remove();
            }
        }
    }
}

class good_case_11 {
    // ActiveMQ JMS with static ThreadLocal
    public class MessageService {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<javax.jms.Session> jmsSession = new ThreadLocal<>();
        
        public void sendMessage(String message) {
            try {
                QueueConnectionFactory factory = new ActiveMQConnectionFactory("tcp://localhost:61616");
                javax.jms.Connection connection = factory.createConnection();
                javax.jms.Session session = connection.createSession(false, javax.jms.Session.AUTO_AC_REDACTED_TWILIO_ID);
                jmsSession.set(session);
                
                Queue queue = jmsSession.get().createQueue("testQueue");
                javax.jms.MessageProducer producer = jmsSession.get().createProducer(queue);
                javax.jms.TextMessage textMessage = jmsSession.get().createTextMessage(message);
                producer.send(textMessage);
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                jmsSession.remove();
            }
        }
    }
}

class good_case_12 {
    // Quartz Scheduler with static ThreadLocal
    public class ScheduledJob implements Job {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<JobExecutionContext> jobContext = new ThreadLocal<>();
        
        @Override
        public void execute(JobExecutionContext context) throws JobExecutionException {
            jobContext.set(context);
            try {
                // Use job context from ThreadLocal
                System.out.println("Executing job: " + jobContext.get().getJobDetail().getKey());
            } finally {
                jobContext.remove();
            }
        }
    }
}

class good_case_13 {
    // Google Cloud Storage with static ThreadLocal
    public class CloudStorageService {
        private Storage storage = StorageOptions.getDefaultInstance().getService();
        // ok: java-non-static-threadlocal
        private static ThreadLocal<String> bucketContext = new ThreadLocal<>();
        
        public void uploadFile(String bucketName, String fileName, byte[] content) {
            bucketContext.set(bucketName);
            try {
                storage.create(
                    com.google.cloud.storage.BlobInfo.newBuilder(bucketContext.get(), fileName).build(),
                    content
                );
            } finally {
                bucketContext.remove();
            }
        }
    }
}

class good_case_14 {
    // Kafka Producer with static ThreadLocal
    public class KafkaMessageSender {
        private KafkaProducer<String, String> producer;
        // ok: java-non-static-threadlocal
        private static ThreadLocal<String> topicContext = new ThreadLocal<>();
        
        public void sendMessage(String topic, String key, String value) {
            topicContext.set(topic);
            try {
                producer.send(new ProducerRecord<>(topicContext.get(), key, value));
            } finally {
                topicContext.remove();
            }
        }
    }
}

class good_case_15 {
    // Redis Jedis client with static ThreadLocal
    public class RedisService {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<Jedis> jedisContext = new ThreadLocal<>();
        
        public String getValue(String key) {
            Jedis jedis = new Jedis("localhost");
            jedisContext.set(jedis);
            try {
                return jedisContext.get().get(key);
            } finally {
                jedisContext.get().close();
                jedisContext.remove();
            }
        }
    }
}