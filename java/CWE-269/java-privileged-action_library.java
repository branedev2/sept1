import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.security.PrivilegedActionException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Properties;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.io.FileUtils;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.jms.Connection;
import javax.jms.ConnectionFactory;
import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.MessageProducer;
import javax.jms.Queue;
import javax.jms.Session;
import org.apache.activemq.ActiveMQConnectionFactory;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import redis.clients.jedis.Jedis;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoDatabase;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.ConnectionFactory;
import org.quartz.JobBuilder;
import org.quartz.JobDetail;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.quartz.SimpleScheduleBuilder;
import org.quartz.Trigger;
import org.quartz.TriggerBuilder;
import org.quartz.impl.StdSchedulerFactory;

// Security Issue: Improper use of Java's privileged actions can lead to privilege escalation vulnerabilities (CWE-269)

// True Positive Examples (Vulnerable/Insecure Code)

public class PrivilegedActionExamples {
    private static final Logger logger = Logger.getLogger(PrivilegedActionExamples.class.getName());

    // Example 1: Using PrivilegedAction with a large scope in a Spring web controller
    @RestController
    public static class BadSpringExample {
// {fact rule=improper-privilege-management@v1.0 defects=1}
        @RequestMapping("/bad1")
        public String bad_case_1(HttpServletRequest request) {
            String fileName = request.getParameter("file");
            
            // ruleid: java-privileged-action
            return AccessController.doPrivileged(new PrivilegedAction<String>() {
                @Override
                public String run() {
                    // Too much code in privileged block
                    try {
                        // Read system properties
                        Properties props = System.getProperties();
                        
                        // Read file content
                        File file = new File(fileName);
                        String content = new String(Files.readAllBytes(file.toPath()));
                        
                        // Modify system properties
                        props.setProperty("user.config", content);
                        
                        return "Properties updated with file: " + fileName;
                    } catch (Exception e) {
                        return "Error: " + e.getMessage();
                    }
                }
            });
        }
    }
// {/fact}

    // Example 2: Using PrivilegedAction with Apache HTTP Client to download and execute code
// {fact rule=improper-privilege-management@v1.0 defects=1}
    public static void bad_case_2(HttpServletRequest request) {
        String url = request.getParameter("url");
        String outputPath = request.getParameter("output");
        
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet(url);
            
            // ruleid: java-privileged-action
            AccessController.doPrivileged(new PrivilegedAction<Void>() {
                @Override
                public Void run() {
                    try {
                        // Download file
                        File outputFile = new File(outputPath);
                        FileUtils.copyInputStreamToFile(
                            httpClient.execute(httpGet).getEntity().getContent(), 
                            outputFile
                        );
                        
                        // Set executable and execute
                        outputFile.setExecutable(true);
                        Runtime.getRuntime().exec(outputFile.getAbsolutePath());
                        
                        // Clean up
                        httpClient.close();
                    } catch (Exception e) {
                        logger.severe("Error: " + e.getMessage());
                    }
                    return null;
                }
            });
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Example 3: Using PrivilegedExceptionAction with AWS S3 SDK for file operations
    public static void bad_case_3(HttpServletRequest request) {
        String bucketName = request.getParameter("bucket");
        String objectKey = request.getParameter("key");
        String localPath = request.getParameter("path");
        
        try {
            // ruleid: java-privileged-action
            AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
                @Override
                public Void run() throws Exception {
                    // Create S3 client
                    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
                    
                    // Download file from S3
                    File localFile = new File(localPath);
                    s3Client.getObject(bucketName, objectKey, localFile);
                    
                    // Process file
                    if (localFile.exists()) {
                        // Read and modify system properties
                        Properties props = new Properties();
                        props.load(new FileInputStream(localFile));
                        
                        for (String propName : props.stringPropertyNames()) {
                            System.setProperty(propName, props.getProperty(propName));
                        }
                        
                        // Upload modified file back to S3
                        s3Client.putObject(bucketName, objectKey + ".modified", localFile);
                    }
                    return null;
                }
            });
        } catch (PrivilegedActionException e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Example 4: Using PrivilegedAction with Google Cloud Storage
    public static void bad_case_4(HttpServletRequest request) {
        String bucketName = request.getParameter("bucket");
        String blobName = request.getParameter("blob");
        String localPath = request.getParameter("path");
        
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                try {
                    // Initialize Google Cloud Storage
                    Storage storage = StorageOptions.getDefaultInstance().getService();
                    
                    // Download blob to local file
                    File localFile = new File(localPath);
                    com.google.cloud.storage.Blob blob = storage.get(bucketName, blobName);
                    blob.downloadTo(Paths.get(localPath));
                    
                    // Execute commands from the file
                    if (localFile.exists()) {
                        String content = new String(Files.readAllBytes(localFile.toPath()));
                        String[] commands = content.split("\n");
                        
                        for (String command : commands) {
                            if (!command.trim().isEmpty()) {
                                Runtime.getRuntime().exec(command.trim());
                            }
                        }
                    }
                } catch (Exception e) {
                    logger.severe("Error: " + e.getMessage());
                }
                return null;
            }
        });
    }

    // Example 5: Using PrivilegedAction with ActiveMQ JMS
    public static void bad_case_5(HttpServletRequest request) {
        String brokerUrl = request.getParameter("broker");
        String queueName = request.getParameter("queue");
        String configFile = request.getParameter("config");
        
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                Connection connection = null;
                Session session = null;
                
                try {
                    // Create JMS connection
                    ConnectionFactory factory = new ActiveMQConnectionFactory(brokerUrl);
                    connection = factory.createConnection();
                    session = connection.createSession(false, Session.AUTO_AC_REDACTED_TWILIO_ID);
                    
                    // Read configuration file
                    Properties props = new Properties();
                    props.load(new FileInputStream(configFile));
                    
                    // Apply system properties
                    for (String propName : props.stringPropertyNames()) {
                        System.setProperty(propName, props.getProperty(propName));
                    }
                    
                    // Send message to queue
                    Queue queue = session.createQueue(queueName);
                    MessageProducer producer = session.createProducer(queue);
                    Message message = session.createTextMessage("Configuration updated");
                    producer.send(message);
                    
                } catch (Exception e) {
                    logger.severe("Error: " + e.getMessage());
                } finally {
                    try {
                        if (session != null) session.close();
                        if (connection != null) connection.close();
                    } catch (JMSException e) {
                        logger.severe("Error closing resources: " + e.getMessage());
                    }
                }
                return null;
            }
        });
    }

    // Example 6: Using PrivilegedAction with Hibernate ORM
    public static void bad_case_6(HttpServletRequest request) {
        String configPath = request.getParameter("config");
        String query = request.getParameter("query");
        
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                SessionFactory sessionFactory = null;
                org.hibernate.Session session = null;
                
                try {
                    // Initialize Hibernate with custom configuration
                    Configuration config = new Configuration();
                    config.configure(new File(configPath));
                    sessionFactory = config.buildSessionFactory();
                    
                    // Open session and execute query
                    session = sessionFactory.openSession();
                    session.beginTransaction();
                    
                    // Execute potentially dangerous native SQL query
                    session.createNativeQuery(query).executeUpdate();
                    
                    session.getTransaction().commit();
                } catch (Exception e) {
                    logger.severe("Error: " + e.getMessage());
                    if (session != null && session.getTransaction().isActive()) {
                        session.getTransaction().rollback();
                    }
                } finally {
                    if (session != null) session.close();
                    if (sessionFactory != null) sessionFactory.close();
                }
                return null;
            }
        });
    }

    // Example 7: Using PrivilegedAction with Kafka Producer
    public static void bad_case_7(HttpServletRequest request) {
        String bootstrapServers = request.getParameter("servers");
        String topic = request.getParameter("topic");
        String configFile = request.getParameter("config");
        
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                KafkaProducer<String, String> producer = null;
                
                try {
                    // Load properties from file
                    Properties props = new Properties();
                    props.load(new FileInputStream(configFile));
                    
                    // Add Kafka-specific properties
                    props.put("bootstrap.servers", bootstrapServers);
                    props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
                    props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
                    
                    // Create producer and send message
                    producer = new KafkaProducer<>(props);
                    
                    // Read sensitive system properties and send them
                    Properties sysProps = System.getProperties();
                    for (String propName : sysProps.stringPropertyNames()) {
                        producer.send(new ProducerRecord<>(topic, propName, sysProps.getProperty(propName)));
                    }
                } catch (Exception e) {
                    logger.severe("Error: " + e.getMessage());
                } finally {
                    if (producer != null) producer.close();
                }
                return null;
            }
        });
    }

    // Example 8: Using PrivilegedAction with Redis client
    public static void bad_case_8(HttpServletRequest request) {
        String redisHost = request.getParameter("host");
        int redisPort = Integer.parseInt(request.getParameter("port"));
        String filePath = request.getParameter("file");
        
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                Jedis jedis = null;
                
                try {
                    // Connect to Redis
                    jedis = new Jedis(redisHost, redisPort);
                    
                    // Read file and store in Redis
                    File file = new File(filePath);
                    byte[] content = Files.readAllBytes(file.toPath());
                    
                    // Store file content in Redis
                    jedis.set(filePath.getBytes(), content);
                    
                    // Execute system commands based on Redis values
                    for (String key : jedis.keys("command:*")) {
                        String command = jedis.get(key);
                        Runtime.getRuntime().exec(command);
                    }
                } catch (Exception e) {
                    logger.severe("Error: " + e.getMessage());
                } finally {
                    if (jedis != null) jedis.close();
                }
                return null;
            }
        });
    }

    // Example 9: Using PrivilegedAction with MongoDB
    public static void bad_case_9(HttpServletRequest request) {
        String mongoHost = request.getParameter("host");
        int mongoPort = Integer.parseInt(request.getParameter("port"));
        String dbName = request.getParameter("db");
        String filePath = request.getParameter("file");
        
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                MongoClient mongoClient = null;
                
                try {
                    // Connect to MongoDB
                    mongoClient = new MongoClient(mongoHost, mongoPort);
                    MongoDatabase database = mongoClient.getDatabase(dbName);
                    
                    // Read file and store in MongoDB
                    File file = new File(filePath);
                    String content = new String(Files.readAllBytes(file.toPath()));
                    
                    // Create document and insert
                    org.bson.Document doc = new org.bson.Document("fileName", filePath)
                            .append("content", content);
                    
                    database.getCollection("files").insertOne(doc);
                    
                    // Update system properties
                    Properties props = new Properties();
                    props.load(new FileInputStream(file));
                    
                    for (String propName : props.stringPropertyNames()) {
                        System.setProperty(propName, props.getProperty(propName));
                    }
                } catch (Exception e) {
                    logger.severe("Error: " + e.getMessage());
                } finally {
                    if (mongoClient != null) mongoClient.close();
                }
                return null;
            }
        });
    }

    // Example 10: Using PrivilegedAction with RabbitMQ
    public static void bad_case_10(HttpServletRequest request) {
        String rabbitHost = request.getParameter("host");
        String queueName = request.getParameter("queue");
        String filePath = request.getParameter("file");
        
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                com.rabbitmq.client.Connection connection = null;
                Channel channel = null;
                
                try {
                    // Connect to RabbitMQ
                    ConnectionFactory factory = new ConnectionFactory();
                    factory.setHost(rabbitHost);
                    connection = factory.newConnection();
                    channel = connection.createChannel();
                    
                    // Declare queue
                    channel.queueDeclare(queueName, false, false, false, null);
                    
                    // Read file and send to queue
                    File file = new File(filePath);
                    byte[] content = Files.readAllBytes(file.toPath());
                    
                    // Send message
                    channel.basicPublish("", queueName, null, content);
                    
                    // Execute commands from file
                    String[] commands = new String(content).split("\n");
                    for (String command : commands) {
                        if (!command.trim().isEmpty()) {
                            Runtime.getRuntime().exec(command.trim());
                        }
                    }
                } catch (Exception e) {
                    logger.severe("Error: " + e.getMessage());
                } finally {
                    try {
                        if (channel != null) channel.close();
                        if (connection != null) connection.close();
                    } catch (Exception e) {
                        logger.severe("Error closing resources: " + e.getMessage());
                    }
                }
                return null;
            }
        });
    }

    // Example 11: Using PrivilegedAction with Quartz Scheduler
    public static void bad_case_11(HttpServletRequest request) {
        String jobName = request.getParameter("job");
        String cronExpression = request.getParameter("cron");
        String scriptPath = request.getParameter("script");
        
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                try {
                    // Initialize Quartz scheduler
                    Scheduler scheduler = StdSchedulerFactory.getDefaultScheduler();
                    scheduler.start();
                    
                    // Create job that executes a script
                    JobDetail job = JobBuilder.newJob(ScriptExecutionJob.class)
                            .withIdentity(jobName)
                            .usingJobData("scriptPath", scriptPath)
                            .build();
                    
                    // Schedule job with cron expression from request
                    Trigger trigger = TriggerBuilder.newTrigger()
                            .withIdentity(jobName + "Trigger")
                            .withSchedule(CronScheduleBuilder.cronSchedule(cronExpression))
                            .build();
                    
                    scheduler.scheduleJob(job, trigger);
                    
                    // Also immediately execute the script
                    File script = new File(scriptPath);
                    if (script.exists()) {
                        Runtime.getRuntime().exec("sh " + scriptPath);
                    }
                } catch (SchedulerException | IOException e) {
                    logger.severe("Error: " + e.getMessage());
                }
                return null;
            }
        });
    }

    // Example 12: Using PrivilegedAction with URL connection
    public static void bad_case_12(HttpServletRequest request) {
        String urlString = request.getParameter("url");
        String outputPath = request.getParameter("output");
        
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                try {
                    // Open URL connection
                    URL url = new URL(urlString);
                    URLConnection connection = url.openConnection();
                    
                    // Download content
                    byte[] content = connection.getInputStream().readAllBytes();
                    
                    // Save to file
                    File outputFile = new File(outputPath);
                    FileOutputStream fos = new FileOutputStream(outputFile);
                    fos.write(content);
                    fos.close();
                    
                    // Execute if it's a script
                    if (outputPath.endsWith(".sh") || outputPath.endsWith(".bat")) {
                        outputFile.setExecutable(true);
                        Runtime.getRuntime().exec(outputFile.getAbsolutePath());
                    }
                    
                    // Also modify system properties
                    if (outputPath.endsWith(".properties")) {
                        Properties props = new Properties();
                        props.load(new FileInputStream(outputFile));
                        
                        for (String propName : props.stringPropertyNames()) {
                            System.setProperty(propName, props.getProperty(propName));
                        }
                    }
                } catch (Exception e) {
                    logger.severe("Error: " + e.getMessage());
                }
                return null;
            }
        });
    }

    // Example 13: Using PrivilegedAction with custom implementation
    public static void bad_case_13(HttpServletRequest request) {
        String configPath = request.getParameter("config");
        
        // ruleid: java-privileged-action
        PrivilegedAction<Void> action = new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                try {
                    // Load configuration
                    Properties config = new Properties();
                    config.load(new FileInputStream(configPath));
                    
                    // Apply all properties as system properties
                    for (String propName : config.stringPropertyNames()) {
                        System.setProperty(propName, config.getProperty(propName));
                    }
                    
                    // Execute commands from configuration
                    String commandsProperty = config.getProperty("commands");
                    if (commandsProperty != null) {
                        String[] commands = commandsProperty.split(";");
                        for (String command : commands) {
                            Runtime.getRuntime().exec(command.trim());
                        }
                    }
                    
                    // Modify file permissions
                    String permissionsProperty = config.getProperty("permissions");
                    if (permissionsProperty != null) {
                        String[] permissions = permissionsProperty.split(";");
                        for (String permission : permissions) {
                            String[] parts = permission.split(":");
                            if (parts.length == 2) {
                                File file = new File(parts[0]);
                                if (file.exists()) {
                                    file.setExecutable("true".equals(parts[1]));
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    logger.severe("Error: " + e.getMessage());
                }
                return null;
            }
        };
        
        AccessController.doPrivileged(action);
    }

    // Example 14: Using PrivilegedAction with file system operations
    public static void bad_case_14(HttpServletRequest request) {
        String sourcePath = request.getParameter("source");
        String targetPath = request.getParameter("target");
        
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                try {
                    // Copy file with elevated privileges
                    Path source = Paths.get(sourcePath);
                    Path target = Paths.get(targetPath);
                    
                    // Read source file
                    byte[] content = Files.readAllBytes(source);
                    
                    // Write to target file
                    Files.write(target, content);
                    
                    // Set permissions
                    File targetFile = target.toFile();
                    targetFile.setReadable(true, false); // readable by everyone
                    targetFile.setWritable(true, false); // writable by everyone
                    targetFile.setExecutable(true, false); // executable by everyone
                    
                    // Also execute if it's a script
                    if (targetPath.endsWith(".sh") || targetPath.endsWith(".bat")) {
                        Runtime.getRuntime().exec(targetPath);
                    }
                } catch (Exception e) {
                    logger.severe("Error: " + e.getMessage());
                }
                return null;
            }
        });
    }

    // Example 15: Using PrivilegedAction with system property manipulation
    public static void bad_case_15(HttpServletRequest request) {
        String propertyFile = request.getParameter("properties");
        
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                try {
                    // Load properties from file
                    Properties props = new Properties();
                    props.load(new FileInputStream(propertyFile));
                    
                    // Apply all properties as system properties
                    for (String propName : props.stringPropertyNames()) {
                        System.setProperty(propName, props.getProperty(propName));
                    }
                    
                    // Create a new properties file with all system properties
                    Properties allProps = System.getProperties();
                    File outputFile = new File(propertyFile + ".all");
                    FileOutputStream fos = new FileOutputStream(outputFile);
                    allProps.store(fos, "All System Properties");
                    fos.close();
                    
                    // Make the file readable by everyone
                    outputFile.setReadable(true, false);
                } catch (Exception e) {
                    logger.severe("Error: " + e.getMessage());
                }
                return null;
            }
        });
    }

    // True Negative Examples (Safe/Secure Code)

    // Example 1: Properly scoped PrivilegedAction with Spring web controller
    @RestController
    public static class GoodSpringExample {
        @RequestMapping("/good1")
        public String good_case_1(HttpServletRequest request) {
            String fileName = request.getParameter("file");
            
            // Validate file path before using in privileged action
            File file = new File(fileName);
            if (!file.exists() || !file.isFile() || !file.canRead()) {
                return "Invalid file";
            }
            
            try {
                // ok: java-privileged-action
                String content = AccessController.doPrivileged(new PrivilegedAction<String>() {
                    @Override
                    public String run() {
                        try {
                            // Minimal privileged operation - just reading the file
                            return new String(Files.readAllBytes(file.toPath()));
                        } catch (IOException e) {
                            return "Error reading file: " + e.getMessage();
                        }
                    }
                });
                
                // Process content outside privileged block
                return "File content length: " + content.length();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }

    // Example 2: Properly scoped PrivilegedAction with Apache HTTP Client
    public static void good_case_2(HttpServletRequest request) {
        String url = request.getParameter("url");
        String outputPath = request.getParameter("output");
        
        try {
            // Validate parameters
            if (url == null || outputPath == null) {
                logger.warning("Invalid parameters");
                return;
            }
            
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet(url);
            
            // Download file outside privileged block
            File outputFile = new File(outputPath);
            FileUtils.copyInputStreamToFile(
                httpClient.execute(httpGet).getEntity().getContent(), 
                outputFile
            );
            
            // Only use privileged action for specific permission check
            // ok: java-privileged-action
            boolean canExecute = AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
                @Override
                public Boolean run() {
                    // Minimal privileged operation - just checking if file can be executed
                    return outputFile.canExecute();
                }
            });
            
            if (canExecute) {
                logger.info("File is executable");
            }
            
            httpClient.close();
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Example 3: Properly scoped PrivilegedExceptionAction with AWS S3 SDK
    public static void good_case_3(HttpServletRequest request) {
        String bucketName = request.getParameter("bucket");
        String objectKey = request.getParameter("key");
        String localPath = request.getParameter("path");
        
        try {
            // Create S3 client outside privileged block
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
            
            // Download file from S3 outside privileged block
            File localFile = new File(localPath);
            s3Client.getObject(bucketName, objectKey, localFile);
            
            // Only use privileged action for specific file operation
            // ok: java-privileged-action
            AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
                @Override
                public Void run() throws Exception {
                    // Minimal privileged operation - just reading the file
                    if (localFile.exists()) {
                        FileInputStream fis = new FileInputStream(localFile);
                        fis.close();
                    }
                    return null;
                }
            });
            
            // Process file outside privileged block
            if (localFile.exists()) {
                // Read properties
                Properties props = new Properties();
                props.load(new FileInputStream(localFile));
                
                // Use properties safely
                logger.info("Loaded " + props.size() + " properties");
            }
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Example 4: Properly scoped PrivilegedAction with Google Cloud Storage
    public static void good_case_4(HttpServletRequest request) {
        String bucketName = request.getParameter("bucket");
        String blobName = request.getParameter("blob");
        String localPath = request.getParameter("path");
        
        try {
            // Initialize Google Cloud Storage outside privileged block
            Storage storage = StorageOptions.getDefaultInstance().getService();
            
            // Get blob reference outside privileged block
            com.google.cloud.storage.Blob blob = storage.get(bucketName, blobName);
            
            if (blob != null) {
                // Use minimal privileged action for file operation
                // ok: java-privileged-action
                AccessController.doPrivileged(new PrivilegedAction<Void>() {
                    @Override
                    public Void run() {
                        try {
                            // Minimal privileged operation - just creating the file
                            File localFile = new File(localPath);
                            if (!localFile.exists()) {
                                localFile.createNewFile();
                            }
                        } catch (IOException e) {
                            logger.severe("Error creating file: " + e.getMessage());
                        }
                        return null;
                    }
                });
                
                // Download blob outside privileged block
                blob.downloadTo(Paths.get(localPath));
                
                // Process file outside privileged block
                File localFile = new File(localPath);
                if (localFile.exists()) {
                    logger.info("Downloaded blob size: " + localFile.length());
                }
            }
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Example 5: Properly scoped PrivilegedAction with ActiveMQ JMS
    public static void good_case_5(HttpServletRequest request) {
        String brokerUrl = request.getParameter("broker");
        String queueName = request.getParameter("queue");
        String configFile = request.getParameter("config");
        
        try {
            // Create JMS connection outside privileged block
            ConnectionFactory factory = new ActiveMQConnectionFactory(brokerUrl);
            Connection connection = factory.createConnection();
            Session session = connection.createSession(false, Session.AUTO_AC_REDACTED_TWILIO_ID);
            
            // Only use privileged action for file operation
            Properties props = new Properties();
            
            // ok: java-privileged-action
            boolean fileLoaded = AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
                @Override
                public Boolean run() {
                    try {
                        // Minimal privileged operation - just reading the file
                        File file = new File(configFile);
                        if (file.exists() && file.canRead()) {
                            props.load(new FileInputStream(file));
                            return true;
                        }
                        return false;
                    } catch (IOException e) {
                        logger.severe("Error reading file: " + e.getMessage());
                        return false;
                    }
                }
            });
            
            // Send message to queue outside privileged block
            if (fileLoaded) {
                Queue queue = session.createQueue(queueName);
                MessageProducer producer = session.createProducer(queue);
                Message message = session.createTextMessage("Configuration loaded with " + props.size() + " properties");
                producer.send(message);
            }
            
            // Close resources
            session.close();
            connection.close();
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Example 6: Properly scoped PrivilegedAction with Hibernate ORM
    public static void good_case_6(HttpServletRequest request) {
        String configPath = request.getParameter("config");
        String query = request.getParameter("query");
        
        try {
            // Validate query outside privileged block
            if (query == null || query.toLowerCase().contains("drop") || query.toLowerCase().contains("delete")) {
                logger.warning("Potentially dangerous query rejected");
                return;
            }
            
            // Only use privileged action for file operation
            // ok: java-privileged-action
            File configFile = AccessController.doPrivileged(new PrivilegedAction<File>() {
                @Override
                public File run() {
                    // Minimal privileged operation - just accessing the file
                    File file = new File(configPath);
                    return file.exists() && file.canRead() ? file : null;
                }
            });
            
            if (configFile != null) {
                // Initialize Hibernate outside privileged block
                Configuration config = new Configuration();
                config.configure(configFile);
                SessionFactory sessionFactory = config.buildSessionFactory();
                
                // Execute query outside privileged block
                org.hibernate.Session session = sessionFactory.openSession();
                session.beginTransaction();
                session.createNativeQuery(query).executeUpdate();
                session.getTransaction().commit();
                session.close();
                sessionFactory.close();
            }
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Example 7: Properly scoped PrivilegedAction with Kafka Producer
    public static void good_case_7(HttpServletRequest request) {
        String bootstrapServers = request.getParameter("servers");
        String topic = request.getParameter("topic");
        String configFile = request.getParameter("config");
        
        try {
            // Only use privileged action for file operation
            Properties fileProps = new Properties();
            
            // ok: java-privileged-action
            boolean configLoaded = AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
                @Override
                public Boolean run() {
                    try {
                        // Minimal privileged operation - just reading the file
                        File file = new File(configFile);
                        if (file.exists() && file.canRead()) {
                            fileProps.load(new FileInputStream(file));
                            return true;
                        }
                        return false;
                    } catch (IOException e) {
                        logger.severe("Error reading file: " + e.getMessage());
                        return false;
                    }
                }
            });
            
            if (configLoaded) {
                // Create Kafka properties outside privileged block
                Properties kafkaProps = new Properties();
                kafkaProps.put("bootstrap.servers", bootstrapServers);
                kafkaProps.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
                kafkaProps.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
                
                // Add properties from config file
                for (String propName : fileProps.stringPropertyNames()) {
                    kafkaProps.put(propName, fileProps.getProperty(propName));
                }
                
                // Create producer and send message outside privileged block
                KafkaProducer<String, String> producer = new KafkaProducer<>(kafkaProps);
                producer.send(new ProducerRecord<>(topic, "config", "loaded"));
                producer.close();
            }
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Example 8: Properly scoped PrivilegedAction with Redis client
    public static void good_case_8(HttpServletRequest request) {
        String redisHost = request.getParameter("host");
        int redisPort = Integer.parseInt(request.getParameter("port"));
        String filePath = request.getParameter("file");
        
        try {
            // Only use privileged action for file operation
            // ok: java-privileged-action
            byte[] fileContent = AccessController.doPrivileged(new PrivilegedAction<byte[]>() {
                @Override
                public byte[] run() {
                    try {
                        // Minimal privileged operation - just reading the file
                        File file = new File(filePath);
                        if (file.exists() && file.canRead()) {
                            return Files.readAllBytes(file.toPath());
                        }
                        return new byte[0];
                    } catch (IOException e) {
                        logger.severe("Error reading file: " + e.getMessage());
                        return new byte[0];
                    }
                }
            });
            
            if (fileContent.length > 0) {
                // Connect to Redis outside privileged block
                Jedis jedis = new Jedis(redisHost, redisPort);
                
                // Store file content in Redis
                jedis.set(filePath.getBytes(), fileContent);
                
                jedis.close();
            }
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Example 9: Properly scoped PrivilegedAction with MongoDB
    public static void good_case_9(HttpServletRequest request) {
        String mongoHost = request.getParameter("host");
        int mongoPort = Integer.parseInt(request.getParameter("port"));
        String dbName = request.getParameter("db");
        String filePath = request.getParameter("file");
        
        try {
            // Only use privileged action for file operation
            // ok: java-privileged-action
            String fileContent = AccessController.doPrivileged(new PrivilegedAction<String>() {
                @Override
                public String run() {
                    try {
                        // Minimal privileged operation - just reading the file
                        File file = new File(filePath);
                        if (file.exists() && file.canRead()) {
                            return new String(Files.readAllBytes(file.toPath()));
                        }
                        return "";
                    } catch (IOException e) {
                        logger.severe("Error reading file: " + e.getMessage());
                        return "";
                    }
                }
            });
            
            if (!fileContent.isEmpty()) {
                // Connect to MongoDB outside privileged block
                MongoClient mongoClient = new MongoClient(mongoHost, mongoPort);
                MongoDatabase database = mongoClient.getDatabase(dbName);
                
                // Create document and insert outside privileged block
                org.bson.Document doc = new org.bson.Document("fileName", filePath)
                        .append("content", fileContent);
                
                database.getCollection("files").insertOne(doc);
                
                mongoClient.close();
            }
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Example 10: Properly scoped PrivilegedAction with RabbitMQ
    public static void good_case_10(HttpServletRequest request) {
        String rabbitHost = request.getParameter("host");
        String queueName = request.getParameter("queue");
        String filePath = request.getParameter("file");
        
        try {
            // Only use privileged action for file operation
            // ok: java-privileged-action
            byte[] fileContent = AccessController.doPrivileged(new PrivilegedAction<byte[]>() {
                @Override
                public byte[] run() {
                    try {
                        // Minimal privileged operation - just reading the file
                        File file = new File(filePath);
                        if (file.exists() && file.canRead()) {
                            return Files.readAllBytes(file.toPath());
                        }
                        return new byte[0];
                    } catch (IOException e) {
                        logger.severe("Error reading file: " + e.getMessage());
                        return new byte[0];
                    }
                }
            });
            
            if (fileContent.length > 0) {
                // Connect to RabbitMQ outside privileged block
                ConnectionFactory factory = new ConnectionFactory();
                factory.setHost(rabbitHost);
                com.rabbitmq.client.Connection connection = factory.newConnection();
                Channel channel = connection.createChannel();
                
                // Declare queue and send message outside privileged block
                channel.queueDeclare(queueName, false, false, false, null);
                channel.basicPublish("", queueName, null, fileContent);
                
                channel.close();
                connection.close();
            }
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Example 11: Properly scoped PrivilegedAction with Quartz Scheduler
    public static void good_case_11(HttpServletRequest request) {
        String jobName = request.getParameter("job");
        String cronExpression = request.getParameter("cron");
        String scriptPath = request.getParameter("script");
        
        try {
            // Validate script path outside privileged block
            File script = new File(scriptPath);
            if (!script.exists() || !script.isFile()) {
                logger.warning("Invalid script path");
                return;
            }
            
            // Only use privileged action for file permission check
            // ok: java-privileged-action
            boolean canExecute = AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
                @Override
                public Boolean run() {
                    // Minimal privileged operation - just checking if file can be executed
                    return script.canExecute();
                }
            });
            
            if (!canExecute) {
                logger.warning("Script is not executable");
                return;
            }
            
            // Initialize Quartz scheduler outside privileged block
            Scheduler scheduler = StdSchedulerFactory.getDefaultScheduler();
            scheduler.start();
            
            // Create job that executes a script
            JobDetail job = JobBuilder.newJob(ScriptExecutionJob.class)
                    .withIdentity(jobName)
                    .usingJobData("scriptPath", scriptPath)
                    .build();
            
            // Schedule job with cron expression from request
            Trigger trigger = TriggerBuilder.newTrigger()
                    .withIdentity(jobName + "Trigger")
                    .withSchedule(CronScheduleBuilder.cronSchedule(cronExpression))
                    .build();
            
            scheduler.scheduleJob(job, trigger);
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Example 12: Properly scoped PrivilegedAction with URL connection
    public static void good_case_12(HttpServletRequest request) {
        String urlString = request.getParameter("url");
        String outputPath = request.getParameter("output");
        
        try {
            // Open URL connection outside privileged block
            URL url = new URL(urlString);
            URLConnection connection = url.openConnection();
            
            // Download content outside privileged block
            byte[] content = connection.getInputStream().readAllBytes();
            
            // Only use privileged action for file operation
            // ok: java-privileged-action
            AccessController.doPrivileged(new PrivilegedAction<Void>() {
                @Override
                public Void run() {
                    try {
                        // Minimal privileged operation - just creating the file
                        File outputFile = new File(outputPath);
                        if (!outputFile.exists()) {
                            outputFile.createNewFile();
                        }
                    } catch (IOException e) {
                        logger.severe("Error creating file: " + e.getMessage());
                    }
                    return null;
                }
            });
            
            // Save to file outside privileged block
            FileOutputStream fos = new FileOutputStream(outputPath);
            fos.write(content);
            fos.close();
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Example 13: Properly scoped PrivilegedAction with custom implementation
    public static void good_case_13(HttpServletRequest request) {
        String configPath = request.getParameter("config");
        
        try {
            // Only use privileged action for file operation
            // ok: java-privileged-action
            Properties config = AccessController.doPrivileged(new PrivilegedAction<Properties>() {
                @Override
                public Properties run() {
                    try {
                        // Minimal privileged operation - just reading the file
                        Properties props = new Properties();
                        File file = new File(configPath);
                        if (file.exists() && file.canRead()) {
                            props.load(new FileInputStream(file));
                        }
                        return props;
                    } catch (IOException e) {
                        logger.severe("Error reading file: " + e.getMessage());
                        return new Properties();
                    }
                }
            });
            
            // Process properties outside privileged block
            for (String propName : config.stringPropertyNames()) {
                logger.info("Property: " + propName + " = " + config.getProperty(propName));
            }
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Example 14: Properly scoped PrivilegedAction with file system operations
    public static void good_case_14(HttpServletRequest request) {
        String sourcePath = request.getParameter("source");
        String targetPath = request.getParameter("target");
        
        try {
            // Validate paths outside privileged block
            Path source = Paths.get(sourcePath);
            Path target = Paths.get(targetPath);
            
            if (!Files.exists(source) || !Files.isReadable(source)) {
                logger.warning("Source file does not exist or is not readable");
                return;
            }
            
            // Read source file outside privileged block
            byte[] content = Files.readAllBytes(source);
            
            // Only use privileged action for target file creation
            // ok: java-privileged-action
            AccessController.doPrivileged(new PrivilegedAction<Void>() {
                @Override
                public Void run() {
                    try {
                        // Minimal privileged operation - just creating the file
                        File targetFile = target.toFile();
                        if (!targetFile.exists()) {
                            targetFile.createNewFile();
                        }
                    } catch (IOException e) {
                        logger.severe("Error creating file: " + e.getMessage());
                    }
                    return null;
                }
            });
            
            // Write to target file outside privileged block
            Files.write(target, content);
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Example 15: Properly scoped PrivilegedAction with system property access
    public static void good_case_15(HttpServletRequest request) {
        String propertyName = request.getParameter("property");
        
        try {
            // Validate property name outside privileged block
            if (propertyName == null || propertyName.isEmpty()) {
                logger.warning("Invalid property name");
                return;
            }
            
            // Only use privileged action for system property access
            // ok: java-privileged-action
            String propertyValue = AccessController.doPrivileged(new PrivilegedAction<String>() {
                @Override
                public String run() {
                    // Minimal privileged operation - just getting a system property
                    return System.getProperty(propertyName);
                }
            });
            
            // Process property value outside privileged block
            if (propertyValue != null) {
                logger.info("Property " + propertyName + " = " + propertyValue);
            } else {
                logger.info("Property " + propertyName + " not found");
            }
        } catch (Exception e) {
            logger.severe("Error: " + e.getMessage());
        }
    }

    // Helper class for Quartz example
    public static class ScriptExecutionJob implements org.quartz.Job {
        @Override
        public void execute(org.quartz.JobExecutionContext context) {
            String scriptPath = context.getJobDetail().getJobDataMap().getString("scriptPath");
            try {
                Runtime.getRuntime().exec(scriptPath);
            } catch (IOException e) {
                logger.severe("Error executing script: " + e.getMessage());
            }
        }
    }
}
// {/fact}