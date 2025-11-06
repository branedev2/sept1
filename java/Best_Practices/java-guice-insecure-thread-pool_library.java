import com.google.inject.*;
import com.google.inject.name.Names;
import java.util.concurrent.*;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.ClientConfiguration;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.CommandLine;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import org.apache.commons.net.ftp.FTPClient;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.core.http.HttpClient;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;
import com.google.api.gax.core.ExecutorProvider;
import com.google.api.gax.core.FixedExecutorProvider;
import com.google.api.gax.core.InstantiatingExecutorProvider;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.apache.http.HttpHost;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import com.rabbitmq.client.ConnectionFactory;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientOptions;
import com.mongodb.ConnectionPoolSettings;
import org.apache.commons.dbcp2.BasicDataSource;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

// Security Issue: Creating thread pools outside of Guice modules in an application circumvents Guice's centralized management

// True Positive Examples (Vulnerable/Insecure Code)

class bad_case_1 extends HttpServlet {
    // Using ExecutorService directly in a servlet without Guice
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        // ruleid: java-guice-insecure-thread-pool
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        
        String param = request.getParameter("task");
        executorService.submit(() -> {
            // Process the task
            System.out.println("Processing: " + param);
        });
    }
}

class bad_case_2 {
    // Using ScheduledExecutorService in a Spring controller without Guice
    @RestController
    public class TaskSchedulerController {
        @GetMapping("/schedule")
        public String scheduleTask(@RequestParam String taskName) {
            // ruleid: java-guice-insecure-thread-pool
            ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(5);
            
            scheduler.schedule(() -> {
                System.out.println("Executing task: " + taskName);
            }, 1000, TimeUnit.MILLISECONDS);
            
            return "Task scheduled: " + taskName;
        }
    }
}

class bad_case_3 {
    // Using ForkJoinPool in an Apache HTTP client wrapper without Guice
    public void executeHttpRequests(String[] urls) {
        // ruleid: java-guice-insecure-thread-pool
        ForkJoinPool customThreadPool = new ForkJoinPool(10);
        
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            customThreadPool.submit(() -> {
                for (String url : urls) {
                    try {
                        httpClient.execute(new HttpGet(url));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }).get();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class bad_case_4 {
    // Using ThreadPoolExecutor with AWS S3 client without Guice
    public void processS3Objects(String bucketName) {
        // ruleid: java-guice-insecure-thread-pool
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            10, 20, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        s3Client.listObjects(bucketName).getObjectSummaries().forEach(summary -> {
            executor.execute(() -> {
                // Process S3 object
                System.out.println("Processing: " + summary.getKey());
            });
        });
    }
}

class bad_case_5 {
    // Using ExecutorService with Apache Commons Exec without Guice
    public void executeCommands(String[] commands) {
        // ruleid: java-guice-insecure-thread-pool
        ExecutorService executorService = Executors.newCachedThreadPool();
        
        for (String cmd : commands) {
            executorService.submit(() -> {
                try {
                    CommandLine commandLine = CommandLine.parse(cmd);
                    DefaultExecutor executor = new DefaultExecutor();
                    executor.execute(commandLine);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
    }
}

class bad_case_6 {
    // Using ExecutorService with JSch (SSH client) without Guice
    public void executeRemoteCommands(String host, String user, String password, String[] commands) {
        // ruleid: java-guice-insecure-thread-pool
        ExecutorService executorService = Executors.newFixedThreadPool(5);
        
        executorService.submit(() -> {
            try {
                JSch jsch = new JSch();
                Session session = jsch.getSession(user, host, 22);
                session.setPassword(password);
                session.connect();
                
                for (String command : commands) {
                    // Execute SSH command
                }
                
                session.disconnect();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }
}

class bad_case_7 {
    // Using ThreadPoolExecutor with FTP client without Guice
    public void downloadFiles(String server, String username, String password, String[] files) {
        // ruleid: java-guice-insecure-thread-pool
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            5, 10, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<>(100));
        
        for (String file : files) {
            executor.execute(() -> {
                FTPClient ftpClient = new FTPClient();
                try {
                    ftpClient.connect(server);
                    ftpClient.login(username, password);
                    // Download file
                    ftpClient.disconnect();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
    }
}

class bad_case_8 {
    // Using ExecutorService with Google Cloud Storage without Guice
    public void processGcsFiles(String bucketName) {
        // ruleid: java-guice-insecure-thread-pool
        ExecutorService executorService = Executors.newWorkStealingPool(10);
        
        Storage storage = StorageOptions.getDefaultInstance().getService();
        storage.list(bucketName).iterateAll().forEach(blob -> {
            executorService.submit(() -> {
                // Process GCS blob
                System.out.println("Processing: " + blob.getName());
            });
        });
    }
}

class bad_case_9 {
    // Using ThreadPoolExecutor with AWS DynamoDB without Guice
    public void processDynamoDbItems(String tableName) {
        // ruleid: java-guice-insecure-thread-pool
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            10, 20, 60L, TimeUnit.SECONDS, new SynchronousQueue<>(),
            new ThreadPoolExecutor.CallerRunsPolicy());
        
        DynamoDbClient dynamoDbClient = DynamoDbClient.create();
        
        dynamoDbClient.scanPaginator(r -> r.tableName(tableName)).items().forEach(item -> {
            executor.execute(() -> {
                // Process DynamoDB item
                System.out.println("Processing item: " + item);
            });
        });
    }
}

class bad_case_10 {
    // Using ExecutorService with Kafka Producer without Guice
    public void sendKafkaMessages(String bootstrapServers, String topic, String[] messages) {
        // ruleid: java-guice-insecure-thread-pool
        ExecutorService executorService = Executors.newSingleThreadExecutor();
        
        Properties props = new Properties();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
        
        KafkaProducer<String, String> producer = new KafkaProducer<>(props);
        
        for (String message : messages) {
            executorService.submit(() -> {
                producer.send(new org.apache.kafka.clients.producer.ProducerRecord<>(topic, message));
            });
        }
    }
}

class bad_case_11 {
    // Using ScheduledThreadPoolExecutor with Azure Blob Storage without Guice
    public void monitorBlobChanges(String connectionString, String containerName) {
        // ruleid: java-guice-insecure-thread-pool
        ScheduledThreadPoolExecutor scheduler = new ScheduledThreadPoolExecutor(2);
        
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString(connectionString)
            .buildClient();
        
        scheduler.scheduleAtFixedRate(() -> {
            blobServiceClient.getBlobContainerClient(containerName)
                .listBlobs()
                .forEach(blob -> {
                    System.out.println("Found blob: " + blob.getName());
                });
        }, 0, 5, TimeUnit.MINUTES);
    }
}

class bad_case_12 {
    // Using ExecutorService with Elasticsearch client without Guice
    public void indexDocuments(String[] documents) {
        // ruleid: java-guice-insecure-thread-pool
        ExecutorService executorService = Executors.newFixedThreadPool(5);
        
        RestClient restClient = RestClient.builder(
            new HttpHost("localhost", 9200, "http")).build();
        
        for (String document : documents) {
            executorService.submit(() -> {
                try {
                    // Index document to Elasticsearch
                    System.out.println("Indexing document: " + document);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
    }
}

class bad_case_13 {
    // Using ThreadPoolExecutor with Redis/Jedis without Guice
    public void cacheValues(String[] keys, String[] values) {
        // ruleid: java-guice-insecure-thread-pool
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            5, 10, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
        
        JedisPool jedisPool = new JedisPool(new JedisPoolConfig(), "localhost");
        
        for (int i = 0; i < keys.length; i++) {
            final String key = keys[i];
            final String value = values[i];
            
            executor.execute(() -> {
                try (redis.clients.jedis.Jedis jedis = jedisPool.getResource()) {
                    jedis.set(key, value);
                }
            });
        }
    }
}

class bad_case_14 {
    // Using ExecutorService with Hadoop FileSystem without Guice
    public void processHdfsFiles(String[] paths) throws Exception {
        // ruleid: java-guice-insecure-thread-pool
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);
        
        for (String path : paths) {
            executorService.submit(() -> {
                try {
                    if (fs.exists(new org.apache.hadoop.fs.Path(path))) {
                        // Process HDFS file
                        System.out.println("Processing: " + path);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
    }
}

class bad_case_15 {
    // Using ThreadPoolExecutor with RabbitMQ without Guice
    public void sendMessages(String[] messages) {
        // ruleid: java-guice-insecure-thread-pool
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            3, 5, 30, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
        
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost");
        
        try {
            com.rabbitmq.client.Connection connection = factory.newConnection();
            com.rabbitmq.client.Channel channel = connection.createChannel();
            
            for (String message : messages) {
                executor.execute(() -> {
                    try {
                        channel.basicPublish("", "queue_name", null, message.getBytes());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// True Negative Examples (Safe/Secure Code)

class good_case_1 {
    // Using ExecutorService with Guice in a servlet
    static class ExecutorModule extends AbstractModule {
        @Override
        protected void configure() {
            bind(ExecutorService.class).toInstance(Executors.newFixedThreadPool(10));
        }
    }
    
    static class TaskServlet extends HttpServlet {
        @Inject
        private ExecutorService executorService;
        
        protected void doGet(HttpServletRequest request, HttpServletResponse response) {
            String param = request.getParameter("task");
            // ok: java-guice-insecure-thread-pool
            executorService.submit(() -> {
                // Process the task
                System.out.println("Processing: " + param);
            });
        }
    }
}

class good_case_2 {
    // Using ScheduledExecutorService with Guice in a Spring controller
    static class SchedulerModule extends AbstractModule {
        @Override
        protected void configure() {
            bind(ScheduledExecutorService.class)
                .toInstance(Executors.newScheduledThreadPool(5));
        }
    }
    
    @RestController
    public static class TaskSchedulerController {
        @Inject
        private ScheduledExecutorService scheduler;
        
        @GetMapping("/schedule")
        public String scheduleTask(@RequestParam String taskName) {
            // ok: java-guice-insecure-thread-pool
            scheduler.schedule(() -> {
                System.out.println("Executing task: " + taskName);
            }, 1000, TimeUnit.MILLISECONDS);
            
            return "Task scheduled: " + taskName;
        }
    }
}

class good_case_3 {
    // Using ForkJoinPool with Guice for Apache HTTP client
    static class HttpClientModule extends AbstractModule {
        @Override
        protected void configure() {
            bind(ForkJoinPool.class).toInstance(new ForkJoinPool(10));
            bind(CloseableHttpClient.class).toInstance(HttpClients.createDefault());
        }
    }
    
    static class HttpService {
        @Inject
        private ForkJoinPool threadPool;
        
        @Inject
        private CloseableHttpClient httpClient;
        
        public void executeHttpRequests(String[] urls) throws Exception {
            // ok: java-guice-insecure-thread-pool
            threadPool.submit(() -> {
                for (String url : urls) {
                    try {
                        httpClient.execute(new HttpGet(url));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }).get();
        }
    }
}

class good_case_4 {
    // Using ThreadPoolExecutor with Guice for AWS S3
    static class AwsModule extends AbstractModule {
        @Override
        protected void configure() {
            ThreadPoolExecutor executor = new ThreadPoolExecutor(
                10, 20, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
            bind(ThreadPoolExecutor.class).toInstance(executor);
            bind(AmazonS3.class).toInstance(AmazonS3ClientBuilder.standard().build());
        }
    }
    
    static class S3Service {
        @Inject
        private ThreadPoolExecutor executor;
        
        @Inject
        private AmazonS3 s3Client;
        
        public void processS3Objects(String bucketName) {
            s3Client.listObjects(bucketName).getObjectSummaries().forEach(summary -> {
                // ok: java-guice-insecure-thread-pool
                executor.execute(() -> {
                    // Process S3 object
                    System.out.println("Processing: " + summary.getKey());
                });
            });
        }
    }
}

class good_case_5 {
    // Using ExecutorService with Guice for Apache Commons Exec
    static class CommandModule extends AbstractModule {
        @Override
        protected void configure() {
            bind(ExecutorService.class)
                .annotatedWith(Names.named("commandExecutor"))
                .toInstance(Executors.newCachedThreadPool());
        }
    }
    
    static class CommandService {
        @Inject
        @Named("commandExecutor")
        private ExecutorService executorService;
        
        public void executeCommands(String[] commands) {
            for (String cmd : commands) {
                // ok: java-guice-insecure-thread-pool
                executorService.submit(() -> {
                    try {
                        CommandLine commandLine = CommandLine.parse(cmd);
                        DefaultExecutor executor = new DefaultExecutor();
                        executor.execute(commandLine);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            }
        }
    }
}

class good_case_6 {
    // Using ExecutorService with Guice for JSch (SSH client)
    static class SshModule extends AbstractModule {
        @Override
        protected void configure() {
            bind(ExecutorService.class)
                .annotatedWith(Names.named("sshExecutor"))
                .toInstance(Executors.newFixedThreadPool(5));
        }
    }
    
    static class SshService {
        @Inject
        @Named("sshExecutor")
        private ExecutorService executorService;
        
        public void executeRemoteCommands(String host, String user, String password, String[] commands) {
            // ok: java-guice-insecure-thread-pool
            executorService.submit(() -> {
                try {
                    JSch jsch = new JSch();
                    Session session = jsch.getSession(user, host, 22);
                    session.setPassword(password);
                    session.connect();
                    
                    for (String command : commands) {
                        // Execute SSH command
                    }
                    
                    session.disconnect();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
    }
}

class good_case_7 {
    // Using ThreadPoolExecutor with Guice for FTP client
    static class FtpModule extends AbstractModule {
        @Override
        protected void configure() {
            ThreadPoolExecutor executor = new ThreadPoolExecutor(
                5, 10, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<>(100));
            bind(ThreadPoolExecutor.class).annotatedWith(Names.named("ftpExecutor")).toInstance(executor);
        }
    }
    
    static class FtpService {
        @Inject
        @Named("ftpExecutor")
        private ThreadPoolExecutor executor;
        
        public void downloadFiles(String server, String username, String password, String[] files) {
            for (String file : files) {
                // ok: java-guice-insecure-thread-pool
                executor.execute(() -> {
                    FTPClient ftpClient = new FTPClient();
                    try {
                        ftpClient.connect(server);
                        ftpClient.login(username, password);
                        // Download file
                        ftpClient.disconnect();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            }
        }
    }
}

class good_case_8 {
    // Using ExecutorService with Guice for Google Cloud Storage
    static class GcsModule extends AbstractModule {
        @Override
        protected void configure() {
            bind(ExecutorService.class)
                .annotatedWith(Names.named("gcsExecutor"))
                .toInstance(Executors.newWorkStealingPool(10));
            bind(Storage.class).toInstance(StorageOptions.getDefaultInstance().getService());
        }
    }
    
    static class GcsService {
        @Inject
        @Named("gcsExecutor")
        private ExecutorService executorService;
        
        @Inject
        private Storage storage;
        
        public void processGcsFiles(String bucketName) {
            storage.list(bucketName).iterateAll().forEach(blob -> {
                // ok: java-guice-insecure-thread-pool
                executorService.submit(() -> {
                    // Process GCS blob
                    System.out.println("Processing: " + blob.getName());
                });
            });
        }
    }
}

class good_case_9 {
    // Using ThreadPoolExecutor with Guice for AWS DynamoDB
    static class DynamoDbModule extends AbstractModule {
        @Override
        protected void configure() {
            ThreadPoolExecutor executor = new ThreadPoolExecutor(
                10, 20, 60L, TimeUnit.SECONDS, new SynchronousQueue<>(),
                new ThreadPoolExecutor.CallerRunsPolicy());
            bind(ThreadPoolExecutor.class).annotatedWith(Names.named("dynamoExecutor")).toInstance(executor);
            bind(DynamoDbClient.class).toInstance(DynamoDbClient.create());
        }
    }
    
    static class DynamoDbService {
        @Inject
        @Named("dynamoExecutor")
        private ThreadPoolExecutor executor;
        
        @Inject
        private DynamoDbClient dynamoDbClient;
        
        public void processDynamoDbItems(String tableName) {
            dynamoDbClient.scanPaginator(r -> r.tableName(tableName)).items().forEach(item -> {
                // ok: java-guice-insecure-thread-pool
                executor.execute(() -> {
                    // Process DynamoDB item
                    System.out.println("Processing item: " + item);
                });
            });
        }
    }
}

class good_case_10 {
    // Using ExecutorService with Guice for Kafka Producer
    static class KafkaModule extends AbstractModule {
        @Override
        protected void configure() {
            bind(ExecutorService.class)
                .annotatedWith(Names.named("kafkaExecutor"))
                .toInstance(Executors.newSingleThreadExecutor());
        }
        
        @Provides
        KafkaProducer<String, String> provideKafkaProducer(String bootstrapServers) {
            Properties props = new Properties();
            props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
            props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
            props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
            return new KafkaProducer<>(props);
        }
    }
    
    static class KafkaService {
        @Inject
        @Named("kafkaExecutor")
        private ExecutorService executorService;
        
        @Inject
        private KafkaProducer<String, String> producer;
        
        public void sendKafkaMessages(String topic, String[] messages) {
            for (String message : messages) {
                // ok: java-guice-insecure-thread-pool
                executorService.submit(() -> {
                    producer.send(new org.apache.kafka.clients.producer.ProducerRecord<>(topic, message));
                });
            }
        }
    }
}

class good_case_11 {
    // Using ScheduledThreadPoolExecutor with Guice for Azure Blob Storage
    static class AzureModule extends AbstractModule {
        @Override
        protected void configure() {
            bind(ScheduledThreadPoolExecutor.class)
                .toInstance(new ScheduledThreadPoolExecutor(2));
        }
        
        @Provides
        BlobServiceClient provideBlobServiceClient(String connectionString) {
            return new BlobServiceClientBuilder()
                .connectionString(connectionString)
                .buildClient();
        }
    }
    
    static class AzureBlobService {
        @Inject
        private ScheduledThreadPoolExecutor scheduler;
        
        @Inject
        private BlobServiceClient blobServiceClient;
        
        public void monitorBlobChanges(String containerName) {
            // ok: java-guice-insecure-thread-pool
            scheduler.scheduleAtFixedRate(() -> {
                blobServiceClient.getBlobContainerClient(containerName)
                    .listBlobs()
                    .forEach(blob -> {
                        System.out.println("Found blob: " + blob.getName());
                    });
            }, 0, 5, TimeUnit.MINUTES);
        }
    }
}

class good_case_12 {
    // Using ExecutorService with Guice for Elasticsearch client
    static class ElasticsearchModule extends AbstractModule {
        @Override
        protected void configure() {
            bind(ExecutorService.class)
                .annotatedWith(Names.named("elasticsearchExecutor"))
                .toInstance(Executors.newFixedThreadPool(5));
            bind(RestClient.class).toInstance(
                RestClient.builder(new HttpHost("localhost", 9200, "http")).build());
        }
    }
    
    static class ElasticsearchService {
        @Inject
        @Named("elasticsearchExecutor")
        private ExecutorService executorService;
        
        @Inject
        private RestClient restClient;
        
        public void indexDocuments(String[] documents) {
            for (String document : documents) {
                // ok: java-guice-insecure-thread-pool
                executorService.submit(() -> {
                    try {
                        // Index document to Elasticsearch
                        System.out.println("Indexing document: " + document);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            }
        }
    }
}

class good_case_13 {
    // Using ThreadPoolExecutor with Guice for Redis/Jedis
    static class RedisModule extends AbstractModule {
        @Override
        protected void configure() {
            ThreadPoolExecutor executor = new ThreadPoolExecutor(
                5, 10, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
            bind(ThreadPoolExecutor.class).annotatedWith(Names.named("redisExecutor")).toInstance(executor);
            
            JedisPoolConfig poolConfig = new JedisPoolConfig();
            JedisPool jedisPool = new JedisPool(poolConfig, "localhost");
            bind(JedisPool.class).toInstance(jedisPool);
        }
    }
    
    static class RedisService {
        @Inject
        @Named("redisExecutor")
        private ThreadPoolExecutor executor;
        
        @Inject
        private JedisPool jedisPool;
        
        public void cacheValues(String[] keys, String[] values) {
            for (int i = 0; i < keys.length; i++) {
                final String key = keys[i];
                final String value = values[i];
                
                // ok: java-guice-insecure-thread-pool
                executor.execute(() -> {
                    try (redis.clients.jedis.Jedis jedis = jedisPool.getResource()) {
                        jedis.set(key, value);
                    }
                });
            }
        }
    }
}

class good_case_14 {
    // Using ExecutorService with Guice for Hadoop FileSystem
    static class HadoopModule extends AbstractModule {
        @Override
        protected void configure() {
            bind(ExecutorService.class)
                .annotatedWith(Names.named("hadoopExecutor"))
                .toInstance(Executors.newFixedThreadPool(10));
        }
        
        @Provides
        FileSystem provideFileSystem() throws Exception {
            Configuration conf = new Configuration();
            return FileSystem.get(conf);
        }
    }
    
    static class HadoopService {
        @Inject
        @Named("hadoopExecutor")
        private ExecutorService executorService;
        
        @Inject
        private FileSystem fs;
        
        public void processHdfsFiles(String[] paths) {
            for (String path : paths) {
                // ok: java-guice-insecure-thread-pool
                executorService.submit(() -> {
                    try {
                        if (fs.exists(new org.apache.hadoop.fs.Path(path))) {
                            // Process HDFS file
                            System.out.println("Processing: " + path);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            }
        }
    }
}

class good_case_15 {
    // Using ThreadPoolExecutor with Guice for RabbitMQ
    static class RabbitMqModule extends AbstractModule {
        @Override
        protected void configure() {
            ThreadPoolExecutor executor = new ThreadPoolExecutor(
                3, 5, 30, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
            bind(ThreadPoolExecutor.class).annotatedWith(Names.named("rabbitExecutor")).toInstance(executor);
        }
        
        @Provides
        com.rabbitmq.client.Connection provideRabbitConnection() throws Exception {
            ConnectionFactory factory = new ConnectionFactory();
            factory.setHost("localhost");
            return factory.newConnection();
        }
    }
    
    static class RabbitMqService {
        @Inject
        @Named("rabbitExecutor")
        private ThreadPoolExecutor executor;
        
        @Inject
        private com.rabbitmq.client.Connection connection;
        
        public void sendMessages(String[] messages) {
            try {
                com.rabbitmq.client.Channel channel = connection.createChannel();
                
                for (String message : messages) {
                    // ok: java-guice-insecure-thread-pool
                    executor.execute(() -> {
                        try {
                            channel.basicPublish("", "queue_name", null, message.getBytes());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    });
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}