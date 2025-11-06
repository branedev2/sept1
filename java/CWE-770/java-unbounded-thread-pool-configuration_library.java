import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.tomcat.util.threads.ThreadPoolExecutor;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.MoreExecutors;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.apache.http.HttpHost;
import org.apache.activemq.ActiveMQConnectionFactory;
import javax.jms.Connection;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import redis.clients.jedis.JedisPool;
import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.PoolingOptions;
import com.mongodb.MongoClientOptions;
import org.quartz.impl.StdSchedulerFactory;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.conn.PoolingNHttpClientConnectionManager;
import org.apache.http.impl.nio.reactor.DefaultConnectingIOReactor;
import org.apache.http.nio.reactor.IOReactorException;
import org.apache.http.nio.reactor.ConnectingIOReactor;
import java.util.Properties;
import java.util.HashMap;
import java.util.Map;

// Security Issue: Unbounded Thread Pool Configuration (CWE-770)

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    // Using Java's ExecutorService with unbounded work queue
    // ruleid: java-unbounded-thread-pool-configuration
    ExecutorService executorService = Executors.newFixedThreadPool(10);
    
    // This uses an unbounded LinkedBlockingQueue by default which can lead to OOM
    for (int i = 0; i < 10000; i++) {
        executorService.submit(() -> {
            // Task that processes some work
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
    }
}

public void bad_case_2() {
    // Using Java's cached thread pool which can create unlimited threads
    // ruleid: java-unbounded-thread-pool-configuration
    ExecutorService executorService = Executors.newCachedThreadPool();
    
    // This can create an unlimited number of threads if tasks keep coming in
    for (int i = 0; i < 1000; i++) {
        executorService.submit(() -> {
            // Some long-running task
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
    }
}

public void bad_case_3() {
    // Spring Framework's ThreadPoolTaskExecutor with unbounded queue
    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(5);
    executor.setMaxPoolSize(10);
    // No queue capacity set - defaults to Integer.MAX_VALUE
    // ruleid: java-unbounded-thread-pool-configuration
    executor.initialize();
    
    for (int i = 0; i < 10000; i++) {
        executor.submit(() -> {
            // Task implementation
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
    }
}

public void bad_case_4() {
    // Apache HttpClient with unbounded connection pool
    PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
    // ruleid: java-unbounded-thread-pool-configuration
    connectionManager.setMaxTotal(Integer.MAX_VALUE);
    connectionManager.setDefaultMaxPerRoute(Integer.MAX_VALUE);
    
    CloseableHttpClient httpClient = HttpClients.custom()
            .setConnectionManager(connectionManager)
            .build();
    
    // Using the client with potentially unlimited connections
    // This could lead to resource exhaustion
}

public void bad_case_5() {
    // Tomcat ThreadPoolExecutor with unbounded queue
    java.util.concurrent.BlockingQueue<Runnable> queue = new LinkedBlockingQueue<>(); // Unbounded queue
    
    // ruleid: java-unbounded-thread-pool-configuration
    org.apache.tomcat.util.threads.ThreadPoolExecutor executor = 
        new org.apache.tomcat.util.threads.ThreadPoolExecutor(
            10, 10, 60, TimeUnit.SECONDS, queue);
    
    // Adding many tasks that could potentially fill up memory
    for (int i = 0; i < 100000; i++) {
        executor.execute(() -> {
            // Task implementation
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
    }
}

public void bad_case_6() {
    // AWS SDK with unbounded thread pool
    ClientConfiguration clientConfig = new ClientConfiguration();
    // ruleid: java-unbounded-thread-pool-configuration
    clientConfig.setMaxConnections(Integer.MAX_VALUE);
    
    AmazonS3ClientBuilder.standard()
        .withClientConfiguration(clientConfig)
        .build();
    
    // This client could potentially create too many connections
}

public void bad_case_7() {
    // Guava's ListeningExecutorService with unbounded work queue
    // ruleid: java-unbounded-thread-pool-configuration
    ExecutorService executorService = Executors.newFixedThreadPool(5);
    ListeningExecutorService listeningExecutorService = MoreExecutors.listeningDecorator(executorService);
    
    // Using an executor with default unbounded queue
    for (int i = 0; i < 50000; i++) {
        listeningExecutorService.submit(() -> {
            // Task implementation
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return null;
        });
    }
}

public void bad_case_8() {
    // HikariCP connection pool with unbounded queue
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
    config.setUsername("user");
    config.setPassword("password");
    // ruleid: java-unbounded-thread-pool-configuration
    config.setMaximumPoolSize(Integer.MAX_VALUE);
    
    HikariDataSource dataSource = new HikariDataSource(config);
    
    // Using the datasource with potentially unlimited connections
}

public void bad_case_9() {
    // Elasticsearch RestClient with unbounded connection pool
    try {
        RestClientBuilder builder = RestClient.builder(new HttpHost("localhost", 9200, "http"));
        
        // ruleid: java-unbounded-thread-pool-configuration
        builder.setHttpClientConfigCallback(httpClientBuilder -> {
            PoolingNHttpClientConnectionManager connectionManager = new PoolingNHttpClientConnectionManager(
                    new DefaultConnectingIOReactor());
            connectionManager.setMaxTotal(Integer.MAX_VALUE);
            connectionManager.setDefaultMaxPerRoute(Integer.MAX_VALUE);
            return httpClientBuilder.setConnectionManager(connectionManager);
        });
        
        RestClient restClient = builder.build();
        // Using the client with potentially unlimited connections
    } catch (IOReactorException e) {
        e.printStackTrace();
    }
}

public void bad_case_10() {
    // ActiveMQ with unbounded thread pool
    ActiveMQConnectionFactory connectionFactory = new ActiveMQConnectionFactory("tcp://localhost:61616");
    
    // ruleid: java-unbounded-thread-pool-configuration
    ThreadPoolExecutor executor = new ThreadPoolExecutor(
        5, Integer.MAX_VALUE, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
    
    try {
        Connection connection = connectionFactory.createConnection();
        // Using the connection with unbounded thread pool for message processing
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11() {
    // Netty EventLoopGroup with unbounded queue
    // ruleid: java-unbounded-thread-pool-configuration
    EventLoopGroup eventLoopGroup = new NioEventLoopGroup(0); // Unlimited threads based on CPU cores
    
    // Using the event loop group for handling network events
    // This could potentially create too many threads under high load
}

public void bad_case_12() {
    // Vert.x with unbounded event loop pool
    // ruleid: java-unbounded-thread-pool-configuration
    VertxOptions options = new VertxOptions()
        .setEventLoopPoolSize(Integer.MAX_VALUE);
    
    Vertx vertx = Vertx.vertx(options);
    
    // Using Vert.x with potentially unlimited event loop threads
}

public void bad_case_13() {
    // Kafka Producer with unbounded buffer memory
    Properties props = new Properties();
    props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
    props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
    props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
    // ruleid: java-unbounded-thread-pool-configuration
    props.put(ProducerConfig.BUFFER_MEMORY_CONFIG, Long.MAX_VALUE);
    
    KafkaProducer<String, String> producer = new KafkaProducer<>(props);
    
    // Using the producer with potentially unlimited buffer memory
}

public void bad_case_14() {
    // Redis Jedis Pool with unbounded connections
    GenericObjectPoolConfig poolConfig = new GenericObjectPoolConfig();
    // ruleid: java-unbounded-thread-pool-configuration
    poolConfig.setMaxTotal(Integer.MAX_VALUE);
    poolConfig.setMaxIdle(Integer.MAX_VALUE);
    
    JedisPool jedisPool = new JedisPool(poolConfig, "localhost", 6379);
    
    // Using the pool with potentially unlimited connections
}

public void bad_case_15() {
    // Cassandra driver with unbounded connection pool
    PoolingOptions poolingOptions = new PoolingOptions();
    // ruleid: java-unbounded-thread-pool-configuration
    poolingOptions.setMaxConnectionsPerHost(HostDistance.LOCAL, Integer.MAX_VALUE);
    
    Cluster cluster = Cluster.builder()
        .addContactPoint("127.0.0.1")
        .withPoolingOptions(poolingOptions)
        .build();
    
    // Using the cluster with potentially unlimited connections
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    // Using Java's ExecutorService with bounded work queue
    // ok: java-unbounded-thread-pool-configuration
    ExecutorService executorService = new ThreadPoolExecutor(
        5, 10, 60L, TimeUnit.SECONDS, new ArrayBlockingQueue<>(1000));
    
    // This uses a bounded queue which prevents OOM
    for (int i = 0; i < 10000; i++) {
        try {
            executorService.submit(() -> {
                // Task that processes some work
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        } catch (RejectedExecutionException e) {
            // Handle rejection - could log, retry later, or use other strategies
            System.out.println("Task rejected: " + e.getMessage());
        }
    }
}

public void good_case_2() {
    // Using Java's ExecutorService with rejection policy
    // ok: java-unbounded-thread-pool-configuration
    ExecutorService executorService = new ThreadPoolExecutor(
        5, 10, 60L, TimeUnit.SECONDS, 
        new LinkedBlockingQueue<>(1000),
        new ThreadPoolExecutor.CallerRunsPolicy());
    
    // This has a bounded queue and a rejection policy
    for (int i = 0; i < 1000; i++) {
        executorService.submit(() -> {
            // Some task
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
    }
}

public void good_case_3() {
    // Spring Framework's ThreadPoolTaskExecutor with bounded queue
    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(5);
    executor.setMaxPoolSize(10);
    // ok: java-unbounded-thread-pool-configuration
    executor.setQueueCapacity(1000);
    executor.setRejectedExecutionHandler(new ThreadPoolExecutor.AbortPolicy());
    executor.initialize();
    
    for (int i = 0; i < 10000; i++) {
        try {
            executor.submit(() -> {
                // Task implementation
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        } catch (RejectedExecutionException e) {
            // Handle rejection
            System.out.println("Task rejected: " + e.getMessage());
        }
    }
}

public void good_case_4() {
    // Apache HttpClient with bounded connection pool
    PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
    // ok: java-unbounded-thread-pool-configuration
    connectionManager.setMaxTotal(100);
    connectionManager.setDefaultMaxPerRoute(20);
    
    CloseableHttpClient httpClient = HttpClients.custom()
            .setConnectionManager(connectionManager)
            .build();
    
    // Using the client with reasonable connection limits
}

public void good_case_5() {
    // Tomcat ThreadPoolExecutor with bounded queue
    java.util.concurrent.BlockingQueue<Runnable> queue = new ArrayBlockingQueue<>(1000); // Bounded queue
    
    // ok: java-unbounded-thread-pool-configuration
    org.apache.tomcat.util.threads.ThreadPoolExecutor executor = 
        new org.apache.tomcat.util.threads.ThreadPoolExecutor(
            10, 20, 60, TimeUnit.SECONDS, queue, 
            new ThreadPoolExecutor.AbortPolicy());
    
    // Adding tasks with proper bounds
    for (int i = 0; i < 100000; i++) {
        try {
            executor.execute(() -> {
                // Task implementation
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        } catch (RejectedExecutionException e) {
            // Handle rejection
            System.out.println("Task rejected: " + e.getMessage());
        }
    }
}

public void good_case_6() {
    // AWS SDK with bounded thread pool
    ClientConfiguration clientConfig = new ClientConfiguration();
    // ok: java-unbounded-thread-pool-configuration
    clientConfig.setMaxConnections(100);
    
    AmazonS3ClientBuilder.standard()
        .withClientConfiguration(clientConfig)
        .build();
    
    // This client has a reasonable limit on connections
}

public void good_case_7() {
    // Guava's ListeningExecutorService with bounded work queue
    // ok: java-unbounded-thread-pool-configuration
    ExecutorService executorService = new ThreadPoolExecutor(
        5, 10, 60L, TimeUnit.SECONDS, 
        new ArrayBlockingQueue<>(1000),
        new ThreadPoolExecutor.CallerRunsPolicy());
    
    ListeningExecutorService listeningExecutorService = MoreExecutors.listeningDecorator(executorService);
    
    // Using an executor with bounded queue
    for (int i = 0; i < 50000; i++) {
        try {
            listeningExecutorService.submit(() -> {
                // Task implementation
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return null;
            });
        } catch (RejectedExecutionException e) {
            // Handle rejection
            System.out.println("Task rejected: " + e.getMessage());
        }
    }
}

public void good_case_8() {
    // HikariCP connection pool with reasonable limits
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
    config.setUsername("user");
    config.setPassword("password");
    // ok: java-unbounded-thread-pool-configuration
    config.setMaximumPoolSize(20);
    
    HikariDataSource dataSource = new HikariDataSource(config);
    
    // Using the datasource with reasonable connection limits
}

public void good_case_9() {
    // Elasticsearch RestClient with bounded connection pool
    try {
        RestClientBuilder builder = RestClient.builder(new HttpHost("localhost", 9200, "http"));
        
        // ok: java-unbounded-thread-pool-configuration
        builder.setHttpClientConfigCallback(httpClientBuilder -> {
            PoolingNHttpClientConnectionManager connectionManager = new PoolingNHttpClientConnectionManager(
                    new DefaultConnectingIOReactor());
            connectionManager.setMaxTotal(100);
            connectionManager.setDefaultMaxPerRoute(20);
            return httpClientBuilder.setConnectionManager(connectionManager);
        });
        
        RestClient restClient = builder.build();
        // Using the client with reasonable connection limits
    } catch (IOReactorException e) {
        e.printStackTrace();
    }
}

public void good_case_10() {
    // ActiveMQ with bounded thread pool
    ActiveMQConnectionFactory connectionFactory = new ActiveMQConnectionFactory("tcp://localhost:61616");
    
    // ok: java-unbounded-thread-pool-configuration
    ThreadPoolExecutor executor = new ThreadPoolExecutor(
        5, 20, 60L, TimeUnit.SECONDS, 
        new ArrayBlockingQueue<>(1000),
        new ThreadPoolExecutor.CallerRunsPolicy());
    
    try {
        Connection connection = connectionFactory.createConnection();
        // Using the connection with bounded thread pool for message processing
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    // Netty EventLoopGroup with bounded threads
    // ok: java-unbounded-thread-pool-configuration
    EventLoopGroup eventLoopGroup = new NioEventLoopGroup(16); // Fixed number of threads
    
    // Using the event loop group for handling network events
    // This has a reasonable limit on threads
}

public void good_case_12() {
    // Vert.x with bounded event loop pool
    // ok: java-unbounded-thread-pool-configuration
    VertxOptions options = new VertxOptions()
        .setEventLoopPoolSize(16);
    
    Vertx vertx = Vertx.vertx(options);
    
    // Using Vert.x with reasonable event loop thread limits
}

public void good_case_13() {
    // Kafka Producer with bounded buffer memory
    Properties props = new Properties();
    props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
    props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
    props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
    // ok: java-unbounded-thread-pool-configuration
    props.put(ProducerConfig.BUFFER_MEMORY_CONFIG, 33554432); // 32MB
    
    KafkaProducer<String, String> producer = new KafkaProducer<>(props);
    
    // Using the producer with reasonable buffer memory limits
}

public void good_case_14() {
    // Redis Jedis Pool with bounded connections
    GenericObjectPoolConfig poolConfig = new GenericObjectPoolConfig();
    // ok: java-unbounded-thread-pool-configuration
    poolConfig.setMaxTotal(100);
    poolConfig.setMaxIdle(20);
    
    JedisPool jedisPool = new JedisPool(poolConfig, "localhost", 6379);
    
    // Using the pool with reasonable connection limits
}

public void good_case_15() {
    // Cassandra driver with bounded connection pool
    PoolingOptions poolingOptions = new PoolingOptions();
    // ok: java-unbounded-thread-pool-configuration
    poolingOptions.setMaxConnectionsPerHost(HostDistance.LOCAL, 32);
    
    Cluster cluster = Cluster.builder()
        .addContactPoint("127.0.0.1")
        .withPoolingOptions(poolingOptions)
        .build();
    
    // Using the cluster with reasonable connection limits
}