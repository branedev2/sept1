import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import java.util.Timer;
import java.util.TimerTask;
import org.quartz.*;
import org.quartz.impl.StdSchedulerFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.HttpResponse;
import org.springframework.web.client.RestTemplate;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.scheduling.concurrent.CustomizableThreadFactory;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.transfer.TransferManager;
import com.amazonaws.services.s3.transfer.TransferManagerBuilder;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import io.netty.util.concurrent.DefaultThreadFactory;
import okhttp3.*;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.apache.activemq.ActiveMQConnectionFactory;
import javax.jms.*;
import akka.actor.ActorSystem;
import akka.actor.Props;
import akka.actor.UntypedActor;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.ext.web.Router;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import java.util.Properties;
import java.util.Arrays;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import org.apache.http.HttpHost;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.monitor.FileAlterationMonitor;
import org.apache.commons.io.monitor.FileAlterationObserver;
import java.io.File;
import java.net.Socket;
import java.net.ServerSocket;
import java.io.IOException;
import java.net.URL;
import java.net.HttpURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// Security Issue: Non-daemon threads prevent JVM from exiting until they complete, which can cause service hang during shutdown.

// True Positive Examples (Vulnerable/Insecure Code)
class BadCases {
// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        String taskName = request.getParameter("taskName");
        
        // ruleid: java-non-daemon-thread
        Thread backgroundThread = new Thread(() -> {
            while (true) {
                System.out.println("Processing task: " + taskName);
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });
        backgroundThread.start(); // Non-daemon thread will prevent JVM shutdown
    }

    public void bad_case_2(HttpServletRequest request) {
        String poolSize = request.getParameter("poolSize");
        int size = Integer.parseInt(poolSize);
        
        // ruleid: java-non-daemon-thread
        ExecutorService executorService = Executors.newFixedThreadPool(size);
        
        executorService.submit(() -> {
            System.out.println("Executing task in fixed thread pool");
        });
        // No shutdown call, non-daemon threads in pool will prevent JVM exit
    }

    public void bad_case_3(HttpServletRequest request) {
        String timerName = request.getParameter("timerName");
        
        // ruleid: java-non-daemon-thread
        Timer timer = new Timer(timerName);
        
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                System.out.println("Timer task executed");
            }
        }, 1000, 5000);
        // Timer uses non-daemon threads by default
    }

    public void bad_case_4(HttpServletRequest request) throws SchedulerException {
        String jobName = request.getParameter("jobName");
        
        // ruleid: java-non-daemon-thread
        Scheduler scheduler = StdSchedulerFactory.getDefaultScheduler();
        
        JobDetail job = JobBuilder.newJob(SimpleJob.class)
                .withIdentity(jobName)
                .build();
                
        Trigger trigger = TriggerBuilder.newTrigger()
                .withIdentity("trigger1")
                .startNow()
                .build();
                
        scheduler.scheduleJob(job, trigger);
        scheduler.start();
        // Quartz scheduler uses non-daemon threads by default
    }

    public void bad_case_5(HttpServletRequest request) {
        String url = request.getParameter("url");
        
        // ruleid: java-non-daemon-thread
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            5, 10, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
            
        executor.execute(() -> {
            try {
                URL apiUrl = new URL(url);
                HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
                connection.setRequestMethod("GET");
                connection.getResponseCode();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        // ThreadPoolExecutor uses non-daemon threads by default
    }

    public void bad_case_6(HttpServletRequest request) {
        String message = request.getParameter("message");
        
        // ruleid: java-non-daemon-thread
        BasicThreadFactory factory = new BasicThreadFactory.Builder()
                .namingPattern("worker-%d")
                .priority(Thread.MAX_PRIORITY)
                .build();
                
        ExecutorService executor = Executors.newSingleThreadExecutor(factory);
        executor.submit(() -> System.out.println("Processing: " + message));
        // Apache Commons Lang BasicThreadFactory creates non-daemon threads by default
    }

    public void bad_case_7(HttpServletRequest request) {
        String endpoint = request.getParameter("endpoint");
        
        // ruleid: java-non-daemon-thread
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(10);
        executor.setQueueCapacity(25);
        executor.initialize();
        
        executor.execute(() -> {
            RestTemplate restTemplate = new RestTemplate();
            restTemplate.getForObject(endpoint, String.class);
        });
        // Spring's ThreadPoolTaskExecutor uses non-daemon threads by default
    }

    public void bad_case_8(HttpServletRequest request) {
        String bucketName = request.getParameter("bucket");
        String key = request.getParameter("key");
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // ruleid: java-non-daemon-thread
        TransferManager transferManager = TransferManagerBuilder.standard()
                .withS3Client(s3Client)
                .build();
                
        File file = new File("temp.txt");
        transferManager.download(bucketName, key, file);
        // AWS TransferManager uses non-daemon threads by default
    }

    public void bad_case_9(HttpServletRequest request) {
        String serverUrl = request.getParameter("serverUrl");
        
        // ruleid: java-non-daemon-thread
        QueuedThreadPool threadPool = new QueuedThreadPool(10);
        threadPool.setName("jetty-pool");
        
        try {
            threadPool.start();
            // Use the thread pool for some operations
            threadPool.execute(() -> {
                System.out.println("Connecting to: " + serverUrl);
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
        // Jetty QueuedThreadPool uses non-daemon threads by default
    }

    public void bad_case_10(HttpServletRequest request) {
        String brokerUrl = request.getParameter("brokerUrl");
        
        try {
            ActiveMQConnectionFactory connectionFactory = new ActiveMQConnectionFactory(brokerUrl);
            Connection connection = connectionFactory.createConnection();
            
            // ruleid: java-non-daemon-thread
            connection.start();
            
            Session session = connection.createSession(false, Session.AUTO_AC_REDACTED_TWILIO_ID);
            Destination destination = session.createQueue("TEST.FOO");
            MessageConsumer consumer = session.createConsumer(destination);
            // ActiveMQ connection creates non-daemon threads by default
        } catch (JMSException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11(HttpServletRequest request) {
        String actorName = request.getParameter("actorName");
        
        // ruleid: java-non-daemon-thread
        ActorSystem system = ActorSystem.create("MySystem");
        
        system.actorOf(Props.create(SimpleActor.class), actorName);
        // Akka ActorSystem uses non-daemon threads by default
    }

    public void bad_case_12(HttpServletRequest request) {
        int port = Integer.parseInt(request.getParameter("port"));
        
        // ruleid: java-non-daemon-thread
        Vertx vertx = Vertx.vertx();
        
        Router router = Router.router(vertx);
        router.route().handler(ctx -> {
            ctx.response().end("Hello from Vert.x!");
        });
        
        vertx.createHttpServer().requestHandler(router).listen(port);
        // Vert.x creates non-daemon threads by default
    }

    public void bad_case_13(HttpServletRequest request) {
        String topic = request.getParameter("topic");
        
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("group.id", "test-group");
        props.put("key.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        props.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        
        // ruleid: java-non-daemon-thread
        KafkaConsumer<String, String> consumer = new KafkaConsumer<>(props);
        consumer.subscribe(Arrays.asList(topic));
        
        Thread consumerThread = new Thread(() -> {
            while (true) {
                consumer.poll(100);
            }
        });
        consumerThread.start();
        // Kafka consumer thread is non-daemon by default
    }

    public void bad_case_14(HttpServletRequest request) {
        String directory = request.getParameter("directory");
        
        // ruleid: java-non-daemon-thread
        FileAlterationMonitor monitor = new FileAlterationMonitor(5000);
        FileAlterationObserver observer = new FileAlterationObserver(new File(directory));
        monitor.addObserver(observer);
        
        try {
            monitor.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
        // Apache Commons IO FileAlterationMonitor uses non-daemon threads by default
    }

    public void bad_case_15(HttpServletRequest request) {
        int port = Integer.parseInt(request.getParameter("port"));
        
        // ruleid: java-non-daemon-thread
        Thread serverThread = new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(port)) {
                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    // Handle client connection
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        serverThread.start();
        // Custom server thread is non-daemon by default
    }
}
// {/fact}

// True Negative Examples (Safe/Secure Code)
class GoodCases {
// {fact rule=resource-allocation-without-limits@v1.0 defects=0}
    public void good_case_1(HttpServletRequest request) {
        String taskName = request.getParameter("taskName");
        
        Thread backgroundThread = new Thread(() -> {
            while (true) {
                System.out.println("Processing task: " + taskName);
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });
        // ok: java-non-daemon-thread
        backgroundThread.setDaemon(true);
        backgroundThread.start();
    }

    public void good_case_2(HttpServletRequest request) {
        String poolSize = request.getParameter("poolSize");
        int size = Integer.parseInt(poolSize);
        
        // ok: java-non-daemon-thread
        ThreadFactory daemonFactory = r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        };
        ExecutorService executorService = Executors.newFixedThreadPool(size, daemonFactory);
        
        executorService.submit(() -> {
            System.out.println("Executing task in daemon thread pool");
        });
    }

    public void good_case_3(HttpServletRequest request) {
        String timerName = request.getParameter("timerName");
        
        // ok: java-non-daemon-thread
        Timer timer = new Timer(timerName, true);  // true = daemon
        
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                System.out.println("Timer task executed");
            }
        }, 1000, 5000);
    }

    public void good_case_4(HttpServletRequest request) throws SchedulerException {
        String jobName = request.getParameter("jobName");
        
        // Create properties with daemon threads enabled
        Properties props = new Properties();
        props.setProperty("org.quartz.threadPool.makeThreadsDaemons", "true");
        
        // ok: java-non-daemon-thread
        StdSchedulerFactory factory = new StdSchedulerFactory(props);
        Scheduler scheduler = factory.getScheduler();
        
        JobDetail job = JobBuilder.newJob(SimpleJob.class)
                .withIdentity(jobName)
                .build();
                
        Trigger trigger = TriggerBuilder.newTrigger()
                .withIdentity("trigger1")
                .startNow()
                .build();
                
        scheduler.scheduleJob(job, trigger);
        scheduler.start();
    }

    public void good_case_5(HttpServletRequest request) {
        String url = request.getParameter("url");
        
        // ok: java-non-daemon-thread
        ThreadFactory daemonThreadFactory = new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r);
                t.setDaemon(true);
                return t;
            }
        };
        
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            5, 10, 60, TimeUnit.SECONDS, 
            new LinkedBlockingQueue<>(), daemonThreadFactory);
            
        executor.execute(() -> {
            try {
                URL apiUrl = new URL(url);
                HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
                connection.setRequestMethod("GET");
                connection.getResponseCode();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    public void good_case_6(HttpServletRequest request) {
        String message = request.getParameter("message");
        
        // ok: java-non-daemon-thread
        BasicThreadFactory factory = new BasicThreadFactory.Builder()
                .namingPattern("worker-%d")
                .daemon(true)
                .priority(Thread.MAX_PRIORITY)
                .build();
                
        ExecutorService executor = Executors.newSingleThreadExecutor(factory);
        executor.submit(() -> System.out.println("Processing: " + message));
    }

    public void good_case_7(HttpServletRequest request) {
        String endpoint = request.getParameter("endpoint");
        
        // ok: java-non-daemon-thread
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(10);
        executor.setQueueCapacity(25);
        executor.setDaemon(true);
        executor.initialize();
        
        executor.execute(() -> {
            RestTemplate restTemplate = new RestTemplate();
            restTemplate.getForObject(endpoint, String.class);
        });
    }

    public void good_case_8(HttpServletRequest request) {
        String bucketName = request.getParameter("bucket");
        String key = request.getParameter("key");
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        
        // Create daemon thread factory
        ThreadFactory daemonFactory = new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r);
                t.setDaemon(true);
                return t;
            }
        };
        
        // ok: java-non-daemon-thread
        TransferManager transferManager = TransferManagerBuilder.standard()
                .withS3Client(s3Client)
                .withExecutorFactory(() -> Executors.newFixedThreadPool(10, daemonFactory))
                .build();
                
        File file = new File("temp.txt");
        transferManager.download(bucketName, key, file);
    }

    public void good_case_9(HttpServletRequest request) {
        String serverUrl = request.getParameter("serverUrl");
        
        // ok: java-non-daemon-thread
        QueuedThreadPool threadPool = new QueuedThreadPool(10);
        threadPool.setName("jetty-pool");
        threadPool.setDaemon(true);
        
        try {
            threadPool.start();
            // Use the thread pool for some operations
            threadPool.execute(() -> {
                System.out.println("Connecting to: " + serverUrl);
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10(HttpServletRequest request) {
        String brokerUrl = request.getParameter("brokerUrl");
        
        try {
            ActiveMQConnectionFactory connectionFactory = new ActiveMQConnectionFactory(brokerUrl);
            Connection connection = connectionFactory.createConnection();
            
            // Set up a shutdown hook to close the connection
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    connection.close();
                } catch (JMSException e) {
                    e.printStackTrace();
                }
            }));
            
            // ok: java-non-daemon-thread
            connection.start();
            
            Session session = connection.createSession(false, Session.AUTO_AC_REDACTED_TWILIO_ID);
            Destination destination = session.createQueue("TEST.FOO");
            MessageConsumer consumer = session.createConsumer(destination);
            
            // Create a daemon thread for the consumer
            Thread consumerThread = new Thread(() -> {
                try {
                    consumer.setMessageListener(message -> {
                        // Process message
                    });
                } catch (JMSException e) {
                    e.printStackTrace();
                }
            });
            consumerThread.setDaemon(true);
            consumerThread.start();
        } catch (JMSException e) {
            e.printStackTrace();
        }
    }

    public void good_case_11(HttpServletRequest request) {
        String actorName = request.getParameter("actorName");
        
        // Configure Akka to use daemon threads
        Config config = ConfigFactory.parseString("akka.daemonic = on");
        
        // ok: java-non-daemon-thread
        ActorSystem system = ActorSystem.create("MySystem", config);
        
        system.actorOf(Props.create(SimpleActor.class), actorName);
        
        // Register shutdown hook to terminate the actor system
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            system.terminate();
        }));
    }

    public void good_case_12(HttpServletRequest request) {
        int port = Integer.parseInt(request.getParameter("port"));
        
        // Configure Vert.x to use daemon threads
        VertxOptions options = new VertxOptions()
                .setUseDaemonThread(true);
        
        // ok: java-non-daemon-thread
        Vertx vertx = Vertx.vertx(options);
        
        Router router = Router.router(vertx);
        router.route().handler(ctx -> {
            ctx.response().end("Hello from Vert.x!");
        });
        
        vertx.createHttpServer().requestHandler(router).listen(port);
    }

    public void good_case_13(HttpServletRequest request) {
        String topic = request.getParameter("topic");
        
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("group.id", "test-group");
        props.put("key.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        props.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        
        // ok: java-non-daemon-thread
        KafkaConsumer<String, String> consumer = new KafkaConsumer<>(props);
        consumer.subscribe(Arrays.asList(topic));
        
        Thread consumerThread = new Thread(() -> {
            try {
                while (true) {
                    consumer.poll(100);
                }
            } finally {
                consumer.close();
            }
        });
        consumerThread.setDaemon(true);
        consumerThread.start();
    }

    public void good_case_14(HttpServletRequest request) {
        String directory = request.getParameter("directory");
        
        // ok: java-non-daemon-thread
        FileAlterationMonitor monitor = new FileAlterationMonitor(5000);
        FileAlterationObserver observer = new FileAlterationObserver(new File(directory));
        monitor.addObserver(observer);
        
        // Set the thread factory to create daemon threads
        Field threadField;
        try {
            threadField = FileAlterationMonitor.class.getDeclaredField("thread");
            threadField.setAccessible(true);
            Thread monitorThread = new Thread(() -> {
                try {
                    monitor.run();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            monitorThread.setDaemon(true);
            threadField.set(monitor, monitorThread);
            
            monitor.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15(HttpServletRequest request) {
        int port = Integer.parseInt(request.getParameter("port"));
        
        Thread serverThread = new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(port)) {
                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    // Handle client connection
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        // ok: java-non-daemon-thread
        serverThread.setDaemon(true);
        serverThread.start();
    }
}
// {/fact}

// Helper classes
class SimpleJob implements Job {
    public void execute(JobExecutionContext context) throws JobExecutionException {
        System.out.println("Simple job executed!");
    }
}

class SimpleActor extends UntypedActor {
    @Override
    public void onReceive(Object message) {
        System.out.println("Received message: " + message);
    }
}

class Config {
    public static Config parseString(String config) {
        return new Config();
    }
}

class ConfigFactory {
    public static Config parseString(String config) {
        return new Config();
    }
}