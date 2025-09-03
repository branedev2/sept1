import java.util.concurrent.*;
import java.io.*;
import java.net.*;
import java.util.*;
import org.apache.http.*;
import org.apache.http.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import com.amazonaws.services.lambda.*;
import com.amazonaws.services.lambda.model.*;
import com.google.common.util.concurrent.*;
import javax.servlet.http.*;
import okhttp3.*;
import retrofit2.*;
import retrofit2.http.*;
import com.fasterxml.jackson.databind.*;
import org.apache.commons.io.*;
import org.quartz.*;
import org.quartz.impl.*;
import java.sql.*;
import javax.jms.*;
import org.apache.activemq.*;
import org.elasticsearch.client.*;
import org.apache.kafka.clients.producer.*;
import redis.clients.jedis.*;
import com.rabbitmq.client.*;
import io.netty.bootstrap.*;
import io.netty.channel.*;

// Security Issue: Improper shutdown of ExecutorService instances can lead to memory leaks and resource exhaustion

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    // Standard Java ExecutorService with potential exception before shutdown
    ExecutorService executorService = Executors.newFixedThreadPool(10);
    try {
        executorService.submit(() -> {
            System.out.println("Task executed");
        });
        
        // Some code that might throw an exception
        String data = null;
        int length = data.length(); // NullPointerException
        
        // ruleid: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    } catch (Exception e) {
        System.out.println("Exception caught: " + e.getMessage());
        // No shutdown in catch block
    }
}

public void bad_case_2() {
    // Spring RestTemplate with ExecutorService for async operations
    RestTemplate restTemplate = new RestTemplate();
    ExecutorService executorService = Executors.newCachedThreadPool();
    
    try {
        executorService.submit(() -> {
            ResponseEntity<String> response = restTemplate.getForEntity("https://api.example.com", String.class);
            System.out.println(response.getBody());
        });
        
        // Code that might throw exception
        HttpURLConnection connection = (HttpURLConnection) new URL("https://invalid-url").openConnection();
        connection.connect(); // Might throw IOException
        
        // ruleid: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    } catch (Exception e) {
        System.out.println("Connection failed: " + e.getMessage());
    }
}

public void bad_case_3() {
    // AWS SDK with ExecutorService for parallel processing
    ExecutorService executorService = Executors.newFixedThreadPool(5);
    AmazonLambdaClient lambdaClient = new AmazonLambdaClient();
    
    try {
        executorService.submit(() -> {
            InvokeRequest request = new InvokeRequest()
                .withFunctionName("my-function");
            lambdaClient.invoke(request);
        });
        
        // Code that might throw exception
        File configFile = new File("/non-existent/config.json");
        FileInputStream fis = new FileInputStream(configFile); // FileNotFoundException
        
        // ruleid: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    } catch (Exception e) {
        System.out.println("Failed to process: " + e.getMessage());
    }
}

public void bad_case_4() {
    // OkHttp client with ExecutorService for async HTTP requests
    OkHttpClient client = new OkHttpClient();
    ExecutorService executorService = Executors.newSingleThreadExecutor();
    
    try {
        Request request = new Request.Builder()
            .url("https://api.example.com/data")
            .build();
            
        executorService.submit(() -> {
            try {
                Response response = client.newCall(request).execute();
                System.out.println(response.body().string());
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        
        // Code that might throw exception
        int[] array = new int[3];
        int value = array[5]; // ArrayIndexOutOfBoundsException
        
        // ruleid: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    } catch (Exception e) {
        System.out.println("Error: " + e.getMessage());
    }
}

public void bad_case_5() {
    // Retrofit API client with ExecutorService
    ExecutorService executorService = Executors.newFixedThreadPool(3);
    Retrofit retrofit = new Retrofit.Builder()
        .baseUrl("https://api.example.com/")
        .build();
    
    try {
        executorService.submit(() -> {
            // Some API call
            System.out.println("API call executed");
        });
        
        // Code that might throw exception
        Map<String, Object> map = null;
        Object value = map.get("key"); // NullPointerException
        
        // ruleid: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    } catch (Exception e) {
        System.out.println("Error in API call: " + e.getMessage());
    }
}

public void bad_case_6() {
    // Quartz Scheduler with ExecutorService
    ExecutorService executorService = Executors.newScheduledThreadPool(2);
    
    try {
        StdSchedulerFactory factory = new StdSchedulerFactory();
        Scheduler scheduler = factory.getScheduler();
        
        executorService.submit(() -> {
            try {
                scheduler.start();
            } catch (SchedulerException e) {
                e.printStackTrace();
            }
        });
        
        // Code that might throw exception
        String input = null;
        boolean check = input.equals("test"); // NullPointerException
        
        // ruleid: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    } catch (Exception e) {
        System.out.println("Scheduler error: " + e.getMessage());
    }
}

public void bad_case_7() {
    // JDBC database connection with ExecutorService
    ExecutorService executorService = Executors.newFixedThreadPool(5);
    
    try {
        executorService.submit(() -> {
            try {
                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "pass");
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery("SELECT * FROM users");
                while (rs.next()) {
                    System.out.println(rs.getString("name"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        });
        
        // Code that might throw exception
        int result = 100 / 0; // ArithmeticException
        
        // ruleid: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    } catch (Exception e) {
        System.out.println("Database error: " + e.getMessage());
    }
}

public void bad_case_8() {
    // ActiveMQ JMS with ExecutorService
    ExecutorService executorService = Executors.newCachedThreadPool();
    
    try {
        ActiveMQConnectionFactory connectionFactory = new ActiveMQConnectionFactory("tcp://localhost:61616");
        
        executorService.submit(() -> {
            try {
                Connection connection = connectionFactory.createConnection();
                connection.start();
                // Process messages
            } catch (JMSException e) {
                e.printStackTrace();
            }
        });
        
        // Code that might throw exception
        List<String> list = null;
        String firstItem = list.get(0); // NullPointerException
        
        // ruleid: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    } catch (Exception e) {
        System.out.println("JMS error: " + e.getMessage());
    }
}

public void bad_case_9() {
    // Elasticsearch client with ExecutorService
    ExecutorService executorService = Executors.newFixedThreadPool(3);
    
    try {
        RestClient restClient = RestClient.builder(
            new HttpHost("localhost", 9200, "http")).build();
        
        executorService.submit(() -> {
            try {
                Request request = new Request("GET", "/index/_search");
                Response response = restClient.performRequest(request);
                // Process response
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        
        // Code that might throw exception
        String[] array = null;
        int length = array.length; // NullPointerException
        
        // ruleid: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    } catch (Exception e) {
        System.out.println("Elasticsearch error: " + e.getMessage());
    }
}

public void bad_case_10() {
    // Kafka producer with ExecutorService
    ExecutorService executorService = Executors.newSingleThreadExecutor();
    
    try {
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        KafkaProducer<String, String> producer = new KafkaProducer<>(props);
        
        executorService.submit(() -> {
            producer.send(new ProducerRecord<>("topic", "key", "value"));
        });
        
        // Code that might throw exception
        Object obj = "string";
        Integer num = (Integer) obj; // ClassCastException
        
        // ruleid: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    } catch (Exception e) {
        System.out.println("Kafka error: " + e.getMessage());
    }
}

public void bad_case_11() {
    // Redis Jedis client with ExecutorService
    ExecutorService executorService = Executors.newFixedThreadPool(2);
    
    try {
        Jedis jedis = new Jedis("localhost");
        
        executorService.submit(() -> {
            jedis.set("key", "value");
            String value = jedis.get("key");
            System.out.println(value);
        });
        
        // Code that might throw exception
        String str = null;
        char c = str.charAt(0); // NullPointerException
        
        // ruleid: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    } catch (Exception e) {
        System.out.println("Redis error: " + e.getMessage());
    }
}

public void bad_case_12() {
    // RabbitMQ client with ExecutorService
    ExecutorService executorService = Executors.newFixedThreadPool(3);
    
    try {
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost");
        
        executorService.submit(() -> {
            try {
                Connection connection = factory.newConnection();
                Channel channel = connection.createChannel();
                // Use channel
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        
        // Code that might throw exception
        int[] arr = new int[2];
        int val = arr[5]; // ArrayIndexOutOfBoundsException
        
        // ruleid: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    } catch (Exception e) {
        System.out.println("RabbitMQ error: " + e.getMessage());
    }
}

public void bad_case_13() {
    // Netty server with ExecutorService
    ExecutorService executorService = Executors.newCachedThreadPool();
    
    try {
        EventLoopGroup bossGroup = new NioEventLoopGroup();
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        
        executorService.submit(() -> {
            try {
                ServerBootstrap b = new ServerBootstrap();
                b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class);
                // Configure and start server
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        
        // Code that might throw exception
        Map<String, String> map = Collections.emptyMap();
        map.put("key", "value"); // UnsupportedOperationException
        
        // ruleid: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    } catch (Exception e) {
        System.out.println("Netty error: " + e.getMessage());
    }
}

public void bad_case_14() {
    // Google Guava ListeningExecutorService
    ListeningExecutorService executorService = MoreExecutors.listeningDecorator(
        Executors.newFixedThreadPool(10));
    
    try {
        ListenableFuture<String> future = executorService.submit(() -> {
            return "Task result";
        });
        
        // Code that might throw exception
        String value = null;
        int length = value.length(); // NullPointerException
        
        // ruleid: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    } catch (Exception e) {
        System.out.println("Guava executor error: " + e.getMessage());
    }
}

public void bad_case_15() {
    // Java CompletableFuture with ExecutorService
    ExecutorService executorService = Executors.newWorkStealingPool();
    
    try {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            return "Async task result";
        }, executorService);
        
        // Code that might throw exception
        List<String> list = Arrays.asList("one", "two");
        list.add("three"); // UnsupportedOperationException
        
        // ruleid: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    } catch (Exception e) {
        System.out.println("CompletableFuture error: " + e.getMessage());
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    // Standard Java ExecutorService with proper shutdown in finally block
    ExecutorService executorService = Executors.newFixedThreadPool(10);
    try {
        executorService.submit(() -> {
            System.out.println("Task executed");
        });
        
        // Some code that might throw an exception
        String data = null;
        if (data != null) {
            int length = data.length();
        }
    } catch (Exception e) {
        System.out.println("Exception caught: " + e.getMessage());
    } finally {
        // ok: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    }
}

public void good_case_2() {
    // Spring RestTemplate with ExecutorService and proper shutdown
    RestTemplate restTemplate = new RestTemplate();
    ExecutorService executorService = Executors.newCachedThreadPool();
    
    try {
        executorService.submit(() -> {
            ResponseEntity<String> response = restTemplate.getForEntity("https://api.example.com", String.class);
            System.out.println(response.getBody());
        });
        
        // Code that might throw exception
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL("https://invalid-url").openConnection();
            connection.connect();
        } catch (IOException e) {
            System.out.println("Connection error handled");
        }
    } catch (Exception e) {
        System.out.println("Connection failed: " + e.getMessage());
    } finally {
        // ok: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    }
}

public void good_case_3() {
    // AWS SDK with ExecutorService and proper shutdown
    ExecutorService executorService = Executors.newFixedThreadPool(5);
    AmazonLambdaClient lambdaClient = new AmazonLambdaClient();
    
    try {
        executorService.submit(() -> {
            InvokeRequest request = new InvokeRequest()
                .withFunctionName("my-function");
            lambdaClient.invoke(request);
        });
        
        // Code that might throw exception - safely handled
        File configFile = new File("/non-existent/config.json");
        if (configFile.exists()) {
            FileInputStream fis = new FileInputStream(configFile);
        }
    } catch (Exception e) {
        System.out.println("Failed to process: " + e.getMessage());
    } finally {
        // ok: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    }
}

public void good_case_4() {
    // OkHttp client with ExecutorService and proper shutdown
    OkHttpClient client = new OkHttpClient();
    ExecutorService executorService = Executors.newSingleThreadExecutor();
    
    try {
        Request request = new Request.Builder()
            .url("https://api.example.com/data")
            .build();
            
        executorService.submit(() -> {
            try {
                Response response = client.newCall(request).execute();
                System.out.println(response.body().string());
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        
        // Code that might throw exception - safely handled
        int[] array = new int[3];
        if (array.length > 5) {
            int value = array[5];
        }
    } catch (Exception e) {
        System.out.println("Error: " + e.getMessage());
    } finally {
        // ok: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    }
}

public void good_case_5() {
    // Retrofit API client with ExecutorService and proper shutdown
    ExecutorService executorService = Executors.newFixedThreadPool(3);
    Retrofit retrofit = new Retrofit.Builder()
        .baseUrl("https://api.example.com/")
        .build();
    
    try {
        executorService.submit(() -> {
            // Some API call
            System.out.println("API call executed");
        });
        
        // Code that might throw exception - safely handled
        Map<String, Object> map = null;
        if (map != null) {
            Object value = map.get("key");
        }
    } catch (Exception e) {
        System.out.println("Error in API call: " + e.getMessage());
    } finally {
        // ok: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    }
}

public void good_case_6() {
    // Quartz Scheduler with ExecutorService and proper shutdown
    ExecutorService executorService = Executors.newScheduledThreadPool(2);
    
    try {
        StdSchedulerFactory factory = new StdSchedulerFactory();
        Scheduler scheduler = factory.getScheduler();
        
        executorService.submit(() -> {
            try {
                scheduler.start();
            } catch (SchedulerException e) {
                e.printStackTrace();
            }
        });
        
        // Code that might throw exception - safely handled
        String input = null;
        if (input != null) {
            boolean check = input.equals("test");
        }
    } catch (Exception e) {
        System.out.println("Scheduler error: " + e.getMessage());
    } finally {
        // ok: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    }
}

public void good_case_7() {
    // JDBC database connection with ExecutorService and proper shutdown
    ExecutorService executorService = Executors.newFixedThreadPool(5);
    
    try {
        executorService.submit(() -> {
            try {
                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "pass");
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery("SELECT * FROM users");
                while (rs.next()) {
                    System.out.println(rs.getString("name"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        });
        
        // Code that might throw exception - safely handled
        int divisor = 0;
        if (divisor != 0) {
            int result = 100 / divisor;
        }
    } catch (Exception e) {
        System.out.println("Database error: " + e.getMessage());
    } finally {
        // ok: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    }
}

public void good_case_8() {
    // ActiveMQ JMS with ExecutorService and proper shutdown
    ExecutorService executorService = Executors.newCachedThreadPool();
    
    try {
        ActiveMQConnectionFactory connectionFactory = new ActiveMQConnectionFactory("tcp://localhost:61616");
        
        executorService.submit(() -> {
            try {
                Connection connection = connectionFactory.createConnection();
                connection.start();
                // Process messages
            } catch (JMSException e) {
                e.printStackTrace();
            }
        });
        
        // Code that might throw exception - safely handled
        List<String> list = null;
        if (list != null && !list.isEmpty()) {
            String firstItem = list.get(0);
        }
    } catch (Exception e) {
        System.out.println("JMS error: " + e.getMessage());
    } finally {
        // ok: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    }
}

public void good_case_9() {
    // Elasticsearch client with ExecutorService and proper shutdown
    ExecutorService executorService = Executors.newFixedThreadPool(3);
    
    try {
        RestClient restClient = RestClient.builder(
            new HttpHost("localhost", 9200, "http")).build();
        
        executorService.submit(() -> {
            try {
                Request request = new Request("GET", "/index/_search");
                Response response = restClient.performRequest(request);
                // Process response
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        
        // Code that might throw exception - safely handled
        String[] array = null;
        if (array != null) {
            int length = array.length;
        }
    } catch (Exception e) {
        System.out.println("Elasticsearch error: " + e.getMessage());
    } finally {
        // ok: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    }
}

public void good_case_10() {
    // Kafka producer with ExecutorService and proper shutdown
    ExecutorService executorService = Executors.newSingleThreadExecutor();
    
    try {
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        KafkaProducer<String, String> producer = new KafkaProducer<>(props);
        
        executorService.submit(() -> {
            producer.send(new ProducerRecord<>("topic", "key", "value"));
        });
        
        // Code that might throw exception - safely handled
        Object obj = "string";
        if (obj instanceof Integer) {
            Integer num = (Integer) obj;
        }
    } catch (Exception e) {
        System.out.println("Kafka error: " + e.getMessage());
    } finally {
        // ok: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    }
}

public void good_case_11() {
    // Redis Jedis client with ExecutorService and proper shutdown
    ExecutorService executorService = Executors.newFixedThreadPool(2);
    
    try {
        Jedis jedis = new Jedis("localhost");
        
        executorService.submit(() -> {
            jedis.set("key", "value");
            String value = jedis.get("key");
            System.out.println(value);
        });
        
        // Code that might throw exception - safely handled
        String str = null;
        if (str != null && !str.isEmpty()) {
            char c = str.charAt(0);
        }
    } catch (Exception e) {
        System.out.println("Redis error: " + e.getMessage());
    } finally {
        // ok: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    }
}

public void good_case_12() {
    // RabbitMQ client with ExecutorService and proper shutdown
    ExecutorService executorService = Executors.newFixedThreadPool(3);
    
    try {
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost");
        
        executorService.submit(() -> {
            try {
                Connection connection = factory.newConnection();
                Channel channel = connection.createChannel();
                // Use channel
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        
        // Code that might throw exception - safely handled
        int[] arr = new int[2];
        if (arr.length > 5) {
            int val = arr[5];
        }
    } catch (Exception e) {
        System.out.println("RabbitMQ error: " + e.getMessage());
    } finally {
        // ok: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    }
}

public void good_case_13() {
    // Netty server with ExecutorService and proper shutdown
    ExecutorService executorService = Executors.newCachedThreadPool();
    
    try {
        EventLoopGroup bossGroup = new NioEventLoopGroup();
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        
        executorService.submit(() -> {
            try {
                ServerBootstrap b = new ServerBootstrap();
                b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class);
                // Configure and start server
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        
        // Code that might throw exception - safely handled
        Map<String, String> map = Collections.emptyMap();
        if (!(map instanceof Collections.UnmodifiableMap)) {
            map.put("key", "value");
        }
    } catch (Exception e) {
        System.out.println("Netty error: " + e.getMessage());
    } finally {
        // ok: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    }
}

public void good_case_14() {
    // Google Guava ListeningExecutorService with proper shutdown
    ListeningExecutorService executorService = MoreExecutors.listeningDecorator(
        Executors.newFixedThreadPool(10));
    
    try {
        ListenableFuture<String> future = executorService.submit(() -> {
            return "Task result";
        });
        
        // Code that might throw exception - safely handled
        String value = null;
        if (value != null) {
            int length = value.length();
        }
    } catch (Exception e) {
        System.out.println("Guava executor error: " + e.getMessage());
    } finally {
        // ok: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    }
}

public void good_case_15() {
    // Java CompletableFuture with ExecutorService and proper shutdown
    ExecutorService executorService = Executors.newWorkStealingPool();
    
    try {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            return "Async task result";
        }, executorService);
        
        // Code that might throw exception - safely handled
        List<String> list = Arrays.asList("one", "two");
        if (!(list instanceof Collections.UnmodifiableCollection)) {
            list.add("three");
        }
    } catch (Exception e) {
        System.out.println("CompletableFuture error: " + e.getMessage());
    } finally {
        // ok: java-improper-shutdown-of-executor-service
        executorService.shutdown();
    }
}