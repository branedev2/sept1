import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.HttpClients;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoClient;
import com.mongodb.ConnectionString;
import com.mongodb.client.MongoDatabase;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import java.util.Properties;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.common.StorageSharedKeyCredential;
import com.azure.storage.blob.models.BlobStorageException;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.drive.Drive;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import org.apache.http.HttpHost;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.Channel;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.concurrent.TimeoutException;

public class ClientConstructorExamples {

    // True Positive Examples (Vulnerable/Insecure Code)

// {fact rule=client-constructor-deprecated-rule@v1.0 defects=1}
    public void bad_case_1() {
        try {
            // ruleid: java-client-constructor-deprecated
            DefaultHttpClient httpClient = new DefaultHttpClient();
            HttpGet request = new HttpGet("https://api.example.com/data");
            HttpResponse response = httpClient.execute(request);
            System.out.println("Response status: " + response.getStatusLine());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // ruleid: java-client-constructor-deprecated
            AmazonS3 s3Client = new AmazonS3Client(new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
            boolean exists = s3Client.doesBucketExistV2("my-bucket");
            System.out.println("Bucket exists: " + exists);
        } catch (AmazonServiceException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        // ruleid: java-client-constructor-deprecated
        MongoClient mongoClient = new MongoClient("localhost", 27017);
        MongoDatabase database = mongoClient.getDatabase("test");
        System.out.println("Connected to database: " + database.getName());
    }

    public void bad_case_4() {
        try {
            // ruleid: java-client-constructor-deprecated
            TransportClient client = TransportClient.builder()
                .build()
                .addTransportAddress(new TransportAddress(InetAddress.getByName("localhost"), 9300));
            
            System.out.println("Connected nodes: " + client.connectedNodes());
            client.close();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        // ruleid: java-client-constructor-deprecated
        Jedis jedis = new Jedis("localhost");
        jedis.set("key", "value");
        String value = jedis.get("key");
        System.out.println("Retrieved value: " + value);
        jedis.close();
    }

    public void bad_case_6() {
        try {
            // ruleid: java-client-constructor-deprecated
            HttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
            JsonFactory jsonFactory = JacksonFactory.getDefaultInstance();
            
            Drive service = new Drive.Builder(httpTransport, jsonFactory, null)
                .setApplicationName("Drive API Example")
                .build();
                
            System.out.println("Drive service created");
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        
        // ruleid: java-client-constructor-deprecated
        Producer<String, String> producer = new KafkaProducer<>(props);
        producer.send(new ProducerRecord<>("topic", "key", "value"));
        producer.close();
    }

    public void bad_case_8() {
        try {
            ConnectionFactory factory = new ConnectionFactory();
            factory.setHost("localhost");
            
            // ruleid: java-client-constructor-deprecated
            com.rabbitmq.client.Connection connection = factory.newConnection();
            Channel channel = connection.createChannel();
            
            channel.queueDeclare("queue_name", false, false, false, null);
            channel.basicPublish("", "queue_name", null, "Hello World!".getBytes());
            
            channel.close();
            connection.close();
        } catch (IOException | TimeoutException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        try {
            // ruleid: java-client-constructor-deprecated
            Connection connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/test", 
                "username", 
                "password"
            );
            System.out.println("Database connected!");
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        // ruleid: java-client-constructor-deprecated
        JedisPool pool = new JedisPool("localhost", 6379);
        try (Jedis jedis = pool.getResource()) {
            jedis.set("key", "value");
        }
        pool.close();
    }

    public void bad_case_11() {
        // ruleid: java-client-constructor-deprecated
        MongoClient mongoClient = new MongoClient(new MongoClientURI("mongodb://localhost:27017"));
        MongoDatabase database = mongoClient.getDatabase("test");
        System.out.println("Connected to database: " + database.getName());
        mongoClient.close();
    }

    public void bad_case_12() {
        try {
            // ruleid: java-client-constructor-deprecated
            RestClient lowLevelClient = RestClient.builder(
                new HttpHost("localhost", 9200, "http")).build();
            
            System.out.println("Elasticsearch client created");
            lowLevelClient.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        // ruleid: java-client-constructor-deprecated
        AmazonS3 s3Client = new AmazonS3Client();
        s3Client.setRegion(com.amazonaws.regions.Region.getRegion(com.amazonaws.regions.Regions.US_WEST_2));
        boolean exists = s3Client.doesBucketExistV2("my-bucket");
        System.out.println("Bucket exists: " + exists);
    }

    public void bad_case_14() {
        try {
            // ruleid: java-client-constructor-deprecated
            DefaultHttpClient httpClient = new DefaultHttpClient();
            httpClient.getParams().setParameter("http.socket.timeout", 5000);
            HttpGet request = new HttpGet("https://api.example.com/data");
            HttpResponse response = httpClient.execute(request);
            System.out.println("Response status: " + response.getStatusLine());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        // ruleid: java-client-constructor-deprecated
        StorageSharedKeyCredential credential = new StorageSharedKeyCredential("accountName", "accountKey");
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .endpoint("https://accountName.blob.core.windows.net/")
            .credential(credential)
            .buildClient();
        
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("container");
        System.out.println("Container URL: " + containerClient.getBlobContainerUrl());
    }

    // True Negative Examples (Safe/Secure Code)

    public void good_case_1() {
        try {
            // ok: java-client-constructor-deprecated
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://api.example.com/data");
            CloseableHttpResponse response = httpClient.execute(request);
            System.out.println("Response status: " + response.getStatusLine());
            response.close();
            httpClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            // ok: java-client-constructor-deprecated
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                    new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")))
                .withRegion("us-west-2")
                .build();
            
            boolean exists = s3Client.doesBucketExistV2("my-bucket");
            System.out.println("Bucket exists: " + exists);
        } catch (AmazonServiceException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        // ok: java-client-constructor-deprecated
        com.mongodb.client.MongoClient mongoClient = MongoClients.create("mongodb://localhost:27017");
        MongoDatabase database = mongoClient.getDatabase("test");
        System.out.println("Connected to database: " + database.getName());
        ((com.mongodb.client.MongoClient)mongoClient).close();
    }

    public void good_case_4() {
        try {
            // ok: java-client-constructor-deprecated
            RestHighLevelClient client = new RestHighLevelClient(
                RestClient.builder(new HttpHost("localhost", 9200, "http")));
            
            System.out.println("Elasticsearch client created");
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        // ok: java-client-constructor-deprecated
        JedisPoolConfig poolConfig = new JedisPoolConfig();
        poolConfig.setMaxTotal(10);
        JedisPool pool = new JedisPool(poolConfig, "localhost", 6379);
        
        try (Jedis jedis = pool.getResource()) {
            jedis.set("key", "value");
            String value = jedis.get("key");
            System.out.println("Retrieved value: " + value);
        }
        pool.close();
    }

    public void good_case_6() {
        try {
            // ok: java-client-constructor-deprecated
            HttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
            JsonFactory jsonFactory = JacksonFactory.getDefaultInstance();
            
            // Using a builder pattern with proper authentication
            Drive.Builder builder = new Drive.Builder(httpTransport, jsonFactory, null)
                .setApplicationName("Drive API Example");
            
            Drive service = builder.build();
            System.out.println("Drive service created properly");
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        
        // ok: java-client-constructor-deprecated
        try (Producer<String, String> producer = new KafkaProducer<>(props)) {
            producer.send(new ProducerRecord<>("topic", "key", "value"));
        }
    }

    public void good_case_8() {
        try {
            ConnectionFactory factory = new ConnectionFactory();
            factory.setHost("localhost");
            factory.setPort(5672);
            
            // ok: java-client-constructor-deprecated
            try (com.rabbitmq.client.Connection connection = factory.newConnection();
                 Channel channel = connection.createChannel()) {
                
                channel.queueDeclare("queue_name", false, false, false, null);
                channel.basicPublish("", "queue_name", null, "Hello World!".getBytes());
            }
        } catch (IOException | TimeoutException e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            // ok: java-client-constructor-deprecated
            try (Connection connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/test?useSSL=true", 
                "username", 
                "password")) {
                
                System.out.println("Database connected securely!");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        // ok: java-client-constructor-deprecated
        com.mongodb.client.MongoClient mongoClient = MongoClients.create(
            new ConnectionString("mongodb://localhost:27017")
        );
        
        MongoDatabase database = mongoClient.getDatabase("test");
        System.out.println("Connected to database: " + database.getName());
        mongoClient.close();
    }

    public void good_case_11() {
        // ok: java-client-constructor-deprecated
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .connectionString("DefaultEndpointsProtocol=https;AccountName=accountName;AccountKey=accountKey;EndpointSuffix=core.windows.net")
            .buildClient();
        
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("container");
        System.out.println("Container URL: " + containerClient.getBlobContainerUrl());
    }

    public void good_case_12() {
        try {
            // ok: java-client-constructor-deprecated
            CloseableHttpClient httpClient = HttpClientBuilder.create()
                .setMaxConnTotal(100)
                .setMaxConnPerRoute(20)
                .build();
            
            HttpGet request = new HttpGet("https://api.example.com/data");
            CloseableHttpResponse response = httpClient.execute(request);
            System.out.println("Response status: " + response.getStatusLine());
            response.close();
            httpClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        // ok: java-client-constructor-deprecated
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
            .withRegion("us-west-2")
            .build();
            
        boolean exists = s3Client.doesBucketExistV2("my-bucket");
        System.out.println("Bucket exists: " + exists);
    }

    public void good_case_14() {
        try {
            // ok: java-client-constructor-deprecated
            RestHighLevelClient client = new RestHighLevelClient(
                RestClient.builder(
                    new HttpHost("localhost", 9200, "http"),
                    new HttpHost("localhost", 9201, "http")
                ).setRequestConfigCallback(
                    requestConfigBuilder -> requestConfigBuilder
                        .setConnectTimeout(5000)
                        .setSocketTimeout(60000)
                )
            );
            
            System.out.println("Elasticsearch client created with proper configuration");
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        // ok: java-client-constructor-deprecated
        StorageSharedKeyCredential credential = new StorageSharedKeyCredential("accountName", "accountKey");
        BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
            .endpoint("https://accountName.blob.core.windows.net/")
            .credential(credential)
            .retryOptions(new com.azure.core.http.policy.RetryOptions())
            .buildClient();
        
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("container");
        System.out.println("Container URL: " + containerClient.getBlobContainerUrl());
    }
}
// {/fact}