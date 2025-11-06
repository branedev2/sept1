import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.BlobContainerClient;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.CloseableHttpClient;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.DriveScopes;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.regions.Region;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClientBuilder;
import org.apache.http.HttpHost;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoClient;
import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.Channel;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringSerializer;
import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.Session;
import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.CqlSessionBuilder;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPSClient;
import org.apache.commons.net.ftp.FTPClientConfig;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import org.apache.commons.mail.Email;
import org.apache.commons.mail.SimpleEmail;
import org.apache.commons.mail.DefaultAuthenticator;
import org.apache.commons.mail.EmailConstants;
import com.sendgrid.SendGrid;
import com.sendgrid.Request;
import com.sendgrid.Method;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Content;
import com.sendgrid.helpers.mail.objects.Email;

import java.io.IOException;
import java.net.URI;
import java.util.Properties;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.net.InetSocketAddress;

// Security Issue: Deprecated client constructors pose a security risk by potentially exposing sensitive configuration data

// True Positive Examples (Vulnerable/Insecure Code)
public class DeprecatedClientConstructorExamples {

// {fact rule=client-constructor-deprecated-rule@v1.0 defects=1}
    public void bad_case_1() {
        String accessKey = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        
        // ruleid: java-client-constructor-deprecated
        AmazonS3Client s3Client = new AmazonS3Client(new BasicAWSCredentials(accessKey, secretKey));
        
        s3Client.listBuckets();
    }
    
    public void bad_case_2() {
        // ruleid: java-client-constructor-deprecated
        HttpClient httpClient = new DefaultHttpClient();
        
        // Using deprecated HttpClient constructor which may not have proper security configurations
        httpClient.getParams().setParameter("http.socket.timeout", 5000);
    }
    
    public void bad_case_3() {
        String connectionString = "mongodb://username:password@localhost:27017/admin";
        
        // ruleid: java-client-constructor-deprecated
        MongoClient mongoClient = new MongoClient(new MongoClientURI(connectionString));
        
        mongoClient.getDatabase("test").getCollection("users").find().first();
    }
    
    public void bad_case_4() {
        // ruleid: java-client-constructor-deprecated
        AmazonDynamoDBClient dynamoDBClient = new AmazonDynamoDBClient();
        
        dynamoDBClient.listTables();
    }
    
    public void bad_case_5() {
        // ruleid: java-client-constructor-deprecated
        Jedis jedis = new Jedis("localhost", 6379);
        
        jedis.set("key", "value");
        jedis.close();
    }
    
    public void bad_case_6() throws Exception {
        JSch jsch = new JSch();
        
        // ruleid: java-client-constructor-deprecated
        com.jcraft.jsch.Session session = jsch.getSession("username", "hostname", 22);
        session.setPassword("password");
        
        java.util.Properties config = new java.util.Properties();
        config.put("StrictHostKeyChecking", "no"); // Insecure configuration
        session.setConfig(config);
        session.connect();
    }
    
    public void bad_case_7() throws Exception {
        // ruleid: java-client-constructor-deprecated
        FTPClient ftpClient = new FTPClient();
        
        ftpClient.connect("ftp.example.com");
        ftpClient.login("username", "password");
    }
    
    public void bad_case_8() {
        // ruleid: java-client-constructor-deprecated
        Cluster cluster = Cluster.builder()
                .addContactPoint("127.0.0.1")
                .withCredentials("cassandra", "cassandra")
                .build();
        
        Session session = cluster.connect();
        session.execute("SELECT * FROM system.local");
    }
    
    public void bad_case_9() throws Exception {
        // ruleid: java-client-constructor-deprecated
        RestHighLevelClient client = new RestHighLevelClient(
                RestClient.builder(new HttpHost("localhost", 9200, "http")));
        
        client.info();
    }
    
    public void bad_case_10() {
        Properties props = new Properties();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        
        // ruleid: java-client-constructor-deprecated
        Producer<String, String> producer = new KafkaProducer<>(props);
        
        producer.send(new ProducerRecord<>("topic", "key", "value"));
    }
    
    public void bad_case_11() throws Exception {
        // ruleid: java-client-constructor-deprecated
        org.apache.commons.mail.Email email = new SimpleEmail();
        email.setHostName("smtp.gmail.com");
        email.setSmtpPort(465);
        email.setAuthenticator(new DefaultAuthenticator("username", "password"));
        email.setSSLOnConnect(true);
        email.setFrom("user@gmail.com");
        email.setSubject("Test Mail");
        email.setMsg("This is a test mail");
        email.addTo("foo@bar.com");
        email.send();
    }
    
    public void bad_case_12() throws Exception {
        Configuration conf = new Configuration();
        conf.set("fs.defaultFS", "hdfs://localhost:9000");
        
        // ruleid: java-client-constructor-deprecated
        FileSystem hdfs = FileSystem.get(conf);
        
        hdfs.createNewFile(new Path("/user/test/file.txt"));
    }
    
    public void bad_case_13() {
        // ruleid: java-client-constructor-deprecated
        OkHttpClient client = new OkHttpClient();
        
        Request request = new Request.Builder()
                .url("https://api.example.com/data")
                .build();
        
        try {
            Response response = client.newCall(request).execute();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_14() throws Exception {
        // ruleid: java-client-constructor-deprecated
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost");
        factory.setUsername("guest");
        factory.setPassword("guest");
        
        Connection connection = factory.newConnection();
        Channel channel = connection.createChannel();
        
        channel.queueDeclare("hello", false, false, false, null);
        channel.basicPublish("", "hello", null, "Hello World!".getBytes());
    }
    
    public void bad_case_15() {
        // ruleid: java-client-constructor-deprecated
        SendGrid sendGrid = new SendGrid("SG.REDAC_REDACTED_TWILIO_ID_SENDGRID_KEY");
        
        com.sendgrid.helpers.mail.Email from = new com.sendgrid.helpers.mail.objects.Email("test@example.com");
        String subject = "Test Email";
        com.sendgrid.helpers.mail.Email to = new com.sendgrid.helpers.mail.objects.Email("recipient@example.com");
        Content content = new Content("text/plain", "Hello World!");
        Mail mail = new Mail(from, subject, to, content);
        
        try {
            Request request = new Request();
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());
            sendGrid.api(request);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1() {
        // ok: java-client-constructor-deprecated
        AmazonS3ClientBuilder s3ClientBuilder = AmazonS3ClientBuilder.standard()
                .withRegion("us-west-2")
                .withCredentials(new com.amazonaws.auth.DefaultAWSCredentialsProviderChain());
        
        com.amazonaws.services.s3.AmazonS3 s3Client = s3ClientBuilder.build();
        s3Client.listBuckets();
    }
    
    public void good_case_2() {
        // ok: java-client-constructor-deprecated
        CloseableHttpClient httpClient = HttpClients.createDefault();
        
        // Using recommended HttpClient creation method with proper security configurations
        httpClient.getParams().setParameter("http.socket.timeout", 5000);
    }
    
    public void good_case_3() {
        String connectionString = "mongodb://username:password@localhost:27017/admin";
        
        // ok: java-client-constructor-deprecated
        com.mongodb.client.MongoClient mongoClient = MongoClients.create(connectionString);
        
        mongoClient.getDatabase("test").getCollection("users").find().first();
    }
    
    public void good_case_4() {
        // ok: java-client-constructor-deprecated
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.standard()
                .withRegion("us-west-2")
                .build();
        
        dynamoDBClient.listTables();
    }
    
    public void good_case_5() {
        JedisPoolConfig poolConfig = new JedisPoolConfig();
        poolConfig.setMaxTotal(10);
        poolConfig.setMaxIdle(5);
        poolConfig.setMinIdle(1);
        
        // ok: java-client-constructor-deprecated
        JedisPool jedisPool = new JedisPool(poolConfig, "localhost", 6379);
        
        try (Jedis jedis = jedisPool.getResource()) {
            jedis.set("key", "value");
        }
        jedisPool.close();
    }
    
    public void good_case_6() throws Exception {
        JSch jsch = new JSch();
        
        // ok: java-client-constructor-deprecated
        com.jcraft.jsch.Session session = jsch.getSession("username", "hostname", 22);
        session.setPassword("password");
        
        // Using more secure configuration
        java.util.Properties config = new java.util.Properties();
        config.put("StrictHostKeyChecking", "yes");
        session.setConfig(config);
        session.connect();
    }
    
    public void good_case_7() throws Exception {
        FTPClientConfig config = new FTPClientConfig();
        
        // ok: java-client-constructor-deprecated
        FTPSClient ftpsClient = new FTPSClient(true);
        ftpsClient.configure(config);
        
        ftpsClient.connect("ftps.example.com");
        ftpsClient.login("username", "password");
    }
    
    public void good_case_8() {
        // ok: java-client-constructor-deprecated
        CqlSessionBuilder sessionBuilder = CqlSession.builder()
                .addContactPoint(new InetSocketAddress("127.0.0.1", 9042))
                .withLocalDatacenter("datacenter1")
                .withAuthCredentials("cassandra", "cassandra");
        
        CqlSession session = sessionBuilder.build();
        session.execute("SELECT * FROM system.local");
    }
    
    public void good_case_9() throws Exception {
        // ok: java-client-constructor-deprecated
        RestClientBuilder builder = RestClient.builder(new HttpHost("localhost", 9200, "http"));
        RestHighLevelClient client = new RestHighLevelClientBuilder(builder.build())
                .setApiCompatibilityMode(true)
                .build();
        
        client.info();
    }
    
    public void good_case_10() {
        Properties props = new Properties();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        props.put(ProducerConfig.SECURITY_PROVIDERS_CONFIG, "org.apache.kafka.common.security.plain.PlainLoginModule");
        
        // ok: java-client-constructor-deprecated
        Producer<String, String> producer = new KafkaProducer<>(props);
        
        producer.send(new ProducerRecord<>("topic", "key", "value"));
    }
    
    public void good_case_11() throws Exception {
        // ok: java-client-constructor-deprecated
        org.apache.commons.mail.Email email = new SimpleEmail();
        email.setHostName("smtp.gmail.com");
        email.setSmtpPort(465);
        email.setAuthenticator(new DefaultAuthenticator("username", "password"));
        email.setSSLOnConnect(true);
        email.setSSLCheckServerIdentity(true);
        email.setStartTLSEnabled(true);
        email.setStartTLSRequired(true);
        email.setFrom("user@gmail.com");
        email.setSubject("Test Mail");
        email.setMsg("This is a test mail");
        email.addTo("foo@bar.com");
        email.send();
    }
    
    public void good_case_12() throws Exception {
        Configuration conf = new Configuration();
        conf.set("fs.defaultFS", "hdfs://localhost:9000");
        conf.set("hadoop.security.authentication", "kerberos");
        conf.set("hadoop.security.authorization", "true");
        
        // ok: java-client-constructor-deprecated
        FileSystem hdfs = FileSystem.newInstance(new URI("hdfs://localhost:9000"), conf);
        
        hdfs.createNewFile(new Path("/user/test/file.txt"));
    }
    
    public void good_case_13() {
        // ok: java-client-constructor-deprecated
        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
                .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
                .build();
        
        Request request = new Request.Builder()
                .url("https://api.example.com/data")
                .build();
        
        try {
            Response response = client.newCall(request).execute();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_14() throws Exception {
        // ok: java-client-constructor-deprecated
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost");
        factory.setUsername("guest");
        factory.setPassword("guest");
        factory.useSslProtocol();
        
        Connection connection = factory.newConnection();
        Channel channel = connection.createChannel();
        
        Map<String, Object> args = new HashMap<>();
        args.put("x-message-ttl", 60000);
        
        channel.queueDeclare("hello", false, false, false, args);
        channel.basicPublish("", "hello", null, "Hello World!".getBytes());
    }
    
    public void good_case_15() {
        // ok: java-client-constructor-deprecated
        SendGrid sendGrid = new SendGrid(System.getenv("SENDGRID_API_KEY"));
        
        com.sendgrid.helpers.mail.Email from = new com.sendgrid.helpers.mail.objects.Email("test@example.com");
        String subject = "Test Email";
        com.sendgrid.helpers.mail.Email to = new com.sendgrid.helpers.mail.objects.Email("recipient@example.com");
        Content content = new Content("text/plain", "Hello World!");
        Mail mail = new Mail(from, subject, to, content);
        
        try {
            Request request = new Request();
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());
            sendGrid.api(request);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
    
    public static void main(String[] args) {
        System.out.println("Examples for deprecated client constructors vulnerability detection");
    }
}
// {/fact}