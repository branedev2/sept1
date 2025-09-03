import java.io.IOException;
import java.sql.SQLException;
import java.net.HttpURLConnection;
import java.net.URL;
import org.springframework.web.client.RestTemplate;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.ChannelExec;
import org.apache.commons.net.ftp.FTPClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.BlobContainerClient;
import com.mongodb.MongoClient;
import com.mongodb.MongoException;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.ElasticsearchException;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.Channel;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.exceptions.JedisException;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.errors.KafkaException;
import javax.jms.JMSException;
import javax.jms.Session;
import javax.jms.MessageProducer;
import javax.jms.TextMessage;
import javax.jms.Connection;
import javax.jms.ConnectionFactory;
import javax.jms.Queue;
import org.apache.activemq.ActiveMQConnectionFactory;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseException;
import com.google.firebase.database.FirebaseDatabase;
import org.apache.commons.vfs2.FileObject;
import org.apache.commons.vfs2.FileSystemException;
import org.apache.commons.vfs2.FileSystemManager;
import org.apache.commons.vfs2.VFS;
import java.util.logging.Logger;
import java.util.logging.Level;

// Security Issue: Overly broad catch blocks can mask different types of exceptions, potentially hiding bugs or security vulnerabilities

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    // Spring RestTemplate with overly broad exception handling
    RestTemplate restTemplate = new RestTemplate();
    String url = "https://api.example.com/data";
    
    try {
        String response = restTemplate.getForObject(url, String.class);
        System.out.println("Response: " + response);
    } 
    // ruleid: java-poor-error-handling
    catch (Exception e) {
        // This catch block is too broad and masks all types of exceptions
        System.out.println("Error occurred: " + e.getMessage());
    }
}

public void bad_case_2() {
    // Apache HttpClient with overly broad exception handling
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
        HttpGet request = new HttpGet("https://api.example.com/users");
        httpClient.execute(request);
    } 
    // ruleid: java-poor-error-handling
    catch (Exception e) {
        // Broad catch hides specific HTTP errors, connection issues, etc.
        System.out.println("Failed to execute request: " + e.getMessage());
    }
}

public void bad_case_3() {
    // OkHttp client with overly broad exception handling
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
        .url("https://api.example.com/products")
        .build();
    
    try {
        okhttp3.Response response = client.newCall(request).execute();
        System.out.println(response.body().string());
    } 
    // ruleid: java-poor-error-handling
    catch (Throwable t) {
        // Even worse than Exception - catches absolutely everything
        System.out.println("Request failed: " + t.getMessage());
    }
}

public void bad_case_4() {
    // AWS S3 SDK with overly broad exception handling
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    
    try {
        s3Client.getObject("my-bucket", "my-object-key");
    } 
    // ruleid: java-poor-error-handling
    catch (Exception e) {
        // Masks specific AWS errors like access denied, no such bucket, etc.
        System.out.println("S3 operation failed: " + e.getMessage());
    }
}

public void bad_case_5() {
    // Google HTTP Client with overly broad exception handling
    HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
    
    try {
        HttpRequest request = requestFactory.buildGetRequest(new GenericUrl("https://api.example.com/data"));
        String rawResponse = request.execute().parseAsString();
        System.out.println("Response: " + rawResponse);
    } 
    // ruleid: java-poor-error-handling
    catch (Exception e) {
        // Masks HTTP errors, parsing issues, and other specific exceptions
        System.out.println("Request failed: " + e.getMessage());
    }
}

public void bad_case_6() {
    // Apache Commons Exec with overly broad exception handling
    CommandLine cmdLine = CommandLine.parse("ls -la");
    DefaultExecutor executor = new DefaultExecutor();
    
    try {
        int exitValue = executor.execute(cmdLine);
        System.out.println("Process exited with code: " + exitValue);
    } 
    // ruleid: java-poor-error-handling
    catch (Exception e) {
        // Masks specific execution errors like command not found
        System.out.println("Command execution failed: " + e.getMessage());
    }
}

public void bad_case_7() {
    // JSch (SSH library) with overly broad exception handling
    JSch jsch = new JSch();
    
    try {
        Session session = jsch.getSession("username", "hostname", 22);
        session.setPassword("password");
        session.connect();
        
        ChannelExec channel = (ChannelExec) session.openChannel("exec");
        channel.setCommand("ls -la");
        channel.connect();
        channel.disconnect();
        session.disconnect();
    } 
    // ruleid: java-poor-error-handling
    catch (Exception e) {
        // Masks authentication failures, connection issues, etc.
        System.out.println("SSH operation failed: " + e.getMessage());
    }
}

public void bad_case_8() {
    // Apache Commons Net FTP with overly broad exception handling
    FTPClient ftpClient = new FTPClient();
    
    try {
        ftpClient.connect("ftp.example.com");
        ftpClient.login("username", "password");
        ftpClient.retrieveFile("remote.txt", System.out);
        ftpClient.disconnect();
    } 
    // ruleid: java-poor-error-handling
    catch (Exception e) {
        // Masks connection issues, authentication failures, file not found, etc.
        System.out.println("FTP operation failed: " + e.getMessage());
    }
}

public void bad_case_9() {
    // Azure Blob Storage with overly broad exception handling
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
        .connectionString("DefaultEndpointsProtocol=https;AccountName=account;AccountKey=key;EndpointSuffix=core.windows.net")
        .buildClient();
    
    try {
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("container-name");
        containerClient.getBlobClient("blob-name").downloadToFile("local-path.txt");
    } 
    // ruleid: java-poor-error-handling
    catch (Exception e) {
        // Masks authentication issues, container not found, etc.
        System.out.println("Azure blob operation failed: " + e.getMessage());
    }
}

public void bad_case_10() {
    // MongoDB client with overly broad exception handling
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    
    try {
        mongoClient.getDatabase("test").getCollection("users").find().first();
        mongoClient.close();
    } 
    // ruleid: java-poor-error-handling
    catch (Exception e) {
        // Masks connection issues, authentication failures, etc.
        System.out.println("MongoDB operation failed: " + e.getMessage());
    }
}

public void bad_case_11() {
    // Elasticsearch client with overly broad exception handling
    RestHighLevelClient client = new RestHighLevelClient(
        RestClient.builder(new HttpHost("localhost", 9200, "http")));
    
    try {
        client.ping();
        client.close();
    } 
    // ruleid: java-poor-error-handling
    catch (Exception e) {
        // Masks specific Elasticsearch errors
        System.out.println("Elasticsearch operation failed: " + e.getMessage());
    }
}

public void bad_case_12() {
    // AWS DynamoDB SDK with overly broad exception handling
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    
    try {
        dynamoDbClient.listTables();
    } 
    // ruleid: java-poor-error-handling
    catch (Exception e) {
        // Masks specific DynamoDB errors like access denied
        System.out.println("DynamoDB operation failed: " + e.getMessage());
    }
}

public void bad_case_13() {
    // RabbitMQ client with overly broad exception handling
    ConnectionFactory factory = new ConnectionFactory();
    factory.setHost("localhost");
    
    try {
        Connection connection = factory.newConnection();
        Channel channel = connection.createChannel();
        channel.queueDeclare("queue-name", false, false, false, null);
        channel.basicPublish("", "queue-name", null, "Hello World".getBytes());
        channel.close();
        connection.close();
    } 
    // ruleid: java-poor-error-handling
    catch (Exception e) {
        // Masks connection issues, channel errors, etc.
        System.out.println("RabbitMQ operation failed: " + e.getMessage());
    }
}

public void bad_case_14() {
    // Redis Jedis client with overly broad exception handling
    Jedis jedis = new Jedis("localhost");
    
    try {
        jedis.set("key", "value");
        jedis.close();
    } 
    // ruleid: java-poor-error-handling
    catch (Exception e) {
        // Masks connection issues, Redis errors, etc.
        System.out.println("Redis operation failed: " + e.getMessage());
    }
}

public void bad_case_15() {
    // Kafka producer with overly broad exception handling
    KafkaProducer<String, String> producer = new KafkaProducer<>(new java.util.Properties());
    
    try {
        producer.send(new ProducerRecord<>("topic", "key", "value"));
        producer.close();
    } 
    // ruleid: java-poor-error-handling
    catch (Exception e) {
        // Masks specific Kafka errors like topic not found
        System.out.println("Kafka operation failed: " + e.getMessage());
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    // Spring RestTemplate with specific exception handling
    RestTemplate restTemplate = new RestTemplate();
    String url = "https://api.example.com/data";
    
    try {
        String response = restTemplate.getForObject(url, String.class);
        System.out.println("Response: " + response);
    } 
    // ok: java-poor-error-handling
    catch (org.springframework.web.client.HttpClientErrorException e) {
        System.out.println("Client error: " + e.getStatusCode() + " - " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (org.springframework.web.client.HttpServerErrorException e) {
        System.out.println("Server error: " + e.getStatusCode() + " - " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (org.springframework.web.client.ResourceAccessException e) {
        System.out.println("Resource access error: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (Exception e) {
        // Still have a catch-all, but only after handling specific cases
        System.out.println("Unexpected error: " + e.getMessage());
        throw e; // Re-throw to allow proper handling up the call stack
    }
}

public void good_case_2() {
    // Apache HttpClient with specific exception handling
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
        HttpGet request = new HttpGet("https://api.example.com/users");
        httpClient.execute(request);
    } 
    // ok: java-poor-error-handling
    catch (org.apache.http.client.ClientProtocolException e) {
        System.out.println("Client protocol error: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (java.net.UnknownHostException e) {
        System.out.println("Unknown host: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (java.io.IOException e) {
        System.out.println("I/O error: " + e.getMessage());
    }
}

public void good_case_3() {
    // OkHttp client with specific exception handling
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
        .url("https://api.example.com/products")
        .build();
    
    try {
        okhttp3.Response response = client.newCall(request).execute();
        System.out.println(response.body().string());
    } 
    // ok: java-poor-error-handling
    catch (java.net.MalformedURLException e) {
        System.out.println("Malformed URL: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (java.io.IOException e) {
        System.out.println("I/O error during request: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (RuntimeException e) {
        System.out.println("Runtime error: " + e.getMessage());
        throw e; // Re-throw to allow proper handling up the call stack
    }
}

public void good_case_4() {
    // AWS S3 SDK with specific exception handling
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    
    try {
        s3Client.getObject("my-bucket", "my-object-key");
    } 
    // ok: java-poor-error-handling
    catch (com.amazonaws.services.s3.model.AmazonS3Exception e) {
        if (e.getStatusCode() == 404) {
            System.out.println("Object not found: " + e.getMessage());
        } else if (e.getStatusCode() == 403) {
            System.out.println("Access denied: " + e.getMessage());
        } else {
            System.out.println("S3 error: " + e.getMessage());
        }
    } 
    // ok: java-poor-error-handling
    catch (com.amazonaws.SdkClientException e) {
        System.out.println("AWS SDK client error: " + e.getMessage());
    }
}

public void good_case_5() {
    // Google HTTP Client with specific exception handling
    HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
    
    try {
        HttpRequest request = requestFactory.buildGetRequest(new GenericUrl("https://api.example.com/data"));
        String rawResponse = request.execute().parseAsString();
        System.out.println("Response: " + rawResponse);
    } 
    // ok: java-poor-error-handling
    catch (com.google.api.client.http.HttpResponseException e) {
        System.out.println("HTTP error " + e.getStatusCode() + ": " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (java.io.IOException e) {
        System.out.println("I/O error: " + e.getMessage());
    }
}

public void good_case_6() {
    // Apache Commons Exec with specific exception handling
    CommandLine cmdLine = CommandLine.parse("ls -la");
    DefaultExecutor executor = new DefaultExecutor();
    
    try {
        int exitValue = executor.execute(cmdLine);
        System.out.println("Process exited with code: " + exitValue);
    } 
    // ok: java-poor-error-handling
    catch (ExecuteException e) {
        System.out.println("Execution failed with exit code " + e.getExitValue() + ": " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (IOException e) {
        System.out.println("I/O error during execution: " + e.getMessage());
    }
}

public void good_case_7() {
    // JSch (SSH library) with specific exception handling
    JSch jsch = new JSch();
    
    try {
        Session session = jsch.getSession("username", "hostname", 22);
        session.setPassword("password");
        session.connect();
        
        ChannelExec channel = (ChannelExec) session.openChannel("exec");
        channel.setCommand("ls -la");
        channel.connect();
        channel.disconnect();
        session.disconnect();
    } 
    // ok: java-poor-error-handling
    catch (JSchException e) {
        System.out.println("SSH error: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (IOException e) {
        System.out.println("I/O error: " + e.getMessage());
    }
}

public void good_case_8() {
    // Apache Commons Net FTP with specific exception handling
    FTPClient ftpClient = new FTPClient();
    
    try {
        ftpClient.connect("ftp.example.com");
        ftpClient.login("username", "password");
        ftpClient.retrieveFile("remote.txt", System.out);
        ftpClient.disconnect();
    } 
    // ok: java-poor-error-handling
    catch (java.net.UnknownHostException e) {
        System.out.println("Unknown host: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (java.net.ConnectException e) {
        System.out.println("Connection failed: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (IOException e) {
        System.out.println("I/O error: " + e.getMessage());
    }
}

public void good_case_9() {
    // Azure Blob Storage with specific exception handling
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
        .connectionString("DefaultEndpointsProtocol=https;AccountName=account;AccountKey=key;EndpointSuffix=core.windows.net")
        .buildClient();
    
    try {
        BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("container-name");
        containerClient.getBlobClient("blob-name").downloadToFile("local-path.txt");
    } 
    // ok: java-poor-error-handling
    catch (com.azure.storage.blob.models.BlobStorageException e) {
        System.out.println("Blob storage error " + e.getStatusCode() + ": " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (IOException e) {
        System.out.println("I/O error: " + e.getMessage());
    }
}

public void good_case_10() {
    // MongoDB client with specific exception handling
    MongoClient mongoClient = new MongoClient("localhost", 27017);
    
    try {
        mongoClient.getDatabase("test").getCollection("users").find().first();
        mongoClient.close();
    } 
    // ok: java-poor-error-handling
    catch (MongoException e) {
        System.out.println("MongoDB error: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (IllegalStateException e) {
        System.out.println("Illegal state: " + e.getMessage());
    }
}

public void good_case_11() {
    // Elasticsearch client with specific exception handling
    RestHighLevelClient client = new RestHighLevelClient(
        RestClient.builder(new HttpHost("localhost", 9200, "http")));
    
    try {
        client.ping();
        client.close();
    } 
    // ok: java-poor-error-handling
    catch (ElasticsearchException e) {
        System.out.println("Elasticsearch error: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (IOException e) {
        System.out.println("I/O error: " + e.getMessage());
    }
}

public void good_case_12() {
    // AWS DynamoDB SDK with specific exception handling
    DynamoDbClient dynamoDbClient = DynamoDbClient.create();
    
    try {
        dynamoDbClient.listTables();
    } 
    // ok: java-poor-error-handling
    catch (DynamoDbException e) {
        System.out.println("DynamoDB error: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (software.amazon.awssdk.core.exception.SdkClientException e) {
        System.out.println("AWS SDK client error: " + e.getMessage());
    }
}

public void good_case_13() {
    // RabbitMQ client with specific exception handling
    ConnectionFactory factory = new ConnectionFactory();
    factory.setHost("localhost");
    
    try {
        Connection connection = factory.newConnection();
        Channel channel = connection.createChannel();
        channel.queueDeclare("queue-name", false, false, false, null);
        channel.basicPublish("", "queue-name", null, "Hello World".getBytes());
        channel.close();
        connection.close();
    } 
    // ok: java-poor-error-handling
    catch (com.rabbitmq.client.ShutdownSignalException e) {
        System.out.println("RabbitMQ shutdown: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (com.rabbitmq.client.AlreadyClosedException e) {
        System.out.println("Channel already closed: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (java.io.IOException e) {
        System.out.println("I/O error: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (java.util.concurrent.TimeoutException e) {
        System.out.println("Connection timeout: " + e.getMessage());
    }
}

public void good_case_14() {
    // Redis Jedis client with specific exception handling
    Jedis jedis = new Jedis("localhost");
    
    try {
        jedis.set("key", "value");
        jedis.close();
    } 
    // ok: java-poor-error-handling
    catch (JedisException e) {
        System.out.println("Redis error: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (IllegalStateException e) {
        System.out.println("Illegal state: " + e.getMessage());
    }
}

public void good_case_15() {
    // Apache Commons VFS with specific exception handling
    try {
        FileSystemManager fsManager = VFS.getManager();
        FileObject file = fsManager.resolveFile("sftp://username:password@example.com/path/to/file");
        file.getContent();
    } 
    // ok: java-poor-error-handling
    catch (FileSystemException e) {
        System.out.println("VFS error: " + e.getMessage());
    } 
    // ok: java-poor-error-handling
    catch (RuntimeException e) {
        Logger.getLogger(getClass().getName()).log(Level.SEVERE, "Unexpected error", e);
        throw e; // Re-throw to allow proper handling up the call stack
    }
}