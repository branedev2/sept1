import java.net.URL;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.client.methods.HttpPost;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.security.cert.X509Certificate;
import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.ClientConfiguration;

import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPSClient;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;

import org.apache.commons.mail.Email;
import org.apache.commons.mail.SimpleEmail;
import org.apache.commons.mail.HtmlEmail;

import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.Message;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.InternetAddress;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;

import org.apache.commons.vfs2.FileSystemOptions;
import org.apache.commons.vfs2.provider.ftp.FtpFileSystemConfigBuilder;
import org.apache.commons.vfs2.FileSystemManager;
import org.apache.commons.vfs2.VFS;

import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.ServerAddress;

import org.apache.activemq.ActiveMQConnectionFactory;
import javax.jms.Connection;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import java.util.Properties;

// Security Issue: Using clear-text protocols instead of secure alternatives (CWE-319)

public class ClearTextProtocolExamples {

    // True Positive Examples (Vulnerable/Insecure Code)
    
// {fact rule=insecure-cookie@v1.0 defects=1}
    public void bad_case_1() throws MalformedURLException, IOException {
        // Java's built-in HttpURLConnection with clear-text HTTP
        String endpoint = "api/data";
        // ruleid: java-clear-text-protocol
        URL url = new URL("http://example.com/" + endpoint);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        int responseCode = connection.getResponseCode();
        System.out.println("Response Code: " + responseCode);
    }

    public void bad_case_2() throws IOException {
        // Apache HttpClient with clear-text HTTP
        HttpClient httpClient = HttpClients.createDefault();
        String userId = "12345";
        // ruleid: java-clear-text-protocol
        HttpGet request = new HttpGet("http://api.example.org/users/" + userId);
        httpClient.execute(request);
    }

    public void bad_case_3() throws IOException {
        // OkHttp client with clear-text HTTP
        OkHttpClient client = new OkHttpClient();
        String productId = "electronics/laptops";
        // ruleid: java-clear-text-protocol
        Request request = new Request.Builder()
            .url("http://store.example.com/products/" + productId)
            .build();
        Response response = client.newCall(request).execute();
    }

    public void bad_case_4() {
        // Spring RestTemplate with clear-text HTTP
        RestTemplate restTemplate = new RestTemplate();
        String customerId = "customer123";
        // ruleid: java-clear-text-protocol
        ResponseEntity<String> response = restTemplate.getForEntity(
            "http://crm.example.com/customers/" + customerId, String.class);
    }

    public void bad_case_5() throws IOException {
        // Apache Commons Net FTP (clear-text file transfer)
        FTPClient ftpClient = new FTPClient();
        String filename = "report.pdf";
        // ruleid: java-clear-text-protocol
        ftpClient.connect("ftp.example.com", 21);
        ftpClient.login("username", "password");
        ftpClient.retrieveFile(filename, System.out);
    }

    public void bad_case_6() throws Exception {
        // Telnet protocol (clear-text terminal)
        org.apache.commons.net.telnet.TelnetClient telnetClient = new org.apache.commons.net.telnet.TelnetClient();
        String server = "mainframe.example.com";
        // ruleid: java-clear-text-protocol
        telnetClient.connect(server, 23);
    }

    public void bad_case_7() throws Exception {
        // SMTP without TLS (clear-text email)
        Email email = new SimpleEmail();
        // ruleid: java-clear-text-protocol
        email.setHostName("smtp.example.com");
        email.setSmtpPort(25);
        email.setFrom("user@example.com");
        email.addTo("recipient@example.com");
        email.setSubject("Test Email");
        email.setMsg("This is a test email");
        email.send();
    }

    public void bad_case_8() {
        // Redis without TLS (clear-text database connection)
        String redisHost = "cache.example.com";
        // ruleid: java-clear-text-protocol
        Jedis jedis = new Jedis(redisHost, 6379);
        jedis.set("key", "value");
    }

    public void bad_case_9() throws Exception {
        // Google HTTP Client with clear-text HTTP
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        String apiEndpoint = "search";
        // ruleid: java-clear-text-protocol
        HttpRequest request = requestFactory.buildGetRequest(
            new GenericUrl("http://api.example.net/" + apiEndpoint));
        String rawResponse = request.execute().parseAsString();
    }

    public void bad_case_10() {
        // Jetty Server with HTTP (clear-text web server)
        Server server = new Server();
        // ruleid: java-clear-text-protocol
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(8080);
        server.addConnector(connector);
    }

    public void bad_case_11() {
        // Vert.x HTTP Server (clear-text web server)
        Vertx vertx = Vertx.vertx();
        // ruleid: java-clear-text-protocol
        HttpServer server = vertx.createHttpServer();
        server.requestHandler(req -> req.response().end("Hello World!"));
        server.listen(8080);
    }

    public void bad_case_12() throws Exception {
        // Apache Commons VFS with FTP (clear-text file operations)
        FileSystemOptions fsOptions = new FileSystemOptions();
        FtpFileSystemConfigBuilder.getInstance().setPassiveMode(fsOptions, true);
        FileSystemManager fsManager = VFS.getManager();
        String remoteFile = "reports/monthly.csv";
        // ruleid: java-clear-text-protocol
        fsManager.resolveFile("ftp://user:pass@ftp.example.org/" + remoteFile, fsOptions);
    }

    public void bad_case_13() {
        // MongoDB without TLS (clear-text database connection)
        String server = "db.example.com";
        // ruleid: java-clear-text-protocol
        MongoClient mongoClient = new MongoClient(new ServerAddress(server, 27017));
        mongoClient.getDatabase("test").getCollection("data");
    }

    public void bad_case_14() throws Exception {
        // ActiveMQ without TLS (clear-text messaging)
        String brokerUrl = "queue.example.com";
        // ruleid: java-clear-text-protocol
        ActiveMQConnectionFactory factory = new ActiveMQConnectionFactory("tcp://" + brokerUrl + ":61616");
        Connection connection = factory.createConnection();
        connection.start();
    }

    public void bad_case_15() {
        // Kafka Producer without TLS (clear-text messaging)
        Properties props = new Properties();
        String kafkaServer = "kafka.example.com:9092";
        // ruleid: java-clear-text-protocol
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaServer);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
        KafkaProducer<String, String> producer = new KafkaProducer<>(props);
    }

    // True Negative Examples (Safe/Secure Code)
    
    public void good_case_1() throws MalformedURLException, IOException {
        // Java's built-in HttpsURLConnection with HTTPS
        String endpoint = "api/data";
        // ok: java-clear-text-protocol
        URL url = new URL("https://example.com/" + endpoint);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        int responseCode = connection.getResponseCode();
        System.out.println("Response Code: " + responseCode);
    }

    public void good_case_2() throws IOException {
        // Apache HttpClient with HTTPS
        HttpClient httpClient = HttpClients.createDefault();
        String userId = "12345";
        // ok: java-clear-text-protocol
        HttpGet request = new HttpGet("https://api.example.org/users/" + userId);
        httpClient.execute(request);
    }

    public void good_case_3() throws IOException {
        // OkHttp client with HTTPS
        OkHttpClient client = new OkHttpClient();
        String productId = "electronics/laptops";
        // ok: java-clear-text-protocol
        Request request = new Request.Builder()
            .url("https://store.example.com/products/" + productId)
            .build();
        Response response = client.newCall(request).execute();
    }

    public void good_case_4() {
        // Spring RestTemplate with HTTPS
        RestTemplate restTemplate = new RestTemplate();
        String customerId = "customer123";
        // ok: java-clear-text-protocol
        ResponseEntity<String> response = restTemplate.getForEntity(
            "https://crm.example.com/customers/" + customerId, String.class);
    }

    public void good_case_5() throws IOException {
        // Apache Commons Net FTPS (secure file transfer)
        FTPSClient ftpsClient = new FTPSClient(true);
        String filename = "report.pdf";
        // ok: java-clear-text-protocol
        ftpsClient.connect("ftps.example.com", 990);
        ftpsClient.login("username", "password");
        ftpsClient.retrieveFile(filename, System.out);
    }

    public void good_case_6() throws Exception {
        // SSH instead of Telnet (secure terminal)
        JSch jsch = new JSch();
        String server = "mainframe.example.com";
        // ok: java-clear-text-protocol
        Session session = jsch.getSession("username", server, 22);
        session.setPassword("password");
        session.setConfig("StrictHostKeyChecking", "no");
        session.connect();
    }

    public void good_case_7() throws Exception {
        // SMTP with TLS (secure email)
        Email email = new SimpleEmail();
        // ok: java-clear-text-protocol
        email.setHostName("smtp.example.com");
        email.setSmtpPort(587);
        email.setSSLOnConnect(true);
        email.setStartTLSEnabled(true);
        email.setFrom("user@example.com");
        email.addTo("recipient@example.com");
        email.setSubject("Test Email");
        email.setMsg("This is a test email");
        email.send();
    }

    public void good_case_8() {
        // Redis with TLS (secure database connection)
        String redisHost = "cache.example.com";
        JedisPoolConfig poolConfig = new JedisPoolConfig();
        // ok: java-clear-text-protocol
        JedisPool jedisPool = new JedisPool(poolConfig, redisHost, 6379, 2000, "password", true);
        try (Jedis jedis = jedisPool.getResource()) {
            jedis.set("key", "value");
        }
    }

    public void good_case_9() throws Exception {
        // Google HTTP Client with HTTPS
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        String apiEndpoint = "search";
        // ok: java-clear-text-protocol
        HttpRequest request = requestFactory.buildGetRequest(
            new GenericUrl("https://api.example.net/" + apiEndpoint));
        String rawResponse = request.execute().parseAsString();
    }

    public void good_case_10() throws Exception {
        // Jetty Server with HTTPS (secure web server)
        Server server = new Server();
        
        // Setup SSL
        HttpConfiguration https = new HttpConfiguration();
        https.addCustomizer(new SecureRequestCustomizer());
        
        SslContextFactory sslContextFactory = new SslContextFactory.Server();
        sslContextFactory.setKeyStorePath("keystore.jks");
        sslContextFactory.setKeyStorePassword("password");
        
        // ok: java-clear-text-protocol
        ServerConnector sslConnector = new ServerConnector(server,
            new SslConnectionFactory(sslContextFactory, "http/1.1"),
            new HttpConnectionFactory(https));
        sslConnector.setPort(8443);
        server.addConnector(sslConnector);
    }

    public void good_case_11() {
        // Vert.x HTTPS Server (secure web server)
        Vertx vertx = Vertx.vertx();
        HttpServerOptions options = new HttpServerOptions()
            .setSsl(true)
            .setKeyStoreOptions(
                new JksOptions()
                    .setPath("keystore.jks")
                    .setPassword("password")
            );
        
        // ok: java-clear-text-protocol
        HttpServer server = vertx.createHttpServer(options);
        server.requestHandler(req -> req.response().end("Hello World!"));
        server.listen(8443);
    }

    public void good_case_12() throws Exception {
        // Apache Commons VFS with SFTP (secure file operations)
        FileSystemOptions fsOptions = new FileSystemOptions();
        SftpFileSystemConfigBuilder.getInstance().setStrictHostKeyChecking(fsOptions, "no");
        FileSystemManager fsManager = VFS.getManager();
        String remoteFile = "reports/monthly.csv";
        // ok: java-clear-text-protocol
        fsManager.resolveFile("sftp://user:pass@sftp.example.org/" + remoteFile, fsOptions);
    }

    public void good_case_13() {
        // MongoDB with TLS (secure database connection)
        String server = "db.example.com";
        // ok: java-clear-text-protocol
        MongoClientURI uri = new MongoClientURI("mongodb://user:password@" + server + 
            ":27017/database?ssl=true&sslInvalidHostNameAllowed=true");
        MongoClient mongoClient = new MongoClient(uri);
        mongoClient.getDatabase("test").getCollection("data");
    }

    public void good_case_14() throws Exception {
        // ActiveMQ with TLS (secure messaging)
        String brokerUrl = "queue.example.com";
        // ok: java-clear-text-protocol
        ActiveMQConnectionFactory factory = new ActiveMQConnectionFactory("ssl://" + brokerUrl + ":61617");
        Connection connection = factory.createConnection();
        connection.start();
    }

    public void good_case_15() {
        // Kafka Producer with TLS (secure messaging)
        Properties props = new Properties();
        String kafkaServer = "kafka.example.com:9093";
        // ok: java-clear-text-protocol
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaServer);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
        props.put("security.protocol", "SSL");
        props.put("ssl.truststore.location", "/path/to/truststore.jks");
        props.put("ssl.truststore.password", "password");
        KafkaProducer<String, String> producer = new KafkaProducer<>(props);
    }
}
// {/fact}