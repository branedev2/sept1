import javax.net.ssl.*;
import java.net.*;
import java.io.*;
import java.security.*;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.catalina.connector.Connector;
import okhttp3.OkHttpClient;
import com.amazonaws.ClientConfiguration;
import com.google.api.client.http.javanet.NetHttpTransport;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.JksOptions;
import io.vertx.core.Vertx;
import io.vertx.core.net.NetServerOptions;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.ext.web.client.WebClient;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.SecureProtocolSocketFactory;
import org.apache.commons.httpclient.HttpClient as CommonsHttpClient;
import com.rabbitmq.client.ConnectionFactory;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.clients.CommonClientConfigs;
import java.util.Properties;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.KafkaProducer;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisSentinelPool;
import com.mongodb.MongoClientSettings;
import com.mongodb.ConnectionString;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.neo4j.driver.Config;
import com.couchbase.client.java.env.ClusterEnvironment;
import com.couchbase.client.java.Cluster;
import com.couchbase.client.core.env.SecurityConfig;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import java.util.HashMap;
import java.util.Map;

// Security Issue: Using insecure SSL/TLS versions (older than TLS 1.2)

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    try {
        // Using javax.net.ssl.SSLContext with insecure TLS version
        // ruleid: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(null, null, new SecureRandom());
        
        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://example.com").openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        connection.connect();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_2() {
    try {
        // Apache HttpClient with insecure TLS version
        SSLContextBuilder builder = new SSLContextBuilder();
        // ruleid: java-insecure-tls-version
        builder.useProtocol("SSLv3");
        
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
            builder.build(),
            new String[] { "SSLv3" },
            null,
            SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        
        HttpClient client = HttpClients.custom()
            .setSSLSocketFactory(sslsf)
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3() {
    // Spring Boot with insecure TLS version
    @Configuration
    class ServerConfig {
        @Bean
        public WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> webServerFactoryCustomizer() {
            return factory -> {
                Ssl ssl = new Ssl();
                // ruleid: java-insecure-tls-version
                ssl.setEnabledProtocols(new String[] { "TLSv1", "TLSv1.1" });
                factory.setSsl(ssl);
            };
        }
    }
}

public void bad_case_4() {
    try {
        // Jetty server with insecure TLS version
        Server server = new Server();
        ServerConnector connector = new ServerConnector(server);
        
        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        sslContextFactory.setKeyStorePath("/path/to/keystore");
        sslContextFactory.setKeyStorePassword("password");
        // ruleid: java-insecure-tls-version
        sslContextFactory.setIncludeProtocols("TLSv1");
        
        ServerConnector sslConnector = new ServerConnector(server, sslContextFactory);
        sslConnector.setPort(8443);
        server.addConnector(sslConnector);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    // Tomcat connector with insecure TLS version
    Connector connector = new Connector();
    connector.setPort(8443);
    connector.setSecure(true);
    connector.setScheme("https");
    
    SSLHostConfig sslHostConfig = new SSLHostConfig();
    // ruleid: java-insecure-tls-version
    sslHostConfig.setProtocols("TLSv1+TLSv1.1");
    connector.addSslHostConfig(sslHostConfig);
}

public void bad_case_6() {
    // OkHttp client with insecure TLS version
    try {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        
        OkHttpClient client = new OkHttpClient.Builder()
            .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).getTrustManagers()[0])
            // ruleid: java-insecure-tls-version
            .connectionSpecs(Arrays.asList(ConnectionSpec.COMPATIBLE_TLS)) // This includes TLSv1.0
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    // AWS SDK with insecure TLS version
    ClientConfiguration clientConfig = new ClientConfiguration();
    // ruleid: java-insecure-tls-version
    clientConfig.setSecureProtocol("TLSv1");
    
    AmazonS3Client s3Client = new AmazonS3Client(clientConfig);
}

public void bad_case_8() {
    // Google API Client with insecure TLS version
    try {
        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(null, null, new SecureRandom());
        
        // ruleid: java-insecure-tls-version
        NetHttpTransport transport = new NetHttpTransport.Builder()
            .setSslSocketFactory(sslContext.getSocketFactory())
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9() {
    // Vert.x with insecure TLS version
    Vertx vertx = Vertx.vertx();
    
    HttpServerOptions options = new HttpServerOptions()
        .setSsl(true)
        .setKeyStoreOptions(new JksOptions()
            .setPath("/path/to/keystore.jks")
            .setPassword("password"));
    
    // ruleid: java-insecure-tls-version
    options.addEnabledSecureTransportProtocol("TLSv1");
    
    vertx.createHttpServer(options)
        .requestHandler(req -> req.response().end("Hello!"))
        .listen(8443);
}

public void bad_case_10() {
    // Apache Commons HttpClient with insecure TLS version
    try {
        SSLContext sslContext = SSLContext.getInstance("SSLv3");
        sslContext.init(null, null, new SecureRandom());
        
        SecureProtocolSocketFactory socketFactory = new MySecureProtocolSocketFactory(sslContext);
        
        // ruleid: java-insecure-tls-version
        Protocol https = new Protocol("https", socketFactory, 443);
        Protocol.registerProtocol("https", https);
        
        CommonsHttpClient client = new CommonsHttpClient();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11() {
    // RabbitMQ with insecure TLS version
    ConnectionFactory factory = new ConnectionFactory();
    factory.setHost("localhost");
    factory.setPort(5671);
    factory.useSslProtocol();
    
    try {
        // ruleid: java-insecure-tls-version
        factory.useSslProtocol("TLSv1");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12() {
    // Kafka with insecure TLS version
    Properties props = new Properties();
    props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
    props.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SSL");
    // ruleid: java-insecure-tls-version
    props.put(SslConfigs.SSL_ENABLED_PROTOCOLS_CONFIG, "TLSv1,TLSv1.1");
    
    KafkaProducer<String, String> producer = new KafkaProducer<>(props);
}

public void bad_case_13() {
    // Redis Jedis with insecure TLS version
    try {
        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(null, null, new SecureRandom());
        
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        
        // ruleid: java-insecure-tls-version
        JedisPool jedisPool = new JedisPool(new JedisPoolConfig(), "localhost", 6379, 
            2000, "password", true, sslSocketFactory, null, null);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14() {
    // MongoDB with insecure TLS version
    try {
        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(null, null, new SecureRandom());
        
        // ruleid: java-insecure-tls-version
        MongoClientSettings settings = MongoClientSettings.builder()
            .applyConnectionString(new ConnectionString("mongodb://localhost:27017"))
            .applyToSslSettings(builder -> {
                builder.enabled(true)
                       .context(sslContext);
            })
            .build();
        
        MongoClient mongoClient = MongoClients.create(settings);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15() {
    // Neo4j with insecure TLS version
    try {
        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(null, null, new SecureRandom());
        
        // ruleid: java-insecure-tls-version
        Config config = Config.builder()
            .withEncryption()
            .withTrustStrategy(TrustStrategy.trustAllCertificates())
            .withCustomSSLContext(sslContext)
            .build();
        
        Driver driver = GraphDatabase.driver("neo4j://localhost:7687", 
            AuthTokens.basic("neo4j", "password"), config);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    try {
        // Using javax.net.ssl.SSLContext with secure TLS version
        // ok: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        
        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://example.com").openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        connection.connect();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    try {
        // Apache HttpClient with secure TLS version
        SSLContextBuilder builder = new SSLContextBuilder();
        // ok: java-insecure-tls-version
        builder.useProtocol("TLSv1.2");
        
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
            builder.build(),
            new String[] { "TLSv1.2", "TLSv1.3" },
            null,
            SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        
        HttpClient client = HttpClients.custom()
            .setSSLSocketFactory(sslsf)
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3() {
    // Spring Boot with secure TLS version
    @Configuration
    class ServerConfig {
        @Bean
        public WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> webServerFactoryCustomizer() {
            return factory -> {
                Ssl ssl = new Ssl();
                // ok: java-insecure-tls-version
                ssl.setEnabledProtocols(new String[] { "TLSv1.2", "TLSv1.3" });
                factory.setSsl(ssl);
            };
        }
    }
}

public void good_case_4() {
    try {
        // Jetty server with secure TLS version
        Server server = new Server();
        ServerConnector connector = new ServerConnector(server);
        
        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        sslContextFactory.setKeyStorePath("/path/to/keystore");
        sslContextFactory.setKeyStorePassword("password");
        // ok: java-insecure-tls-version
        sslContextFactory.setIncludeProtocols("TLSv1.2", "TLSv1.3");
        
        ServerConnector sslConnector = new ServerConnector(server, sslContextFactory);
        sslConnector.setPort(8443);
        server.addConnector(sslConnector);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    // Tomcat connector with secure TLS version
    Connector connector = new Connector();
    connector.setPort(8443);
    connector.setSecure(true);
    connector.setScheme("https");
    
    SSLHostConfig sslHostConfig = new SSLHostConfig();
    // ok: java-insecure-tls-version
    sslHostConfig.setProtocols("TLSv1.2+TLSv1.3");
    connector.addSslHostConfig(sslHostConfig);
}

public void good_case_6() {
    // OkHttp client with secure TLS version
    try {
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        
        // ok: java-insecure-tls-version
        OkHttpClient client = new OkHttpClient.Builder()
            .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).getTrustManagers()[0])
            .connectionSpecs(Arrays.asList(ConnectionSpec.MODERN_TLS)) // TLS 1.2+ only
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7() {
    // AWS SDK with secure TLS version
    ClientConfiguration clientConfig = new ClientConfiguration();
    // ok: java-insecure-tls-version
    clientConfig.setSecureProtocol("TLSv1.2");
    
    AmazonS3Client s3Client = new AmazonS3Client(clientConfig);
}

public void good_case_8() {
    // Google API Client with secure TLS version
    try {
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        
        // ok: java-insecure-tls-version
        NetHttpTransport transport = new NetHttpTransport.Builder()
            .setSslSocketFactory(sslContext.getSocketFactory())
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9() {
    // Vert.x with secure TLS version
    Vertx vertx = Vertx.vertx();
    
    HttpServerOptions options = new HttpServerOptions()
        .setSsl(true)
        .setKeyStoreOptions(new JksOptions()
            .setPath("/path/to/keystore.jks")
            .setPassword("password"));
    
    // ok: java-insecure-tls-version
    options.addEnabledSecureTransportProtocol("TLSv1.2");
    options.addEnabledSecureTransportProtocol("TLSv1.3");
    
    vertx.createHttpServer(options)
        .requestHandler(req -> req.response().end("Hello!"))
        .listen(8443);
}

public void good_case_10() {
    // Apache Commons HttpClient with secure TLS version
    try {
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        
        SecureProtocolSocketFactory socketFactory = new MySecureProtocolSocketFactory(sslContext);
        
        // ok: java-insecure-tls-version
        Protocol https = new Protocol("https", socketFactory, 443);
        Protocol.registerProtocol("https", https);
        
        CommonsHttpClient client = new CommonsHttpClient();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    // RabbitMQ with secure TLS version
    ConnectionFactory factory = new ConnectionFactory();
    factory.setHost("localhost");
    factory.setPort(5671);
    
    try {
        // ok: java-insecure-tls-version
        factory.useSslProtocol("TLSv1.2");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12() {
    // Kafka with secure TLS version
    Properties props = new Properties();
    props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
    props.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SSL");
    // ok: java-insecure-tls-version
    props.put(SslConfigs.SSL_ENABLED_PROTOCOLS_CONFIG, "TLSv1.2,TLSv1.3");
    
    KafkaProducer<String, String> producer = new KafkaProducer<>(props);
}

public void good_case_13() {
    // Redis Jedis with secure TLS version
    try {
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        
        SSLParameters sslParameters = new SSLParameters();
        sslParameters.setProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
        
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        
        // ok: java-insecure-tls-version
        JedisPool jedisPool = new JedisPool(new JedisPoolConfig(), "localhost", 6379, 
            2000, "password", true, sslSocketFactory, sslParameters, null);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14() {
    // MongoDB with secure TLS version
    try {
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        
        // ok: java-insecure-tls-version
        MongoClientSettings settings = MongoClientSettings.builder()
            .applyConnectionString(new ConnectionString("mongodb://localhost:27017"))
            .applyToSslSettings(builder -> {
                builder.enabled(true)
                       .context(sslContext);
            })
            .build();
        
        MongoClient mongoClient = MongoClients.create(settings);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15() {
    // Neo4j with secure TLS version
    try {
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        
        // ok: java-insecure-tls-version
        Config config = Config.builder()
            .withEncryption()
            .withTrustStrategy(TrustStrategy.trustAllCertificates())
            .withCustomSSLContext(sslContext)
            .build();
        
        Driver driver = GraphDatabase.driver("neo4j://localhost:7687", 
            AuthTokens.basic("neo4j", "password"), config);
    } catch (Exception e) {
        e.printStackTrace();
    }
}