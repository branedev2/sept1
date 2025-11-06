import java.net.URL;
import java.net.HttpURLConnection;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;

import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.drive.Drive;

import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.services.s3.S3Client;

import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClientConfig;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

import com.azure.core.http.HttpClient;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;

import com.rabbitmq.client.ConnectionFactory;

import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.JedisSslParameters;

// Security Issue: Disabled TLS Certificate Verification

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() throws Exception {
    // Java's HttpsURLConnection with disabled certificate verification
    TrustManager[] trustAllCerts = new TrustManager[] {
        new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
            
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }
            
            // ruleid: java-no-tls-cert-verification
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
                // No verification
            }
        }
    };
    
    SSLContext sc = SSLContext.getInstance("TLS");
    sc.init(null, trustAllCerts, new SecureRandom());
    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    
    URL url = new URL("https://example.com");
    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
    conn.connect();
}

public void bad_case_2() throws Exception {
    // Apache HttpClient with disabled certificate verification
    // ruleid: java-no-tls-cert-verification
    SSLContextBuilder builder = new SSLContextBuilder();
    builder.loadTrustMaterial(null, new TrustStrategy() {
        @Override
        public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            return true; // Trust all certificates
        }
    });
    
    SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
            builder.build(), new String[] { "TLSv1.2" }, null,
            SSLConnectionSocketFactory.getDefaultHostnameVerifier());
    
    HttpClient client = HttpClients.custom()
            .setSSLSocketFactory(sslsf)
            .build();
    
    HttpGet request = new HttpGet("https://example.com");
    client.execute(request);
}

public void bad_case_3() throws Exception {
    // OkHttp client with disabled certificate verification
    OkHttpClient.Builder builder = new OkHttpClient.Builder();
    
    // ruleid: java-no-tls-cert-verification
    TrustManager[] trustAllCerts = new TrustManager[] {
        new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }
    };
    
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, trustAllCerts, new SecureRandom());
    
    builder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0]);
    builder.hostnameVerifier((hostname, session) -> true);
    
    OkHttpClient client = builder.build();
    Request request = new Request.Builder()
            .url("https://example.com")
            .build();
    
    Response response = client.newCall(request).execute();
}

public void bad_case_4() throws Exception {
    // Spring RestTemplate with disabled certificate verification
    // ruleid: java-no-tls-cert-verification
    TrustManager[] trustAllCerts = new TrustManager[] {
        new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return null; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {}
            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        }
    };
    
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, trustAllCerts, new SecureRandom());
    
    HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
    HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    
    SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
    RestTemplate restTemplate = new RestTemplate(requestFactory);
    
    String response = restTemplate.getForObject("https://example.com", String.class);
}

public void bad_case_5() throws Exception {
    // AWS SDK with disabled certificate verification
    ClientConfiguration clientConfig = new ClientConfiguration();
    
    // ruleid: java-no-tls-cert-verification
    clientConfig.getApacheHttpClientConfig().setSslSocketFactory(
        new SSLConnectionSocketFactory(
            SSLContext.getInstance("TLS"),
            new String[] { "TLSv1.2" },
            null,
            (hostname, session) -> true // Disable hostname verification
        )
    );
    
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
            .withRegion("us-west-2")
            .withClientConfiguration(clientConfig)
            .build();
    
    s3Client.listBuckets();
}

public void bad_case_6() throws Exception {
    // Google API Client with disabled certificate verification
    // ruleid: java-no-tls-cert-verification
    TrustManager[] trustAllCerts = new TrustManager[] {
        new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return null; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {}
            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        }
    };
    
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, trustAllCerts, new SecureRandom());
    
    HttpTransport httpTransport = new NetHttpTransport.Builder()
            .setSslSocketFactory(sslContext.getSocketFactory())
            .doNotValidateCertificate() // This explicitly disables certificate validation
            .build();
    
    JsonFactory jsonFactory = JacksonFactory.getDefaultInstance();
    Drive service = new Drive.Builder(httpTransport, jsonFactory, null)
            .setApplicationName("MyApplication")
            .build();
}

public void bad_case_7() throws Exception {
    // AWS SDK v2 with disabled certificate verification
    // ruleid: java-no-tls-cert-verification
    SdkHttpClient httpClient = ApacheHttpClient.builder()
            .tlsTrustManagersProvider(() -> new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            })
            .build();
    
    S3Client s3 = S3Client.builder()
            .httpClient(httpClient)
            .build();
}

public void bad_case_8() throws Exception {
    // AsyncHttpClient with disabled certificate verification
    // ruleid: java-no-tls-cert-verification
    DefaultAsyncHttpClientConfig.Builder configBuilder = new DefaultAsyncHttpClientConfig.Builder();
    configBuilder.setUseInsecureTrustManager(true); // This explicitly uses an insecure trust manager
    
    AsyncHttpClient client = new DefaultAsyncHttpClient(configBuilder.build());
    client.prepareGet("https://example.com").execute().get();
}

public void bad_case_9() throws Exception {
    // Netty with disabled certificate verification
    // ruleid: java-no-tls-cert-verification
    SslContext sslContext = SslContextBuilder.forClient()
            .trustManager(InsecureTrustManagerFactory.INSTANCE) // This uses an insecure trust manager
            .build();
    
    // Use this SSL context with a Netty HTTP client
    io.netty.bootstrap.Bootstrap bootstrap = new io.netty.bootstrap.Bootstrap();
    // Configure bootstrap with the insecure SSL context
}

public void bad_case_10() throws Exception {
    // Retrofit with disabled certificate verification
    // ruleid: java-no-tls-cert-verification
    OkHttpClient unsafeOkHttpClient = new OkHttpClient.Builder()
            .hostnameVerifier((hostname, session) -> true)
            .sslSocketFactory(
                SSLContext.getInstance("TLS").getSocketFactory(),
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                    
                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                    
                    @Override
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                }
            )
            .build();
    
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://example.com/")
            .client(unsafeOkHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build();
}

public void bad_case_11() throws Exception {
    // Azure SDK with disabled certificate verification
    // ruleid: java-no-tls-cert-verification
    HttpClient httpClient = new NettyAsyncHttpClientBuilder()
            .sslContext(SslContextBuilder.forClient()
                    .trustManager(InsecureTrustManagerFactory.INSTANCE)
                    .build())
            .build();
    
    // Use this HTTP client with Azure services
}

public void bad_case_12() throws Exception {
    // Jetty HttpClient with disabled certificate verification
    // ruleid: java-no-tls-cert-verification
    SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
    sslContextFactory.setTrustAll(true); // Trust all certificates
    
    HttpClient httpClient = new HttpClient(sslContextFactory);
    httpClient.start();
    
    org.eclipse.jetty.client.api.ContentResponse response = httpClient.GET("https://example.com");
}

public void bad_case_13() throws Exception {
    // MongoDB client with disabled certificate verification
    // ruleid: java-no-tls-cert-verification
    MongoClientSettings settings = MongoClientSettings.builder()
            .applyToSslSettings(builder -> 
                builder.invalidHostNameAllowed(true) // Allow invalid hostnames
            )
            .build();
    
    MongoClient mongoClient = MongoClients.create(settings);
}

public void bad_case_14() throws Exception {
    // RabbitMQ with disabled certificate verification
    ConnectionFactory factory = new ConnectionFactory();
    factory.setHost("localhost");
    factory.setPort(5671);
    factory.useSslProtocol();
    
    // ruleid: java-no-tls-cert-verification
    factory.setSocketConfigurator(socket -> {
        if (socket instanceof SSLSocket) {
            ((SSLSocket) socket).setEnabledProtocols(new String[] {"TLSv1.2"});
            // Disable hostname verification
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        }
    });
    
    com.rabbitmq.client.Connection connection = factory.newConnection();
}

public void bad_case_15() throws Exception {
    // Redis Jedis with disabled certificate verification
    JedisPoolConfig poolConfig = new JedisPoolConfig();
    JedisSslParameters sslParameters = new JedisSslParameters();
    
    // ruleid: java-no-tls-cert-verification
    sslParameters.setTrustManager(new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        
        @Override
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    });
    
    JedisPool jedisPool = new JedisPool(poolConfig, "redis.example.com", 6379, 
            2000, null, 0, null, sslParameters);
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() throws Exception {
    // Java's HttpsURLConnection with proper certificate verification
    // ok: java-no-tls-cert-verification
    URL url = new URL("https://example.com");
    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
    conn.connect(); // Uses the default SSLSocketFactory which validates certificates
}

public void good_case_2() throws Exception {
    // Apache HttpClient with proper certificate verification
    // ok: java-no-tls-cert-verification
    HttpClient client = HttpClients.createDefault(); // Uses default SSL context which validates certificates
    HttpGet request = new HttpGet("https://example.com");
    client.execute(request);
}

public void good_case_3() throws Exception {
    // OkHttp client with proper certificate verification
    // ok: java-no-tls-cert-verification
    OkHttpClient client = new OkHttpClient(); // Default configuration validates certificates
    Request request = new Request.Builder()
            .url("https://example.com")
            .build();
    
    Response response = client.newCall(request).execute();
}

public void good_case_4() throws Exception {
    // Spring RestTemplate with proper certificate verification
    // ok: java-no-tls-cert-verification
    RestTemplate restTemplate = new RestTemplate(); // Default configuration validates certificates
    String response = restTemplate.getForObject("https://example.com", String.class);
}

public void good_case_5() throws Exception {
    // AWS SDK with proper certificate verification
    // ok: java-no-tls-cert-verification
    AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
            .withRegion("us-west-2")
            .build(); // Default configuration validates certificates
    
    s3Client.listBuckets();
}

public void good_case_6() throws Exception {
    // Google API Client with proper certificate verification
    // ok: java-no-tls-cert-verification
    HttpTransport httpTransport = new NetHttpTransport(); // Default configuration validates certificates
    JsonFactory jsonFactory = JacksonFactory.getDefaultInstance();
    
    Drive service = new Drive.Builder(httpTransport, jsonFactory, null)
            .setApplicationName("MyApplication")
            .build();
}

public void good_case_7() throws Exception {
    // AWS SDK v2 with proper certificate verification
    // ok: java-no-tls-cert-verification
    S3Client s3 = S3Client.builder()
            .region(Region.US_WEST_2)
            .build(); // Default configuration validates certificates
}

public void good_case_8() throws Exception {
    // AsyncHttpClient with proper certificate verification
    // ok: java-no-tls-cert-verification
    AsyncHttpClient client = new DefaultAsyncHttpClient(); // Default configuration validates certificates
    client.prepareGet("https://example.com").execute().get();
}

public void good_case_9() throws Exception {
    // Netty with proper certificate verification
    // ok: java-no-tls-cert-verification
    SslContext sslContext = SslContextBuilder.forClient()
            .build(); // Default configuration validates certificates
    
    // Use this SSL context with a Netty HTTP client
    io.netty.bootstrap.Bootstrap bootstrap = new io.netty.bootstrap.Bootstrap();
    // Configure bootstrap with the secure SSL context
}

public void good_case_10() throws Exception {
    // Retrofit with proper certificate verification
    // ok: java-no-tls-cert-verification
    OkHttpClient client = new OkHttpClient(); // Default configuration validates certificates
    
    Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://example.com/")
            .client(client)
            .addConverterFactory(GsonConverterFactory.create())
            .build();
}

public void good_case_11() throws Exception {
    // Azure SDK with proper certificate verification
    // ok: java-no-tls-cert-verification
    HttpClient httpClient = new NettyAsyncHttpClientBuilder()
            .build(); // Default configuration validates certificates
    
    // Use this HTTP client with Azure services
}

public void good_case_12() throws Exception {
    // Jetty HttpClient with proper certificate verification
    // ok: java-no-tls-cert-verification
    SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
    // Default configuration validates certificates
    
    HttpClient httpClient = new HttpClient(sslContextFactory);
    httpClient.start();
    
    org.eclipse.jetty.client.api.ContentResponse response = httpClient.GET("https://example.com");
}

public void good_case_13() throws Exception {
    // MongoDB client with proper certificate verification
    // ok: java-no-tls-cert-verification
    MongoClientSettings settings = MongoClientSettings.builder()
            .applyToSslSettings(builder -> 
                builder.enabled(true) // Enable SSL with default certificate validation
            )
            .build();
    
    MongoClient mongoClient = MongoClients.create(settings);
}

public void good_case_14() throws Exception {
    // RabbitMQ with proper certificate verification
    // ok: java-no-tls-cert-verification
    ConnectionFactory factory = new ConnectionFactory();
    factory.setHost("localhost");
    factory.setPort(5671);
    factory.useSslProtocol(); // Uses default SSL context which validates certificates
    
    com.rabbitmq.client.Connection connection = factory.newConnection();
}

public void good_case_15() throws Exception {
    // Redis Jedis with proper certificate verification
    // ok: java-no-tls-cert-verification
    JedisPoolConfig poolConfig = new JedisPoolConfig();
    JedisSslParameters sslParameters = new JedisSslParameters(); // Default configuration validates certificates
    
    JedisPool jedisPool = new JedisPool(poolConfig, "redis.example.com", 6379, 
            2000, null, 0, null, sslParameters);
}