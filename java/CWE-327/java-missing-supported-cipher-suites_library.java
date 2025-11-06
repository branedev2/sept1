import java.net.URL;
import java.net.HttpURLConnection;
import java.security.KeyStore;
import javax.net.ssl.*;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.io.IOException;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;

import okhttp3.OkHttpClient;
import okhttp3.ConnectionSpec;
import okhttp3.TlsVersion;
import okhttp3.CipherSuite;

import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

import com.squareup.okhttp.OkHttpClient;

import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClientConfig;

import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.http.AmazonHttpClient;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;

import com.ning.http.client.AsyncHttpClientConfig;

import org.glassfish.jersey.client.JerseyClient;
import org.glassfish.jersey.client.JerseyClientBuilder;
import org.glassfish.jersey.SslConfigurator;

import com.netflix.client.config.IClientConfig;
import com.netflix.client.config.DefaultClientConfigImpl;
import com.netflix.niws.client.http.RestClient;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;

import feign.Client;
import feign.httpclient.ApacheHttpClient;

import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;

// Security Issue: Missing supported cipher suites in HTTP clients

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    // Using standard Java HttpsURLConnection with weak cipher suites
    try {
        URL url = new URL("https://api.example.com");
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        
        // ruleid: java-missing-supported-cipher-suites
        String[] weakCipherSuites = {
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA"
        };
        
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        connection.setSSLSocketFactory(socketFactory);
        connection.setRequestMethod("GET");
        connection.connect();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_2() {
    // Apache HttpClient with outdated cipher suites
    try {
        // ruleid: java-missing-supported-cipher-suites
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        
        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
            sslContext,
            new String[] {"TLSv1", "TLSv1.1"}, // Outdated TLS versions
            new String[] {"TLS_RSA_WITH_AES_128_CBC_SHA"}, // Limited cipher suite
            SSLConnectionSocketFactory.getDefaultHostnameVerifier()
        );
        
        HttpClient client = HttpClients.custom()
            .setSSLSocketFactory(sslSocketFactory)
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3() {
    // OkHttp3 client with weak cipher suites
    // ruleid: java-missing-supported-cipher-suites
    ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        .tlsVersions(TlsVersion.TLS_1_1)
        .cipherSuites(
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA
        )
        .build();

    OkHttpClient client = new OkHttpClient.Builder()
        .connectionSpecs(Arrays.asList(spec, ConnectionSpec.CLEARTEXT))
        .build();
}

public void bad_case_4() {
    // Spring RestTemplate with custom SSLContext but missing strong cipher suites
    try {
        // ruleid: java-missing-supported-cipher-suites
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        
        org.apache.http.impl.client.HttpClientBuilder clientBuilder = org.apache.http.impl.client.HttpClientBuilder.create();
        org.apache.http.conn.ssl.SSLConnectionSocketFactory socketFactory = new org.apache.http.conn.ssl.SSLConnectionSocketFactory(
            sslContext,
            new String[] {"TLSv1.1"}, // Not including TLSv1.3
            null, // Using default cipher suites which might be weak
            org.apache.http.conn.ssl.SSLConnectionSocketFactory.getDefaultHostnameVerifier()
        );
        
        clientBuilder.setSSLSocketFactory(socketFactory);
        requestFactory.setHttpClient(clientBuilder.build());
        
        RestTemplate restTemplate = new RestTemplate(requestFactory);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    // OkHttp (older version) with weak cipher suites
    try {
        // ruleid: java-missing-supported-cipher-suites
        com.squareup.okhttp.OkHttpClient client = new com.squareup.okhttp.OkHttpClient();
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        
        client.setSslSocketFactory(sslContext.getSocketFactory());
        // No explicit cipher suite configuration, using potentially weak defaults
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    // AsyncHttpClient with weak cipher suites
    try {
        // ruleid: java-missing-supported-cipher-suites
        DefaultAsyncHttpClientConfig.Builder configBuilder = new DefaultAsyncHttpClientConfig.Builder();
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        configBuilder.setSslContext(sslContext);
        
        // No explicit cipher suite configuration, using potentially weak defaults
        AsyncHttpClient client = new DefaultAsyncHttpClient(configBuilder.build());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    // AWS SDK v2 Apache HTTP client with weak cipher suites
    try {
        // ruleid: java-missing-supported-cipher-suites
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        
        ApacheHttpClient.Builder builder = ApacheHttpClient.builder()
            .tlsKeyManagersProvider(() -> null)
            .tlsTrustManagersProvider(() -> null)
            // No explicit cipher suite configuration, using potentially weak defaults
            .sslProvider(() -> sslContext);
        
        SdkHttpClient httpClient = builder.build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    // AWS SDK v1 with weak cipher suites
    // ruleid: java-missing-supported-cipher-suites
    ClientConfiguration clientConfig = new ClientConfiguration();
    // Using default HTTPS protocol which might not include the strongest cipher suites
    clientConfig.setProtocol(com.amazonaws.Protocol.HTTPS);
    
    // No explicit cipher suite configuration, using potentially weak defaults
    AmazonHttpClient client = new AmazonHttpClient(clientConfig);
}

public void bad_case_9() {
    // Google HTTP Client with weak cipher suites
    try {
        // ruleid: java-missing-supported-cipher-suites
        NetHttpTransport.Builder builder = new NetHttpTransport.Builder();
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        
        builder.setSslSocketFactory(sslContext.getSocketFactory());
        // No explicit cipher suite configuration, using potentially weak defaults
        
        HttpTransport httpTransport = builder.build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10() {
    // Jetty HTTP Client with weak cipher suites
    // ruleid: java-missing-supported-cipher-suites
    SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
    sslContextFactory.setIncludeProtocols("TLSv1.1");
    sslContextFactory.setIncludeCipherSuites("TLS_RSA_WITH_AES_128_CBC_SHA");
    // Limited to older protocols and cipher suites
    
    org.eclipse.jetty.client.HttpClient client = new org.eclipse.jetty.client.HttpClient(sslContextFactory);
}

public void bad_case_11() {
    // Vert.x Web Client with weak cipher suites
    Vertx vertx = Vertx.vertx();
    
    // ruleid: java-missing-supported-cipher-suites
    HttpClientOptions options = new HttpClientOptions()
        .setSsl(true)
        .setEnabledSecureTransportProtocols(new HashSet<>(Arrays.asList("TLSv1.1")))
        .setEnabledCipherSuites(Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA"));
    
    WebClient client = WebClient.create(vertx, new WebClientOptions(options));
}

public void bad_case_12() {
    // Ning AsyncHttpClient with weak cipher suites
    // ruleid: java-missing-supported-cipher-suites
    AsyncHttpClientConfig config = new AsyncHttpClientConfig.Builder()
        .setSSLContext(createWeakSslContext())
        .build();
    
    com.ning.http.client.AsyncHttpClient client = new com.ning.http.client.AsyncHttpClient(config);
}

private SSLContext createWeakSslContext() {
    try {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        return sslContext;
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void bad_case_13() {
    // Jersey Client with weak cipher suites
    // ruleid: java-missing-supported-cipher-suites
    SslConfigurator sslConfig = SslConfigurator.newInstance()
        .securityProtocol("TLSv1.1");
    
    SSLContext sslContext = sslConfig.createSSLContext();
    
    JerseyClient client = JerseyClientBuilder.createClient()
        .sslContext(sslContext)
        .build();
}

public void bad_case_14() {
    // Netflix Ribbon RestClient with weak cipher suites
    // ruleid: java-missing-supported-cipher-suites
    IClientConfig clientConfig = new DefaultClientConfigImpl();
    clientConfig.loadProperties("ribbon-client");
    // No explicit cipher suite configuration, using potentially weak defaults
    
    RestClient client = new RestClient(clientConfig);
}

public void bad_case_15() {
    // Feign HTTP Client with weak cipher suites
    try {
        // ruleid: java-missing-supported-cipher-suites
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        
        org.apache.http.impl.client.HttpClientBuilder httpClientBuilder = org.apache.http.impl.client.HttpClientBuilder.create();
        httpClientBuilder.setSSLContext(sslContext);
        // No explicit cipher suite configuration, using potentially weak defaults
        
        org.apache.http.client.HttpClient httpClient = httpClientBuilder.build();
        Client feignClient = new ApacheHttpClient(httpClient);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    // Using standard Java HttpsURLConnection with strong cipher suites
    try {
        URL url = new URL("https://api.example.com");
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(null, null, null);
        
        // ok: java-missing-supported-cipher-suites
        String[] strongCipherSuites = {
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        };
        
        SSLParameters sslParams = new SSLParameters();
        sslParams.setCipherSuites(strongCipherSuites);
        
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        connection.setSSLSocketFactory(socketFactory);
        connection.setSSLParameters(sslParams);
        connection.setRequestMethod("GET");
        connection.connect();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    // Apache HttpClient with strong cipher suites
    try {
        // ok: java-missing-supported-cipher-suites
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(null, null, null);
        
        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
            sslContext,
            new String[] {"TLSv1.2", "TLSv1.3"}, // Modern TLS versions
            new String[] {
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            },
            SSLConnectionSocketFactory.getDefaultHostnameVerifier()
        );
        
        HttpClient client = HttpClients.custom()
            .setSSLSocketFactory(sslSocketFactory)
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3() {
    // OkHttp3 client with strong cipher suites
    List<CipherSuite> strongCipherSuites = new ArrayList<>();
    strongCipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
    strongCipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
    strongCipherSuites.add(CipherSuite.TLS_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256);
    strongCipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    strongCipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
    
    // ok: java-missing-supported-cipher-suites
    ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        .tlsVersions(TlsVersion.TLS_1_2, TlsVersion.TLS_1_3)
        .cipherSuites(strongCipherSuites.toArray(new CipherSuite[0]))
        .build();

    OkHttpClient client = new OkHttpClient.Builder()
        .connectionSpecs(Arrays.asList(spec, ConnectionSpec.CLEARTEXT))
        .build();
}

public void good_case_4() {
    // Spring RestTemplate with custom SSLContext and strong cipher suites
    try {
        // ok: java-missing-supported-cipher-suites
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(null, null, null);
        
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        
        org.apache.http.impl.client.HttpClientBuilder clientBuilder = org.apache.http.impl.client.HttpClientBuilder.create();
        org.apache.http.conn.ssl.SSLConnectionSocketFactory socketFactory = new org.apache.http.conn.ssl.SSLConnectionSocketFactory(
            sslContext,
            new String[] {"TLSv1.2", "TLSv1.3"}, // Modern TLS versions
            new String[] {
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            },
            org.apache.http.conn.ssl.SSLConnectionSocketFactory.getDefaultHostnameVerifier()
        );
        
        clientBuilder.setSSLSocketFactory(socketFactory);
        requestFactory.setHttpClient(clientBuilder.build());
        
        RestTemplate restTemplate = new RestTemplate(requestFactory);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    // OkHttp (older version) with strong cipher suites
    try {
        // ok: java-missing-supported-cipher-suites
        com.squareup.okhttp.OkHttpClient client = new com.squareup.okhttp.OkHttpClient();
        
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, null);
        
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        
        // Explicitly enable strong cipher suites
        String[] strongCipherSuites = {
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        };
        
        client.setSslSocketFactory(new StrongCipherSocketFactory(sslSocketFactory, strongCipherSuites));
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// Helper class for good_case_5
class StrongCipherSocketFactory extends SSLSocketFactory {
    private final SSLSocketFactory delegate;
    private final String[] cipherSuites;
    
    public StrongCipherSocketFactory(SSLSocketFactory delegate, String[] cipherSuites) {
        this.delegate = delegate;
        this.cipherSuites = cipherSuites;
    }
    
    @Override
    public String[] getDefaultCipherSuites() {
        return cipherSuites;
    }
    
    @Override
    public String[] getSupportedCipherSuites() {
        return cipherSuites;
    }
    
    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        SSLSocket socket = (SSLSocket) delegate.createSocket(s, host, port, autoClose);
        socket.setEnabledCipherSuites(cipherSuites);
        return socket;
    }
    
    @Override
    public Socket createSocket(String host, int port) throws IOException {
        SSLSocket socket = (SSLSocket) delegate.createSocket(host, port);
        socket.setEnabledCipherSuites(cipherSuites);
        return socket;
    }
    
    @Override
    public Socket createSocket(String host, int port, java.net.InetAddress localHost, int localPort) throws IOException {
        SSLSocket socket = (SSLSocket) delegate.createSocket(host, port, localHost, localPort);
        socket.setEnabledCipherSuites(cipherSuites);
        return socket;
    }
    
    @Override
    public Socket createSocket(java.net.InetAddress host, int port) throws IOException {
        SSLSocket socket = (SSLSocket) delegate.createSocket(host, port);
        socket.setEnabledCipherSuites(cipherSuites);
        return socket;
    }
    
    @Override
    public Socket createSocket(java.net.InetAddress address, int port, java.net.InetAddress localAddress, int localPort) throws IOException {
        SSLSocket socket = (SSLSocket) delegate.createSocket(address, port, localAddress, localPort);
        socket.setEnabledCipherSuites(cipherSuites);
        return socket;
    }
}

public void good_case_6() {
    // AsyncHttpClient with strong cipher suites
    try {
        // ok: java-missing-supported-cipher-suites
        DefaultAsyncHttpClientConfig.Builder configBuilder = new DefaultAsyncHttpClientConfig.Builder();
        
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, null);
        
        // Configure with strong cipher suites
        SSLParameters sslParameters = sslContext.getDefaultSSLParameters();
        sslParameters.setProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
        sslParameters.setCipherSuites(new String[] {
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        });
        
        configBuilder.setSslContext(sslContext);
        configBuilder.setSslEngineFactory(new CustomSslEngineFactory(sslContext, sslParameters));
        
        AsyncHttpClient client = new DefaultAsyncHttpClient(configBuilder.build());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// Helper class for good_case_6
class CustomSslEngineFactory implements io.netty.handler.ssl.SslEngineFactory {
    private final SSLContext sslContext;
    private final SSLParameters sslParameters;
    
    public CustomSslEngineFactory(SSLContext sslContext, SSLParameters sslParameters) {
        this.sslContext = sslContext;
        this.sslParameters = sslParameters;
    }
    
    @Override
    public SSLEngine newSslEngine() {
        SSLEngine engine = sslContext.createSSLEngine();
        engine.setSSLParameters(sslParameters);
        return engine;
    }
    
    @Override
    public SSLEngine newSslEngine(String peerHost, int peerPort) {
        SSLEngine engine = sslContext.createSSLEngine(peerHost, peerPort);
        engine.setSSLParameters(sslParameters);
        return engine;
    }
}

public void good_case_7() {
    // AWS SDK v2 Apache HTTP client with strong cipher suites
    try {
        // ok: java-missing-supported-cipher-suites
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        KeyManager[] keyManagers = null;
        TrustManager[] trustManagers = null;
        sslContext.init(keyManagers, trustManagers, null);
        
        // Configure with strong cipher suites
        SSLParameters sslParameters = sslContext.getDefaultSSLParameters();
        sslParameters.setProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
        sslParameters.setCipherSuites(new String[] {
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        });
        
        ApacheHttpClient.Builder builder = ApacheHttpClient.builder()
            .tlsKeyManagersProvider(() -> keyManagers)
            .tlsTrustManagersProvider(() -> trustManagers)
            .sslProvider(() -> sslContext);
        
        SdkHttpClient httpClient = builder.build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    // AWS SDK v1 with strong cipher suites
    // ok: java-missing-supported-cipher-suites
    ClientConfiguration clientConfig = new ClientConfiguration();
    clientConfig.setProtocol(com.amazonaws.Protocol.HTTPS);
    
    // Configure with strong cipher suites
    clientConfig.setTlsKeyManagersProvider(() -> null);
    clientConfig.setTlsTrustManagersProvider(() -> null);
    clientConfig.setCipherSuites("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
    clientConfig.setSecureRandom(new java.security.SecureRandom());
    
    AmazonHttpClient client = new AmazonHttpClient(clientConfig);
}

public void good_case_9() {
    // Google HTTP Client with strong cipher suites
    try {
        // ok: java-missing-supported-cipher-suites
        NetHttpTransport.Builder builder = new NetHttpTransport.Builder();
        
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, null);
        
        // Configure with strong cipher suites
        SSLSocketFactory socketFactory = new StrongCipherSocketFactoryForGoogle(sslContext.getSocketFactory());
        builder.setSslSocketFactory(socketFactory);
        
        HttpTransport httpTransport = builder.build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// Helper class for good_case_9
class StrongCipherSocketFactoryForGoogle extends SSLSocketFactory {
    private final SSLSocketFactory delegate;
    private final String[] strongCipherSuites = {
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    };
    
    public StrongCipherSocketFactoryForGoogle(SSLSocketFactory delegate) {
        this.delegate = delegate;
    }
    
    @Override
    public String[] getDefaultCipherSuites() {
        return strongCipherSuites;
    }
    
    @Override
    public String[] getSupportedCipherSuites() {
        return strongCipherSuites;
    }
    
    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        SSLSocket socket = (SSLSocket) delegate.createSocket(s, host, port, autoClose);
        socket.setEnabledCipherSuites(strongCipherSuites);
        return socket;
    }
    
    @Override
    public Socket createSocket(String host, int port) throws IOException {
        SSLSocket socket = (SSLSocket) delegate.createSocket(host, port);
        socket.setEnabledCipherSuites(strongCipherSuites);
        return socket;
    }
    
    @Override
    public Socket createSocket(String host, int port, java.net.InetAddress localHost, int localPort) throws IOException {
        SSLSocket socket = (SSLSocket) delegate.createSocket(host, port, localHost, localPort);
        socket.setEnabledCipherSuites(strongCipherSuites);
        return socket;
    }
    
    @Override
    public Socket createSocket(java.net.InetAddress host, int port) throws IOException {
        SSLSocket socket = (SSLSocket) delegate.createSocket(host, port);
        socket.setEnabledCipherSuites(strongCipherSuites);
        return socket;
    }
    
    @Override
    public Socket createSocket(java.net.InetAddress address, int port, java.net.InetAddress localAddress, int localPort) throws IOException {
        SSLSocket socket = (SSLSocket) delegate.createSocket(address, port, localAddress, localPort);
        socket.setEnabledCipherSuites(strongCipherSuites);
        return socket;
    }
}

public void good_case_10() {
    // Jetty HTTP Client with strong cipher suites
    // ok: java-missing-supported-cipher-suites
    SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
    sslContextFactory.setIncludeProtocols("TLSv1.2", "TLSv1.3");
    sslContextFactory.setIncludeCipherSuites(
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384"
    );
    
    org.eclipse.jetty.client.HttpClient client = new org.eclipse.jetty.client.HttpClient(sslContextFactory);
}

public void good_case_11() {
    // Vert.x Web Client with strong cipher suites
    Vertx vertx = Vertx.vertx();
    
    // ok: java-missing-supported-cipher-suites
    HttpClientOptions options = new HttpClientOptions()
        .setSsl(true)
        .setEnabledSecureTransportProtocols(new HashSet<>(Arrays.asList("TLSv1.2", "TLSv1.3")))
        .setEnabledCipherSuites(Arrays.asList(
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384"
        ));
    
    WebClient client = WebClient.create(vertx, new WebClientOptions(options));
}

public void good_case_12() {
    // Ning AsyncHttpClient with strong cipher suites
    // ok: java-missing-supported-cipher-suites
    AsyncHttpClientConfig config = new AsyncHttpClientConfig.Builder()
        .setSSLContext(createStrongSslContext())
        .build();
    
    com.ning.http.client.AsyncHttpClient client = new com.ning.http.client.AsyncHttpClient(config);
}

private SSLContext createStrongSslContext() {
    try {
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, null);
        
        // Configure with strong cipher suites
        SSLParameters sslParameters = sslContext.getDefaultSSLParameters();
        sslParameters.setProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
        sslParameters.setCipherSuites(new String[] {
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        });
        
        return sslContext;
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void good_case_13() {
    // Jersey Client with strong cipher suites
    // ok: java-missing-supported-cipher-suites
    SslConfigurator sslConfig = SslConfigurator.newInstance()
        .securityProtocol("TLSv1.2")
        .enabledCipherSuites(
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        );
    
    SSLContext sslContext = sslConfig.createSSLContext();
    
    JerseyClient client = JerseyClientBuilder.createClient()
        .sslContext(sslContext)
        .build();
}

public void good_case_14() {
    // Netflix Ribbon RestClient with strong cipher suites
    // ok: java-missing-supported-cipher-suites
    IClientConfig clientConfig = new DefaultClientConfigImpl();
    clientConfig.loadProperties("ribbon-client");
    
    // Configure with strong cipher suites
    System.setProperty("https.cipherSuites", 
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256," +
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384," +
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256," +
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    );
    System.setProperty("https.protocols", "TLSv1.2,TLSv1.3");
    
    RestClient client = new RestClient(clientConfig);
}

public void good_case_15() {
    // Netty with strong cipher suites
    try {
        // ok: java-missing-supported-cipher-suites
        SslContext sslContext = SslContextBuilder.forClient()
            .protocols("TLSv1.2", "TLSv1.3")
            .ciphers(Arrays.asList(
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384"
            ), SupportedCipherSuiteFilter.INSTANCE)
            .build();
        
        // Use this SslContext with a Netty HTTP client
    } catch (Exception e) {
        e.printStackTrace();
    }
}